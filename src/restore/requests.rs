//! Asynchronous restored requests, isolated archives and worker lifetime.
use super::{ContextState, RESTORED_PORT, options::ASYNC_DATA_TYPES};
use crate::{asr, mux::Session, wire};
use anyhow::{Result, bail, ensure};
use plist::Value;
use std::{
    collections::HashMap,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

/// Asynchronous requests always use their own device-supplied service port.
/// Keeping the control connection in one thread prevents interleaved plist frames.
pub struct AsyncRequests {
    session: Session,
    workers: HashMap<u16, JoinHandle<()>>,
    errors: mpsc::Receiver<String>,
    sender: mpsc::Sender<String>,
}
impl AsyncRequests {
    pub fn new(session: &Session) -> Self {
        let (sender, errors) = mpsc::channel();
        Self {
            session: session.clone(),
            workers: HashMap::new(),
            errors,
            sender,
        }
    }
    pub fn spawn(&mut self, state: &ContextState, request: Value) -> Result<()> {
        let kind = wire::string(&request, &["DataType"])?;
        ensure!(
            ASYNC_DATA_TYPES.contains(&kind),
            "unsupported async data type {kind}"
        );
        for (_, worker) in self.workers.extract_if(|_, worker| worker.is_finished()) {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("async worker panicked"))?;
        }
        self.check()?;
        ensure!(
            self.workers.len() < 16,
            "too many active asynchronous data requests"
        );
        let port = asr::data_port(&request, 0)?;
        ensure!(
            port != 0 && port != RESTORED_PORT,
            "async request requires a separate DataPort"
        );
        ensure!(
            !self.workers.contains_key(&port),
            "async DataPort {port} is already in use"
        );
        // HTTP assets do not read the IPSW. Other handlers receive their own
        // archive so ZIP seeks cannot race with another image/component reader.
        let assets = state.assets.clone();
        let mut state = if matches!(kind, "URLAsset" | "StreamedImageDecryptionKey") {
            None
        } else {
            Some(state.reopen()?)
        };
        let session = self.session.clone();
        let sender = self.sender.clone();
        let kind = kind.to_owned();
        let worker = thread::Builder::new()
            .name(format!("zalivka-{kind}"))
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        let mut stream = session.connect_retry(port, Duration::from_secs(60))?;
                        if let Some(state) = &mut state {
                            state.serve_on(&session, &mut stream, &request)
                        } else {
                            let response = assets.response(&request)?;
                            wire::send_binary(&mut stream, &response)
                        }
                    }))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("async worker panicked")));
                if let Err(error) = result {
                    let _ = sender.send(format!(
                        "asynchronous {kind} on DataPort {port} failed: {error:#}"
                    ));
                    session.cancel();
                }
            })?;
        self.workers.insert(port, worker);
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        if let Ok(error) = self.errors.try_recv() {
            bail!("{error}");
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        for (_, worker) in self.workers.drain() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("async worker panicked"))?;
        }
        self.check()
    }
}
impl Drop for AsyncRequests {
    fn drop(&mut self) {
        self.session.cancel();
        for (_, worker) in self.workers.drain() {
            let _ = worker.join();
        }
    }
}
