//! Asynchronous restored requests, isolated archives and worker lifetime.
use super::{ContextState, data::serve_asset, data_type::DataType};
use crate::{mux::Session, wire};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    collections::HashMap,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_WORKERS: usize = 16;
type Completion = (u16, Result<()>);

/// Asynchronous requests own their service ports and ZIP readers. Completion
/// returns both the result and the port, so reaping and error reporting agree.
pub struct AsyncRequests {
    session: Session,
    workers: HashMap<u16, JoinHandle<()>>,
    completed: mpsc::Receiver<Completion>,
    sender: mpsc::Sender<Completion>,
}

impl AsyncRequests {
    pub fn new(session: &Session) -> Self {
        let (sender, completed) = mpsc::channel();
        Self {
            session: session.clone(),
            workers: HashMap::new(),
            completed,
            sender,
        }
    }

    pub fn spawn(&mut self, state: &ContextState, request: Value) -> Result<()> {
        let kind = wire::data_type(&request)?;
        let data_type =
            DataType::parse(kind).with_context(|| format!("unsupported async data type {kind}"))?;
        self.check()?;
        ensure!(
            self.workers.len() < MAX_WORKERS,
            "too many active asynchronous data requests"
        );
        let port = data_type.data_port(&request, true)?;
        ensure!(
            !self.workers.contains_key(&port),
            "async DataPort {port} is already in use"
        );
        // HTTP assets do not read the IPSW. Other handlers receive their own
        // archive so ZIP seeks cannot race with another image/component reader.
        let assets = state.assets.clone();
        let mut state = if data_type == DataType::Asset {
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
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut stream = session.connect_retry(port, Duration::from_secs(60))?;
                    if let Some(state) = &mut state {
                        state.serve_on(&session, &mut stream, &request, data_type)
                    } else {
                        serve_asset(&assets, &mut stream, &request)
                    }
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("async worker panicked")))
                .with_context(|| format!("asynchronous {kind} on DataPort {port} failed"));
                let failed = result.is_err();
                // Publish the original error before waking a blocked control read
                // through cancellation. check() must see the cause, not just cancel.
                let _ = sender.send((port, result));
                if failed {
                    session.cancel();
                }
            })?;
        self.workers.insert(port, worker);
        Ok(())
    }

    pub fn check(&mut self) -> Result<()> {
        while let Ok((port, result)) = self.completed.try_recv() {
            self.complete(port, result)?;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        while !self.workers.is_empty() {
            let (port, result) = self.completed.recv().context("waiting for async workers")?;
            self.complete(port, result)?;
        }
        Ok(())
    }

    fn complete(&mut self, port: u16, result: Result<()>) -> Result<()> {
        let worker = self
            .workers
            .remove(&port)
            .context("unknown async worker completion")?;
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("async worker panicked"))?;
        result
    }
}

impl Drop for AsyncRequests {
    fn drop(&mut self) {
        self.session.cancel();
        // Removing one completed worker at a time leaves every other handle here
        // for cancellation and joining, including an early error from finish().
        for (_, worker) in self.workers.drain() {
            let _ = worker.join();
        }
    }
}
