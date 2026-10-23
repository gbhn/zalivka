//! FDR control v2 and the TCP proxy used by restoreOS to recover device factory data.
mod protocol;
use crate::mux::{MuxStream, Session};
use anyhow::{Context, Result, bail, ensure};
pub use protocol::validate_proxy_target;
use protocol::{connection_handshake, control_handshake, ping, proxy_handshake, read_exact_idle};
use std::{
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct Fdr {
    session: Session,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    errors: mpsc::Receiver<String>,
}

impl Fdr {
    pub fn start(session: &Session) -> Result<Self> {
        let (mut control, port, version) = match control_handshake(session, 2) {
            Ok((control, port)) => (control, port, 2),
            Err(error) => {
                eprintln!("FDR v2 handshake failed ({error:#}); trying v1");
                let (control, port) = control_handshake(session, 1)?;
                (control, port, 1)
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_session = session.clone();
        let (tx, errors) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("zalivka-fdr".into())
            .spawn(move || {
                let mut children: Vec<JoinHandle<()>> = Vec::new();
                let result = control_loop(
                    &mut control,
                    port,
                    version,
                    &worker_session,
                    &worker_stop,
                    &mut children,
                );
                if let Err(e) = result
                    && !worker_stop.load(Ordering::Relaxed)
                {
                    let _ = tx.send(format!("FDR control failed: {e:#}"));
                    worker_session.cancel();
                }
                for child in children {
                    let _ = child.join();
                }
            })?;
        Ok(Self {
            session: session.clone(),
            stop,
            worker: Some(worker),
            errors,
        })
    }

    pub fn check(&self) -> Result<()> {
        if let Ok(error) = self.errors.try_recv() {
            bail!("{error}");
        }
        Ok(())
    }

    /// Final restore status ends FDR work. Suppress teardown errors without
    /// cancelling the shared session while its main channel acknowledges status.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn control_loop(
    control: &mut MuxStream,
    port: u16,
    version: u8,
    session: &Session,
    stop: &Arc<AtomicBool>,
    children: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    let mut sync_id = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let mut cmd = [0; 2];
        if !read_exact_idle(control, &mut cmd, stop)? {
            break;
        }
        match u16::from_le_bytes(cmd) {
            1 => {
                if !read_exact_idle(control, &mut cmd, stop)? {
                    ensure!(stop.load(Ordering::Relaxed), "FDR sync command truncated");
                    break;
                }
                for child in children.extract_if(.., |child| child.is_finished()) {
                    child
                        .join()
                        .map_err(|_| anyhow::anyhow!("FDR worker panicked"))?;
                }
                ensure!(children.len() < 64, "too many active FDR connections");
                sync_id += 1;
                eprintln!("FDR Sync {sync_id}: connecting port {port}");
                // Match the reference Sync ordering: complete HelloConn
                // before accepting another Sync. Only proxy handling is
                // concurrent; parallel connects could reorder requests.
                let connection = (|| -> Result<MuxStream> {
                    let mut connection = session.connect(port)?;
                    connection.write_all(b"HelloConn\0")?;
                    connection_handshake(&mut connection, version)
                        .context("FDR connection handshake")?;
                    Ok(connection)
                })();
                let connection = match connection {
                    Ok(connection) => connection,
                    Err(error) => {
                        if !stop.load(Ordering::Relaxed) {
                            eprintln!(
                                "FDR Sync {sync_id} connection failed: {error:#}; waiting for restored status"
                            );
                        }
                        continue;
                    }
                };
                eprintln!("FDR Sync {sync_id}: HelloConn completed");
                let child_stop = Arc::clone(stop);
                let child_id = sync_id;
                children.push(
                    thread::Builder::new()
                        .name("zalivka-fdr-connection".into())
                        .spawn(move || {
                            let result = handle_connection(connection, &child_stop);
                            // FDR connections have independent lifetimes. The
                            // device can close one or request a replacement;
                            // restored's final status decides restore success.
                            if let Err(e) = result
                                && !child_stop.load(Ordering::Relaxed)
                            {
                                eprintln!(
                                    "FDR connection {child_id} on port {port} ended with an error: {e:#}; waiting for restored status"
                                );
                            } else if !child_stop.load(Ordering::Relaxed) {
                                eprintln!("FDR connection {child_id}: closed");
                            }
                        })?,
                );
            }
            0xbbaa => ping(control)?,
            n => bail!("unsupported FDR control command {n:#x}"),
        }
    }
    Ok(())
}

impl Drop for Fdr {
    fn drop(&mut self) {
        self.stop();
        self.session.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn handle_connection(mut stream: MuxStream, stop: &AtomicBool) -> Result<()> {
    let mut cmd = [0; 2];
    while read_exact_idle(&mut stream, &mut cmd, stop).context("reading FDR connection command")? {
        match u16::from_le_bytes(cmd) {
            0xbbaa => {
                eprintln!("FDR connection: Ping");
                ping(&mut stream)?;
            }
            0x105 => {
                let (host, port) = proxy_handshake(&mut stream)?;
                eprintln!("FDR proxy: connecting {host}:{port}");
                let mut socket =
                    crate::proxy::connect(&host, port).context("connecting FDR Apple endpoint")?;
                stream.set_read_timeout(Duration::from_millis(100));
                let mut buffer = vec![0; 32768];
                while !stop.load(Ordering::Relaxed) {
                    match stream.read(&mut buffer) {
                        Ok(0) => return Ok(()),
                        Ok(n) => socket.write_all(&buffer[..n])?,
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => return Err(e.into()),
                    }
                    match socket.read(&mut buffer) {
                        Ok(0) => return Ok(()),
                        Ok(n) => stream.write_all(&buffer[..n])?,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                return Ok(());
            }
            n => bail!("unsupported FDR connection command {n:#x}"),
        }
    }
    Ok(())
}
