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
    time::{Duration, Instant},
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
                crate::log!(Debug, "fdr:control", "v2: {error:#}; falling back to v1");
                let (control, port) = control_handshake(session, 1)?;
                (control, port, 1)
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_session = session.clone();
        let (tx, errors) = mpsc::channel();
        let worker =
            thread::Builder::new()
                .name("zalivka-fdr".into())
                .spawn(crate::progress::inherit(move || {
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
                        crate::log!(Error, "fdr:control", "{e:#}");
                        let _ = tx.send(format!("FDR control failed: {e:#}"));
                        worker_session.cancel();
                    }
                    // EOF on control also ends its proxy children. Otherwise idle
                    // children can keep this worker blocked in join indefinitely.
                    worker_stop.store(true, Ordering::Relaxed);
                    for child in children {
                        let _ = child.join();
                    }
                    crate::log!(Trace, "fdr:control", "Stopped");
                }))?;
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
        crate::log!(Trace, "fdr:control", "Stopping");
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
        crate::log!(
            Trace,
            "fdr:control",
            "Command={:#06x}",
            u16::from_le_bytes(cmd)
        );
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
                crate::log!(Debug, "fdr:conn", "Sync {sync_id}: port={port}");
                // Match the reference Sync ordering: complete HelloConn
                // before accepting another Sync. Only proxy handling is
                // concurrent; parallel connects could reorder requests.
                let connection = (|| -> Result<MuxStream> {
                    let mut connection = session.connect(port)?;
                    connection.set_log_source("fdr:conn");
                    connection.set_read_timeout(Duration::from_secs(20));
                    connection.write_all(b"HelloConn\0")?;
                    connection_handshake(&mut connection, version)
                        .context("FDR connection handshake")?;
                    Ok(connection)
                })();
                let connection = match connection {
                    Ok(connection) => connection,
                    Err(error) => {
                        if !stop.load(Ordering::Relaxed) {
                            crate::log!(Warning, "fdr:conn", "Sync {sync_id}: {error:#}");
                        }
                        continue;
                    }
                };
                crate::log!(Debug, "fdr:conn", "Sync {sync_id}: HelloConn complete");
                let child_stop = Arc::clone(stop);
                let child_id = sync_id;
                children.push(
                    thread::Builder::new()
                        .name("zalivka-fdr-connection".into())
                        .spawn(crate::progress::inherit(move || {
                            let result =
                                handle_connection(connection, &child_stop, crate::proxy::connect);
                            // FDR connections have independent lifetimes. The
                            // device can close one or request a replacement;
                            // restored's final status decides restore success.
                            if let Err(e) = result
                                && !child_stop.load(Ordering::Relaxed)
                            {
                                crate::log!(
                                    Warning,
                                    "fdr:conn",
                                    "Sync {child_id}, port {port}: {e:#}"
                                );
                            } else if !child_stop.load(Ordering::Relaxed) {
                                crate::log!(Debug, "fdr:conn", "Sync {child_id}: closed");
                            }
                        }))?,
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

pub(crate) fn handle_connection<S: Read + Write>(
    mut stream: MuxStream,
    stop: &AtomicBool,
    mut connect: impl FnMut(&str, u16) -> Result<S>,
) -> Result<()> {
    stream.set_log_source("fdr:conn");
    let channel = stream.local_port();
    stream.set_read_timeout(Duration::from_secs(1));
    let mut cmd = [0; 2];
    while read_exact_idle(&mut stream, &mut cmd, stop).context("reading FDR connection command")? {
        crate::log!(
            Trace,
            "fdr:conn",
            "Command={:#06x}",
            u16::from_le_bytes(cmd)
        );
        match u16::from_le_bytes(cmd) {
            0xbbaa => {
                crate::log!(Trace, "fdr:conn", "Ping");
                stream.set_read_timeout(Duration::from_secs(20));
                ping(&mut stream)?;
                stream.set_read_timeout(Duration::from_secs(1));
            }
            _ if cmd[0] == 5 && cmd[1] != 0 => {
                stream.set_read_timeout(Duration::from_secs(20));
                let (host, port, mut socket) =
                    proxy_handshake(&mut stream, cmd[1], |host, port| {
                        crate::log!(Debug, "fdr:proxy", "Connecting to {host}:{port}");
                        let connecting = Instant::now();
                        let socket = connect(host, port)?;
                        crate::log!(
                            Debug,
                            "fdr:proxy",
                            "{host}:{port}: connected in {:.3} s",
                            connecting.elapsed().as_secs_f64()
                        );
                        Ok(socket)
                    })?;
                stream.set_read_timeout(Duration::from_millis(100));
                let mut buffer = vec![0; 32768];
                let relaying = Instant::now();
                let mut from_mac = 0u64;
                let mut from_upstream = 0u64;
                let result = (|| -> Result<&str> {
                    while !stop.load(Ordering::Relaxed) {
                        match stream.read(&mut buffer) {
                            Ok(0) => return Ok("EOF from Mac"),
                            Ok(n) => {
                                crate::logging::bytes(
                                    "fdr:proxy",
                                    format_args!("#{channel} {host}:{port} TX offset={from_mac}"),
                                    &buffer[..n],
                                );
                                from_mac += n as u64;
                                socket
                                    .write_all(&buffer[..n])
                                    .context("writing FDR payload to proxy/Apple")?;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(e) => return Err(e).context("reading FDR payload from Mac"),
                        }
                        match socket.read(&mut buffer) {
                            Ok(0) => return Ok("EOF from proxy/Apple"),
                            Ok(n) => {
                                crate::logging::bytes(
                                    "fdr:proxy",
                                    format_args!(
                                        "#{channel} {host}:{port} RX offset={from_upstream}"
                                    ),
                                    &buffer[..n],
                                );
                                from_upstream += n as u64;
                                stream
                                    .write_all(&buffer[..n])
                                    .context("writing FDR payload to Mac")?;
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                ) => {}
                            Err(e) => {
                                return Err(e).context("reading FDR payload from proxy/Apple");
                            }
                        }
                    }
                    Ok("FDR stopped")
                })();
                let reason = match &result {
                    Ok(reason) => (*reason).to_owned(),
                    Err(error) => format!("{error:#}"),
                };
                crate::log!(
                    Debug,
                    "fdr:proxy",
                    "{host}:{port}: {reason}; TX={from_mac} B, RX={from_upstream} B; {:.3} s",
                    relaying.elapsed().as_secs_f64()
                );
                return result.map(|_| ());
            }
            n => bail!("unsupported FDR connection command {n:#x}"),
        }
    }
    Ok(())
}
