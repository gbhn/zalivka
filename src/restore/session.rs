//! Restored message loop, reconnect policy and final status acknowledgement.
use super::{
    AsyncRequests, RestoreSession,
    attestation::Attestation,
    connection::confirm_restore_service,
    events::{log_checkpoint, log_progress, operation_weights, record_message},
    options,
};
use crate::{
    mux::{MuxStream, Session},
    wire,
};
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use std::{
    fs::File,
    io::{Read, Write},
    time::{Duration, Instant},
};

pub fn validate_final_status(message: &Value) -> Result<()> {
    ensure!(
        wire::string(message, &["MsgType"])? == "StatusMsg",
        "expected a final StatusMsg"
    );
    let code = wire::get(message, &["Status"])?
        .as_signed_integer()
        .context("invalid StatusMsg.Status: expected signed plist integer")?;
    let amr = wire::get(message, &["AMRError"])
        .ok()
        .map(|v| {
            v.as_signed_integer()
                .context("invalid StatusMsg.AMRError: expected signed plist integer")
        })
        .transpose()?
        .unwrap_or(0);
    ensure!(
        code == 0 && amr == 0,
        "restored failed: Status={code}, AMRError={amr}, Log={}",
        wire::string(message, &["Log"]).unwrap_or("unavailable")
    );
    Ok(())
}

pub(super) fn acknowledge_final_status(main: &mut impl Write) -> Result<()> {
    // Socket EOF negotiation is not available on our direct USB-mux transport:
    // it uses RST for teardown, not TCP FIN. Do not promise a socket half-close.
    wire::send(
        main,
        &wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())]),
    )
    .context("acknowledging final restore status")
}

pub(super) fn finish_final_status(
    main: &mut impl Write,
    message: &Value,
    finish_requests: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let status = validate_final_status(message).and_then(|()| finish_requests());
    // Try the ACK even if a request worker failed. Preserve the device or worker
    // failure when acknowledging also fails or the session is already cancelled.
    let acknowledged = acknowledge_final_status(main);
    status.and(acknowledged)
}

pub(super) fn wait_for_restore_close(
    main: &mut MuxStream,
    session: &Session,
    timeout: Duration,
) -> Result<()> {
    let previous_timeout = main.read_timeout();
    let deadline = Instant::now() + timeout;
    let result = (|| {
        let mut buffer = [0; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(
                !remaining.is_zero(),
                "restore channel did not close after final ACK"
            );
            main.set_read_timeout(remaining);
            match main.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    if session.disconnected() {
                        return Ok(());
                    }
                    return Err(error).context("waiting for device to close the restore channel");
                }
            }
        }
    })();
    main.set_read_timeout(previous_timeout);
    result
}

/// One connection attempt. Drop request workers before FDR so cancellation
/// releases blocked mux reads before either group is joined.
struct Connection {
    requests: AsyncRequests,
    fdr: crate::fdr::Fdr,
    main: MuxStream,
    session: Session,
}

impl Connection {
    fn new(session: &Session, main: MuxStream) -> Result<Self> {
        let fdr = crate::fdr::Fdr::start(session)?;
        Ok(Self {
            requests: AsyncRequests::new(session),
            fdr,
            main,
            session: session.clone(),
        })
    }

    fn check(&mut self) -> Result<()> {
        self.requests.check()?;
        self.fdr.check()
    }

    fn receive(&mut self, log: &mut Option<File>) -> Result<Value> {
        self.check()?;
        let received = wire::receive(&mut self.main);
        // A worker publishes its cause before cancelling the mux. Preserve
        // that cause when cancellation wakes a blocked control-channel read.
        self.check()?;
        let message =
            received.context("reading restored message before a successful final status")?;
        if let Some(warning) = record_message(log, &message) {
            crate::logging::publish(warning);
        }
        Ok(message)
    }

    fn finish(&mut self, message: &Value, attestation: &Attestation) -> Result<()> {
        finish_final_status(&mut self.main, message, || {
            self.requests.finish()?;
            attestation.finish()
        })?;
        crate::log!(Debug, "restore:usb", "Waiting for channel closure");
        wait_for_restore_close(&mut self.main, &self.session, Duration::from_secs(60))?;
        crate::log!(Debug, "restore:usb", "Channel closed");
        Ok(())
    }
}

impl RestoreSession {
    fn await_final_status(
        &mut self,
        connection: &mut Connection,
        log: &mut Option<File>,
        attestation: &mut Attestation,
        provisioning_error: &mut bool,
    ) -> Result<Value> {
        loop {
            let message = connection.receive(log)?;
            match wire::string(&message, &["MsgType"])? {
                "DataRequestMsg" => {
                    self.serve(&connection.session, &mut connection.main, &message)?
                }
                "AsyncDataRequestMsg" => connection.requests.spawn(self, message)?,
                "StatusMsg" => {
                    // Stop FDR before acknowledgement, but keep the connection
                    // and all request workers alive until finalization finishes.
                    connection.fdr.stop();
                    return Ok(message);
                }
                "ProgressMsg" => {
                    if let Some(event) = operation_weights(&message) {
                        event.emit();
                    }
                    log_progress(&message, crate::logging::publish)?.emit();
                }
                "CheckpointMsg" => {
                    let (event, failed) = log_checkpoint(&message, crate::logging::publish)?;
                    *provisioning_error |= failed;
                    event.emit();
                }
                "AsyncWait" => {}
                "RestoreProtocol" => ensure!(
                    wire::string(&message, &["Arguments", "RestoreProtocol"])? == "MuxSocket",
                    "device requested an unsupported restore transport"
                ),
                "RestoreAttestation" => {
                    if let Some(reply) = attestation.handle(&message)? {
                        wire::send(&mut connection.main, &reply)?;
                    }
                }
                "RestoredCrash" => bail!("restored crashed: {message:?}"),
                "PreviousRestoreLogMsg" => crate::log!(
                    Trace,
                    "restored:log",
                    "Previous journal: {}",
                    wire::string(&message, &["PreviousRestoreLog"]).unwrap_or("unavailable")
                ),
                name => bail!("unsupported restored message {name}; the restore did not complete"),
            }
        }
    }
}

/// Each connection must confirm the device identity and restored protocol.
/// Reconnect only during the working phase, before a final status arrives.
pub(super) fn run(
    state: &mut RestoreSession,
    mut bootx_error: Option<anyhow::Error>,
    mut log: Option<File>,
    mut attestation: Attestation,
    mut connect: impl FnMut(&crate::device::DeviceInfo) -> Result<(Session, MuxStream, u64)>,
) -> Result<()> {
    let mut started = false;
    let mut provisioning_error = false;
    let mut protocol = None;
    for attempt in 0..=3 {
        let (session, main, version) =
            confirm_restore_service(bootx_error.take(), || connect(&state.context.device))?;
        if let Some(previous) = protocol {
            ensure!(
                version == previous,
                "restored protocol changed after reconnection; restart from DFU explicitly"
            );
        }
        protocol = Some(version);
        let outcome = (|| -> Result<_> {
            let mut connection = Connection::new(&session, main)?;
            if !started {
                // A partially written StartRestore must never be replayed.
                started = true;
                wire::send(
                    &mut connection.main,
                    &wire::dict([
                        ("Request", "StartRestore".into()),
                        ("Label", "zalivka".into()),
                        ("RestoreProtocolVersion", version.into()),
                        ("RestoreOptions", options(&state.context.restore.identity)?),
                    ]),
                )?;
            }
            let message = state.await_final_status(
                &mut connection,
                &mut log,
                &mut attestation,
                &mut provisioning_error,
            )?;
            Ok((connection, message))
        })();
        match outcome {
            Ok((mut connection, message)) => {
                // Final status leaves the reconnect loop. Worker, attestation,
                // ACK and closure failures are terminal regardless of USB state.
                connection.finish(&message, &attestation)?;
                crate::log!(
                    Info,
                    "restore",
                    "Success; ECID={:016x}",
                    state.context.device.ecid
                );
                if provisioning_error {
                    let message = "Could not obtain Apple certificates. Connect the Mac to Wi-Fi or Ethernet and complete activation.";
                    crate::log!(
                        Warning,
                        "restore",
                        "Apple certificate error; Mac activation required"
                    );
                    crate::progress::Event::ProvisioningWarning {
                        message: message.into(),
                    }
                    .emit();
                }
                return Ok(());
            }
            Err(error) if session.disconnected() && attempt < 3 => {
                session.cancel();
                crate::log!(
                    Warning,
                    "restore:usb",
                    "Connection lost: {error:#}; waiting for Mac"
                );
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}
