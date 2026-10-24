//! Restored message loop, reconnect policy and final status acknowledgement.
use super::{
    AsyncRequests, ContextState,
    connection::{confirm_restore_service, wait_restored},
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

pub(super) fn acknowledge_final_status(main: &mut MuxStream) -> Result<()> {
    // Socket EOF negotiation is not available on our direct USB-mux transport:
    // it uses RST for teardown, not TCP FIN. Do not promise a socket half-close.
    wire::send(
        main,
        &wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())]),
    )
    .context("acknowledging final restore status")
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

pub(super) fn attestation_reply(message: &Value) -> Result<Value> {
    let state = wire::string(message, &["RestoreAttestationState"])?;
    ensure!(
        state == "RestoreShouldAttest",
        "unexpected restore attestation state {state}: certificate verification is not implemented"
    );
    eprintln!("Restore attestation was requested but will not be verified by this client");
    Ok(wire::dict([("RestoreShouldAttest", false.into())]))
}

pub(super) fn log_progress(
    message: &Value,
    mut output: impl Write,
) -> Result<crate::progress::Event> {
    let operation = wire::get(message, &["Operation"])
        .and_then(wire::number)
        .context("invalid ProgressMsg.Operation")?;
    let value = wire::get(message, &["Progress"])?;
    let progress = value.as_signed_integer().with_context(|| {
        format!("invalid ProgressMsg.Progress: expected signed plist integer, got {value:?}")
    })?;
    // restored sends -1 while waiting for storage: no percentage is available yet.
    if progress < 0 {
        writeln!(
            output,
            "Operation {operation}: progress unavailable ({progress})"
        )?;
    } else {
        writeln!(output, "Operation {operation}: {progress}%")?;
    }
    Ok(crate::progress::Event::OperationProgress {
        operation,
        progress,
    })
}

pub(super) fn log_checkpoint(
    message: &Value,
    mut output: impl Write,
) -> Result<Option<crate::progress::Event>> {
    let id = wire::number(wire::get(message, &["CHECKPOINT_ID"])?)?;
    let name = wire::string(message, &["CHECKPOINT_NAME"]).unwrap_or("unknown");
    let result = wire::get(message, &["CHECKPOINT_RESULT"])?
        .as_signed_integer()
        .context("invalid checkpoint result")?;
    let phase = if wire::boolean(message, &["CHECKPOINT_COMPLETE"]) {
        "completed"
    } else {
        "started"
    };
    // Checkpoints describe individual steps; only StatusMsg decides the final result.
    writeln!(
        output,
        "Checkpoint {phase}: id=0x{id:x}, name={name}, result={result}"
    )?;
    for (key, label) in [
        ("CHECKPOINT_WARNING", "warning"),
        ("CHECKPOINT_ERROR", "error"),
    ] {
        if let Ok(text) = wire::string(message, &[key]) {
            writeln!(output, "Checkpoint {label}: id=0x{id:x}, {text}")?;
        }
    }
    Ok((!wire::boolean(message, &["CHECKPOINT_COMPLETE"]))
        .then(|| crate::progress::Event::Checkpoint { name: name.into() }))
}

pub(super) fn run(
    state: &mut ContextState,
    mut bootx_error: Option<anyhow::Error>,
    mut log: Option<File>,
) -> Result<()> {
    let ecid = state.device.ecid;
    let mut started = false;
    let mut final_received = false;
    let mut protocol = None;
    for attempt in 0..=3 {
        let (session, mut main, version) =
            confirm_restore_service(bootx_error.take(), || wait_restored(&state.device))?;
        if let Some(previous) = protocol {
            ensure!(
                version == previous,
                "restored protocol changed after reconnection; restart from DFU explicitly"
            );
        }
        protocol = Some(version);
        let outcome = (|| -> Result<()> {
            let fdr = crate::fdr::Fdr::start(&session)?;
            let mut requests = AsyncRequests::new(&session);
            if !started {
                // A partially written StartRestore must never be replayed.
                started = true;
                wire::send(
                    &mut main,
                    &wire::dict([
                        ("Request", "StartRestore".into()),
                        ("Label", "zalivka".into()),
                        ("RestoreProtocolVersion", version.into()),
                        ("RestoreOptions", options(&state.restore.identity)?),
                    ]),
                )?;
            }
            loop {
                requests.check()?;
                fdr.check()?;
                let received = wire::receive(&mut main);
                requests.check()?;
                fdr.check()?;
                let message = received
                    .context("reading restored message before a successful final status")?;
                if let Some(log) = &mut log {
                    serde_json::to_writer(&mut *log, &message)?;
                    log.write_all(b"\n")?;
                    log.flush()?;
                }
                match wire::string(&message, &["MsgType"])? {
                    "DataRequestMsg" => state.serve(&session, &mut main, &message)?,
                    "AsyncDataRequestMsg" => requests.spawn(state, message)?,
                    "StatusMsg" => {
                        final_received = true;
                        fdr.stop();
                        let status = validate_final_status(&message);
                        if status.is_ok() {
                            requests.finish()?;
                        }
                        let acknowledged = acknowledge_final_status(&mut main);
                        // A failed final status must also be acknowledged. Keep
                        // the device's failure if the acknowledgement disconnects.
                        status?;
                        acknowledged?;
                        eprintln!("Restore service reported success for ECID {ecid:016x}");
                        eprintln!("Waiting for the device to close the restore channel after ACK");
                        wait_for_restore_close(&mut main, &session, Duration::from_secs(60))?;
                        eprintln!(
                            "Restore channel closed after final ACK; restore attestation was not verified"
                        );
                        return Ok(());
                    }
                    "ProgressMsg" => log_progress(&message, std::io::stderr().lock())?.emit(),
                    "CheckpointMsg" => {
                        if let Some(event) = log_checkpoint(&message, std::io::stderr().lock())? {
                            event.emit();
                        }
                    }
                    "AsyncWait" => {}
                    "RestoreProtocol" => ensure!(
                        wire::string(&message, &["Arguments", "RestoreProtocol"])? == "MuxSocket",
                        "device requested an unsupported restore transport"
                    ),
                    "RestoreAttestation" => wire::send(&mut main, &attestation_reply(&message)?)?,
                    "RestoredCrash" => bail!("restored crashed: {message:?}"),
                    "PreviousRestoreLogMsg" => eprintln!(
                        "Previous restore log: {}",
                        wire::string(&message, &["PreviousRestoreLog"]).unwrap_or("unavailable")
                    ),
                    name => {
                        bail!("unsupported restored message {name}; the restore did not complete")
                    }
                }
            }
        })();
        match outcome {
            // Returning releases the restore channels before the caller starts
            // USB networking. A booted Mac need not advertise its DFU ECID.
            Ok(()) => return Ok(()),
            Err(error) if !final_received && session.disconnected() && attempt < 3 => {
                session.cancel();
                eprintln!(
                    "USB removed ({error:#}); waiting for the same ECID. Pending transfers are discarded; restored must issue fresh data requests. StartRestore will not be repeated."
                );
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}
