//! Restored message loop, reconnect policy and final status acknowledgement.
use super::{
    AsyncRequests, RestoreSession,
    attestation::Attestation,
    connection::{confirm_restore_service, wait_restored},
    options,
};
use crate::{
    logging::{Level, Record},
    mux::{MuxStream, Session},
    wire,
};
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use std::{
    collections::BTreeMap,
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

pub(super) fn log_progress(
    message: &Value,
    mut output: impl FnMut(Record),
) -> Result<crate::progress::Event> {
    let operation = wire::get(message, &["Operation"])
        .and_then(wire::number)
        .context("invalid ProgressMsg.Operation")?;
    let value = wire::get(message, &["Progress"])?;
    let progress = value.as_signed_integer().with_context(|| {
        format!("invalid ProgressMsg.Progress: expected signed plist integer, got {value:?}")
    })?;
    output(Record::new(
        Level::Debug,
        "restored:op",
        if progress == -1 {
            format!("Operation {operation}: no percentage")
        } else if progress < 0 {
            format!("Operation {operation}: percentage unavailable ({progress})")
        } else {
            format!("Operation {operation}: {progress}%")
        },
    ));
    Ok(crate::progress::Event::OperationProgress {
        operation,
        progress,
    })
}

/// These optional weights are progress hints, not a condition for restoring.
pub(super) fn operation_weights(message: &Value) -> Option<crate::progress::Event> {
    let weights =
        wire::dictionary(wire::get(message, &["OperationWeights", "operation_weights"]).ok()?)
            .ok()?;
    let ids =
        wire::dictionary(wire::get(message, &["OperationWeights", "operation_ids"]).ok()?).ok()?;
    let mut operations = BTreeMap::new();
    for (key, value) in weights {
        let operation = wire::number(ids.get(key)?).ok()?;
        let weight = wire::number(value).ok()?;
        if operations.insert(operation, weight).is_some() {
            return None;
        }
    }
    operations
        .values()
        .any(|weight| *weight > 0)
        .then_some(())?;
    let mut progresses = BTreeMap::new();
    if let Some(values) =
        wire::optional(message, &["OperationWeights", "operation_progresses"]).ok()?
    {
        for (key, value) in wire::dictionary(values).ok()? {
            let operation = wire::number(ids.get(key)?).ok()?;
            let weight = operations.get(&operation)?;
            // Apple's PRProgressDecodeWeights stores completed weight units.
            // Values above the operation's weight are capped by its decoder.
            let completed = wire::number(value).ok()?.min(*weight);
            if progresses.insert(operation, completed).is_some() {
                return None;
            }
        }
    }
    Some(crate::progress::Event::OperationWeights {
        weights: operations.into_iter().collect(),
        progresses: progresses.into_iter().collect(),
    })
}

pub(super) fn log_checkpoint(
    message: &Value,
    mut output: impl FnMut(Record),
) -> Result<crate::progress::Event> {
    let id = wire::number(wire::get(message, &["CHECKPOINT_ID"])?)?;
    let name = wire::string(message, &["CHECKPOINT_NAME"]).unwrap_or("unknown");
    let result = wire::get(message, &["CHECKPOINT_RESULT"])?
        .as_signed_integer()
        .context("invalid checkpoint result")?;
    let complete = wire::optional_boolean(message, &["CHECKPOINT_COMPLETE"])?.unwrap_or(false);
    let phase = if complete { "completed" } else { "started" };
    // Checkpoints describe individual steps; only StatusMsg decides the final result.
    output(Record::new(
        if result == 0 {
            Level::Debug
        } else {
            Level::Warning
        },
        "restored:cp",
        format!("{name}: {phase}; id=0x{id:x}, result={result}"),
    ));
    for (key, level) in [
        ("CHECKPOINT_WARNING", Level::Warning),
        ("CHECKPOINT_ERROR", Level::Error),
    ] {
        if let Ok(text) = wire::string(message, &[key]) {
            output(Record::new(
                level,
                "restored:cp",
                format!("{name} (0x{id:x}): {text}"),
            ));
        }
    }
    if !complete {
        output(Record::new(
            Level::Info,
            "restore",
            format!("Mac stage: {}", name.replace('_', " ")),
        ));
    }
    Ok(crate::progress::Event::Checkpoint {
        name: name.into(),
        complete,
    })
}

pub(super) fn provisioning_failed(message: &Value) -> bool {
    matches!(
        wire::string(message, &["CHECKPOINT_NAME"]).ok(),
        Some("create_production_ucrt" | "create_production_dcrt")
    ) && wire::optional_boolean(message, &["CHECKPOINT_COMPLETE"])
        .ok()
        .flatten()
        == Some(true)
        && (wire::get(message, &["CHECKPOINT_RESULT"])
            .ok()
            .and_then(Value::as_signed_integer)
            .is_some_and(|result| result != 0)
            || wire::string(message, &["CHECKPOINT_ERROR"])
                .is_ok_and(|error| !error.trim().is_empty()))
}

/// Once firmware is running, a diagnostic write must not interrupt the device
/// protocol. A partial JSON line also makes the transcript unsafe to append to.
pub(super) fn record_message(log: &mut Option<impl Write>, message: &Value) -> Option<Record> {
    let output = log.as_mut()?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(&mut *output, message)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    })();
    let error = result.err()?;
    *log = None;
    Some(Record::new(
        Level::Warning,
        "transcript",
        format!(
            "JSONL journal incomplete: {error:#}. Further recording disabled; restore continues."
        ),
    ))
}

pub(super) fn run(
    state: &mut RestoreSession,
    mut bootx_error: Option<anyhow::Error>,
    mut log: Option<File>,
    mut attestation: Attestation,
) -> Result<()> {
    let ecid = state.context.device.ecid;
    let mut started = false;
    let mut final_received = false;
    let mut provisioning_error = false;
    let mut protocol = None;
    for attempt in 0..=3 {
        let (session, mut main, version) =
            confirm_restore_service(bootx_error.take(), || wait_restored(&state.context.device))?;
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
                        ("RestoreOptions", options(&state.context.restore.identity)?),
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
                if let Some(warning) = record_message(&mut log, &message) {
                    crate::logging::publish(warning);
                }
                match wire::string(&message, &["MsgType"])? {
                    "DataRequestMsg" => state.serve(&session, &mut main, &message)?,
                    "AsyncDataRequestMsg" => requests.spawn(state, message)?,
                    "StatusMsg" => {
                        final_received = true;
                        fdr.stop();
                        finish_final_status(&mut main, &message, || {
                            requests.finish()?;
                            attestation.finish()
                        })?;
                        crate::log!(Info, "restore", "Success; ECID={ecid:016x}");
                        crate::log!(Debug, "restore:usb", "Waiting for channel closure");
                        wait_for_restore_close(&mut main, &session, Duration::from_secs(60))?;
                        crate::log!(Debug, "restore:usb", "Channel closed");
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
                    "ProgressMsg" => {
                        if let Some(event) = operation_weights(&message) {
                            event.emit();
                        }
                        let event = log_progress(&message, crate::logging::publish)?;
                        event.emit();
                    }
                    "CheckpointMsg" => {
                        let event = log_checkpoint(&message, crate::logging::publish)?;
                        // A zero checkpoint result and final Status=0 do not
                        // guarantee that Apple issued the activation certificates.
                        // Keep this warning through reconnects and later steps.
                        provisioning_error |= provisioning_failed(&message);
                        event.emit();
                    }
                    "AsyncWait" => {}
                    "RestoreProtocol" => ensure!(
                        wire::string(&message, &["Arguments", "RestoreProtocol"])? == "MuxSocket",
                        "device requested an unsupported restore transport"
                    ),
                    "RestoreAttestation" => {
                        if let Some(reply) = attestation.handle(&message)? {
                            wire::send(&mut main, &reply)?;
                        }
                    }
                    "RestoredCrash" => bail!("restored crashed: {message:?}"),
                    "PreviousRestoreLogMsg" => crate::log!(
                        Trace,
                        "restored:log",
                        "Previous journal: {}",
                        wire::string(&message, &["PreviousRestoreLog"]).unwrap_or("unavailable")
                    ),
                    name => {
                        bail!("unsupported restored message {name}; the restore did not complete")
                    }
                }
            }
        })();
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) if !final_received && session.disconnected() && attempt < 3 => {
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
