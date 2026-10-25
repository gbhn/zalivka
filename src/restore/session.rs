//! Restored message loop, reconnect policy and final status acknowledgement.
use super::{
    AsyncRequests, ContextState,
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
        "restored",
        if progress < 0 {
            format!("Операция {operation}: процент выполнения недоступен ({progress})")
        } else {
            format!("Операция {operation}: {progress}%")
        },
    ));
    Ok(crate::progress::Event::OperationProgress {
        operation,
        progress,
    })
}

pub(super) fn log_checkpoint(
    message: &Value,
    mut output: impl FnMut(Record),
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
    output(Record::new(
        if result == 0 {
            Level::Debug
        } else {
            Level::Warning
        },
        "restored",
        format!("Checkpoint {phase}: id=0x{id:x}, name={name}, result={result}"),
    ));
    for (key, level) in [
        ("CHECKPOINT_WARNING", Level::Warning),
        ("CHECKPOINT_ERROR", Level::Error),
    ] {
        if let Ok(text) = wire::string(message, &[key]) {
            // eCfg is device-generated data, not an IPSW firmware component.
            // Preserve the device's warning; a successful checkpoint alone
            // does not establish why this particular Mac has no eCfg record.
            let missing_ecfg = key == "CHECKPOINT_WARNING"
                && id == 0x1504
                && name == "update_fdr_ean"
                && result == 0
                && wire::boolean(message, &["CHECKPOINT_COMPLETE"])
                && wire::dictionary(message)?.get("CHECKPOINT_ERROR").is_none()
                && text == "update_fdr_ean missing data for eCfg.";
            output(Record::new(
                level,
                "restored",
                if missing_ecfg {
                    format!(
                        "{name} (0x{id:x}): {text} Mac не вернул данные класса eCfg при переносе FDR в EAN; этап завершён с result=0"
                    )
                } else {
                    format!("{name} (0x{id:x}): {text}")
                },
            ));
        }
    }
    if !wire::boolean(message, &["CHECKPOINT_COMPLETE"]) {
        let stage = match name {
            "wait_for_storage" => Some("Проверка накопителя"),
            "perform_main_os_prepare" => Some("Подготовка macOS"),
            "perform_restore_installing" => Some("Установка macOS"),
            "update_device_firmware" => Some("Обновление прошивки Mac"),
            "recovery_os_restore" => Some("Установка recoveryOS"),
            "populate_isc_preboot_volume" => Some("Подготовка загрузочных файлов"),
            "seal_system_volume" => Some("Проверка системного тома"),
            "cleanup_send_final_status" => Some("Завершение восстановления"),
            _ => None,
        };
        if let Some(stage) = stage {
            output(Record::new(Level::Info, "restore", stage));
        }
    }
    Ok((!wire::boolean(message, &["CHECKPOINT_COMPLETE"]))
        .then(|| crate::progress::Event::Checkpoint { name: name.into() }))
}

pub(super) fn run(
    state: &mut ContextState,
    mut bootx_error: Option<anyhow::Error>,
    mut log: Option<File>,
    mut attestation: Attestation,
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
                        finish_final_status(&mut main, &message, || {
                            requests.finish()?;
                            attestation.finish()
                        })?;
                        crate::log!(
                            Info,
                            "restore",
                            "Mac подтвердил успешное восстановление, ECID {ecid:016x}"
                        );
                        crate::log!(
                            Debug,
                            "restore",
                            "Ожидание закрытия канала восстановления после подтверждения"
                        );
                        wait_for_restore_close(&mut main, &session, Duration::from_secs(60))?;
                        crate::log!(
                            Debug,
                            "restore",
                            "Канал восстановления закрыт после подтверждения"
                        );
                        return Ok(());
                    }
                    "ProgressMsg" => log_progress(&message, crate::logging::publish)?.emit(),
                    "CheckpointMsg" => {
                        if let Some(event) = log_checkpoint(&message, crate::logging::publish)? {
                            event.emit();
                        }
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
                        Debug,
                        "restore",
                        "Предыдущий журнал восстановления: {}",
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
                crate::log!(
                    Warning,
                    "restore",
                    "USB-соединение потеряно: {error:#}. Ожидание Mac с тем же ECID; восстановление продолжится по новым запросам устройства"
                );
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}
