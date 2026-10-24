//! Restore-service connection and identity checks.
use super::RESTORED_PORT;
use crate::{
    device::DeviceInfo,
    mux::{MuxStream, Session},
    usb::MuxUsb,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

/// Query an existing service without booting firmware or starting a restore.
pub fn query_value(stream: &mut (impl Read + Write), key: &str) -> Result<Value> {
    wire::send(
        stream,
        &wire::dict([
            ("Request", "QueryValue".into()),
            ("QueryKey", key.into()),
            ("Label", "zalivka".into()),
        ]),
    )?;
    wire::receive(stream).with_context(|| format!("reading {key}"))
}

pub(super) fn confirm_restore_service<T>(
    bootx_error: Option<anyhow::Error>,
    connect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(error) = &bootx_error {
        eprintln!("{error:#}; checking whether the same device started restored");
    }
    match connect() {
        Ok(service) => {
            if bootx_error.is_some() {
                eprintln!("Restore service identity confirmed after bootx USB error; continuing");
            }
            Ok(service)
        }
        Err(error) => match bootx_error {
            Some(bootx) => Err(bootx.context(format!(
                "restore service not confirmed after bootx ({error:#}); re-enter DFU before retrying"
            ))),
            None => Err(error),
        },
    }
}

pub(super) fn wait_restored(device: &DeviceInfo) -> Result<(Session, MuxStream, u64)> {
    eprintln!("Waiting for the restore service");
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut last_error = None;
    let mut reported_error = None;
    loop {
        for candidate in MuxUsb::candidates()? {
            let result = (|| -> Result<_> {
                let session = Session::new(MuxUsb::open(&candidate)?)?;
                let mut stream = session.connect(RESTORED_PORT)?;
                stream.set_read_timeout(Duration::from_secs(10));
                wire::send(
                    &mut stream,
                    &wire::dict([("Request", "QueryType".into()), ("Label", "zalivka".into())]),
                )?;
                let query = wire::receive(&mut stream)?;
                ensure!(
                    wire::string(&query, &["Type"])? == "com.apple.mobile.restored",
                    "not the restored service"
                );
                let version = wire::number(wire::get(&query, &["RestoreProtocolVersion"])?)?;
                let hardware = query_value(&mut stream, "HardwareInfo")?;
                let hw = wire::get(&hardware, &["HardwareInfo"])?;
                ensure!(
                    wire::number(wire::get(hw, &["UniqueChipID"])?)? == device.ecid,
                    "restore service ECID mismatch"
                );
                ensure!(
                    wire::number(wire::get(hw, &["ChipID"])?)? == u64::from(device.chip_id),
                    "restore service chip mismatch"
                );
                ensure!(
                    wire::number(wire::get(hw, &["BoardID"])?)? == u64::from(device.board_id),
                    "restore service board mismatch"
                );
                stream.set_read_timeout(Duration::from_secs(300));
                Ok((session, stream, version))
            })();
            match result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    let message = format!("{error:#}");
                    if reported_error.as_ref() != Some(&message) {
                        eprintln!("Restore service connection pending: {message}");
                        reported_error = Some(message);
                    }
                    last_error = Some(error);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(last_error
                .unwrap_or_else(|| anyhow::anyhow!("no USB multiplex interface found"))
                .context(format!(
                    "restore service did not appear for ECID {:016x}",
                    device.ecid
                )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
