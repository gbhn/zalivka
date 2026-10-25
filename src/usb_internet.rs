//! Temporary internet access over the Mac's CDC-NCM USB interface.
mod dns;
mod link;
use crate::usb::ncm_interface;
use link::Link;
mod ncm;
mod router;
use anyhow::{Context, Result, ensure};
use nusb::MaybeFuture;
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
pub struct Target {
    pub bus: String,
    pub ports: Vec<u8>,
}
impl Target {
    pub fn for_ecid(ecid: u64) -> Result<Self> {
        let info = nusb::list_devices()
            .wait()?
            .find(|d| {
                d.vendor_id() == crate::usb::APPLE_VENDOR
                    && d.serial_number().is_some_and(|s| {
                        crate::device::Mode::from_pid(d.product_id())
                            .and_then(|m| crate::device::DeviceInfo::parse(s, m).ok())
                            .is_some_and(|d| d.ecid == ecid)
                    })
            })
            .context("target USB port was not found")?;
        Ok(Self {
            bus: info.bus_id().into(),
            ports: info.port_chain().to_vec(),
        })
    }
    fn matches(&self, info: &nusb::DeviceInfo) -> bool {
        !self.ports.is_empty() && info.bus_id() == self.bus && info.port_chain() == self.ports
    }
}
#[derive(Debug, Serialize)]
pub struct Status {
    pub serial: String,
    pub product_id: u16,
    pub bus: String,
    pub ports: Vec<u8>,
    pub control_interface: u8,
    pub data_interface: u8,
    pub accessible: bool,
    pub error: Option<String>,
}
pub(crate) fn mac(info: &nusb::DeviceInfo) -> bool {
    info.vendor_id() == crate::usb::APPLE_VENDOR
        && matches!(info.product_id(), 0x1902 | 0x1903 | 0x1905)
}
pub(crate) fn find(
    serial: Option<&str>,
    target: Option<&Target>,
) -> Result<Option<nusb::DeviceInfo>> {
    let candidates: Vec<_> = nusb::list_devices()
        .wait()?
        .filter(mac)
        .filter(|i| {
            serial.is_none_or(|s| {
                i.serial_number()
                    .is_some_and(|v| v.trim_end_matches('\0') == s)
            }) && target.is_none_or(|t| t.matches(i))
        })
        .collect();
    ensure!(
        candidates.len() <= 1,
        "multiple Macs connected; specify --serial"
    );
    Ok(candidates.into_iter().next())
}
pub fn prepare(serial: Option<&str>, restore: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let info =
            find(serial, None)?.context("connect the Mac on its activation or setup screen")?;
        let serial = info
            .serial_number()
            .context("Mac USB serial is missing")?
            .trim_end_matches('\0');
        ensure!(
            !serial.is_empty()
                && serial.len() <= 64
                && serial.bytes().all(|b| b.is_ascii_alphanumeric()),
            "invalid Mac USB serial"
        );
        if !restore {
            let interfaces = crate::windows::ncm::status()?;
            let selected: Vec<_> = interfaces.iter().filter(|i| i.serial == serial).collect();
            if !selected.is_empty() && selected.iter().all(|i| i.ready) {
                return Ok(());
            }
        }
        let args = format!(
            "usb-internet prepare-elevated --serial {serial}{}",
            if restore { " --restore" } else { "" }
        );
        let code = crate::windows::setup::run_elevated(&args)?;
        ensure!(
            code == 0,
            "USB network driver preparation failed (code {code}); see the USB network driver log"
        );
        if !restore {
            let status = status()?
                .into_iter()
                .find(|s| s.serial == serial)
                .context("Mac disconnected during driver preparation; reconnect the USB cable")?;
            ensure!(
                status.accessible,
                "USB network driver is not ready: {}",
                status.error.unwrap_or_default()
            );
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (serial, restore);
        anyhow::bail!("USB network driver preparation is available on Windows only");
    }
}
#[cfg(windows)]
pub fn prepare_elevated(serial: &str, restore: bool) -> Result<()> {
    let directory = crate::storage::log_directory()?;
    let result = crate::windows::ncm::prepare(serial, restore);
    let record = match &result {
        Ok(()) => crate::logging::Record::new(
            crate::logging::Level::Info,
            "drivers",
            "Подготовка сетевого USB-драйвера завершена",
        ),
        Err(error) => crate::logging::Record::new(
            crate::logging::Level::Error,
            "drivers",
            format!("{error:#}"),
        ),
    };
    record.write_to(std::fs::File::create(
        directory.join("usb-network-driver.log"),
    )?)?;
    result
}
pub fn status() -> Result<Vec<Status>> {
    let mut result = vec![];
    for info in nusb::list_devices().wait()?.filter(mac) {
        let device = info.open().wait()?;
        let selected = ncm_interface(device.active_configuration()?)?;
        let access = link::claim_pair(&device, selected).map(drop);
        result.push(Status {
            serial: info
                .serial_number()
                .unwrap_or_default()
                .trim_end_matches('\0')
                .into(),
            product_id: info.product_id(),
            bus: info.bus_id().into(),
            ports: info.port_chain().to_vec(),
            control_interface: selected.control,
            data_interface: selected.data,
            accessible: access.is_ok(),
            error: access.err().map(|e| e.to_string()),
        });
    }
    Ok(result)
}
pub fn share(
    serial: Option<&str>,
    target: Option<&Target>,
    duration: Option<Duration>,
) -> Result<()> {
    ensure!(
        cfg!(windows),
        "USB internet sharing currently supports Windows hosts"
    );
    crate::progress::Event::InternetWaiting.emit();
    crate::log!(Info, "usb-internet", "Ожидание USB-сети Mac (до 90 секунд)");
    crate::log!(
        Info,
        "usb-internet",
        "Если macOS запущена, а USB-сеть не появилась, переподключите кабель к тому же USB-порту"
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let info = loop {
        if let Some(info) = find(serial, target)? {
            break info;
        }
        ensure!(
            Instant::now() < deadline,
            "Mac USB network did not appear within 90 seconds; reconnect the cable to the same USB port, then start USB internet sharing"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    #[cfg(windows)]
    {
        let device = info.open().wait()?;
        let selected = ncm_interface(device.active_configuration()?)?;
        let accessible = link::claim_pair(&device, selected).is_ok();
        if !accessible {
            crate::progress::Event::InternetPreparing.emit();
            crate::log!(
                Info,
                "usb-internet",
                "Подготовка сетевого драйвера Mac. Подтвердите запрос прав администратора Windows"
            );
            prepare(
                info.serial_number().map(|s| s.trim_end_matches('\0')),
                false,
            )?;
            crate::progress::Event::InternetWaiting.emit();
        }
    }
    let info = find(
        info.serial_number().map(|s| s.trim_end_matches('\0')),
        target,
    )?
    .context("Mac disconnected during network preparation; reconnect the USB cable")?;
    let mut link = Link::open(&info)?;
    let mut router = router::Router::new();
    crate::progress::Event::InternetReady.emit();
    crate::log!(
        Info,
        "usb-internet",
        "Интернет по USB включён. Ожидание сетевых запросов Mac"
    );
    let started = Instant::now();
    let mut report = started;
    let mut packets = 0u64;
    let mut active = false;
    let mut previous_bytes = (0u64, 0u64);
    while duration.is_none_or(|limit| started.elapsed() < limit) {
        // Drain ready reads immediately after activity; wait only when idle.
        let wait = if active {
            Duration::ZERO
        } else {
            Duration::from_millis(2)
        };
        let frames = link.receive(wait)?;
        active = !frames.is_empty();
        for frame in frames {
            packets += 1;
            if packets <= 20 && frame.len() >= 14 {
                crate::log!(
                    Debug,
                    "usb-internet",
                    "Ethernet: тип {:02x}{:02x}, длина {}",
                    frame[12],
                    frame[13],
                    frame.len()
                );
            }
            router.receive(frame);
        }
        router.poll();
        let frames = router.transmit();
        active |= !frames.is_empty();
        link.send(&frames)?;
        let now = Instant::now();
        let interval = now.duration_since(report);
        if interval >= Duration::from_secs(1) {
            let bytes = router.bytes();
            crate::progress::Event::InternetSpeed {
                upload_bytes_per_second: (bytes.0 - previous_bytes.0) as f64
                    / interval.as_secs_f64(),
                download_bytes_per_second: (bytes.1 - previous_bytes.1) as f64
                    / interval.as_secs_f64(),
            }
            .emit();
            previous_bytes = bytes;
            report = now;
        }
    }
    crate::log!(Info, "usb-internet", "Раздача интернета по USB остановлена");
    Ok(())
}
