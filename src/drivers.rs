#[cfg(target_os = "linux")]
mod linux;

use crate::{device::Mode, usb::APPLE_VENDOR};
use anyhow::{Context, Result, ensure};
use nusb::MaybeFuture;
use serde::Serialize;
use std::{fs::File, io::Write, path::Path};

pub const UDEV_RULES: &str = include_str!("../packaging/70-zalivka.rules");

#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    pub apple_service_installed: bool,
    pub apple_service_running: bool,
    pub apple_driver_installed: bool,
    pub compatible_usb_driver: bool,
}

impl HostStatus {
    pub fn needs_preparation(&self) -> bool {
        self.apple_service_running || !self.apple_driver_installed
    }

    pub fn blocking_reason(&self) -> Option<&'static str> {
        if self.apple_service_running {
            Some("Stop Apple Mobile Device Service before restoring")
        } else if !self.apple_driver_installed && !self.compatible_usb_driver {
            Some("Install the Apple USB driver")
        } else {
            None
        }
    }
}

pub fn host_status() -> Result<Option<HostStatus>> {
    #[cfg(windows)]
    return crate::windows::setup::status().map(Some);
    #[cfg(not(windows))]
    Ok(None)
}

/// Check before downloading firmware or sending anything to the device.
pub fn check_host() -> Result<()> {
    if let Some(status) = host_status()?
        && let Some(reason) = status.blocking_reason()
    {
        anyhow::bail!("{reason}. Open Windows setup in Zalivka or run zalivka drivers prepare.");
    }
    Ok(())
}

pub fn prepare_windows() -> Result<bool> {
    #[cfg(windows)]
    return crate::windows::setup::run(crate::windows::setup::Action::Prepare).inspect(|reboot| {
        crate::log!(Info, "drivers", "Setup complete; reboot={reboot}");
    });
    #[cfg(not(windows))]
    anyhow::bail!("Driver setup is only available on Windows")
}

#[cfg(windows)]
pub fn run_elevated_helper() -> Option<u32> {
    crate::windows::setup::run_helper()
}

/// Remove Apple restore device records and reinstall the signed USB package.
pub fn reset_windows() -> Result<bool> {
    #[cfg(windows)]
    return crate::windows::setup::run(crate::windows::setup::Action::Reset).inspect(|reboot| {
        crate::log!(Info, "drivers", "Reset complete; reboot={reboot}");
    });
    #[cfg(not(windows))]
    anyhow::bail!("USB driver reset is only available on Windows")
}

pub fn open_installed_apps() -> Result<()> {
    #[cfg(windows)]
    return crate::windows::setup::open_installed_apps();
    #[cfg(not(windows))]
    anyhow::bail!("Windows apps are unavailable on this operating system")
}

#[derive(Serialize)]
pub struct UsbDiagnostic {
    pub product_id: String,
    pub serial: Option<String>,
    pub interfaces: Vec<u8>,
    pub accessible: bool,
    pub transport: Option<String>,
    pub dfu_state: Option<u8>,
    pub error: Option<String>,
    #[cfg(windows)]
    pub driver: Option<String>,
    #[cfg(windows)]
    pub instance_id: String,
    #[cfg(windows)]
    pub reset_error: Option<String>,
}

/// Does not require the device to be accessible through WinUSB/udev already.
pub fn doctor() -> Result<Vec<UsbDiagnostic>> {
    diagnostics(false)
}

pub(crate) fn diagnostics(restore_only: bool) -> Result<Vec<UsbDiagnostic>> {
    let mut diagnostics = vec![];
    for info in nusb::list_devices()
        .wait()
        .context("enumerating USB devices")?
    {
        if info.vendor_id() != APPLE_VENDOR {
            continue;
        }
        let mode = Mode::from_pid(info.product_id());
        // Preparing a Mac must not probe an unrelated iPhone in normal mode.
        if restore_only && mode.is_none() && ![0x12ac, 0x1881].contains(&info.product_id()) {
            continue;
        }
        let mux: Vec<u8> = info
            .interfaces()
            .filter(|i| (i.class(), i.subclass(), i.protocol()) == crate::usb::MUX_INTERFACE)
            .map(|i| i.interface_number())
            .collect();
        if mode.is_none() && mux.is_empty() && info.product_id() != 0x1881 {
            continue;
        }
        let mut interfaces = if mux.is_empty() { vec![0] } else { mux };
        let mut dfu_state = None;
        #[cfg(windows)]
        let mut reset_error = None;
        let probe = (|| -> Result<String> {
            if info.product_id() == 0x1881 {
                let device = info.open().wait()?;
                let mut kis = crate::usb::Kis::open(&device, &info)?;
                kis.info()?;
                return Ok("kis".into());
            }
            let device = info
                .open()
                .wait()
                .context("opening USB device and reading descriptors")?;
            // Use the same descriptors as the actual transport, including a
            // recovery interface whose number is not zero.
            let number = match mode {
                Some(Mode::Dfu | Mode::PortDfu) => 0,
                Some(Mode::Recovery) => {
                    crate::usb::recovery_interface(device.active_configuration()?)?.0
                }
                None => crate::usb::mux_interface(&device)?.number,
            };
            interfaces = vec![number];
            let interface = crate::usb::UsbInterface::claim(&device, &info, number)?;
            if matches!(mode, Some(Mode::Dfu | Mode::PortDfu)) {
                let state = interface
                    .control_in(
                        nusb::transfer::ControlIn {
                            control_type: nusb::transfer::ControlType::Class,
                            recipient: nusb::transfer::Recipient::Interface,
                            request: 5,
                            value: 0,
                            index: u16::from(number),
                            length: 1,
                        },
                        std::time::Duration::from_secs(10),
                    )
                    .context("reading DFU state")?;
                ensure!(state.len() == 1, "invalid DFU GETSTATE reply");
                dfu_state = Some(state[0]);
                #[cfg(windows)]
                {
                    reset_error = interface
                        .check_reset_access(&info)
                        .err()
                        .map(|e| format!("{e:#}"));
                }
            }
            Ok(interface.transport().into())
        })();
        diagnostics.push(UsbDiagnostic {
            product_id: format!("{:04x}", info.product_id()),
            serial: info.serial_number().map(str::to_owned),
            interfaces,
            accessible: probe.is_ok(),
            transport: probe.as_ref().ok().cloned(),
            dfu_state,
            error: probe.err().map(|e| format!("{e:#}")),
            #[cfg(windows)]
            driver: info.driver().map(str::to_owned),
            #[cfg(windows)]
            instance_id: info.instance_id().to_string_lossy().into_owned(),
            #[cfg(windows)]
            reset_error,
        });
    }
    Ok(diagnostics)
}

/// A driver source file, not a signed distributable driver package.
pub fn winusb_inf(pid: u16, interface: Option<u8>) -> Result<String> {
    ensure!(pid != 0, "USB PID cannot be zero");
    if Mode::from_pid(pid).is_none() {
        ensure!(
            interface.is_some(),
            "restore-mode devices require an explicit mux interface number"
        );
    }
    let hardware = format!(
        "USB\\VID_05AC&PID_{pid:04X}{}",
        interface
            .map(|i| format!("&MI_{i:02X}"))
            .unwrap_or_default()
    );
    Ok(format!(
        r#"; Build a signed CAT for this INF before installation.
[Version]
Signature="$Windows NT$"
Class=USBDevice
ClassGuid={{88BAE032-5A81-49F0-BC3D-A4FF138216D6}}
Provider=%Provider%
DriverVer=10/20/2026,0.1.0.0
CatalogFile=zalivka.cat
PnpLockdown=1
[Manufacturer]
%Provider%=Models,NTamd64,NTarm64
[Models.NTamd64]
%Device%=Install,{hardware}
[Models.NTarm64]
%Device%=Install,{hardware}
[Install.NT]
Include=winusb.inf
Needs=WINUSB.NT
[Install.NT.Services]
Include=winusb.inf
Needs=WINUSB.NT.Services
[Install.NT.HW]
AddReg=InterfaceGuid
[InterfaceGuid]
HKR,,DeviceInterfaceGUIDs,0x10000,"{{9E338B8E-49E2-4DF6-869C-6013A8CE838A}}"
[Strings]
Provider="Zalivka"
Device="Apple DFU / Restore (WinUSB)"
"#
    ))
}

pub fn export(directory: &Path, pid: u16, interface: Option<u8>) -> Result<()> {
    let inf = winusb_inf(pid, interface)?;
    std::fs::create_dir_all(directory)?;
    for (name, content) in [
        ("zalivka.inf", inf.as_str()),
        ("70-zalivka.rules", UDEV_RULES),
    ] {
        File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?
            .write_all(content.as_bytes())?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn install(inf: &Path) -> Result<bool> {
    crate::windows::package::install(inf)
}

#[cfg(not(windows))]
pub fn install(_inf: &Path) -> Result<bool> {
    anyhow::bail!("WinUSB installation is available only on Windows")
}

/// Install the bundled rule directly; the CLI caller must already have root access.
pub fn install_udev() -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::install();
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("udev installation is available only on Linux")
}

/// Request desktop authorization for the same installer used by the CLI.
pub fn prepare_linux() -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::prepare().inspect(|()| {
        crate::log!(
            Info,
            "udev",
            "USB access configured. Reconnect the USB cable."
        );
    });
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("Linux USB setup is available only on Linux")
}

#[cfg(test)]
#[path = "../tests/unit/drivers.rs"]
mod tests;
