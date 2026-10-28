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
    return crate::windows::setup::prepare();
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
    return crate::windows::setup::cleanup::reset();
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
        if restore_only && mode.is_none() && info.product_id() != 0x12ac {
            continue;
        }
        let mux: Vec<u8> = info
            .interfaces()
            .filter(|i| (i.class(), i.subclass(), i.protocol()) == crate::usb::MUX_INTERFACE)
            .map(|i| i.interface_number())
            .collect();
        if mode.is_none() && mux.is_empty() {
            continue;
        }
        let mut interfaces = if mux.is_empty() { vec![0] } else { mux };
        let mut dfu_state = None;
        #[cfg(windows)]
        let mut reset_error = None;
        let probe = (|| -> Result<String> {
            let device = info
                .open()
                .wait()
                .context("opening USB device and reading descriptors")?;
            // Use the same descriptors as the actual transport, including a
            // recovery interface whose number is not zero.
            let number = match mode {
                Some(Mode::Dfu) => 0,
                Some(Mode::Recovery) => {
                    crate::usb::recovery_interface(device.active_configuration()?)?.0
                }
                None => crate::usb::mux_interface(&device)?.number,
            };
            interfaces = vec![number];
            let interface = crate::usb::UsbInterface::claim(&device, &info, number)?;
            if mode == Some(Mode::Dfu) {
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
#[allow(unsafe_code)]
pub fn install(inf: &Path) -> Result<bool> {
    use std::{
        io::{Read, Seek, SeekFrom},
        time::Instant,
    };
    let inf = inf
        .canonicalize()
        .with_context(|| format!("Opening INF: {}", inf.display()))?;
    ensure!(
        inf.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("inf")),
        "expected a signed driver package's .inf file"
    );
    let setupapi = crate::windows::windows_directory()?.join(r"INF\setupapi.dev.log");
    let offset = std::fs::metadata(&setupapi).map(|m| m.len()).unwrap_or(0);
    crate::log!(Info, "drivers", "Installing driver: {}", inf.display());
    crate::log!(
        Trace,
        "drivers:install",
        "DiInstallDriverW; flags=0; journal={}; offset={offset}",
        setupapi.display()
    );
    let path = crate::windows::wide(&inf);
    let started = Instant::now();
    let mut reboot = 0;
    // Use Windows' normal signature and driver ranking enforcement. No FORCE flag.
    let ok = unsafe {
        windows_sys::Win32::Devices::DeviceAndDriverInstallation::DiInstallDriverW(
            std::ptr::null_mut(),
            path.as_ptr(),
            0,
            &mut reboot,
        )
    };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        let code = error.raw_os_error().unwrap_or(0) as u32;
        crate::log!(
            Error,
            "drivers:install",
            "DiInstallDriverW: 0x{code:08X}; {error}"
        );
        let read_log = (|| -> Result<()> {
            let mut file = File::open(&setupapi)?;
            let end = file.metadata()?.len();
            // Include only this attempt; bound memory if Windows logs heavily.
            let start = if offset <= end { offset } else { 0 };
            let bounded = start.max(end.saturating_sub(65536));
            file.seek(SeekFrom::Start(bounded))?;
            let mut bytes = Vec::new();
            file.take(65536).read_to_end(&mut bytes)?;
            if bytes.is_empty() {
                crate::log!(
                    Debug,
                    "drivers:log",
                    "No new records: {}",
                    setupapi.display()
                );
            } else {
                crate::log!(
                    Trace,
                    "drivers:log",
                    "{bounded}..{end}: {}",
                    setupapi.display()
                );
                // SetupAPI logs can be UTF-16LE; detect its BOM or ASCII NULs.
                let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.get(1) == Some(&0) {
                    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(&bytes);
                    String::from_utf16_lossy(
                        &bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_le_bytes(*b))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    crate::log!(Debug, "drivers:log", "{line}");
                }
            }
            Ok(())
        })();
        if let Err(log_error) = read_log {
            crate::log!(
                Warning,
                "drivers:log",
                "Could not read {}: {log_error:#}",
                setupapi.display()
            );
        }
        return Err(error).with_context(|| format!("driver installation failed: DiInstallDriverW, Win32 {code} (0x{code:08X}), INF={} (requires administrator rights and a signed package)", inf.display()));
    }
    crate::log!(
        Info,
        "drivers:install",
        "Installed in {:.3} s; reboot={}",
        started.elapsed().as_secs_f64(),
        reboot != 0
    );
    Ok(reboot != 0)
}

#[cfg(not(windows))]
pub fn install(_inf: &Path) -> Result<bool> {
    anyhow::bail!("WinUSB installation is available only on Windows")
}

pub fn install_udev() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "udev installation is available only on Linux"
    );
    let path = Path::new("/etc/udev/rules.d/70-zalivka.rules");
    if path.exists() {
        ensure!(
            std::fs::read_to_string(path)? == UDEV_RULES,
            "different udev rule already exists; refusing to overwrite"
        );
    } else {
        File::options()
            .create_new(true)
            .write(true)
            .open(path)
            .context("writing udev rule (requires root)")?
            .write_all(UDEV_RULES.as_bytes())?;
    }
    let status = std::process::Command::new("udevadm")
        .args(["control", "--reload-rules"])
        .status()?;
    ensure!(
        status.success(),
        "udevadm could not reload rules; rule file was saved"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/drivers.rs"]
mod tests;
