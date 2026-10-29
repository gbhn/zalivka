//! Windows host preparation. The embedded Apple CABs are unmodified signed packages.
use super::package::{DRIVERS, Driver};
use super::{wide, windows_directory};
mod cleanup;
mod log;
mod token;
use crate::{device::Mode, drivers::HostStatus, usb::APPLE_VENDOR};
use anyhow::{Context, Result, bail, ensure};
use nusb::MaybeFuture;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::{Duration, Instant},
};
use windows_service::{
    service::{Service, ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64},
        Threading::{
            GetCurrentProcess, GetExitCodeProcess, GetProcessId, IsWow64Process2,
            WaitForSingleObject,
        },
    },
    UI::{
        Shell::{
            IsUserAnAdmin, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            ShellExecuteW,
        },
        WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL},
    },
};

const SERVICE: &str = "Apple Mobile Device Service";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Prepare,
    Reset,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Reset => "reset",
        }
    }

    fn elevated(self) -> Outcome {
        let mut reboot = false;
        let result = match self {
            Self::Prepare => prepare_elevated(&mut reboot),
            Self::Reset => cleanup::reset_elevated(&mut reboot),
        };
        Outcome { result, reboot }
    }
}

/// A later failure cannot undo an earlier request to restart Windows.
struct Outcome {
    result: Result<()>,
    reboot: bool,
}

impl Outcome {
    fn from_exit_code(action: Action, code: u32) -> Self {
        Self {
            result: if matches!(code, 0 | 3010) {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Windows driver {} exited with code {code}. See the installer journal above.",
                    action.name()
                ))
            },
            reboot: matches!(code, 3010 | 3017),
        }
    }

    fn exit_code(&self) -> u32 {
        match (self.result.is_ok(), self.reboot) {
            (true, false) => 0,
            (false, false) => 1,
            (true, true) => 3010,
            (false, true) => 3017,
        }
    }

    fn finish(self) -> Result<bool> {
        if self.reboot {
            crate::progress::Event::RebootRequired.emit();
            crate::log!(
                Warning,
                "drivers",
                "Restart Windows before restoring the Mac."
            );
        }
        self.result?;
        Ok(self.reboot)
    }
}

fn architecture() -> Result<&'static str> {
    let mut process = 0;
    let mut native = 0;
    ensure!(
        unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0,
        "Could not determine Windows architecture: {}",
        std::io::Error::last_os_error()
    );
    match native {
        IMAGE_FILE_MACHINE_AMD64 => Ok("amd64"),
        IMAGE_FILE_MACHINE_ARM64 => Ok("arm64"),
        _ => bail!("Bundled driver supports Windows x64 and ARM64"),
    }
}

fn open_service(access: ServiceAccess) -> Result<Option<Service>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("Opening Windows service manager")?;
    match manager.open_service(SERVICE, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("Opening Apple Mobile Device Service"),
    }
}

fn service_state(service: &Service) -> Result<ServiceState> {
    Ok(service
        .query_status()
        .context("Checking Apple Mobile Device Service")?
        .current_state)
}

pub(crate) fn status() -> Result<HostStatus> {
    let service = open_service(ServiceAccess::QUERY_STATUS)?;
    let active = service
        .as_ref()
        .map(service_state)
        .transpose()?
        .is_some_and(|s| s != ServiceState::Stopped);
    // A working WinUSB binding remains supported even without Apple's package.
    let compatible_usb_driver = nusb::list_devices().wait()?.any(|d| {
        d.vendor_id() == APPLE_VENDOR
            && (Mode::from_pid(d.product_id()).is_some()
                || d.product_id() == 0x1881
                || d.interfaces()
                    .any(|i| (i.class(), i.subclass(), i.protocol()) == crate::usb::MUX_INTERFACE))
            && d.driver()
                .is_some_and(|name| name.eq_ignore_ascii_case("winusb"))
    });
    let installed = super::package::installed()?;
    Ok(HostStatus {
        apple_service_installed: service.is_some(),
        apple_service_running: active,
        apple_driver_installed: installed.contains(&Driver::Usb),
        apple_kis_driver_installed: installed.contains(&Driver::Kis)
            && installed.contains(&Driver::Rsm),
        compatible_usb_driver,
    })
}

fn stop_service() -> Result<()> {
    crate::log!(Info, "drivers:svc", "Stopping {SERVICE}");
    let Some(service) = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)? else {
        crate::log!(Debug, "drivers:svc", "{SERVICE} not installed");
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut previous = None;
    loop {
        let state = service_state(&service)?;
        if previous != Some(state) {
            crate::log!(Debug, "drivers:svc", "{SERVICE}: {state:?}");
            previous = Some(state);
        }
        if state == ServiceState::Stopped {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Apple Mobile Device Service did not stop within 30 seconds. Close iTunes / Apple Devices and retry Windows setup."
        );
        if state != ServiceState::StopPending {
            crate::log!(Trace, "drivers:svc", "SERVICE_CONTROL_STOP: {SERVICE}");
            match service.stop() {
                Ok(_) => {}
                Err(windows_service::Error::Winapi(error))
                    if matches!(error.raw_os_error(), Some(code)
                        if code == ERROR_SERVICE_NOT_ACTIVE as i32
                            || code == ERROR_SERVICE_CANNOT_ACCEPT_CTRL as i32) => {}
                Err(error) => return Err(error).context("Stopping Apple Mobile Device Service"),
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn prepare_elevated(reboot: &mut bool) -> Result<()> {
    let started = Instant::now();
    let admin = unsafe { IsUserAnAdmin() } != 0;
    crate::log!(
        Trace,
        "drivers:process",
        "PID={}; version={}; EXE={}",
        std::process::id(),
        crate::VERSION,
        std::env::current_exe()?.display()
    );
    crate::log!(Debug, "drivers:auth", "IsUserAnAdmin={admin}");
    if let Err(error) = token::log() {
        crate::log!(
            Warning,
            "drivers",
            "Could not read all token information: {error:#}"
        );
    }
    ensure!(
        admin,
        "Windows setup requires administrator rights: IsUserAnAdmin=false. The process token has no active membership in the local Administrators group (S-1-5-32-544). UAC approval and a high integrity level alone do not guarantee membership. Run setup using a local administrator account on this computer."
    );
    let arch = architecture().context("Determining architecture before driver installation")?;
    crate::log!(
        Debug,
        "drivers:host",
        "{arch}; Windows={}",
        windows_directory()?.display()
    );
    // Check the service first; don't replace the driver if stopping the conflict fails.
    stop_service().context("Windows setup: stopping Apple service")?;
    let installed = super::package::installed()?;
    for driver in DRIVERS {
        if installed.contains(&driver) {
            crate::log!(
                Info,
                "drivers",
                "Apple {driver:?} package already installed"
            );
            continue;
        }
        let directory = tempfile::Builder::new()
            .prefix("zalivka-apple-driver-")
            .tempdir()
            .context("Creating temporary Apple driver directory")?;
        crate::log!(
            Info,
            "drivers:cab",
            "Extracting Apple {driver:?} ({arch}): {}",
            directory.path().display()
        );
        let inf = driver
            .unpack(directory.path(), arch)
            .context("Windows setup: extracting Apple package")?;
        // Windows verifies the original CAT. No forced ranking or signing bypass.
        *reboot |=
            super::package::install(&inf).context("Windows setup: installing Apple driver")?;
    }
    crate::log!(Info, "drivers", "Checking installation");
    let host = status()?;
    crate::log!(
        Debug,
        "drivers:status",
        "After installation: {}",
        serde_json::to_string(&host)?
    );
    ensure!(
        !host.apple_service_running,
        "Apple Mobile Device Service restarted. Close iTunes / Apple Devices or uninstall Apple Mobile Device Support in Windows apps."
    );
    ensure!(
        host.apple_driver_installed && host.apple_kis_driver_installed,
        "Windows did not confirm Apple USB and KIS/RSM driver installation"
    );
    crate::log!(
        Info,
        "drivers",
        "Completed in {:.3} s; reboot={reboot}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub(crate) fn run(action: Action) -> Result<bool> {
    let admin = unsafe { IsUserAnAdmin() } != 0;
    crate::log!(
        Debug,
        "drivers:auth",
        "PID={}; IsUserAnAdmin={}",
        std::process::id(),
        admin
    );
    if action == Action::Prepare {
        let host = status()?;
        crate::log!(
            Debug,
            "drivers:status",
            "Before installation: {}",
            serde_json::to_string(&host)?
        );
        if !host.needs_preparation() {
            crate::log!(Info, "drivers", "Driver already installed");
            verify_connected_devices(false)?;
            return Ok(false);
        }
    }

    let outcome = if admin {
        action.elevated()
    } else {
        crate::log!(Info, "drivers:uac", "Approve the administrator prompt");
        Outcome::from_exit_code(action, run_elevated(action)?)
    };
    // Publish the restart requirement before any error or caller-side checks.
    // The elevated account may differ from the account that owns this process.
    let reboot = outcome.finish()?;
    if action == Action::Prepare {
        if !admin {
            let host = status()?;
            crate::log!(
                Debug,
                "drivers:status",
                "After UAC: {}",
                serde_json::to_string(&host)?
            );
            ensure!(
                !host.needs_preparation(),
                "Windows setup could not be confirmed. Open USB diagnostics."
            );
        }
        verify_connected_devices(reboot)?;
    }
    Ok(reboot)
}

fn verify_connected_devices(reboot: bool) -> Result<()> {
    if reboot {
        crate::log!(Info, "drivers", "Check USB after restarting Windows");
        return Ok(());
    }
    let devices =
        crate::drivers::diagnostics(true).context("Checking USB access after Windows setup")?;
    verify_device_access(&devices)
}

fn verify_device_access(devices: &[crate::drivers::UsbDiagnostic]) -> Result<()> {
    for device in devices {
        crate::log!(
            Debug,
            "drivers:usb",
            "After setup: {}",
            serde_json::to_string(device)?
        );
    }
    if devices.is_empty() {
        crate::log!(Info, "drivers:usb", "No Mac connected; access not checked");
    } else {
        let failures: Vec<_> = devices
            .iter()
            .filter(|device| !device.accessible)
            .map(|device| {
                format!(
                    "{} (driver: {}): {}",
                    device.instance_id,
                    device.driver.as_deref().unwrap_or("not assigned"),
                    device
                        .error
                        .as_deref()
                        .unwrap_or("USB interface unavailable")
                )
            })
            .collect();
        ensure!(
            failures.is_empty(),
            "Package installed, but access to the connected device could not be confirmed. Reconnect the Mac; if the error persists, reset Apple USB drivers. {}",
            failures.join("; ")
        );
        crate::log!(Info, "drivers:usb", "Access confirmed");
    }
    Ok(())
}

pub(crate) fn open_installed_apps() -> Result<()> {
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("open").as_ptr(),
            wide("ms-settings:appsfeatures").as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    ensure!(
        result as isize > 32,
        "Could not open Windows apps ({})",
        result as isize
    );
    Ok(())
}

/// Run a specific Zalivka helper through Windows UAC.
fn run_elevated(action: Action) -> Result<u32> {
    let started = Instant::now();
    let pipe = log::LogPipe::new()?;
    let action = action.name();
    let parameters = format!("--driver-helper {action} {}", pipe.id);
    let mut pipe = Some(pipe);
    crate::log!(
        Debug,
        "drivers:uac",
        "Launching {}: {action}",
        std::env::current_exe()?.display()
    );
    let executable = wide(std::env::current_exe()?);
    let verb = wide("runas");
    let arguments = wide(parameters);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = executable.as_ptr();
    info.lpParameters = arguments.as_ptr();
    info.nShow = SW_HIDE;
    ensure!(
        unsafe { ShellExecuteExW(&mut info) } != 0,
        "Windows setup did not start (the administrator prompt may have been cancelled): {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        !info.hProcess.is_null(),
        "Windows did not return an installer process"
    );
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    crate::log!(Debug, "drivers:uac", "PID={}", unsafe {
        GetProcessId(process.as_raw_handle())
    });
    loop {
        let state = unsafe { WaitForSingleObject(process.as_raw_handle(), 100) };
        ensure!(
            state == WAIT_OBJECT_0 || state == WAIT_TIMEOUT,
            "Waiting for Windows setup: {}",
            std::io::Error::last_os_error()
        );
        if let Some(reader) = &mut pipe
            && let Err(error) = reader.drain(|record| {
                crate::logging::publish(crate::logging::Record::new(
                    record.level,
                    record.source,
                    record.message,
                ));
            })
        {
            crate::log!(Warning, "drivers:uac", "Journal incomplete: {error:#}");
            // Closing the reader unblocks the helper if a write is pending.
            pipe = None;
        }
        if state == WAIT_OBJECT_0 {
            break;
        }
    }
    if let Some(reader) = &pipe {
        if !reader.received {
            crate::log!(Warning, "drivers:uac", "Process did not send a journal");
        } else if reader.incomplete() {
            crate::log!(Warning, "drivers:uac", "Last record truncated");
        }
    }
    let mut code = 0;
    ensure!(
        unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0,
        "Windows setup result: {}",
        std::io::Error::last_os_error()
    );
    crate::log!(
        Debug,
        "drivers:uac",
        "Code={code} (0x{code:08X}); {:.3} s",
        started.elapsed().as_secs_f64()
    );
    Ok(code)
}

/// Private UAC entry point, handled before CLI parsing. Only fixed driver
/// actions and a local pipe UUID are accepted; no command or output path.
pub(crate) fn run_helper() -> Option<u32> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--driver-helper")) {
        return None;
    }
    let result = (|| -> Result<u32> {
        let action = args.next().context("missing driver helper action")?;
        let action = match action.to_str() {
            Some("prepare") => Action::Prepare,
            Some("reset") => Action::Reset,
            _ => bail!("invalid driver helper action"),
        };
        let id = args
            .next()
            .and_then(|id| id.into_string().ok())
            .context("missing log pipe identifier")?
            .parse::<uuid::Uuid>()?;
        ensure!(args.next().is_none(), "unexpected driver helper arguments");
        crate::logging::connect_elevated(id)?;
        let outcome = action.elevated();
        if let Err(error) = &outcome.result {
            crate::log!(Error, "drivers:uac", "{error:#}");
        }
        Ok(outcome.exit_code())
    })();
    Some(result.unwrap_or_else(|error| {
        crate::log!(Error, "drivers:uac", "{error:#}");
        1
    }))
}

#[cfg(test)]
#[path = "../../tests/unit/windows/setup.rs"]
mod tests;
