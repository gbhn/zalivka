//! Windows host preparation. The embedded Apple CABs are unmodified signed packages.
use super::{wide, windows_directory};
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
        WAIT_OBJECT_0,
    },
    System::{
        SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64},
        Threading::{
            GetCurrentProcess, GetExitCodeProcess, INFINITE, IsWow64Process2, WaitForSingleObject,
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

fn architecture() -> Result<&'static str> {
    let mut process = 0;
    let mut native = 0;
    ensure!(
        unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0,
        "Не удалось определить архитектуру Windows: {}",
        std::io::Error::last_os_error()
    );
    match native {
        IMAGE_FILE_MACHINE_AMD64 => Ok("amd64"),
        IMAGE_FILE_MACHINE_ARM64 => Ok("arm64"),
        _ => bail!("Встроенный драйвер поддерживает Windows x64 и ARM64"),
    }
}

fn open_service(access: ServiceAccess) -> Result<Option<Service>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("Открытие диспетчера служб Windows")?;
    match manager.open_service(SERVICE, access) {
        Ok(service) => Ok(Some(service)),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("Открытие Apple Mobile Device Service"),
    }
}

fn service_state(service: &Service) -> Result<ServiceState> {
    Ok(service
        .query_status()
        .context("Проверка Apple Mobile Device Service")?
        .current_state)
}

fn apple_driver_installed() -> Result<bool> {
    let prefix = format!("appleusb.inf_{}_", architecture()?);
    for entry in
        std::fs::read_dir(windows_directory()?.join(r"System32\DriverStore\FileRepository"))?
    {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&prefix)
            && [
                "AppleUsb.inf",
                "appleusb.cat",
                "AppleUsbFilter.dll",
                "AppleKmdfFilter.sys",
            ]
            .iter()
            .all(|name| entry.path().join(name).is_file())
        {
            return Ok(true);
        }
    }
    Ok(false)
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
                || d.interfaces()
                    .any(|i| (i.class(), i.subclass(), i.protocol()) == crate::usb::MUX_INTERFACE))
            && d.driver()
                .is_some_and(|name| name.eq_ignore_ascii_case("winusb"))
    });
    Ok(HostStatus {
        apple_service_installed: service.is_some(),
        apple_service_running: active,
        apple_driver_installed: apple_driver_installed()?,
        compatible_usb_driver,
        usb_network_driver_available: super::ncm::available()?,
        usb_network_interfaces: super::ncm::status()?,
    })
}

fn stop_service() -> Result<()> {
    let Some(service) = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)? else {
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = service_state(&service)?;
        if state == ServiceState::Stopped {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Apple Mobile Device Service не остановилась за 30 секунд. Закройте iTunes / Apple Devices и повторите подготовку Windows."
        );
        if state != ServiceState::StopPending {
            match service.stop() {
                Ok(_) => {}
                Err(windows_service::Error::Winapi(error))
                    if matches!(error.raw_os_error(), Some(code)
                        if code == ERROR_SERVICE_NOT_ACTIVE as i32
                            || code == ERROR_SERVICE_CANNOT_ACCEPT_CTRL as i32) => {}
                Err(error) => return Err(error).context("Остановка Apple Mobile Device Service"),
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub(crate) fn prepare_elevated() -> Result<bool> {
    ensure!(
        unsafe { IsUserAnAdmin() } != 0,
        "Для подготовки Windows нужны права администратора"
    );
    // Check the service first; don't replace the driver if stopping the conflict fails.
    stop_service()?;
    let mut reboot = false;
    if !apple_driver_installed()? {
        let directory = tempfile::Builder::new()
            .prefix("zalivka-apple-usb-")
            .tempdir()?;
        let inf = super::package::unpack(directory.path(), architecture()?)?;
        // Windows verifies the original CAT. No forced ranking or signing bypass.
        reboot = crate::drivers::install(&inf)?;
    }
    ensure!(
        super::ncm::available()?,
        "В Windows отсутствует штатный драйвер winusb.inf. Восстановите системные файлы Windows и повторите подготовку."
    );
    let interfaces = super::ncm::status()?;
    let mut serials: Vec<_> = interfaces
        .iter()
        .filter(|i| !i.ready)
        .map(|i| i.serial.as_str())
        .collect();
    serials.sort_unstable();
    serials.dedup();
    for serial in serials {
        super::ncm::prepare(serial, false)?;
    }
    let host = status()?;
    ensure!(
        !host.apple_service_running,
        "Apple Mobile Device Service запустилась снова. Закройте iTunes / Apple Devices или удалите Apple Mobile Device Support в приложениях Windows."
    );
    ensure!(
        host.apple_driver_installed,
        "Windows не подтвердила установку драйвера Apple"
    );
    ensure!(
        !host.needs_preparation(),
        "Windows не подтвердила готовность всех драйверов. Откройте диагностику USB."
    );
    if host.usb_network_interfaces.is_empty() {
        crate::log!(
            Info,
            "drivers",
            "USB-сеть: проверка привязок будет доступна после подключения загруженного Mac."
        );
    }
    Ok(reboot)
}

pub(crate) fn prepare() -> Result<bool> {
    let host = status()?;
    if !host.needs_preparation() {
        crate::log!(
            Info,
            "drivers",
            "Все доступные драйверы уже готовы; повторная установка не требуется."
        );
        if host.usb_network_interfaces.is_empty() {
            crate::log!(
                Info,
                "drivers",
                "USB-сеть: проверка привязок будет доступна после подключения загруженного Mac."
            );
        }
        return Ok(false);
    }
    if unsafe { IsUserAnAdmin() } != 0 {
        return prepare_elevated();
    }
    crate::log!(
        Info,
        "drivers",
        "Подготовка драйверов: подтвердите запрос прав администратора Windows"
    );
    let code = run_elevated("drivers prepare-elevated")?;
    ensure!(
        code == 0 || code == 3010,
        "Подготовка Windows завершилась с кодом {code}. Закройте iTunes / Apple Devices и повторите. Подробности: запустите zalivka drivers prepare из терминала администратора."
    );
    // Elevated credentials can belong to another account; recheck this user's view too.
    let host = status()?;
    ensure!(
        !host.needs_preparation(),
        "Подготовка Windows не подтверждена. Откройте диагностику USB."
    );
    Ok(code == 3010)
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
        "Не удалось открыть список приложений Windows ({})",
        result as isize
    );
    Ok(())
}

/// Run a specific Zalivka helper through Windows UAC.
pub(crate) fn run_elevated(arguments: &str) -> Result<u32> {
    let executable = wide(std::env::current_exe()?);
    let verb = wide("runas");
    let arguments = wide(arguments);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = executable.as_ptr();
    info.lpParameters = arguments.as_ptr();
    info.nShow = SW_HIDE;
    ensure!(
        unsafe { ShellExecuteExW(&mut info) } != 0,
        "Подготовка Windows не запущена (возможно, запрос прав отменён): {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        !info.hProcess.is_null(),
        "Windows не вернула процесс установки"
    );
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    ensure!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } == WAIT_OBJECT_0,
        "Ожидание подготовки Windows: {}",
        std::io::Error::last_os_error()
    );
    let mut code = 0;
    ensure!(
        unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0,
        "Результат подготовки Windows: {}",
        std::io::Error::last_os_error()
    );
    Ok(code)
}
