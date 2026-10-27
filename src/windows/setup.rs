//! Windows host preparation. The embedded Apple CABs are unmodified signed packages.
use super::{wide, windows_directory};
pub(crate) mod cleanup;
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
    let directory = windows_directory()?.join(r"System32\DriverStore\FileRepository");
    crate::log!(
        Debug,
        "drivers",
        "Поиск {prefix}* в {}",
        directory.display()
    );
    for entry in std::fs::read_dir(&directory)
        .with_context(|| format!("Чтение DriverStore: {}", directory.display()))?
    {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&prefix)
        {
            let missing: Vec<_> = super::package::FILES
                .iter()
                .filter(|name| !entry.path().join(name).is_file())
                .collect();
            crate::log!(
                Debug,
                "drivers",
                "Пакет Apple: {}; отсутствующие файлы: {missing:?}",
                entry.path().display()
            );
            if missing.is_empty() {
                return Ok(true);
            }
        }
    }
    crate::log!(
        Debug,
        "drivers",
        "Полный пакет Apple для текущей архитектуры в DriverStore не найден"
    );
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
    })
}

fn stop_service() -> Result<()> {
    crate::log!(Info, "drivers", "Проверка и остановка {SERVICE}");
    let Some(service) = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)? else {
        crate::log!(
            Info,
            "drivers",
            "{SERVICE} не установлена; остановка не требуется"
        );
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut previous = None;
    loop {
        let state = service_state(&service)?;
        if previous != Some(state) {
            crate::log!(Info, "drivers", "{SERVICE}: {state:?}");
            previous = Some(state);
        }
        if state == ServiceState::Stopped {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Apple Mobile Device Service не остановилась за 30 секунд. Закройте iTunes / Apple Devices и повторите подготовку Windows."
        );
        if state != ServiceState::StopPending {
            crate::log!(Debug, "drivers", "Отправка SERVICE_CONTROL_STOP: {SERVICE}");
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
    let started = Instant::now();
    let admin = unsafe { IsUserAnAdmin() } != 0;
    crate::log!(
        Info,
        "drivers",
        "Начало подготовки Windows: PID={}, версия={}, EXE={}",
        std::process::id(),
        crate::VERSION,
        std::env::current_exe()?.display()
    );
    crate::log!(
        Info,
        "drivers",
        "Проверка прав: IsUserAnAdmin={admin}; активная группа Администраторы (S-1-5-32-544) обязательна"
    );
    if let Err(error) = token::log() {
        crate::log!(
            Warning,
            "drivers",
            "Не удалось прочитать все сведения токена: {error:#}"
        );
    }
    ensure!(
        admin,
        "Для подготовки Windows нужны права администратора: IsUserAnAdmin=false. В токене процесса нет активного членства в локальной группе Администраторы (S-1-5-32-544). Подтверждение UAC и высокий уровень целостности сами по себе не гарантируют это членство. Запустите подготовку под учётной записью с правами локального администратора этого компьютера."
    );
    let arch = architecture().context("Определение архитектуры перед установкой драйвера")?;
    crate::log!(
        Info,
        "drivers",
        "Архитектура Windows: {arch}; каталог Windows: {}",
        windows_directory()?.display()
    );
    // Check the service first; don't replace the driver if stopping the conflict fails.
    stop_service().context("Подготовка Windows: остановка службы Apple")?;
    let mut reboot = false;
    if !apple_driver_installed()? {
        let directory = tempfile::Builder::new()
            .prefix("zalivka-apple-usb-")
            .tempdir()
            .context("Создание временного каталога драйвера Apple")?;
        crate::log!(
            Info,
            "drivers",
            "Распаковка встроенного пакета Apple ({arch}): {}",
            directory.path().display()
        );
        let inf = super::package::unpack(directory.path(), arch)
            .context("Подготовка Windows: распаковка пакета Apple")?;
        // Windows verifies the original CAT. No forced ranking or signing bypass.
        reboot = crate::drivers::install(&inf)
            .context("Подготовка Windows: установка драйвера Apple")?;
    } else {
        crate::log!(
            Info,
            "drivers",
            "Полный пакет Apple уже установлен; повторная установка не требуется"
        );
    }
    crate::log!(
        Info,
        "drivers",
        "Итоговая проверка драйверов и службы Apple"
    );
    let host = status()?;
    crate::log!(
        Info,
        "drivers",
        "Windows после установки: {}",
        serde_json::to_string(&host)?
    );
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
    crate::log!(
        Info,
        "drivers",
        "Подготовка Windows завершена за {:.3} с; требуется перезагрузка: {reboot}",
        started.elapsed().as_secs_f64()
    );
    Ok(reboot)
}

pub(crate) fn prepare() -> Result<bool> {
    crate::log!(
        Info,
        "drivers",
        "Проверка Windows перед подготовкой; PID={}; IsUserAnAdmin={}",
        std::process::id(),
        unsafe { IsUserAnAdmin() } != 0
    );
    let host = status()?;
    crate::log!(
        Info,
        "drivers",
        "Windows до установки: {}",
        serde_json::to_string(&host)?
    );
    if !host.needs_preparation() {
        crate::log!(
            Info,
            "drivers",
            "Все доступные драйверы уже готовы; повторная установка не требуется."
        );
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
        "Подготовка Windows завершилась с кодом {code}. Причина указана в сообщениях установщика выше."
    );
    // Elevated credentials can belong to another account; recheck this user's view too.
    let host = status()?;
    crate::log!(
        Info,
        "drivers",
        "Windows после завершения UAC: {}",
        serde_json::to_string(&host)?
    );
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
    let started = Instant::now();
    let pipe = log::LogPipe::new()?;
    let parameters = format!("--verbose --elevated-log {} {arguments}", pipe.id);
    let mut pipe = Some(pipe);
    crate::log!(
        Info,
        "drivers",
        "Запуск через UAC: {}; команда: {arguments}",
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
        "Подготовка Windows не запущена (возможно, запрос прав отменён): {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        !info.hProcess.is_null(),
        "Windows не вернула процесс установки"
    );
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    crate::log!(
        Info,
        "drivers",
        "Процесс UAC запущен: PID={}; ожидание журнала установщика",
        unsafe { GetProcessId(process.as_raw_handle()) }
    );
    loop {
        let state = unsafe { WaitForSingleObject(process.as_raw_handle(), 100) };
        ensure!(
            state == WAIT_OBJECT_0 || state == WAIT_TIMEOUT,
            "Ожидание подготовки Windows: {}",
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
            crate::log!(Warning, "drivers", "Журнал установщика неполный: {error:#}");
            // Closing the reader unblocks the helper if a write is pending.
            pipe = None;
        }
        if state == WAIT_OBJECT_0 {
            break;
        }
    }
    if let Some(reader) = &pipe {
        if !reader.received {
            crate::log!(
                Warning,
                "drivers",
                "Процесс UAC не передал ни одной записи журнала. Возможен сбой запуска или подключения к каналу журнала."
            );
        } else if reader.incomplete() {
            crate::log!(Warning, "drivers", "Последняя запись журнала UAC оборвана");
        }
    }
    let mut code = 0;
    ensure!(
        unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0,
        "Результат подготовки Windows: {}",
        std::io::Error::last_os_error()
    );
    crate::log!(
        Info,
        "drivers",
        "Процесс UAC завершён: код={code} (0x{code:08X}); время={:.3} с",
        started.elapsed().as_secs_f64()
    );
    Ok(code)
}
