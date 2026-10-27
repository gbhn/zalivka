//! Remove only Apple restore devnodes; leave driver packages in DriverStore intact.
use super::{architecture, run_elevated, stop_service, wide};
use anyhow::{Context, Result, ensure};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::*,
    Foundation::{ERROR_NO_MORE_ITEMS, GetLastError, INVALID_HANDLE_VALUE},
    Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    UI::Shell::IsUserAnAdmin,
};

// Match whole hardware ID fields. Interface devnodes are removed with their parent.
fn is_restore_device(instance: &str) -> bool {
    let mut parts = instance.split('\\');
    let (Some(bus), Some(hardware), Some(serial)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !bus.eq_ignore_ascii_case("USB") || serial.is_empty() || parts.next().is_some() {
        return false;
    }
    let hardware = hardware.to_ascii_uppercase();
    let hardware = hardware.strip_suffix("&RESTORE_MODE").unwrap_or(&hardware);
    let Some(pid) = hardware.strip_prefix("VID_05AC&PID_") else {
        return false;
    };
    pid.len() == 4
        && u16::from_str_radix(pid, 16)
            .is_ok_and(|pid| crate::device::Mode::from_pid(pid).is_some() || pid == 0x12ac)
}

struct Set(HDEVINFO);
impl Drop for Set {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

struct DriverPrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}
impl DriverPrivilege {
    fn enable() -> Result<Self> {
        let mut token = ptr::null_mut();
        ensure!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    &mut token,
                )
            } != 0,
            "Открытие токена для поиска устройств: {}",
            io::Error::last_os_error()
        );
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut requested: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        requested.PrivilegeCount = 1;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ensure!(
            unsafe {
                LookupPrivilegeValueW(
                    ptr::null(),
                    wide("SeLoadDriverPrivilege").as_ptr(),
                    &mut requested.Privileges[0].Luid,
                )
            } != 0,
            "Поиск SeLoadDriverPrivilege: {}",
            io::Error::last_os_error()
        );
        let mut previous: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        let mut length = 0;
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &requested,
                std::mem::size_of_val(&previous) as u32,
                &mut previous,
                &mut length,
            )
        };
        // AdjustTokenPrivileges can return TRUE with ERROR_NOT_ALL_ASSIGNED.
        let error = unsafe { GetLastError() };
        ensure!(
            ok != 0 && error == 0,
            "Включение SeLoadDriverPrivilege: {}",
            io::Error::from_raw_os_error(error as i32)
        );
        Ok(Self { token, previous })
    }
}
impl Drop for DriverPrivilege {
    fn drop(&mut self) {
        if unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            crate::log!(
                Warning,
                "drivers",
                "Возврат привилегий токена: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn devices() -> Result<(Set, Vec<(String, SP_DEVINFO_DATA)>)> {
    // Deliberately omit DIGCF_PRESENT: stale, disconnected records matter here.
    let raw = unsafe {
        SetupDiGetClassDevsW(
            ptr::null(),
            wide("USB").as_ptr(),
            ptr::null_mut(),
            DIGCF_ALLCLASSES,
        )
    };
    ensure!(
        raw != INVALID_HANDLE_VALUE as isize,
        "Список USB-устройств: {}",
        io::Error::last_os_error()
    );
    let set = Set(raw);
    let mut devices = Vec::new();
    for index in 0.. {
        let mut data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of_val(&data) as u32;
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut data) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(error).context("Перечисление USB-устройств перед сбросом");
        }
        let mut id = [0u16; 512];
        let mut length = 0;
        ensure!(
            unsafe {
                SetupDiGetDeviceInstanceIdW(
                    set.0,
                    &data,
                    id.as_mut_ptr(),
                    id.len() as u32,
                    &mut length,
                )
            } != 0,
            "Чтение идентификатора USB-устройства: {}",
            io::Error::last_os_error()
        );
        ensure!(
            (1..=id.len() as u32).contains(&length),
            "Некорректная длина USB-идентификатора: {length}"
        );
        let instance =
            String::from_utf16(&id[..length as usize - 1]).context("USB-идентификатор UTF-16")?;
        if is_restore_device(&instance) {
            devices.push((instance, data));
        }
    }
    Ok((set, devices))
}

fn rescan() -> Result<()> {
    let mut root = 0;
    let result = unsafe { CM_Locate_DevNodeW(&mut root, ptr::null(), CM_LOCATE_DEVNODE_NORMAL) };
    ensure!(
        result == CR_SUCCESS,
        "Корень дерева устройств: CONFIGRET {result:#x}"
    );
    let result = unsafe { CM_Reenumerate_DevNode(root, CM_REENUMERATE_NORMAL) };
    ensure!(
        result == CR_SUCCESS,
        "Поиск устройств: CONFIGRET {result:#x}"
    );
    crate::log!(
        Info,
        "drivers",
        "Запрос поиска устройств Windows выполнен. Повторное подключение Mac может потребоваться."
    );
    Ok(())
}

// Rescan even after a partial failure so removed devices can be detected again.
fn with_rescan(
    change: impl FnOnce() -> Result<()>,
    scan: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let result = change();
    let scanned = scan();
    match (result, scanned) {
        (Err(error), Err(scan)) => Err(error.context(format!(
            "Повторный поиск устройств также не выполнен: {scan:#}"
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

pub(crate) fn reset_elevated(reboot: &mut bool) -> Result<()> {
    crate::log!(
        Info,
        "drivers",
        "Начало сброса USB-драйверов Apple; версия={}",
        crate::VERSION
    );
    ensure!(
        unsafe { IsUserAnAdmin() } != 0,
        "Для сброса USB-драйверов нужны права локального администратора Windows"
    );
    let _privilege = DriverPrivilege::enable()?;
    let directory = tempfile::Builder::new()
        .prefix("zalivka-apple-reset-")
        .tempdir()?;
    let inf = crate::windows::package::unpack(directory.path(), architecture()?)?;
    let (set, targets) = devices()?;
    crate::log!(
        Info,
        "drivers",
        "Записей DFU / Recovery / Restore для удаления: {}",
        targets.len()
    );
    // Complete all preflight checks before removing anything.
    stop_service()?;
    with_rescan(
        || {
            for (instance, data) in &targets {
                crate::log!(Info, "drivers", "Удаление записи подключения: {instance}");
                let mut required = 0;
                let ok =
                    unsafe { DiUninstallDevice(ptr::null_mut(), set.0, data, 0, &mut required) };
                *reboot |= required != 0;
                ensure!(
                    ok != 0,
                    "Удаление {instance}: {}",
                    io::Error::last_os_error()
                );
            }
            // Keep all DriverStore packages: reinstall the original signed package with normal ranking.
            *reboot |=
                crate::drivers::install(&inf).context("Повторная установка USB-драйвера Apple")?;
            Ok(())
        },
        rescan,
    )?;
    crate::log!(
        Info,
        "drivers",
        "Удаление записей и установка драйвера завершены; требуется перезагрузка: {reboot}"
    );
    Ok(())
}

pub(crate) fn reset() -> Result<bool> {
    let mut reboot = false;
    let result = if unsafe { IsUserAnAdmin() } != 0 {
        reset_elevated(&mut reboot)
    } else {
        let code = run_elevated("drivers reset-elevated")?;
        reboot = matches!(code, 3010 | 3017);
        if code == 0 || code == 3010 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Сброс USB-драйверов завершился с кодом {code}. Причина указана в журнале выше."
            ))
        }
    };
    if reboot {
        crate::progress::Event::RebootRequired.emit();
        crate::log!(
            Warning,
            "drivers",
            "Перезагрузите Windows перед восстановлением Mac."
        );
    }
    result?;
    Ok(reboot)
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/setup/cleanup.rs"]
mod tests;
