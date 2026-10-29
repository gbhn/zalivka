//! Remove only Apple restore devnodes; leave driver packages in DriverStore intact.
use super::{architecture, stop_service, wide};
use crate::windows::DeviceInfoSet;
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
        && u16::from_str_radix(pid, 16).is_ok_and(|pid| {
            crate::device::Mode::from_pid(pid).is_some() || matches!(pid, 0x12ac | 0x1881)
        })
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
            "Opening token for device rescan: {}",
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
            "Looking up SeLoadDriverPrivilege: {}",
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
            "Enabling SeLoadDriverPrivilege: {}",
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
                "Restoring token privileges: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn devices() -> Result<(DeviceInfoSet, Vec<(String, SP_DEVINFO_DATA)>)> {
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
        "USB device list: {}",
        io::Error::last_os_error()
    );
    let set = DeviceInfoSet(raw);
    let mut devices = Vec::new();
    for index in 0.. {
        let mut data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of_val(&data) as u32;
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut data) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(error).context("Enumerating USB devices before reset");
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
            "Reading USB device identifier: {}",
            io::Error::last_os_error()
        );
        ensure!(
            (1..=id.len() as u32).contains(&length),
            "Invalid USB identifier length: {length}"
        );
        let instance =
            String::from_utf16(&id[..length as usize - 1]).context("UTF-16 USB identifier")?;
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
        "Device tree root: CONFIGRET {result:#x}"
    );
    let result = unsafe { CM_Reenumerate_DevNode(root, CM_REENUMERATE_NORMAL) };
    ensure!(result == CR_SUCCESS, "Device rescan: CONFIGRET {result:#x}");
    crate::log!(Info, "drivers:usb", "Device rescan requested");
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
        (Err(error), Err(scan)) => {
            Err(error.context(format!("Device rescan also failed: {scan:#}")))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

pub(super) fn reset_elevated(reboot: &mut bool) -> Result<()> {
    crate::log!(
        Debug,
        "drivers:reset",
        "Resetting Apple USB; version={}",
        crate::VERSION
    );
    ensure!(
        unsafe { IsUserAnAdmin() } != 0,
        "USB driver reset requires local Windows administrator rights"
    );
    let _privilege = DriverPrivilege::enable()?;
    let directory = tempfile::Builder::new()
        .prefix("zalivka-apple-reset-")
        .tempdir()?;
    let arch = architecture()?;
    let mut infs = Vec::new();
    for driver in crate::windows::package::DRIVERS {
        let path = directory.path().join(format!("{driver:?}"));
        std::fs::create_dir(&path)?;
        infs.push(driver.unpack(&path, arch)?);
    }
    let (set, targets) = devices()?;
    crate::log!(
        Info,
        "drivers:reset",
        "Records to remove: {}",
        targets.len()
    );
    // Complete all preflight checks before removing anything.
    stop_service()?;
    with_rescan(
        || {
            for (instance, data) in &targets {
                crate::log!(Debug, "drivers:reset", "Removing {instance}");
                let mut required = 0;
                let ok =
                    unsafe { DiUninstallDevice(ptr::null_mut(), set.0, data, 0, &mut required) };
                *reboot |= required != 0;
                ensure!(
                    ok != 0,
                    "Removing {instance}: {}",
                    io::Error::last_os_error()
                );
            }
            // Keep all DriverStore packages: reinstall the original signed package with normal ranking.
            for inf in &infs {
                *reboot |= crate::windows::package::install(inf)
                    .context("Reinstalling Apple restore driver")?;
            }
            Ok(())
        },
        rescan,
    )?;
    crate::log!(Info, "drivers:reset", "Complete; reboot={reboot}");
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/setup/cleanup.rs"]
mod tests;
