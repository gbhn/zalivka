//! Windows APIs used by USB transport, proxy discovery and host preparation.
use anyhow::{Result, bail, ensure};
use std::{
    ffi::{OsStr, OsString, c_void},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::{
    Win32::Devices::DeviceAndDriverInstallation::{
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CM_Get_Device_Interface_List_SizeW,
        CM_Get_Device_Interface_ListW, CR_BUFFER_SMALL, CR_SUCCESS,
    },
    Win32::{Foundation::HANDLE, System::IO::OVERLAPPED},
    core::GUID,
};

// Shared signature for the testable DeviceIoControl calls in both USB backends.
type Ioctl = unsafe extern "system" fn(
    HANDLE,
    u32,
    *const c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut OVERLAPPED,
) -> i32;

/// Own a SetupAPI set, including its associated device and driver information.
struct DeviceInfoSet(windows_sys::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the set returned by SetupAPI.
        unsafe {
            windows_sys::Win32::Devices::DeviceAndDriverInstallation::SetupDiDestroyDeviceInfoList(
                self.0,
            )
        };
    }
}

pub(crate) mod apple;
pub(crate) mod negotiate;
pub(crate) mod package;
pub(crate) mod proxy;
pub(crate) mod reset;
pub(crate) mod setup;
pub(crate) mod tls;

pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn windows_directory() -> Result<PathBuf> {
    let mut buffer = [0u16; 32768];
    let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    ensure!(
        len > 0 && len < buffer.len(),
        "Could not locate the Windows directory: {}",
        std::io::Error::last_os_error()
    );
    Ok(OsString::from_wide(&buffer[..len]).into())
}

/// Config Manager can change the required buffer size between the two calls.
fn interface_paths(
    guid: &GUID,
    instance: Option<&OsStr>,
    max_length: u32,
) -> Result<Vec<Vec<u16>>> {
    let instance = instance.map(|s| s.encode_wide().collect::<Vec<_>>());
    ensure!(
        instance.as_ref().is_none_or(|s| !s.contains(&0)),
        "invalid USB instance ID"
    );
    let instance = instance.map(|mut s| {
        s.push(0);
        s
    });
    let instance = instance.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    for _ in 0..3 {
        let mut len = 0;
        // SAFETY: GUID and len are valid; instance is null or NUL terminated.
        let status = unsafe {
            CM_Get_Device_Interface_List_SizeW(
                &mut len,
                guid,
                instance,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        ensure!(
            status == CR_SUCCESS && (1..=max_length).contains(&len),
            "enumerating USB paths (CONFIGRET {status:#x})"
        );
        let mut buffer = vec![0u16; len as usize];
        // SAFETY: buffer contains len initialized UTF-16 code units.
        let status = unsafe {
            CM_Get_Device_Interface_ListW(
                guid,
                instance,
                buffer.as_mut_ptr(),
                len,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if status == CR_BUFFER_SMALL {
            continue;
        }
        ensure!(
            status == CR_SUCCESS,
            "reading USB paths (CONFIGRET {status:#x})"
        );
        ensure!(buffer.last() == Some(&0), "unterminated USB path list");
        return Ok(buffer
            .split(|c| *c == 0)
            .filter(|s| !s.is_empty())
            .map(|s| s.iter().copied().chain(Some(0)).collect())
            .collect());
    }
    bail!("USB topology changed repeatedly during enumeration")
}
