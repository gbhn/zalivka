//! The WinUSB API has no device reset. Ask the *parent hub* to cycle just this port.
//! https://learn.microsoft.com/windows-hardware/drivers/ddi/usbioctl/ni-usbioctl-ioctl_usb_hub_cycle_port
use super::Ioctl;
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Devices::Usb::{GUID_DEVINTERFACE_USB_HUB, IOCTL_USB_HUB_CYCLE_PORT, USB_CYCLE_PORT_PARAMS},
    Foundation::{GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    System::IO::DeviceIoControl,
};

fn parent_hub(device: &nusb::DeviceInfo) -> Result<OwnedHandle> {
    ensure!(
        device.port_number() != 0,
        "Windows returned an invalid USB port number"
    );
    let paths = super::interface_paths(
        &GUID_DEVINTERFACE_USB_HUB,
        Some(device.parent_instance_id()),
        65536,
    )?;
    let path = paths
        .first()
        .context("parent device does not expose a USB hub interface")?;
    // SAFETY: path is NUL terminated; optional pointer arguments are null.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context(
            "opening USB hub; Windows administrator privileges are required for DFU reset",
        );
    }
    // SAFETY: CreateFileW returned a fresh owned, valid HANDLE.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Check hub write access without cycling a port or issuing an IOCTL.
pub fn check_access(device: &nusb::DeviceInfo) -> Result<()> {
    drop(parent_hub(device)?);
    Ok(())
}

pub fn cycle_port(device: &nusb::DeviceInfo) -> Result<()> {
    let handle = parent_hub(device)?;
    cycle_port_request(
        handle.as_raw_handle(),
        device.port_number(),
        DeviceIoControl,
    )
}

fn cycle_port_request(handle: HANDLE, port: u32, ioctl: Ioctl) -> Result<()> {
    ensure!(port != 0, "Windows returned an invalid USB port number");
    let mut params = USB_CYCLE_PORT_PARAMS {
        ConnectionIndex: port,
        StatusReturned: 0,
    };
    let buffer = (&mut params as *mut USB_CYCLE_PORT_PARAMS).cast::<c_void>();
    let size = size_of::<USB_CYCLE_PORT_PARAMS>() as u32;
    let mut returned = 0;
    // USB hub drivers require this structure as both input and output: the
    // driver writes StatusReturned back. A null output buffer causes error 122.
    // SAFETY: buffer is a live mutable USB_CYCLE_PORT_PARAMS for both directions,
    // returned is writable and this synchronous hub handle needs no OVERLAPPED.
    let success = unsafe {
        ioctl(
            handle,
            IOCTL_USB_HUB_CYCLE_PORT,
            buffer,
            size,
            buffer,
            size,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error()).context("cycling DFU USB port");
    }
    ensure!(
        returned == size,
        "USB hub returned {returned} bytes for port cycle; expected {size}"
    );
    let status = params.StatusReturned;
    ensure!(
        status == 0,
        "USB hub could not cycle DFU port {port}: USBD status {status:#010x}"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/windows/reset.rs"]
mod tests;
