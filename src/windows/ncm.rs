//! Install the unmodified, signed Windows WinUSB model on only the Mac NCM
//! interfaces. No parent-device filters, USB configuration, or routing changes.
use super::{wide, windows_directory};
use crate::drivers::UsbNetworkInterfaceStatus;
use anyhow::{Context, Result, ensure};
use nusb::MaybeFuture;
use std::ptr;
use windows_sys::{
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::*,
            Properties::{DEVPKEY_Device_Service, DEVPROP_TYPE_STRING},
        },
        System::Registry::*,
        UI::Shell::IsUserAnAdmin,
    },
    core::GUID,
};
mod install;
use install::install;

const GUID_TEXT: &str = "{6E36578F-6547-4BA7-97DE-25D5892F140E}";
fn text(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|c| *c == 0).unwrap_or(s.len())])
}
fn parameters_path(instance: &str) -> Vec<u16> {
    wide(format!(
        "SYSTEM\\CurrentControlSet\\Enum\\{instance}\\Device Parameters"
    ))
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn read_value(key: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>> {
    let mut ty = 0;
    let mut size = 0;
    let name = wide(name);
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            ptr::null_mut(),
            &mut size,
        )
    };
    if result == 2 {
        return Ok(None);
    }
    ensure!(
        result == 0 && size <= 65536,
        "reading NCM interface GUIDs failed"
    );
    let mut bytes = vec![0; size as usize];
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            bytes.as_mut_ptr(),
            &mut size,
        )
    };
    ensure!(result == 0, "reading NCM interface GUIDs failed");
    bytes.truncate(size as usize);
    Ok(Some((ty, bytes)))
}
fn parse_guid(text: &str) -> Result<GUID> {
    ensure!(
        text.len() == 38 && text.starts_with('{') && text.ends_with('}'),
        "invalid interface GUID"
    );
    let uuid = uuid::Uuid::parse_str(text).context("invalid interface GUID")?;
    Ok(GUID::from_u128(uuid.as_u128()))
}

fn interface_guids(ty: u32, bytes: &[u8]) -> Vec<GUID> {
    if !matches!(ty, REG_MULTI_SZ | REG_SZ) || !bytes.len().is_multiple_of(2) {
        return vec![];
    }
    let value: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    value
        .split(|c| *c == 0)
        .take_while(|part| !part.is_empty())
        .take(if ty == REG_SZ { 1 } else { usize::MAX })
        .filter_map(|part| parse_guid(&String::from_utf16(part).ok()?).ok())
        .collect()
}

fn binding_state(service: &str, flags: u32, problem: u32, registered: bool) -> Result<()> {
    ensure!(
        service.eq_ignore_ascii_case("winusb"),
        "WinUSB is not assigned to this interface"
    );
    ensure!(
        flags & DN_HAS_PROBLEM == 0,
        "USB network interface has Windows problem code {problem}"
    );
    ensure!(flags & DN_STARTED != 0, "USB network driver is not started");
    ensure!(registered, "WinUSB device interface is not registered");
    Ok(())
}
fn ready(instance: &str) -> Result<()> {
    let mut node = 0;
    ensure!(
        unsafe { CM_Locate_DevNodeW(&mut node, wide(instance).as_ptr(), 0) } == CR_SUCCESS,
        "USB network interface is not present"
    );
    let mut flags = 0;
    let mut problem = 0;
    ensure!(
        unsafe { CM_Get_DevNode_Status(&mut flags, &mut problem, node, 0) } == CR_SUCCESS,
        "USB network device status is unavailable"
    );
    let mut service = [0u16; 256];
    let mut ty = 0;
    let mut length = std::mem::size_of_val(&service) as u32;
    let found = unsafe {
        CM_Get_DevNode_PropertyW(
            node,
            &DEVPKEY_Device_Service,
            &mut ty,
            service.as_mut_ptr().cast(),
            &mut length,
            0,
        )
    };
    let service = if found == CR_SUCCESS && ty == DEVPROP_TYPE_STRING {
        text(&service)
    } else {
        String::new()
    };
    binding_state(&service, flags, problem, true)?;
    // Read-only: status must neither create registry keys nor claim a USB pipe.
    let mut key = ptr::null_mut();
    let path = parameters_path(instance);
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    ensure!(result == 0, "WinUSB interface parameters are unavailable");
    let key = Key(key);
    for name in ["DeviceInterfaceGUIDs", "DeviceInterfaceGUID"] {
        if let Some((ty, bytes)) = read_value(&key, name)? {
            for guid in interface_guids(ty, &bytes) {
                if !super::interface_paths(&guid, Some(std::ffi::OsStr::new(instance)), 65536)?
                    .is_empty()
                {
                    return Ok(());
                }
            }
        }
    }
    binding_state(&service, flags, problem, false)
}
pub(crate) fn available() -> Result<bool> {
    Ok(windows_directory()?
        .join("INF")
        .join("winusb.inf")
        .is_file())
}
pub(crate) fn status() -> Result<Vec<UsbNetworkInterfaceStatus>> {
    let mut interfaces = vec![];
    for info in nusb::list_devices()
        .wait()?
        .filter(crate::usb_internet::mac)
    {
        let serial = info
            .serial_number()
            .context("Mac USB serial is missing")?
            .trim_end_matches('\0');
        for (number, instance_id) in children(&info)? {
            let result = ready(&instance_id);
            interfaces.push(UsbNetworkInterfaceStatus {
                serial: serial.into(),
                interface: number,
                instance_id,
                ready: result.is_ok(),
                error: result.err().map(|e| format!("{e:#}")),
            });
        }
    }
    Ok(interfaces)
}
fn children(info: &nusb::DeviceInfo) -> Result<Vec<(u8, String)>> {
    let device = info.open().wait()?;
    let selected = crate::usb::ncm_interface(device.active_configuration()?)?;
    let parent = wide(info.instance_id());
    let mut node = 0;
    ensure!(
        unsafe { CM_Locate_DevNodeW(&mut node, parent.as_ptr(), 0) } == CR_SUCCESS,
        "Mac USB parent disappeared"
    );
    let mut child = 0;
    ensure!(
        unsafe { CM_Get_Child(&mut child, node, 0) } == CR_SUCCESS,
        "Mac has no present USB interfaces"
    );
    let mut children = vec![];
    loop {
        let mut id = [0u16; 512];
        if unsafe { CM_Get_Device_IDW(child, id.as_mut_ptr(), id.len() as u32, 0) } == CR_SUCCESS {
            let id = text(&id);
            if let Some(number) = [selected.control, selected.data].into_iter().find(|n| {
                id.split('\\')
                    .nth(1)
                    .is_some_and(|s| s.to_ascii_uppercase().ends_with(&format!("&MI_{n:02X}")))
            }) {
                children.push((number, id));
            }
        }
        let mut next = 0;
        if unsafe { CM_Get_Sibling(&mut next, child, 0) } != CR_SUCCESS {
            break;
        }
        child = next;
    }
    ensure!(
        children.len() == 2,
        "the selected Mac's NCM interface pair could not be identified"
    );
    children.sort_by_key(|(number, _)| *number);
    Ok(children)
}
fn prepare_interfaces(
    interfaces: &[(String, bool)],
    restore: bool,
    mut install: impl FnMut(&str, bool, &mut bool) -> Result<()>,
    mut check_ready: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut changed: Vec<&str> = vec![];
    let result: Result<()> = (|| {
        for (id, ready) in interfaces {
            if !restore && *ready {
                continue;
            }
            let mut modified = false;
            let result = install(id, restore, &mut modified);
            if modified {
                changed.push(id.as_str());
            }
            result?;
        }
        if !restore {
            for (id, _) in interfaces {
                check_ready(id).context("USB network driver installation was not confirmed")?;
            }
        }
        Ok(())
    })();
    if let Err(mut error) = result {
        if !restore {
            for id in changed.into_iter().rev() {
                if let Err(rollback) = install(id, true, &mut false) {
                    error = error.context(format!("NCM rollback failed for {id}: {rollback:#}"));
                }
            }
        }
        return Err(error);
    }
    Ok(())
}
pub(crate) fn prepare(serial: &str, restore: bool) -> Result<()> {
    ensure!(
        unsafe { IsUserAnAdmin() } != 0,
        "administrator rights are required for USB network driver preparation"
    );
    let info = crate::usb_internet::find(Some(serial), None)?
        .context("the selected Mac is disconnected")?;
    let interfaces: Vec<_> = children(&info)?
        .into_iter()
        .map(|(_, id)| {
            let installed = !restore && ready(&id).is_ok();
            if installed {
                eprintln!("USB network driver already ready: {id}");
            } else {
                eprintln!("Preparing USB network interface: {id}");
            }
            (id, installed)
        })
        .collect();
    prepare_interfaces(&interfaces, restore, install, ready)
}

#[cfg(test)]
#[path = "../../tests/unit/windows/ncm.rs"]
mod tests;
