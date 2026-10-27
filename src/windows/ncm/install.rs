//! Change only selected NCM bindings and retain their original registry settings.
use super::{GUID_TEXT, Key, parameters_path, parse_guid, read_value, text};
use crate::windows::{wide, windows_directory};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::{
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::*,
            Properties::{
                DEVPKEY_Device_DriverInfPath, DEVPKEY_Device_DriverInfSection, DEVPROP_TYPE_STRING,
            },
        },
        Foundation::{ERROR_NOT_FOUND, INVALID_HANDLE_VALUE},
        System::Registry::*,
    },
    core::GUID,
};
fn check(ok: i32, what: &str) -> Result<()> {
    if ok == 0 {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error().unwrap_or(0) as u32;
        anyhow::bail!("{what}: Win32 {code} (0x{code:08X}): {error}");
    }
    crate::log!(Debug, "drivers", "USB-сеть: {what}: успешно");
    Ok(())
}
struct Set(HDEVINFO);
impl Drop for Set {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Backup {
    instance: String,
    class: String,
    inf: Option<String>,
    section: Option<String>,
    guids: Option<(u32, Vec<u8>)>,
}

impl Backup {
    fn save(&self, path: &Path) -> Result<()> {
        let directory = path.parent().context("invalid NCM backup path")?;
        let mut saved = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer_pretty(&mut saved, self)?;
        saved.as_file().sync_all()?;
        // Publish only a complete backup. A failed write must not leave a
        // truncated JSON file that a later installation mistakes for a backup.
        saved
            .persist_noclobber(path)
            .map_err(|error| error.error)
            .context("saving original NCM driver settings")?;
        Ok(())
    }
}
fn parameters(instance: &str) -> Result<Key> {
    let path = parameters_path(instance);
    let mut key = ptr::null_mut();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    ensure!(
        result == 0,
        "opening NCM parameters: {}",
        io::Error::from_raw_os_error(result as i32)
    );
    Ok(Key(key))
}

fn set_guids(key: &Key, value: Option<&(u32, Vec<u8>)>) -> Result<()> {
    let name = wide("DeviceInterfaceGUIDs");
    let result = if let Some((ty, bytes)) = value {
        unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                *ty,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        }
    } else {
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) }
    };
    ensure!(
        result == 0 || result == 2,
        "updating NCM interface GUIDs: {}",
        io::Error::from_raw_os_error(result as i32)
    );
    Ok(())
}
fn backup_path(instance: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let directory = crate::storage::app_directory()?.join("usb-network-drivers");
    std::fs::create_dir_all(&directory)?;
    Ok(directory.join(format!("{:x}.json", Sha256::digest(instance.as_bytes()))))
}
pub(super) fn guid_string(g: GUID) -> String {
    let uuid = uuid::Uuid::from_fields(g.data1, g.data2, g.data3, &g.data4);
    format!("{:X}", uuid.braced())
}
fn windows_inf(name: &str) -> Result<Vec<u16>> {
    ensure!(
        name.is_ascii()
            && name.len() > 4
            && name[name.len() - 4..].eq_ignore_ascii_case(".inf")
            && name[..name.len() - 4]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric()),
        "invalid inbox INF name"
    );
    Ok(wide(windows_directory()?.join("INF").join(name)))
}
fn ncm_guids(original: Option<&(u32, Vec<u8>)>) -> Vec<u8> {
    let guids = original
        .filter(|(ty, bytes)| matches!(*ty, REG_MULTI_SZ | REG_SZ) && bytes.len().is_multiple_of(2))
        .map(|(_, bytes)| {
            bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut result = Vec::new();
    let mut registered = false;
    for name in guids
        .split(|unit| *unit == 0)
        .filter(|name| !name.is_empty())
    {
        registered |=
            String::from_utf16(name).is_ok_and(|name| name.eq_ignore_ascii_case(GUID_TEXT));
        result.extend_from_slice(name);
        result.push(0);
    }
    if !registered {
        result.extend(wide(GUID_TEXT));
    }
    result.push(0);
    result.into_iter().flat_map(u16::to_le_bytes).collect()
}

fn original_property(value: &[u16], ty: u32, size: u32) -> Result<String> {
    ensure!(
        ty == DEVPROP_TYPE_STRING
            && size >= 2
            && size as usize <= std::mem::size_of_val(value)
            && size.is_multiple_of(2),
        "invalid original NCM driver property"
    );
    let value = &value[..size as usize / 2];
    ensure!(
        value.last() == Some(&0),
        "unterminated original NCM driver property"
    );
    let value = &value[..value.len() - 1];
    ensure!(
        !value.is_empty() && !value.contains(&0),
        "empty or embedded NUL in original NCM driver property"
    );
    let value = String::from_utf16(value).context("invalid original NCM driver property UTF-16")?;
    Ok(value)
}

pub(super) fn install(instance: &str, restore: bool, changed: &mut bool) -> Result<()> {
    let set = Set(unsafe { SetupDiCreateDeviceInfoList(ptr::null(), ptr::null_mut()) });
    ensure!(
        set.0 != INVALID_HANDLE_VALUE as isize,
        "creating NCM device list failed"
    );
    let mut device = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };
    check(
        unsafe {
            SetupDiOpenDeviceInfoW(
                set.0,
                wide(instance).as_ptr(),
                ptr::null_mut(),
                0,
                &mut device,
            )
        },
        "opening NCM interface",
    )?;
    let key = parameters(instance)?;
    let path = backup_path(instance)?;
    crate::log!(
        Info,
        "drivers",
        "USB-сеть: резервная копия исходных настроек: {}; существует={}",
        path.display(),
        path.exists()
    );
    let backup = if path.exists() {
        let bytes = crate::storage::read_limited(
            std::fs::File::open(&path)?,
            1024 * 1024,
            "saved NCM driver settings exceed 1 MiB",
        )?;
        serde_json::from_slice::<Backup>(&bytes)?
    } else {
        ensure!(!restore, "no saved NCM driver settings for this interface");
        let property = |key| -> Result<Option<String>> {
            let mut value = [0u16; 260];
            let mut size = 0;
            let mut ty = 0;
            let ok = unsafe {
                SetupDiGetDevicePropertyW(
                    set.0,
                    &device,
                    key,
                    &mut ty,
                    value.as_mut_ptr().cast(),
                    std::mem::size_of_val(&value) as u32,
                    &mut size,
                    0,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                    return Ok(None);
                }
                return Err(error)
                    .context("reading original NCM driver property; no driver changes were made");
            }
            original_property(&value, ty, size).map(Some)
        };
        let backup = Backup {
            instance: instance.into(),
            class: guid_string(device.ClassGuid),
            inf: property(&DEVPKEY_Device_DriverInfPath)?,
            section: property(&DEVPKEY_Device_DriverInfSection)?,
            guids: read_value(&key, "DeviceInterfaceGUIDs")?,
        };
        ensure!(
            backup.inf.is_none() || backup.section.is_some(),
            "the original driver section could not be read; no driver changes were made"
        );
        backup.save(&path)?;
        backup
    };
    ensure!(
        backup.instance.eq_ignore_ascii_case(instance),
        "NCM backup identity mismatch"
    );
    let class = if restore {
        backup.class.as_str()
    } else {
        "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"
    };
    let inf_name = if restore {
        backup.inf.as_deref()
    } else {
        Some("winusb.inf")
    };
    let class_guid = parse_guid(class).context("invalid saved NCM class GUID")?;
    let inf = inf_name.map(windows_inf).transpose()?;
    crate::log!(
        Info,
        "drivers",
        "USB-сеть: интерфейс={instance}; исходный INF={:?}; исходная секция={:?}; целевой INF={inf_name:?}; класс={class}",
        backup.inf,
        backup.section
    );
    // The caller owns rollback, including a partially changed current interface.
    // Failures before this point have neither changed bindings nor registry values.
    *changed = true;
    if restore {
        set_guids(&key, backup.guids.as_ref())?;
    } else {
        let bytes = ncm_guids(backup.guids.as_ref());
        set_guids(&key, Some(&(REG_MULTI_SZ, bytes)))?;
    }
    let result = (|| -> Result<()> {
        let class = wide(class);
        check(
            unsafe {
                SetupDiSetDeviceRegistryPropertyW(
                    set.0,
                    &mut device,
                    SPDRP_CLASSGUID,
                    class.as_ptr().cast(),
                    (class.len() * 2) as u32,
                )
            },
            "setting NCM device class",
        )?;
        device.ClassGuid = class_guid;
        let driver = if let Some(inf) = &inf {
            let mut params = SP_DEVINSTALL_PARAMS_W {
                cbSize: std::mem::size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
                ..Default::default()
            };
            check(
                unsafe { SetupDiGetDeviceInstallParamsW(set.0, &device, &mut params) },
                "reading driver search settings",
            )?;
            params.Flags |= DI_ENUMSINGLEINF;
            params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
            ensure!(inf.len() <= params.DriverPath.len(), "INF path is too long");
            params.DriverPath.fill(0);
            params.DriverPath[..inf.len()].copy_from_slice(inf);
            check(
                unsafe { SetupDiSetDeviceInstallParamsW(set.0, &device, &params) },
                "setting inbox driver search",
            )?;
            check(
                unsafe { SetupDiBuildDriverInfoList(set.0, &mut device, SPDIT_CLASSDRIVER) },
                "building inbox driver list",
            )?;
            let section = if restore {
                backup.section.as_deref()
            } else {
                Some("WINUSB")
            };
            let mut driver = None;
            for i in 0..64 {
                let mut d = SP_DRVINFO_DATA_V2_W {
                    cbSize: std::mem::size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
                    ..Default::default()
                };
                if unsafe { SetupDiEnumDriverInfoW(set.0, &device, SPDIT_CLASSDRIVER, i, &mut d) }
                    == 0
                {
                    break;
                }
                let mut detail = SP_DRVINFO_DETAIL_DATA_W {
                    cbSize: std::mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32,
                    ..Default::default()
                };
                unsafe {
                    SetupDiGetDriverInfoDetailW(
                        set.0,
                        &device,
                        &d,
                        &mut detail,
                        std::mem::size_of_val(&detail) as u32,
                        ptr::null_mut(),
                    );
                }
                if section
                    .is_some_and(|section| text(&detail.SectionName).eq_ignore_ascii_case(section))
                {
                    driver = Some(d);
                    break;
                }
            }
            Some(driver.context("inbox USB driver model was not found")?)
        } else {
            None
        };
        let mut reboot = 0;
        crate::log!(
            Info,
            "drivers",
            "USB-сеть: вызов DiInstallDevice для {instance}"
        );
        check(
            unsafe {
                DiInstallDevice(
                    ptr::null_mut(),
                    set.0,
                    &device,
                    driver.as_ref().map_or(ptr::null(), |driver| driver),
                    if driver.is_some() {
                        DIIDFLAG_NOFINISHINSTALLUI
                    } else {
                        DIIDFLAG_INSTALLNULLDRIVER
                    },
                    &mut reboot,
                )
            },
            if driver.is_some() {
                "installing inbox USB driver"
            } else {
                "restoring an unassigned USB interface"
            },
        )?;
        crate::log!(
            Info,
            "drivers",
            "USB-сеть: DiInstallDevice завершён; требуется перезагрузка={}",
            reboot != 0
        );
        ensure!(
            reboot == 0,
            "Windows requires a restart to finish the USB network driver change"
        );
        Ok(())
    })();
    result.with_context(|| {
        format!(
            "NCM interface {instance}; original settings saved in {}",
            path.display()
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/ncm/install.rs"]
mod tests;
