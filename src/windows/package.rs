//! Locate installed Apple drivers and extract the original signed embedded package.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::File,
    io::Cursor,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND,
            ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE,
        },
    },
    core::GUID,
};

const X64_CAB: &[u8] = include_bytes!("../../packaging/apple-usb/apple-usb-x64.cab");
const ARM64_CAB: &[u8] = include_bytes!("../../packaging/apple-usb/apple-usb-arm64.cab");
const X64_SHA256: &str = "8ae3b3001e3733f24ef0178f149c6534f94e57d16e8a0d75647ab979e03151ca";
const ARM64_SHA256: &str = "2d7040ff12724ce300534888aa5727b415f6439896916f602d5605d0737192b4";
pub(super) const FILES: [&str; 5] = [
    "AppleUsb.inf",
    "appleusb.cat",
    "AppleUsbFilter.dll",
    "AppleKmdfFilter.sys",
    "AppleLowerFilter.sys",
];

struct DriverList(HDEVINFO);

impl Drop for DriverList {
    fn drop(&mut self) {
        // SAFETY: this set owns the driver list and all its associated memory.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

fn driver_store_inf(published: &Path) -> Result<Option<PathBuf>> {
    let published = super::wide(published);
    let mut path = [0u16; 260];
    // SAFETY: published is NUL terminated; path is a writable MAX_PATH buffer.
    let ok = unsafe {
        SetupGetInfDriverStoreLocationW(
            published.as_ptr(),
            ptr::null(),
            ptr::null(),
            path.as_mut_ptr(),
            path.len() as u32,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code)
            if [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_NOT_FOUND].contains(&(code as u32)))
        {
            // A package may be removed between enumeration and this lookup.
            return Ok(None);
        }
        return Err(error).context("Finding INF in DriverStore using SetupAPI");
    }
    let end = path
        .iter()
        .position(|c| *c == 0)
        .context("INF path is not terminated")?;
    Ok(Some(OsString::from_wide(&path[..end]).into()))
}

fn complete_apple_package(inf: &Path) -> bool {
    inf.file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("AppleUsb.inf"))
        && inf
            .parent()
            .is_some_and(|directory| FILES.iter().all(|name| directory.join(name).is_file()))
}

pub(super) fn installed() -> Result<bool> {
    const USB_DEVICE: GUID = GUID::from_u128(0x88bae032_5a81_49f0_bc3d_a4ff138216d6);
    // An empty class set works without a connected device. SetupAPI selects the
    // platform's driver models from published INFs, including ExcludeFromSelect.
    let set = unsafe { SetupDiCreateDeviceInfoList(&USB_DEVICE, ptr::null_mut()) };
    ensure!(
        set != INVALID_HANDLE_VALUE as isize,
        "USB driver list: {}",
        std::io::Error::last_os_error()
    );
    let set = DriverList(set);
    let mut parameters = SP_DEVINSTALL_PARAMS_W {
        cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
        ..Default::default()
    };
    ensure!(
        unsafe { SetupDiGetDeviceInstallParamsW(set.0, ptr::null(), &mut parameters) } != 0,
        "USB driver list parameters: {}",
        std::io::Error::last_os_error()
    );
    parameters.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
    ensure!(
        unsafe { SetupDiSetDeviceInstallParamsW(set.0, ptr::null(), &parameters) } != 0,
        "Configuring USB driver list: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe { SetupDiBuildDriverInfoList(set.0, ptr::null_mut(), SPDIT_CLASSDRIVER) } != 0,
        "Enumerating installed USB drivers: {}",
        std::io::Error::last_os_error()
    );
    let mut seen = HashSet::new();
    for index in 0.. {
        let mut driver = SP_DRVINFO_DATA_V2_W {
            cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
            ..Default::default()
        };
        if unsafe {
            SetupDiEnumDriverInfoW(set.0, ptr::null(), SPDIT_CLASSDRIVER, index, &mut driver)
        } == 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(error).context("Reading USB driver list");
        }
        let mut detail = SP_DRVINFO_DETAIL_DATA_W {
            cbSize: size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32,
            ..Default::default()
        };
        // Only the fixed fields are needed. SetupAPI fills them even when the
        // trailing hardware ID list does not fit and reports INSUFFICIENT_BUFFER.
        let ok = unsafe {
            SetupDiGetDriverInfoDetailW(
                set.0,
                ptr::null(),
                &driver,
                &mut detail,
                size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(error).context("Reading USB driver INF");
            }
        }
        let end = detail
            .InfFileName
            .iter()
            .position(|c| *c == 0)
            .context("INF name is not terminated")?;
        let published = PathBuf::from(OsString::from_wide(&detail.InfFileName[..end]));
        if !seen.insert(published.clone()) {
            continue;
        }
        if let Some(inf) = driver_store_inf(&published)?
            && complete_apple_package(&inf)
        {
            crate::log!(
                Debug,
                "drivers",
                "Apple package verified using SetupAPI: {}",
                inf.display()
            );
            return Ok(true);
        }
    }
    crate::log!(
        Debug,
        "drivers",
        "SetupAPI did not find a complete Apple USB package for this Windows installation"
    );
    Ok(false)
}

pub(super) fn unpack(directory: &Path, arch: &str) -> Result<PathBuf> {
    let (bytes, expected) = match arch {
        "amd64" => (X64_CAB, X64_SHA256),
        "arm64" => (ARM64_CAB, ARM64_SHA256),
        _ => bail!("Unsupported driver architecture: {arch}"),
    };
    crate::log!(
        Trace,
        "drivers:cab",
        "{arch}; size={} B; SHA-256={expected}",
        bytes.len()
    );
    ensure!(
        Sha256::digest(bytes).as_slice() == crate::device::decode_hex(expected)?,
        "Bundled Apple driver package is corrupted"
    );
    crate::log!(Debug, "drivers:cab", "SHA-256 verified");
    let mut cabinet =
        cab::Cabinet::new(Cursor::new(bytes)).context("Reading bundled Apple driver package")?;
    // Only these fixed filenames can be extracted into the temporary directory.
    for name in FILES {
        let size = cabinet
            .get_file_entry(name)
            .with_context(|| format!("Driver package is missing {name}"))?
            .uncompressed_size();
        crate::log!(
            Debug,
            "drivers:cab",
            "{name}: {size} B -> {}",
            directory.join(name).display()
        );
        let mut reader = cabinet
            .read_file(name)
            .with_context(|| format!("Reading {name} from CAB"))?;
        let mut output = File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .with_context(|| format!("Creating {}", directory.join(name).display()))?;
        let copied = std::io::copy(&mut reader, &mut output)
            .with_context(|| format!("Extracting Apple driver: {name}"))?;
        ensure!(
            copied == u64::from(size),
            "Incomplete Apple driver file: {name}"
        );
    }
    Ok(directory.join("AppleUsb.inf"))
}

#[cfg(test)]
#[path = "../../tests/unit/windows/package.rs"]
mod tests;
