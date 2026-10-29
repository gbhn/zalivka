//! Find, extract and install signed driver packages through Windows SetupAPI.
use super::DeviceInfoSet;
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
    let set = DeviceInfoSet(set);
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

pub(crate) fn install(inf: &Path) -> Result<bool> {
    use std::{
        io::{Read, Seek, SeekFrom},
        time::Instant,
    };
    let inf = inf
        .canonicalize()
        .with_context(|| format!("Opening INF: {}", inf.display()))?;
    ensure!(
        inf.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("inf")),
        "expected a signed driver package's .inf file"
    );
    let setupapi = super::windows_directory()?.join(r"INF\setupapi.dev.log");
    let offset = std::fs::metadata(&setupapi).map(|m| m.len()).unwrap_or(0);
    crate::log!(Info, "drivers", "Installing driver: {}", inf.display());
    crate::log!(
        Trace,
        "drivers:install",
        "DiInstallDriverW; flags=0; journal={}; offset={offset}",
        setupapi.display()
    );
    let path = super::wide(&inf);
    let started = Instant::now();
    let mut reboot = 0;
    // Use Windows' normal signature and driver ranking enforcement. No FORCE flag.
    let ok = unsafe {
        windows_sys::Win32::Devices::DeviceAndDriverInstallation::DiInstallDriverW(
            std::ptr::null_mut(),
            path.as_ptr(),
            0,
            &mut reboot,
        )
    };
    if ok == 0 {
        let error = std::io::Error::last_os_error();
        let code = error.raw_os_error().unwrap_or(0) as u32;
        crate::log!(
            Error,
            "drivers:install",
            "DiInstallDriverW: 0x{code:08X}; {error}"
        );
        let read_log = (|| -> Result<()> {
            let mut file = File::open(&setupapi)?;
            let end = file.metadata()?.len();
            // Include only this attempt; bound memory if Windows logs heavily.
            let start = if offset <= end { offset } else { 0 };
            let bounded = start.max(end.saturating_sub(65536));
            file.seek(SeekFrom::Start(bounded))?;
            let mut bytes = Vec::new();
            file.take(65536).read_to_end(&mut bytes)?;
            if bytes.is_empty() {
                crate::log!(
                    Debug,
                    "drivers:log",
                    "No new records: {}",
                    setupapi.display()
                );
            } else {
                crate::log!(
                    Trace,
                    "drivers:log",
                    "{bounded}..{end}: {}",
                    setupapi.display()
                );
                // SetupAPI logs can be UTF-16LE; detect its BOM or ASCII NULs.
                let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.get(1) == Some(&0) {
                    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(&bytes);
                    String::from_utf16_lossy(
                        &bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_le_bytes(*b))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    crate::log!(Debug, "drivers:log", "{line}");
                }
            }
            Ok(())
        })();
        if let Err(log_error) = read_log {
            crate::log!(
                Warning,
                "drivers:log",
                "Could not read {}: {log_error:#}",
                setupapi.display()
            );
        }
        return Err(error).with_context(|| format!("driver installation failed: DiInstallDriverW, Win32 {code} (0x{code:08X}), INF={} (requires administrator rights and a signed package)", inf.display()));
    }
    crate::log!(
        Info,
        "drivers:install",
        "Installed in {:.3} s; reboot={}",
        started.elapsed().as_secs_f64(),
        reboot != 0
    );
    Ok(reboot != 0)
}

#[cfg(test)]
#[path = "../../tests/unit/windows/package.rs"]
mod tests;
