//! Bounded metadata reads and native free-space checks for firmware files.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn read_limited(reader: impl Read, limit: u64, error: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= limit, "{error}");
    Ok(data)
}

pub fn available(path: &Path) -> Result<u64> {
    let path = path.canonicalize().context("locating storage volume")?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // Both pointers remain valid; stat is read only after a successful call.
        if unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(
            (u128::from(stat.f_bavail) * u128::from(stat.f_frsize)).min(u128::from(u64::MAX))
                as u64,
        )
    }
    #[cfg(windows)]
    {
        let name = crate::windows::wide(&path);
        let mut bytes = 0;
        // The OS writes the caller's available bytes through a valid u64 pointer.
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                name.as_ptr(),
                &mut bytes,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(bytes)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    anyhow::bail!("storage checks are implemented for Linux and Windows")
}

pub fn require(path: &Path, bytes: u64) -> Result<()> {
    let free = available(path)?;
    ensure!(
        free >= bytes,
        "insufficient disk space: need {bytes} bytes, available {free} on {}",
        path.display()
    );
    Ok(())
}

/// Root shared by firmware cache, diagnostic logs and USB driver backups.
pub fn app_directory() -> Result<PathBuf> {
    fn absolute_env(name: &str) -> Option<PathBuf> {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    }
    let root = if cfg!(windows) {
        absolute_env("LOCALAPPDATA")
            .or_else(|| absolute_env("USERPROFILE").map(|path| path.join("AppData").join("Local")))
    } else {
        absolute_env("XDG_CACHE_HOME")
            .or_else(|| absolute_env("HOME").map(|path| path.join(".cache")))
    };
    let root = root.map_or_else(
        || std::env::current_dir().map(|path| path.join(".cache")),
        Ok,
    )?;
    Ok(root.join("zalivka"))
}

/// Create the existing application log directory without changing its location.
pub fn log_directory() -> Result<PathBuf> {
    let directory = app_directory()?.join("logs");
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
