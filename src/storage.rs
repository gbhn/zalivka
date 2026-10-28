//! Bounded metadata reads and portable free-space checks for firmware files.
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
    fs4::available_space(path).context("checking available storage")
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

pub fn config_directory() -> Result<PathBuf> {
    let absolute_env = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let root = if cfg!(windows) {
        absolute_env("LOCALAPPDATA")
            .or_else(|| absolute_env("USERPROFILE").map(|path| path.join("AppData/Local")))
    } else {
        absolute_env("XDG_CONFIG_HOME")
            .or_else(|| absolute_env("HOME").map(|path| path.join(".config")))
    };
    Ok(root
        .context("could not locate the settings folder")?
        .join("zalivka"))
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod tests;
