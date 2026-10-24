//! Extract the original signed Apple package directly from the embedded CAB.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Cursor,
    path::{Path, PathBuf},
};

const X64_CAB: &[u8] = include_bytes!("../../packaging/apple-usb/apple-usb-x64.cab");
const ARM64_CAB: &[u8] = include_bytes!("../../packaging/apple-usb/apple-usb-arm64.cab");
const X64_SHA256: &str = "8ae3b3001e3733f24ef0178f149c6534f94e57d16e8a0d75647ab979e03151ca";
const ARM64_SHA256: &str = "2d7040ff12724ce300534888aa5727b415f6439896916f602d5605d0737192b4";
const FILES: [&str; 5] = [
    "AppleUsb.inf",
    "appleusb.cat",
    "AppleUsbFilter.dll",
    "AppleKmdfFilter.sys",
    "AppleLowerFilter.sys",
];

pub(super) fn unpack(directory: &Path, arch: &str) -> Result<PathBuf> {
    let (bytes, expected) = match arch {
        "amd64" => (X64_CAB, X64_SHA256),
        "arm64" => (ARM64_CAB, ARM64_SHA256),
        _ => bail!("Неподдерживаемая архитектура драйвера: {arch}"),
    };
    ensure!(
        Sha256::digest(bytes).as_slice() == crate::device::decode_hex(expected)?,
        "Повреждён встроенный пакет драйвера Apple"
    );
    let mut cabinet = cab::Cabinet::new(Cursor::new(bytes))
        .context("Чтение встроенного пакета драйвера Apple")?;
    // Only these fixed filenames can be extracted into the temporary directory.
    for name in FILES {
        let size = cabinet
            .get_file_entry(name)
            .with_context(|| format!("В пакете драйвера отсутствует {name}"))?
            .uncompressed_size();
        let mut reader = cabinet.read_file(name)?;
        let mut output = File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
        let copied = std::io::copy(&mut reader, &mut output)
            .with_context(|| format!("Распаковка драйвера Apple: {name}"))?;
        ensure!(
            copied == u64::from(size),
            "Неполный файл драйвера Apple: {name}"
        );
    }
    Ok(directory.join("AppleUsb.inf"))
}

#[cfg(test)]
#[path = "../../tests/unit/windows/package.rs"]
mod tests;
