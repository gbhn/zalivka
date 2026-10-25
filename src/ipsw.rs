mod digest;
mod identity;
mod verify;
use crate::{img4, wire};
use anyhow::{Context, Result, ensure};
pub use digest::verify_digest;
pub use identity::{Behavior, Identity, IdentitySummary};
use plist::Value;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
pub use verify::Verification;
use zip::ZipArchive;

pub const MAX_COMPONENT: u64 = 1024 * 1024 * 1024;

/// Signing-only entries may omit a path; present metadata must still be valid.
fn component_path(entry: &Value) -> Result<Option<&str>> {
    let Some(info) = wire::dictionary(entry)?.get("Info") else {
        return Ok(None);
    };
    let Some(path) = wire::dictionary(info)?.get("Path") else {
        return Ok(None);
    };
    let path = path.as_string().context("invalid component path")?;
    validate_path(path)?;
    Ok(Some(path))
}

pub struct Ipsw {
    path: PathBuf,
    archive: ZipArchive<BufReader<File>>,
    pub manifest: Arc<Value>,
}

impl Ipsw {
    /// Independent file cursor and ZIP reader for a concurrent restore request.
    /// File::try_clone shares the seek position and cannot be used here.
    pub fn reopen(&self) -> Result<Self> {
        Ok(Self {
            path: self.path.clone(),
            archive: Self::open_archive(&self.path)?,
            manifest: self.manifest.clone(),
        })
    }

    fn open_archive(path: &Path) -> Result<ZipArchive<BufReader<File>>> {
        // IPSWs are ordinary ZIPs at offset zero. Offset autodetection scans
        // large ZIP64 images for self-extracting prefixes, which is very slow
        // over Windows filesystem bridges.
        let archive = ZipArchive::with_config(
            zip::read::Config {
                archive_offset: zip::read::ArchiveOffset::Known(0),
            },
            BufReader::with_capacity(128 * 1024, File::open(path).context("opening IPSW")?),
        )
        .context("reading IPSW ZIP directory")?;
        let mut names = HashSet::new();
        for name in archive.file_names() {
            let name = name?;
            validate_path(&name)?;
            ensure!(
                names.insert(name.to_string()),
                "duplicate IPSW entry {name}"
            );
        }
        Ok(archive)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let mut archive = Self::open_archive(path)?;
        let entry = archive
            .by_name("BuildManifest.plist")
            .context("IPSW has no BuildManifest.plist")?;
        ensure!(entry.size() <= 32 * 1024 * 1024, "BuildManifest too large");
        let manifest = Value::from_reader(std::io::Cursor::new(crate::storage::read_limited(
            entry,
            32 * 1024 * 1024,
            "BuildManifest too large",
        )?))?;
        ensure!(
            wire::get(&manifest, &["BuildIdentities"])?
                .as_array()
                .is_some(),
            "BuildIdentities is not an array"
        );
        let products = wire::get(&manifest, &["SupportedProductTypes"])?
            .as_array()
            .context("invalid product types")?;
        ensure!(
            products
                .iter()
                .any(|v| v.as_string().is_some_and(crate::device::is_mac_product)),
            "this archive does not advertise any Mac or T2 product"
        );
        Ok(Self {
            path: path.into(),
            archive,
            manifest: Arc::new(manifest),
        })
    }

    pub fn contains(&self, path: &str) -> bool {
        self.archive.index_for_name(path).is_some()
    }

    pub fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        validate_path(path)?;
        let entry = self
            .archive
            .by_name(path)
            .with_context(|| format!("missing IPSW component {path}"))?;
        ensure!(
            entry.size() <= MAX_COMPONENT,
            "IPSW entry exceeds memory limit {MAX_COMPONENT}"
        );
        crate::storage::read_limited(
            entry,
            MAX_COMPONENT,
            &format!("IPSW entry exceeds memory limit {MAX_COMPONENT}"),
        )
    }

    pub fn component(&mut self, id: &Identity, name: &str) -> Result<Vec<u8>> {
        let data = self.read(id.path(name)?)?;
        if let Ok(digest) = wire::get(&id.value, &["Manifest", name, "Digest"]) {
            let expected = digest.as_data().context("invalid component digest")?;
            if !expected.is_empty() {
                let inputs = digest::DigestInput::variants(
                    &data,
                    data.len() as u64,
                    img4::restore_tag(name),
                )?;
                digest::verify_component_digest(
                    inputs,
                    expected,
                    |input| input.matches(&data, expected),
                    (name == "Baobab,TCON").then_some(data.as_slice()),
                )
                .with_context(|| format!("component {name} digest mismatch"))?;
            }
        }
        Ok(data)
    }

    pub fn personalized(&mut self, id: &Identity, name: &str, ticket: &Value) -> Result<Vec<u8>> {
        let bytes = if name == "Ap,LocalPolicy" {
            img4::empty_local_policy()
        } else {
            self.component(id, name)?
        };
        // Trusted is a signing attribute, not the IMG4 transport container.
        // InputDevice is an untrusted IM4P but still needs the IMG4 wrapper.
        if name != "Ap,LocalPolicy"
            && !wire::boolean(&id.value, &["Manifest", name, "Trusted"])
            && img4::type_offset(&bytes).is_none()
        {
            return Ok(bytes);
        }
        img4::personalize_with_metadata(name, &bytes, ticket, &id.value)
    }

    /// Stream even multi-gigabyte images without keeping them in memory.
    pub fn stream(&mut self, path: &str, out: &mut impl Write) -> Result<u64> {
        validate_path(path)?;
        let mut entry = self.archive.by_name(path)?;
        Ok(std::io::copy(&mut entry, out)?)
    }

    pub fn size(&mut self, path: &str) -> Result<u64> {
        Ok(self.archive.by_name(path)?.size())
    }

    pub fn unix_mode(&mut self, path: &str) -> Result<u32> {
        let e = self.archive.by_name(path)?;
        Ok(e.unix_mode()
            .unwrap_or(if e.is_dir() { 0o040755 } else { 0o100644 }))
    }

    pub fn files(&self) -> Result<Vec<String>> {
        self.archive
            .file_names()
            .map(|n| Ok(n?.into_owned()))
            .collect()
    }

    /// Separate descriptor so ASR can seek within uncompressed ZIP entries.
    /// Deflated images are expanded into a temporary file by the restore engine.
    pub fn stored_image(&mut self, path: &str) -> Result<Option<ImageReader>> {
        let entry = self.archive.by_name(path)?;
        if entry.compression() != zip::CompressionMethod::Stored {
            return Ok(None);
        }
        let start = entry.data_start().context("ZIP entry has no data offset")?;
        let size = entry.size();
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(start))?;
        Ok(Some(ImageReader {
            file,
            start,
            size,
            position: 0,
        }))
    }

    pub fn preflight(&mut self, id: &Identity) -> Result<()> {
        self.preflight_paths(id)?;
        id.path("OS")?;
        for name in [
            "iBSS",
            "iBEC",
            "RestoreRamDisk",
            "RestoreDeviceTree",
            "RestoreKernelCache",
        ] {
            self.component(id, name)?;
        }
        Ok(())
    }

    pub fn preflight_recovery(&self, id: &Identity) -> Result<()> {
        id.path("OS")?;
        self.preflight_paths(id)
    }

    fn preflight_paths(&self, id: &Identity) -> Result<()> {
        for (name, entry) in id.manifest()? {
            if let Some(path) = component_path(entry)
                .with_context(|| format!("invalid manifest component {name}"))?
            {
                ensure!(self.contains(path), "IPSW is missing {name}: {path}");
            }
        }
        Ok(())
    }
}

pub struct ImageReader {
    file: File,
    start: u64,
    pub size: u64,
    position: u64,
}
impl Read for ImageReader {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let limit = b
            .len()
            .min((self.size - self.position).min(usize::MAX as u64) as usize);
        let n = self.file.read(&mut b[..limit])?;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for ImageReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let n = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.size) + i128::from(n),
        };
        if n < 0 || n > i128::from(self.size) {
            return Err(std::io::Error::other("image seek out of bounds"));
        }
        self.file.seek(SeekFrom::Start(self.start + n as u64))?;
        self.position = n as u64;
        Ok(self.position)
    }
}

pub fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && !path.contains(['\\', ':', '\0']) && !path.starts_with('/'),
        "unsafe archive path {path:?}"
    );
    ensure!(
        Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "unsafe archive path {path:?}"
    );
    ensure!(
        !path.split('/').any(|p| p == "." || p == ".."),
        "unsafe archive path {path:?}"
    );
    Ok(())
}
