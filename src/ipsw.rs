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
pub(crate) fn component_path(entry: &Value) -> Result<Option<&str>> {
    let Some(info) = wire::dictionary(entry)?.get("Info") else {
        return Ok(None);
    };
    let Some(path) = wire::dictionary(info)?.get("Path") else {
        return Ok(None);
    };
    let path = path.as_string().context("invalid component path")?;
    validate_path(path)?;
    ensure!(!path.ends_with('/'), "component path names a directory");
    Ok(Some(path))
}

/// File digests are required for trusted payloads; fileless signing entries
/// may request an empty server-generated measurement. Check both consistently.
pub(crate) fn component_digest(entry: &Value) -> Result<Option<&[u8]>> {
    let trusted = wire::optional_boolean(entry, &["Trusted"])?.unwrap_or(false);
    let digest = wire::optional(entry, &["Digest"])?
        .map(|value| value.as_data().context("invalid component Digest"))
        .transpose()?;
    ensure!(
        !trusted
            || component_path(entry)?.is_none()
            || digest.is_some_and(|digest| !digest.is_empty()),
        "strict restore requires nonempty component Digest for a trusted file"
    );
    if let Some(digest) = digest.filter(|digest| !digest.is_empty()) {
        ensure!(
            [20, 32, 48].contains(&digest.len()),
            "unsupported component Digest size {}",
            digest.len()
        );
    }
    Ok(digest.filter(|digest| !digest.is_empty()))
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
        let mut reopened = Self::open(&self.path)?;
        ensure!(
            reopened.manifest == self.manifest,
            "IPSW BuildManifest changed while restoring"
        );
        reopened.manifest = self.manifest.clone();
        Ok(reopened)
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
                .is_some_and(|identities| !identities.is_empty()),
            "BuildIdentities must be a nonempty array"
        );
        let products = wire::get(&manifest, &["SupportedProductTypes"])?
            .as_array()
            .context("invalid product types")?;
        ensure!(
            !products.is_empty()
                && products
                    .iter()
                    .all(|value| value.as_string().is_some_and(|value| !value.is_empty())),
            "IPSW must declare nonempty SupportedProductTypes"
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
        self.read_limited(path, MAX_COMPONENT)
    }

    fn read_limited(&mut self, path: &str, limit: u64) -> Result<Vec<u8>> {
        validate_path(path)?;
        let entry = self
            .archive
            .by_name(path)
            .with_context(|| format!("missing IPSW component {path}"))?;
        ensure!(
            entry.size() <= limit,
            "IPSW entry exceeds memory limit {limit}"
        );
        crate::storage::read_limited(
            entry,
            limit,
            &format!("IPSW entry exceeds memory limit {limit}"),
        )
    }

    /// Read and verify a namespace bundle once, with its limit checked before allocation.
    pub(crate) fn plist_component(&mut self, id: &Identity, name: &str) -> Result<Vec<u8>> {
        let entry = wire::get(&id.value, &["Manifest", name])?;
        id.payload_type(name)?;
        let expected = component_digest(entry)?
            .context("namespace updater requires a nonempty supported manifest Digest")?;
        let data = self.read_limited(id.path(name)?, crate::firmware::MAX_PLIST_BUNDLE)?;
        let report = crate::firmware::verify_plist_bundle(&data, expected)
            .with_context(|| format!("checking component {name} payload bundle"))?;
        ensure!(
            report.payloads > 0,
            "namespace updater requires a verified plist payload bundle; payload layout is not described"
        );
        ensure!(
            report.manifest_digest || verify_digest(&data, expected).is_ok(),
            "component {name} digest mismatch"
        );
        Ok(data)
    }

    pub fn component(&mut self, id: &Identity, name: &str) -> Result<Vec<u8>> {
        let entry = wire::get(&id.value, &["Manifest", name])?;
        let tag = id.payload_type(name)?;
        let digest = component_digest(entry).with_context(|| format!("checking {name} Digest"))?;
        let data = self.read(id.path(name)?)?;
        if let Some(expected) = digest {
            let inputs = digest::DigestInput::variants(&data, data.len() as u64, tag)?;
            let bundle = crate::firmware::verify_plist_bundle(&data, expected)
                .with_context(|| format!("checking component {name} payload bundle"))?;
            if let Err(error) =
                digest::verify_component_digest(inputs, |input| input.matches(&data, expected))
            {
                ensure!(
                    bundle.manifest_digest,
                    "component {name} digest mismatch: {error}"
                );
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
            && !wire::optional_boolean(&id.value, &["Manifest", name, "Trusted"])?.unwrap_or(false)
            && img4::type_offset(&bytes).is_none()
        {
            return Ok(bytes);
        }
        if name == "Ap,LocalPolicy" {
            img4::personalize(&bytes, crate::tss::ticket(ticket)?)
        } else {
            img4::personalize_with_metadata(name, &bytes, ticket, &id.value)
        }
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
        ensure!(
            entry.compressed_size() == size,
            "stored ZIP entry size mismatch: {path}"
        );
        let mut file = File::open(&self.path)?;
        let archive_size = file.metadata()?.len();
        ensure!(
            start
                .checked_add(size)
                .is_some_and(|end| end <= archive_size),
            "stored ZIP entry extends beyond IPSW: {path}"
        );
        file.seek(SeekFrom::Start(start))?;
        Ok(Some(ImageReader {
            file,
            start,
            size,
            position: 0,
        }))
    }

    pub fn preflight(&mut self, id: &mut Identity) -> Result<()> {
        self.resolve_types(id)?;
        self.preflight_paths(id)?;
        id.path("OS")?;
        for tag in [b"ibss", b"ibec", b"rdsk", b"rdtr", b"rkrn"] {
            let name = id.require_component_type(tag)?;
            self.verify_boot_component(id, name)?;
        }
        Ok(())
    }

    pub fn preflight_recovery(&mut self, id: &mut Identity) -> Result<()> {
        self.resolve_types(id)?;
        id.path("OS")?;
        self.preflight_paths(id)
    }

    pub(crate) fn verify_boot_component(&mut self, id: &Identity, name: &str) -> Result<Vec<u8>> {
        ensure!(
            wire::get(&id.value, &["Manifest", name, "Digest"])?
                .as_data()
                .is_some_and(|digest| !digest.is_empty()),
            "strict restore requires a nonempty boot component Digest for {name}"
        );
        let bytes = self.component(id, name)?;
        let (_, rest) =
            img4::parse(&bytes).with_context(|| format!("invalid boot component {name}"))?;
        ensure!(
            rest.is_empty() && img4::payload_type(&bytes).is_some(),
            "boot component {name} is not a complete IM4P payload"
        );
        Ok(bytes)
    }

    fn preflight_paths(&mut self, id: &Identity) -> Result<()> {
        wire::optional_boolean(&id.value, &["Info", "RequiresUIDMode"])?;
        wire::optional_boolean(&id.value, &["Info", "RequiresNonceSlot"])?;
        for (name, entry) in id.manifest()? {
            component_digest(entry).with_context(|| format!("checking {name} Digest"))?;
            let tag = id.payload_type(name)?;
            img4::nonce_slot(&id.value, tag)?;
            if let Some(info) = wire::dictionary(entry)?.get("Info") {
                let info = wire::dictionary(info)?;
                for key in [
                    "Personalize",
                    "IsLoadedByiBoot",
                    "IsLoadedByiBootStage1",
                    "IsFirmwarePayload",
                    "IsSecondaryFirmwarePayload",
                    "IsFUDFirmware",
                    "IsEarlyAccessFirmware",
                    "IsiBootEANFirmware",
                    "IsiBootNonEssentialFirmware",
                ] {
                    if let Some(value) = info.get(key) {
                        ensure!(
                            value.as_boolean().is_some(),
                            "invalid {name} Info.{key}: expected boolean"
                        );
                    }
                }
                let loaded = info.get("IsLoadedByiBoot").and_then(Value::as_boolean) == Some(true);
                let stage1 = info
                    .get("IsLoadedByiBootStage1")
                    .and_then(Value::as_boolean);
                ensure!(
                    !loaded || stage1.is_some(),
                    "strict restore requires {name} Info.IsLoadedByiBootStage1"
                );
                ensure!(
                    !(loaded || stage1 == Some(true)) || tag.is_some(),
                    "cannot resolve iBoot firmware payload type for {name}: no manifest override or valid IM4P header"
                );
            }
            if let Some(path) = component_path(entry)
                .with_context(|| format!("invalid manifest component {name}"))?
            {
                let file = self
                    .archive
                    .by_name(path)
                    .with_context(|| format!("IPSW is missing {name}: {path}"))?;
                ensure!(
                    !file.is_dir(),
                    "IPSW component {name} is a directory: {path}"
                );
                ensure!(
                    name != "OS" || file.size() != 0,
                    "IPSW filesystem image is empty: {path}"
                );
            }
        }
        Ok(())
    }

    /// Read only IM4P headers, retaining the original manifest for TSS and restored.
    pub(crate) fn resolve_types(&mut self, id: &mut Identity) -> Result<()> {
        let mut types = std::collections::HashMap::new();
        for (name, entry) in id.manifest()? {
            if img4::component_tag(name, Some(entry))?.is_some() {
                continue;
            }
            let Some(path) = component_path(entry)? else {
                continue;
            };
            if types.contains_key(path) {
                continue;
            }
            let entry = self
                .archive
                .by_name(path)
                .with_context(|| format!("missing IPSW component {name}: {path}"))?;
            // A canonical DER sequence header plus the IM4P magic and four-byte
            // type fit in 32 bytes, independently of the image body length.
            let mut prefix = Vec::new();
            entry.take(32).read_to_end(&mut prefix)?;
            types.insert(path.to_owned(), img4::payload_type(&prefix));
        }
        id.file_types = types;
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
        if n == 0 && limit != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated stored IPSW image",
            ));
        }
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
        !path.is_empty()
            && !path.contains(['\\', ':', '\0'])
            && !path.starts_with('/')
            && !path.contains("//"),
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
