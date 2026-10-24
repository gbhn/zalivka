//! Bounded archive and component digest verification, including container ranges.
use super::{Ipsw, component_path};
use crate::{checksum::hasher, firmware, img4, wire};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::digest::DynDigest;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    io::Read,
};

#[derive(Debug, Serialize)]
pub struct Verification {
    pub entries: usize,
    pub uncompressed_bytes: u64,
    pub manifest_digests: usize,
    pub archive_checksum_verified: bool,
    pub aea_content_digests_not_checked: Vec<String>,
    pub tcon_payload_digests_not_checked: Vec<String>,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum DigestInput {
    File,
    Retag([u8; 4]),
    Payload(u64, u64),
}

impl DigestInput {
    pub(super) fn variants(prefix: &[u8], length: u64, tag: Option<[u8; 4]>) -> Result<Vec<Self>> {
        let mut inputs = vec![Self::File];
        if img4::type_offset(prefix).is_some()
            && let Some(tag) = tag
        {
            inputs.push(Self::Retag(tag));
        }
        inputs.extend(
            firmware::payload_ranges(prefix, length)?
                .into_iter()
                .map(|range| Self::Payload(range.start, range.end)),
        );
        Ok(inputs)
    }

    fn update(self, hash: &mut dyn DynDigest, data: &[u8], position: u64) {
        match self {
            Self::Retag(tag) if position == 0 => {
                if let Some(offset) = img4::type_offset(data) {
                    hash.update(&data[..offset]);
                    hash.update(&tag);
                    hash.update(&data[offset + 4..]);
                } else {
                    hash.update(data);
                }
            }
            Self::Payload(start, end) => {
                let start = start.max(position);
                let end = end.min(position + data.len() as u64);
                if start < end {
                    hash.update(&data[(start - position) as usize..(end - position) as usize]);
                }
            }
            _ => hash.update(data),
        }
    }

    pub(super) fn matches(self, data: &[u8], expected: &[u8]) -> Result<bool> {
        let mut hash = hasher(expected.len())
            .with_context(|| format!("unsupported component digest size {}", expected.len()))?;
        self.update(hash.as_mut(), data, 0);
        Ok(hash.finalize().as_ref() == expected)
    }
}

/// Use only the inputs belonging to this component, for both streaming and RAM reads.
/// false means that only TCON metadata matched; its payload digest remains unchecked.
pub(super) fn verify_component_digest(
    inputs: &[DigestInput],
    expected: &[u8],
    mut matches: impl FnMut(DigestInput) -> Result<bool>,
    tcon: Option<&[u8]>,
) -> Result<bool> {
    for &input in inputs {
        if matches(input)? {
            return Ok(true);
        }
    }
    if let Some(bytes) = tcon
        && firmware::tcon_metadata_matches(bytes, expected)?
    {
        return Ok(false);
    }
    bail!("digest verification failed")
}

impl Ipsw {
    /// Exhaust every ZIP stream (including CRC validation) with bounded memory.
    pub fn verify_all(&mut self) -> Result<Verification> {
        type DigestVariants = HashSet<(Option<[u8; 4]>, bool, Vec<u8>)>;
        let mut digests: HashMap<String, DigestVariants> = HashMap::new();
        let mut tcon_paths = HashSet::new();
        for (_, value) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(value, &["Manifest"])?)? {
                let Some(path) = component_path(entry)
                    .with_context(|| format!("invalid manifest component {name}"))?
                else {
                    continue;
                };
                if name == "Baobab,TCON" {
                    tcon_paths.insert(path.to_owned());
                }
                ensure!(
                    self.archive.index_for_name(path).is_some(),
                    "missing manifest component {path}"
                );
                if let Some(digest) = entry.as_dictionary().and_then(|e| e.get("Digest")) {
                    let digest = digest.as_data().context("invalid manifest digest")?;
                    if !digest.is_empty() {
                        ensure!(
                            [20, 32, 48].contains(&digest.len()),
                            "unsupported digest for {path}"
                        );
                        digests.entry(path.into()).or_default().insert((
                            img4::restore_tag(name),
                            name == "Baobab,TCON",
                            digest.to_vec(),
                        ));
                    }
                }
            }
        }
        let mut report = Verification {
            entries: self.archive.len(),
            uncompressed_bytes: 0,
            manifest_digests: 0,
            archive_checksum_verified: false,
            aea_content_digests_not_checked: vec![],
            tcon_payload_digests_not_checked: vec![],
        };
        let mut buffer = vec![0; 2 * 1024 * 1024];
        for i in 0..self.archive.len() {
            let mut entry = self.archive.by_index(i)?;
            let name = entry.name()?.into_owned();
            let expected = digests.get(&name);
            let tcon = tcon_paths.contains(&name);
            ensure!(
                !tcon || entry.size() <= 32 * 1024 * 1024,
                "TCON metadata bundle exceeds 32 MiB"
            );
            let mut tcon_bytes = vec![];
            let mut hashes = HashMap::new();
            let mut inputs = HashMap::new();
            let mut size = 0u64;
            let mut aea = false;
            loop {
                let mut n = 0;
                while n < buffer.len() {
                    let read = entry
                        .read(&mut buffer[n..])
                        .with_context(|| format!("checking ZIP entry {name}"))?;
                    if read == 0 {
                        break;
                    }
                    n += read;
                }
                if tcon {
                    tcon_bytes.extend_from_slice(&buffer[..n]);
                }
                if size == 0 {
                    // Preserve container validation for entries with no manifest digest.
                    if expected.is_none() {
                        DigestInput::variants(&buffer[..n], entry.size(), None)?;
                    }
                    aea = buffer[..n].starts_with(b"AEA1");
                    if aea {
                        // Real AEA manifest digests are not hashes of the encrypted
                        // ZIP entry. Do not report a good archive as corrupt, or
                        // claim the encrypted content digest has been validated.
                        if expected.is_some() {
                            report.aea_content_digests_not_checked.push(name.clone());
                        }
                    }
                    if !aea {
                        for (tag, _, digest) in expected.into_iter().flatten() {
                            let variants = match inputs.entry(*tag) {
                                Entry::Occupied(slot) => slot.into_mut(),
                                Entry::Vacant(slot) => slot.insert(DigestInput::variants(
                                    &buffer[..n],
                                    entry.size(),
                                    *tag,
                                )?),
                            };
                            for &input in variants.iter() {
                                if let Entry::Vacant(slot) = hashes.entry((digest.len(), input)) {
                                    slot.insert(
                                        hasher(digest.len())
                                            .context("unsupported manifest digest size")?,
                                    );
                                }
                            }
                        }
                    }
                }
                if n == 0 {
                    break;
                }
                for ((_, input), hash) in &mut hashes {
                    input.update(hash.as_mut(), &buffer[..n], size);
                }
                size += n as u64;
            }
            ensure!(size == entry.size(), "truncated ZIP entry {name}");
            let actual: HashMap<_, _> = hashes
                .into_iter()
                .map(|(key, hash)| (key, hash.finalize()))
                .collect();
            for (tag, is_tcon, digest) in expected.into_iter().flatten().filter(|_| !aea) {
                let verified = verify_component_digest(
                    &inputs[tag],
                    digest,
                    |input| {
                        Ok(actual
                            .get(&(digest.len(), input))
                            .is_some_and(|hash| hash.as_ref() == digest.as_slice()))
                    },
                    is_tcon.then_some(tcon_bytes.as_slice()),
                )
                .with_context(|| format!("manifest digest mismatch: {name}"))?;
                if !verified {
                    if !report.tcon_payload_digests_not_checked.contains(&name) {
                        report.tcon_payload_digests_not_checked.push(name.clone());
                    }
                    continue;
                }
                report.manifest_digests += 1;
            }
            report.uncompressed_bytes = report
                .uncompressed_bytes
                .checked_add(size)
                .context("IPSW size overflow")?;
            eprintln!(
                "Verified {}/{}: {} ({} MiB)",
                i + 1,
                report.entries,
                name,
                size / 1048576
            );
        }
        Ok(report)
    }
}

pub fn verify_digest(data: &[u8], expected: &[u8]) -> Result<()> {
    ensure!(
        DigestInput::File.matches(data, expected)?,
        "digest verification failed"
    );
    Ok(())
}
