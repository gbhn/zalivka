//! Bounded archive and component digest verification, including container ranges.
use super::{Ipsw, validate_path};
use crate::{checksum::hasher, firmware, img4, wire};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
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
enum DigestInput {
    File,
    Retag([u8; 4]),
    Payload(u64, u64),
}

impl Ipsw {
    /// Exhaust every ZIP stream (including CRC validation) with bounded memory.
    pub fn verify_all(&mut self) -> Result<Verification> {
        type DigestVariants = HashSet<(Option<[u8; 4]>, Vec<u8>)>;
        let mut digests: HashMap<String, DigestVariants> = HashMap::new();
        let mut tcon_paths = HashSet::new();
        for (_, value) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(value, &["Manifest"])?)? {
                let Ok(path) = wire::string(entry, &["Info", "Path"]) else {
                    continue;
                };
                validate_path(path)?;
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
                        digests
                            .entry(path.into())
                            .or_default()
                            .insert((img4::restore_tag(name), digest.to_vec()));
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
            for (tag, digest) in expected.into_iter().flatten() {
                for input in [
                    DigestInput::File,
                    tag.map_or(DigestInput::File, DigestInput::Retag),
                ] {
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        hashes.entry((digest.len(), input))
                    {
                        entry.insert(
                            hasher(digest.len()).context("unsupported manifest digest size")?,
                        );
                    }
                }
            }
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
                if n == 0 {
                    break;
                }
                if tcon {
                    tcon_bytes.extend_from_slice(&buffer[..n]);
                }
                if size == 0 {
                    aea = buffer[..n].starts_with(b"AEA1");
                    if aea {
                        // Real AEA manifest digests are not hashes of the encrypted
                        // ZIP entry. Do not report a good archive as corrupt, or
                        // claim the encrypted content digest has been validated.
                        hashes.clear();
                        if expected.is_some() {
                            report.aea_content_digests_not_checked.push(name.clone());
                        }
                    }
                    let lengths: HashSet<_> = expected
                        .into_iter()
                        .flatten()
                        .map(|(_, d)| d.len())
                        .collect();
                    for range in firmware::payload_ranges(&buffer[..n], entry.size())? {
                        for &len in &lengths {
                            hashes.insert(
                                (len, DigestInput::Payload(range.start, range.end)),
                                hasher(len).context("unsupported manifest digest size")?,
                            );
                        }
                    }
                }
                let patch = if size == 0 {
                    img4::type_offset(&buffer[..n])
                } else {
                    None
                };
                for ((_, input), hash) in &mut hashes {
                    match (*input, patch) {
                        (DigestInput::Retag(tag), Some(offset)) => {
                            hash.update(&buffer[..offset]);
                            hash.update(&tag);
                            hash.update(&buffer[offset + 4..n]);
                        }
                        (DigestInput::Payload(start, end), _) => {
                            let start = start.max(size);
                            let end = end.min(size + n as u64);
                            if start < end {
                                hash.update(
                                    &buffer[(start - size) as usize..(end - size) as usize],
                                );
                            }
                        }
                        _ => hash.update(&buffer[..n]),
                    }
                }
                size += n as u64;
            }
            ensure!(size == entry.size(), "truncated ZIP entry {name}");
            let actual: Vec<_> = hashes.into_values().map(|hash| hash.finalize()).collect();
            for (_, digest) in expected.into_iter().flatten().filter(|_| !aea) {
                let matches = actual.iter().any(|hash| hash.as_ref() == digest.as_slice());
                if !matches && tcon && firmware::tcon_metadata_matches(&tcon_bytes, digest)? {
                    if !report.tcon_payload_digests_not_checked.contains(&name) {
                        report.tcon_payload_digests_not_checked.push(name.clone());
                    }
                    continue;
                }
                ensure!(matches, "manifest digest mismatch: {name}");
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
    let mut hash = hasher(expected.len())
        .with_context(|| format!("unsupported component digest size {}", expected.len()))?;
    hash.update(data);
    ensure!(
        hash.finalize().as_ref() == expected,
        "digest verification failed"
    );
    Ok(())
}
