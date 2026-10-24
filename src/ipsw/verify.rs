//! Collect manifest requirements, stream ZIP entries and report verified digests.
use super::{
    Ipsw, component_path,
    digest::{DigestInput, verify_component_digest},
};
use crate::{checksum::hasher, img4, wire};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    io::{self, Read},
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

#[derive(Hash, PartialEq, Eq)]
struct ComponentDigest {
    tag: Option<[u8; 4]>,
    tcon: bool,
    expected: Vec<u8>,
}

/// Keep exceptions attached to their component, even when paths are shared.
#[derive(Default)]
struct EntryDigests {
    tcon: bool,
    components: HashSet<ComponentDigest>,
}

#[derive(Default)]
struct EntryVerification {
    bytes: u64,
    digests: usize,
    aea_deferred: bool,
    tcon_deferred: bool,
}

impl Ipsw {
    fn manifest_digests(&self) -> Result<HashMap<String, EntryDigests>> {
        let mut entries: HashMap<String, EntryDigests> = HashMap::new();
        for (_, value) in self.identity_values() {
            for (name, entry) in wire::dictionary(wire::get(value, &["Manifest"])?)? {
                let Some(path) = component_path(entry)
                    .with_context(|| format!("invalid manifest component {name}"))?
                else {
                    continue;
                };
                ensure!(self.contains(path), "missing manifest component {path}");
                let requirements = entries.entry(path.into()).or_default();
                let tcon = name == "Baobab,TCON";
                requirements.tcon |= tcon;
                if let Some(digest) = wire::dictionary(entry)?.get("Digest") {
                    let digest = digest.as_data().context("invalid manifest digest")?;
                    if !digest.is_empty() {
                        ensure!(
                            [20, 32, 48].contains(&digest.len()),
                            "unsupported digest for {path}"
                        );
                        requirements.components.insert(ComponentDigest {
                            tag: img4::restore_tag(name),
                            tcon,
                            expected: digest.to_vec(),
                        });
                    }
                }
            }
        }
        Ok(entries)
    }

    /// Exhaust every ZIP stream (including CRC validation) with bounded memory.
    pub fn verify_all(&mut self) -> Result<Verification> {
        let requirements = self.manifest_digests()?;
        let no_digests = EntryDigests::default();
        let mut report = Verification {
            entries: self.archive.len(),
            uncompressed_bytes: 0,
            manifest_digests: 0,
            archive_checksum_verified: false,
            aea_content_digests_not_checked: vec![],
            tcon_payload_digests_not_checked: vec![],
        };
        let mut buffer = vec![0; 2 * 1024 * 1024];
        for index in 0..self.archive.len() {
            let mut entry = self.archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            let length = entry.size();
            let verified = requirements.get(&name).unwrap_or(&no_digests).verify(
                &mut entry,
                &name,
                length,
                &mut buffer,
            )?;
            report.manifest_digests += verified.digests;
            report.uncompressed_bytes = report
                .uncompressed_bytes
                .checked_add(verified.bytes)
                .context("IPSW size overflow")?;
            if verified.aea_deferred {
                report.aea_content_digests_not_checked.push(name.clone());
            }
            if verified.tcon_deferred {
                report.tcon_payload_digests_not_checked.push(name.clone());
            }
            eprintln!(
                "Verified {}/{}: {} ({} MiB)",
                index + 1,
                report.entries,
                name,
                verified.bytes / 1048576,
            );
        }
        Ok(report)
    }
}

impl EntryDigests {
    fn verify(
        &self,
        reader: &mut impl Read,
        name: &str,
        length: u64,
        buffer: &mut [u8],
    ) -> Result<EntryVerification> {
        ensure!(
            !self.tcon || length <= 32 * 1024 * 1024,
            "TCON metadata bundle exceeds 32 MiB"
        );
        let mut n =
            read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        let aea = buffer[..n].starts_with(b"AEA1");
        // Validate containers even when no manifest digest references this entry.
        let inputs = DigestInput::variants(&buffer[..n], length, None)?;
        // AEA manifest digests describe decrypted content, not the ZIP bytes.
        let checks = self
            .components
            .iter()
            .filter(|_| !aea)
            .map(|component| (component, DigestInput::retag(&buffer[..n], component.tag)))
            .collect::<Vec<_>>();
        let mut hashes = HashMap::new();
        for (component, tag) in &checks {
            for input in inputs.iter().copied().chain(*tag) {
                if let Entry::Vacant(slot) = hashes.entry((component.expected.len(), input)) {
                    slot.insert(
                        hasher(component.expected.len())
                            .context("unsupported manifest digest size")?,
                    );
                }
            }
        }
        let mut verified = EntryVerification {
            aea_deferred: aea && !self.components.is_empty(),
            ..Default::default()
        };
        let mut tcon_bytes = Vec::new();
        while n != 0 {
            if self.tcon {
                tcon_bytes.extend_from_slice(&buffer[..n]);
            }
            for ((_, input), hash) in &mut hashes {
                input.update(hash.as_mut(), &buffer[..n], verified.bytes);
            }
            verified.bytes += n as u64;
            n = read_chunk(reader, buffer).with_context(|| format!("checking ZIP entry {name}"))?;
        }
        ensure!(verified.bytes == length, "truncated ZIP entry {name}");
        let actual: HashMap<_, _> = hashes
            .into_iter()
            .map(|(key, hash)| (key, hash.finalize()))
            .collect();
        for (component, tag) in checks {
            let matched = verify_component_digest(
                inputs.iter().copied().chain(tag),
                &component.expected,
                |input| {
                    Ok(actual
                        .get(&(component.expected.len(), input))
                        .is_some_and(|hash| hash.as_ref() == component.expected.as_slice()))
                },
                component.tcon.then_some(tcon_bytes.as_slice()),
            )
            .with_context(|| format!("manifest digest mismatch: {name}"))?;
            if matched {
                verified.digests += 1;
            } else {
                verified.tcon_deferred = true;
            }
        }
        Ok(verified)
    }
}

/// Fill the first block so container headers never depend on short ZIP reads.
fn read_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buffer.len() {
        match reader.read(&mut buffer[n..]) {
            Ok(0) => break,
            Ok(read) => n += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(n)
}

#[cfg(test)]
#[path = "../../tests/unit/ipsw/verify.rs"]
mod tests;
