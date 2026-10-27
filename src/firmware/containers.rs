//! Container parsing and payload digest validation, independent of device names.
use anyhow::{Context, Result, ensure};
use plist::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, ops::Range};

pub(crate) const MAX_PLIST_BUNDLE: u64 = 32 * 1024 * 1024;

pub(crate) fn plist_prefix(bytes: &[u8]) -> bool {
    let bytes = bytes
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(bytes)
        .trim_ascii_start();
    bytes.starts_with(b"bplist00") || bytes.starts_with(b"<?xml") || bytes.starts_with(b"<plist")
}

#[derive(Default)]
pub(crate) struct BundleVerification {
    pub payloads: usize,
    pub manifest_digest: bool,
}

/// Verify named payload records without using controller, model or path names.
pub(crate) fn verify_plist_bundle(bytes: &[u8], expected: &[u8]) -> Result<BundleVerification> {
    if !plist_prefix(bytes) {
        return Ok(BundleVerification::default());
    }
    ensure!(
        bytes.len() as u64 <= MAX_PLIST_BUNDLE,
        "plist payload bundle exceeds memory limit"
    );
    let value =
        Value::from_reader(std::io::Cursor::new(bytes)).context("reading plist payload bundle")?;
    let mut report = BundleVerification::default();
    verify_plist_node(&value, expected, 0, &mut report)?;
    Ok(report)
}

fn verify_plist_node(
    value: &Value,
    expected: &[u8],
    depth: usize,
    report: &mut BundleVerification,
) -> Result<()> {
    ensure!(depth <= 32, "plist payload bundle nested too deeply");
    if let Some(fields) = value.as_dictionary() {
        if let Some(payload) = fields.get("Payload") {
            let payload = payload.as_data().context("invalid bundle Payload")?;
            let digest = fields
                .get("Digest")
                .and_then(Value::as_data)
                .context("bundle payload has no data Digest")?;
            verify_bundle_payload(payload, digest)?;
            report.payloads += 1;
            report.manifest_digest |= digest == expected;
        }
        for (name, child) in fields {
            if name != "Payload" {
                verify_plist_node(child, expected, depth + 1, report)
                    .with_context(|| format!("checking bundle field {name}"))?;
            }
        }
    } else if let Some(values) = value.as_array() {
        for child in values {
            verify_plist_node(child, expected, depth + 1, report)?;
        }
    }
    Ok(())
}

fn verify_bundle_payload(payload: &[u8], digest: &[u8]) -> Result<()> {
    if crate::ipsw::verify_digest(payload, digest).is_ok() {
        return Ok(());
    }
    // DP855 flash-image format: two big-endian lengths, code and data banks.
    // These offsets define the format, not a model/controller selection table.
    if payload.len() == 0xf000 && digest.len() == 32 {
        let code = u32::from_be_bytes(payload[..4].try_into()?) as usize;
        let data = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
        if (1..=0x8000).contains(&code) && (1..=0x6000).contains(&data) {
            let mut hash = Sha256::new();
            hash.update(&payload[..8]);
            hash.update(&payload[0x1000..0x1000 + code]);
            hash.update(&payload[0x9000..0x9000 + data]);
            if hash.finalize().as_slice() == digest {
                return Ok(());
            }
        }
    }
    anyhow::bail!("bundle payload digest mismatch or unsupported digest format")
}

pub(super) struct FtabEntry {
    pub(super) tag: [u8; 4],
    pub(super) range: Range<u64>,
}

/// Validate the complete index before either hashing ranges or copying payloads.
/// Payload bytes may be absent from a streaming prefix.
pub(super) fn ftab_index(bytes: &[u8], length: u64) -> Result<Vec<FtabEntry>> {
    ensure!(
        bytes.len() >= 48 && &bytes[36..40] == b"ftab",
        "invalid FTAB header"
    );
    let count = u32::from_le_bytes(bytes[40..44].try_into()?) as usize;
    ensure!(count <= 65536, "too many FTAB entries");
    let end = 48 + count * 16;
    ensure!(end as u64 <= length, "FTAB index outside file");
    let rows = bytes.get(48..end).context("truncated FTAB index")?;
    let mut entries = Vec::with_capacity(count);
    let mut tags = HashSet::new();
    for row in rows.chunks_exact(16) {
        let tag = row[..4].try_into()?;
        let offset = u64::from(u32::from_le_bytes(row[4..8].try_into()?));
        let size = u64::from(u32::from_le_bytes(row[8..12].try_into()?));
        ensure!(
            offset >= end as u64 && offset + size <= length && tags.insert(tag),
            "invalid or duplicate FTAB entry"
        );
        entries.push(FtabEntry {
            tag,
            range: offset..offset + size,
        });
    }
    let mut ranges: Vec<_> = entries.iter().map(|entry| &entry.range).collect();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    ensure!(
        ranges.windows(2).all(|w| w[0].end <= w[1].start),
        "overlapping FTAB entries"
    );
    Ok(entries)
}

/// Byte ranges hashed by BuildManifest inside FTAB and UARP containers.
/// Only the index must be present in `prefix`; payloads can be streamed later.
pub fn payload_ranges(prefix: &[u8], length: u64) -> Result<Vec<std::ops::Range<u64>>> {
    payload_ranges_inner(prefix, length, 0)
}

fn payload_ranges_inner(
    prefix: &[u8],
    length: u64,
    depth: usize,
) -> Result<Vec<std::ops::Range<u64>>> {
    ensure!(depth <= 4, "firmware containers nested too deeply");
    ensure!(
        prefix.len() as u64 <= length,
        "firmware prefix exceeds file length"
    );
    let entries: Vec<_> = if prefix.get(36..40) == Some(b"ftab") {
        ftab_index(prefix, length)?
            .into_iter()
            // Centauri's 2ftb describes device memory, not a nested on-disk
            // container. Its bytes are hashable, but its offsets are not ours.
            .map(|entry| (entry.range, entry.tag != *b"2ftb"))
            .collect()
    } else {
        uarp_ranges(prefix, length)?
            .into_iter()
            .map(|range| (range, true))
            .collect()
    };
    let mut ranges: Vec<_> = entries.iter().map(|(range, _)| range.clone()).collect();
    // RT15 UARP v3 wraps an FTAB in its FIRM payload. Its manifest digests
    // describe rkos/cphy entries inside that table, plus the separate RRKO.
    for (range, descend) in entries {
        if descend && range.start < prefix.len() as u64 {
            let start = range.start as usize;
            let end = range.end.min(prefix.len() as u64) as usize;
            for child in
                payload_ranges_inner(&prefix[start..end], range.end - range.start, depth + 1)?
            {
                ensure!(ranges.len() < 65536, "too many nested firmware payloads");
                ranges.push(range.start + child.start..range.start + child.end);
            }
        }
    }
    Ok(ranges)
}

/// Read UARP's index independently of recursive payload discovery.
fn uarp_ranges(prefix: &[u8], length: u64) -> Result<Vec<Range<u64>>> {
    if !matches!(prefix.get(..8), Some([0, 0, 0, 2 | 3, 0, 0, 0, 44])) {
        return Ok(vec![]);
    }
    ensure!(prefix.len() >= 44, "truncated UARP header");
    let mut position = u32::from_be_bytes(prefix[36..40].try_into()?) as usize;
    let size = u32::from_be_bytes(prefix[40..44].try_into()?) as usize;
    let end = position.checked_add(size).context("UARP index overflow")?;
    ensure!(
        position >= 44 && end <= prefix.len() && end as u64 <= length && size <= 1024 * 1024,
        "invalid UARP index"
    );
    let mut ranges = Vec::new();
    while position < end {
        let row = &prefix[position..end];
        ensure!(row.len() >= 40, "truncated UARP row");
        let size = u32::from_be_bytes(row[..4].try_into()?) as usize;
        ensure!(size >= 40 && size <= row.len(), "invalid UARP row length");
        let offset = u64::from(u32::from_be_bytes(row[32..36].try_into()?));
        let size_of_payload = u64::from(u32::from_be_bytes(row[36..40].try_into()?));
        ensure!(
            offset >= end as u64 && offset + size_of_payload <= length,
            "UARP payload outside file"
        );
        ranges.push(offset..offset + size_of_payload);
        position += size;
    }
    let mut ordered: Vec<_> = ranges.iter().collect();
    ordered.sort_unstable_by_key(|range| (range.start, range.end));
    ensure!(
        ordered.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "overlapping UARP payloads"
    );
    Ok(ranges)
}

#[cfg(test)]
#[path = "../../tests/unit/firmware/containers.rs"]
mod tests;
