//! FTAB/UARP ranges and metadata used for streamed digest validation.
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Cursor, ops::Range};

/// Baobab's manifest digest identifies firmware inside a plist bundle. Verify
/// the actual firmware and its panel configurations, not just their metadata.
pub fn verify_tcon_digest(bytes: &[u8], digest: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "TCON metadata bundle exceeds 32 MiB"
    );
    let value = Value::from_reader(Cursor::new(bytes)).context("reading TCON plist bundle")?;
    let mut matched = false;
    for (version_name, version) in wire::dictionary(&value)? {
        if wire::get(version, &["firmware", "Digest"])
            .ok()
            .and_then(Value::as_data)
            != Some(digest)
        {
            continue;
        }
        verify_tcon_payload(wire::get(version, &["firmware"])?, true)
            .with_context(|| format!("TCON {version_name} firmware digest mismatch"))?;
        if let Some(panels) = wire::dictionary(version)?.get("device_id") {
            for (panel, components) in wire::dictionary(panels)? {
                for (name, component) in wire::dictionary(components)? {
                    verify_tcon_payload(component, false).with_context(|| {
                        format!("TCON {version_name}/{panel}/{name} digest mismatch")
                    })?;
                }
            }
        }
        matched = true;
    }
    ensure!(matched, "TCON firmware digest does not match manifest");
    Ok(())
}

fn verify_tcon_payload(component: &Value, firmware: bool) -> Result<()> {
    let payload = wire::get(component, &["Payload"])?
        .as_data()
        .context("invalid TCON Payload")?;
    let digest = wire::get(component, &["Digest"])?
        .as_data()
        .context("invalid TCON Digest")?;
    ensure!(
        !payload.is_empty() && digest.len() == 32,
        "invalid TCON payload or SHA-256 digest"
    );
    if Sha256::digest(payload).as_slice() == digest {
        return Ok(());
    }
    // DP855's 60 KiB flash image stores big-endian code/data lengths in its
    // first eight bytes. The digest covers that header, code at 0x1000 and
    // data at 0x9000, excluding flash padding. Checked against every DP855
    // bundle in 26A434 (17 products, including X1769 for j313ap).
    if firmware && payload.len() == 0xf000 {
        let code_len = u32::from_be_bytes(payload[..4].try_into()?) as usize;
        let data_len = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
        ensure!(
            code_len > 0 && code_len <= 0x8000 && data_len > 0 && data_len <= 0x6000,
            "invalid TCON DP855 code/data lengths"
        );
        let mut hash = Sha256::new();
        hash.update(&payload[..8]);
        hash.update(&payload[0x1000..0x1000 + code_len]);
        hash.update(&payload[0x9000..0x9000 + data_len]);
        ensure!(
            hash.finalize().as_slice() == digest,
            "TCON DP855 digest mismatch"
        );
        return Ok(());
    }
    anyhow::bail!("TCON payload digest mismatch")
}

pub(super) struct FtabEntry {
    pub(super) tag: [u8; 4],
    pub(super) range: Range<u64>,
    padding: u32,
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
            padding: u32::from_le_bytes(row[12..16].try_into()?),
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
    Ok(ranges)
}

/// FTAB stores a 48-byte header, followed by 16-byte index entries and payloads.
pub struct Ftab {
    pub header: [u8; 48],
    pub entries: Vec<([u8; 4], Vec<u8>, u32)>,
}
impl Ftab {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let entries = ftab_index(bytes, bytes.len() as u64)?;
        Ok(Self {
            header: bytes[..48].try_into()?,
            // Validate the entire index before copying any firmware payload.
            entries: entries
                .into_iter()
                .map(|entry| {
                    (
                        entry.tag,
                        bytes[entry.range.start as usize..entry.range.end as usize].to_vec(),
                        entry.padding,
                    )
                })
                .collect(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(&self.header[36..40] == b"ftab", "invalid FTAB header");
        ensure!(self.entries.len() <= 65536, "too many FTAB entries");
        let index_end = 48 + self.entries.len() * 16;
        let mut output = self.header.to_vec();
        output[40..44].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        output.resize(index_end, 0);
        let mut seen = HashSet::new();
        for (i, (tag, data, padding)) in self.entries.iter().enumerate() {
            ensure!(seen.insert(tag), "duplicate FTAB tag");
            let offset = u32::try_from(output.len())?;
            let size = u32::try_from(data.len())?;
            let position = 48 + i * 16;
            output[position..position + 4].copy_from_slice(tag);
            output[position + 4..position + 8].copy_from_slice(&offset.to_le_bytes());
            output[position + 8..position + 12].copy_from_slice(&size.to_le_bytes());
            output[position + 12..position + 16].copy_from_slice(&padding.to_le_bytes());
            output.extend_from_slice(data);
        }
        Ok(output)
    }
}
