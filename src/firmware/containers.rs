//! FTAB/UARP ranges and metadata used for streamed digest validation.
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{collections::HashSet, io::Cursor};

/// Baobab's plist bundle contains a firmware digest rather than a hash of the
/// serialized container. Matching metadata is not payload digest verification.
pub fn tcon_metadata_matches(bytes: &[u8], digest: &[u8]) -> Result<bool> {
    let value = Value::from_reader(Cursor::new(bytes)).context("reading TCON plist bundle")?;
    for version in wire::dictionary(&value)?.values() {
        if wire::get(version, &["firmware", "Digest"])
            .ok()
            .and_then(Value::as_data)
            == Some(digest)
            && wire::get(version, &["firmware", "Payload"])
                .ok()
                .and_then(Value::as_data)
                .is_some_and(|d| !d.is_empty())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ftab_rows(bytes: &[u8]) -> Result<&[u8]> {
    ensure!(
        bytes.len() >= 48 && &bytes[36..40] == b"ftab",
        "invalid FTAB header"
    );
    let count = u32::from_le_bytes(bytes[40..44].try_into()?) as usize;
    ensure!(count <= 65536, "too many FTAB entries");
    let end = 48 + count * 16;
    bytes.get(48..end).context("truncated FTAB index")
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
    let mut ranges = vec![];
    if prefix.get(36..40) == Some(b"ftab") {
        let rows = ftab_rows(prefix)?;
        let end = 48 + rows.len();
        for row in rows.chunks_exact(16) {
            let offset = u64::from(u32::from_le_bytes(row[4..8].try_into()?));
            let size = u64::from(u32::from_le_bytes(row[8..12].try_into()?));
            ensure!(
                offset >= end as u64 && offset + size <= length,
                "FTAB payload outside file"
            );
            ranges.push(offset..offset + size);
        }
    } else if matches!(prefix.get(..8), Some([0, 0, 0, 2 | 3, 0, 0, 0, 44])) {
        ensure!(prefix.len() >= 44, "truncated UARP header");
        let header = u32::from_be_bytes(prefix[4..8].try_into()?) as usize;
        let mut position = u32::from_be_bytes(prefix[36..40].try_into()?) as usize;
        let size = u32::from_be_bytes(prefix[40..44].try_into()?) as usize;
        let end = position.checked_add(size).context("UARP index overflow")?;
        ensure!(
            header >= 44 && position >= header && end <= prefix.len() && size <= 1024 * 1024,
            "invalid UARP index"
        );
        while position < end {
            ensure!(end - position >= 40, "truncated UARP row");
            let row = &prefix[position..];
            let size = u32::from_be_bytes(row[..4].try_into()?) as usize;
            ensure!(
                size >= 40 && size <= end - position,
                "invalid UARP row length"
            );
            let offset = u64::from(u32::from_be_bytes(row[32..36].try_into()?));
            let length_of_payload = u64::from(u32::from_be_bytes(row[36..40].try_into()?));
            ensure!(
                offset >= end as u64 && offset + length_of_payload <= length,
                "UARP payload outside file"
            );
            ranges.push(offset..offset + length_of_payload);
            position += size;
        }
    }
    // RT15 UARP v3 wraps an FTAB in its FIRM payload. Its manifest digests
    // describe rkos/cphy entries inside that table, plus the separate RRKO.
    let outer = ranges.clone();
    for (index, range) in outer.into_iter().enumerate() {
        // Centauri's 2ftb is a layout index for device memory, not a nested
        // on-disk container: its offsets intentionally exceed its own size.
        // Keep its byte range hashable without interpreting those offsets.
        if prefix.get(36..40) == Some(b"ftab")
            && prefix.get(48 + index * 16..52 + index * 16) == Some(b"2ftb")
        {
            continue;
        }
        if range.start < prefix.len() as u64 {
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

/// FTAB stores a 48-byte header, followed by 16-byte index entries and payloads.
pub struct Ftab {
    pub header: [u8; 48],
    pub entries: Vec<([u8; 4], Vec<u8>, u32)>,
}
impl Ftab {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let rows = ftab_rows(bytes)?;
        let index_end = 48 + rows.len();
        let mut entries = Vec::new();
        let mut tags = HashSet::new();
        let mut ranges = Vec::new();
        for entry in rows.chunks_exact(16) {
            let tag: [u8; 4] = entry[..4].try_into()?;
            let offset = u32::from_le_bytes(entry[4..8].try_into()?) as usize;
            let size = u32::from_le_bytes(entry[8..12].try_into()?) as usize;
            let end = offset.checked_add(size).context("FTAB entry overflow")?;
            ensure!(
                offset >= index_end && end <= bytes.len() && tags.insert(tag),
                "invalid or duplicate FTAB entry"
            );
            ranges.push((offset, end));
            entries.push((
                tag,
                &bytes[offset..end],
                u32::from_le_bytes(entry[12..16].try_into()?),
            ));
        }
        ranges.sort_unstable();
        ensure!(
            ranges.windows(2).all(|w| w[0].1 <= w[1].0),
            "overlapping FTAB entries"
        );
        Ok(Self {
            header: bytes[..48].try_into()?,
            // Validate the entire index before copying any firmware payload.
            entries: entries
                .into_iter()
                .map(|(tag, data, padding)| (tag, data.to_vec(), padding))
                .collect(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
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
