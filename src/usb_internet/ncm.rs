//! CDC-NCM 1.0 NTB16 framing. Lengths and offsets are untrusted USB input.
use anyhow::{Context, Result, ensure};
use std::ops::Range;

const MAX_FRAME: usize = 16014;
const MAX_DATAGRAMS: usize = 128;

fn word(bytes: &[u8], at: usize) -> Result<usize> {
    let bytes = bytes
        .get(at..)
        .and_then(|bytes| bytes.first_chunk::<2>())
        .context("truncated NCM word")?;
    Ok(u16::from_le_bytes(*bytes) as usize)
}
#[derive(Debug, Clone, Copy)]
pub(super) struct Parameters {
    pub input_size: usize,
    pub output_size: usize,
    pub divisor: usize,
    pub remainder: usize,
    pub alignment: usize,
    pub max_datagrams: usize,
}
impl Parameters {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 28 && (28..=bytes.len()).contains(&word(bytes, 0)?),
            "short NCM parameters"
        );
        ensure!(word(bytes, 2)? & 1 != 0, "NCM NTB16 format is unavailable");
        let input_size = (u32::from_le_bytes(bytes[4..8].try_into()?) as usize).min(32768);
        let output_size = (u32::from_le_bytes(bytes[16..20].try_into()?) as usize).min(65535);
        let divisor = word(bytes, 20)?;
        let remainder = word(bytes, 22)?;
        let alignment = word(bytes, 24)?;
        let max_datagrams = match word(bytes, 26)? {
            0 => MAX_DATAGRAMS,
            limit => limit.min(MAX_DATAGRAMS),
        };
        ensure!(
            (2048..=65535).contains(&input_size) && (2048..=65535).contains(&output_size),
            "invalid NCM transfer sizes"
        );
        ensure!(
            divisor.is_power_of_two() && divisor <= 512 && remainder < divisor,
            "invalid NCM datagram alignment"
        );
        ensure!(
            alignment.is_power_of_two() && alignment <= 512,
            "invalid NCM table alignment"
        );
        Ok(Self {
            input_size,
            output_size,
            divisor,
            remainder,
            alignment,
            max_datagrams,
        })
    }
    pub fn encode(&self, frames: &[Vec<u8>], sequence: u16) -> Result<(Vec<u8>, usize)> {
        let table = 12usize.next_multiple_of(self.alignment);
        // NCM alignment applies to the IP payload after the Ethernet header.
        let aligned = |offset: usize| {
            (offset + 14 + self.divisor - 1 - self.remainder) / self.divisor * self.divisor
                + self.remainder
                - 14
        };
        let mut count = 0;
        let mut span: usize = 0;
        for frame in frames.iter().take(self.max_datagrams) {
            ensure!(
                (14..=MAX_FRAME).contains(&frame.len()),
                "invalid Ethernet frame length"
            );
            // Every datagram starts at the same remainder. Between datagrams,
            // padding depends only on the relative payload length.
            let candidate = span.next_multiple_of(self.divisor) + frame.len();
            if aligned(table + 12 + 4 * (count + 1)) + candidate > self.output_size {
                break;
            }
            span = candidate;
            count += 1;
        }
        ensure!(
            count != 0,
            "NCM frame exceeds negotiated transfer size or empty batch"
        );
        let start = aligned(table + 12 + 4 * count);
        let end = start + span;
        let mut bytes = vec![0; end];
        bytes[..4].copy_from_slice(b"NCMH");
        let mut put =
            |at, value: usize| bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
        put(4, 12);
        put(6, sequence as usize);
        put(8, end);
        put(10, table);
        put(table + 4, 12 + 4 * count);
        bytes[table..table + 4].copy_from_slice(b"NCM0");
        let mut offset = start;
        for (index, frame) in frames[..count].iter().enumerate() {
            let entry = table + 8 + 4 * index;
            bytes[entry..entry + 2].copy_from_slice(&(offset as u16).to_le_bytes());
            bytes[entry + 2..entry + 4].copy_from_slice(&(frame.len() as u16).to_le_bytes());
            bytes[offset..offset + frame.len()].copy_from_slice(frame);
            offset = aligned(offset + frame.len());
        }
        Ok((bytes, count))
    }
}
pub(super) fn decode(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = vec![];
    while !bytes.is_empty() {
        ensure!(
            bytes.len() >= 12 && &bytes[..4] == b"NCMH" && word(bytes, 4)? == 12,
            "invalid NCM NTB16 header"
        );
        let length = word(bytes, 8)?;
        ensure!(
            (12..=bytes.len()).contains(&length),
            "invalid NCM block length"
        );
        let (block, rest) = bytes.split_at(length);
        let ranges = datagrams(block)?;
        frames.extend(ranges.into_iter().map(|range| block[range].to_vec()));
        bytes = rest;
    }
    Ok(frames)
}

/// Validate the whole NTB before copying frames. A datagram may not overlap any
/// table or another datagram, including tables encountered later in the chain.
fn datagrams(block: &[u8]) -> Result<Vec<Range<usize>>> {
    let mut frames = Vec::new();
    let mut tables: Vec<Range<usize>> = Vec::new();
    let mut table = word(block, 10)?;
    while table != 0 {
        ensure!(
            table >= 12
                && table + 8 <= block.len()
                && tables.len() < 32
                && tables.iter().all(|range| range.start != table),
            "invalid or cyclic NCM table"
        );
        ensure!(
            &block[table..table + 4] == b"NCM0",
            "unsupported NCM datagram signature"
        );
        let size = word(block, table + 4)?;
        ensure!(
            size >= 12 && size.is_multiple_of(4) && table + size <= block.len(),
            "invalid NCM table length"
        );
        tables.push(table..table + size);
        let mut terminated = false;
        for at in (table + 8..table + size).step_by(4) {
            let start = word(block, at)?;
            let count = word(block, at + 2)?;
            if start == 0 && count == 0 {
                terminated = true;
                break;
            }
            ensure!(
                start >= 12
                    && (14..=MAX_FRAME).contains(&count)
                    && start + count <= block.len()
                    && frames.len() < MAX_DATAGRAMS,
                "invalid NCM datagram bounds"
            );
            frames.push(start..start + count);
        }
        ensure!(terminated, "unterminated NCM datagram table");
        table = word(block, table + 6)?;
    }
    tables.extend(frames.iter().cloned());
    tables.sort_unstable_by_key(|range| range.start);
    ensure!(
        tables.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "overlapping NCM tables or datagrams"
    );
    Ok(frames)
}
#[cfg(test)]
#[path = "../../tests/unit/usb_internet/ncm.rs"]
mod tests;
