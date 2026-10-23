//! CDC-NCM 1.0 NTB16 framing. Lengths and offsets are untrusted USB input.
use anyhow::{Result, ensure};
const MAX_FRAME: usize = 16014;
fn word(bytes: &[u8], at: usize) -> Result<usize> {
    ensure!(at + 2 <= bytes.len(), "truncated NCM word");
    Ok(u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize)
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
            bytes.len() >= 28 && word(bytes, 0)? >= 28,
            "short NCM parameters"
        );
        ensure!(word(bytes, 2)? & 1 != 0, "NCM NTB16 format is unavailable");
        let dword = |n| u32::from_le_bytes(bytes[n..n + 4].try_into().unwrap()) as usize;
        let input_size = dword(4).min(32768);
        let output_size = dword(16).min(65535);
        let divisor = word(bytes, 20)?;
        let remainder = word(bytes, 22)?;
        let alignment = word(bytes, 24)?;
        let max_datagrams = match word(bytes, 26)? {
            0 => 128,
            limit => limit.min(128),
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
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = vec![];
    let mut base = 0;
    while base < bytes.len() {
        let ntb = &bytes[base..];
        ensure!(
            ntb.len() >= 12 && &ntb[..4] == b"NCMH" && word(ntb, 4)? == 12,
            "invalid NCM NTB16 header"
        );
        let length = word(ntb, 8)?;
        ensure!(
            (12..=ntb.len()).contains(&length),
            "invalid NCM block length"
        );
        let ntb = &ntb[..length];
        let mut table = word(ntb, 10)?;
        let mut seen = vec![];
        while table != 0 {
            ensure!(
                table >= 12 && table + 8 <= length && !seen.contains(&table) && seen.len() < 32,
                "invalid or cyclic NCM table"
            );
            seen.push(table);
            ensure!(
                &ntb[table..table + 4] == b"NCM0",
                "unsupported NCM datagram signature"
            );
            let size = word(ntb, table + 4)?;
            ensure!(
                size >= 12 && size.is_multiple_of(4) && table + size <= length,
                "invalid NCM table length"
            );
            let mut terminated = false;
            for at in (table + 8..table + size).step_by(4) {
                let start = word(ntb, at)?;
                let count = word(ntb, at + 2)?;
                if start == 0 && count == 0 {
                    terminated = true;
                    break;
                }
                ensure!(
                    start >= 12
                        && (14..=MAX_FRAME).contains(&count)
                        && start + count <= length
                        && frames.len() < 128,
                    "invalid NCM datagram bounds"
                );
                ensure!(
                    start + count <= table || start >= table + size,
                    "NCM datagram overlaps its table"
                );
                frames.push(ntb[start..start + count].to_vec());
            }
            ensure!(terminated, "unterminated NCM datagram table");
            table = word(ntb, table + 6)?;
        }
        base += length;
    }
    Ok(frames)
}
#[cfg(test)]
#[path = "../../tests/unit/usb_internet/ncm.rs"]
mod tests;
