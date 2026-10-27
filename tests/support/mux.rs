//! Device-side packets shared by protocol tests and synthetic transports.
use anyhow::{Result, ensure};

pub fn tcp(source: u16, destination: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut header = vec![0; 20];
    header[..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    header[14..16].copy_from_slice(&1024u16.to_be_bytes());
    header.extend_from_slice(data);
    encode_packet(6, 2, 1, 0, &header).unwrap()
}

pub fn version_packet() -> Vec<u8> {
    encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
}

/// Build device fixtures independently of the production frame encoder.
pub fn encode_packet(
    protocol: u32,
    version: u32,
    tx: u16,
    rx: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let size = if version >= 2 { 16 } else { 8 };
    ensure!(payload.len() <= 3 * 16384 - size, "mux fixture exceeds MTU");
    let mut bytes = Vec::with_capacity(size + payload.len());
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(&((size + payload.len()) as u32).to_be_bytes());
    if version >= 2 {
        bytes.extend_from_slice(&0xfeedfaceu32.to_be_bytes());
        bytes.extend_from_slice(&tx.to_be_bytes());
        bytes.extend_from_slice(&rx.to_be_bytes());
    }
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
