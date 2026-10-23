//! USB mux frame encoding and validation.
use super::{DEVICE_MAGIC, HOST_MAGIC, MTU};
use anyhow::{Result, ensure};

pub fn encode_packet(
    protocol: u32,
    version: u32,
    tx: u16,
    rx: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    encode_header(&mut bytes, protocol, version, tx, rx, payload.len())?;
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub(super) fn encode_header(
    bytes: &mut Vec<u8>,
    protocol: u32,
    version: u32,
    tx: u16,
    rx: u16,
    payload_len: usize,
) -> Result<()> {
    let header_size = if version >= 2 { 16 } else { 8 };
    ensure!(
        payload_len + header_size <= MTU,
        "USB mux packet exceeds MTU"
    );
    bytes.clear();
    bytes.reserve(header_size + payload_len);
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(&((header_size + payload_len) as u32).to_be_bytes());
    if version >= 2 {
        bytes.extend_from_slice(&HOST_MAGIC.to_be_bytes());
        bytes.extend_from_slice(&tx.to_be_bytes());
        bytes.extend_from_slice(&rx.to_be_bytes());
    }
    Ok(())
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub protocol: u32,
    pub rx: u16,
    pub payload: &'a [u8],
}
pub fn decode_packet(bytes: &[u8], version: u32) -> Result<Packet<'_>> {
    let size = if version >= 2 { 16 } else { 8 };
    ensure!(bytes.len() >= size, "truncated mux packet");
    let n = u32::from_be_bytes(bytes[4..8].try_into()?) as usize;
    ensure!(n == bytes.len() && n <= 65536, "invalid mux length {n}");
    let rx = if version >= 2 {
        let magic = u32::from_be_bytes(bytes[8..12].try_into()?);
        ensure!(
            matches!(magic, HOST_MAGIC | DEVICE_MAGIC),
            "invalid mux magic {magic:#010x}"
        );
        u16::from_be_bytes(bytes[14..16].try_into()?)
    } else {
        0
    };
    Ok(Packet {
        protocol: u32::from_be_bytes(bytes[..4].try_into()?),
        rx,
        payload: &bytes[size..],
    })
}
