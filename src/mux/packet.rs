//! USB mux frame encoding and validation.
use super::{DEVICE_MAGIC, HOST_MAGIC, MTU};
use anyhow::{Result, ensure};

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
        payload_len <= MTU - header_size,
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

/// A checked TCP header and its borrowed payload, without copying USB data.
pub(super) struct TcpPacket<'a> {
    pub source: u16,
    pub destination: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u32,
    pub data: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(bytes.len() >= 20, "truncated mux TCP header");
        let header_len = usize::from(bytes[12] >> 4) * 4;
        ensure!(
            header_len >= 20 && header_len <= bytes.len(),
            "invalid mux TCP header size"
        );
        Ok(Self {
            source: u16::from_be_bytes(bytes[..2].try_into()?),
            destination: u16::from_be_bytes(bytes[2..4].try_into()?),
            seq: u32::from_be_bytes(bytes[4..8].try_into()?),
            ack: u32::from_be_bytes(bytes[8..12].try_into()?),
            flags: bytes[13],
            window: u32::from(u16::from_be_bytes(bytes[14..16].try_into()?)) << 8,
            data: &bytes[header_len..],
        })
    }
}
