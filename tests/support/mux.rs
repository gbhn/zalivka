//! Device-side packets shared by protocol tests and synthetic transports.
use crate::mux;

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
    mux::encode_packet(6, 2, 1, 0, &header).unwrap()
}

pub fn version_packet() -> Vec<u8> {
    mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
}
