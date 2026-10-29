//! Per-service TCP state, incoming sequence validation and receive windows.
use super::{ACK, RECEIVE_WINDOW, RST, SYN, packet::TcpPacket};
use anyhow::{Result, ensure};
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum State {
    Opening,
    Open,
    Closed,
}

#[derive(Debug)]
pub(super) struct Channel {
    pub destination: u16,
    pub seq: u32,
    pub ack: u32,
    pub peer_ack: u32,
    pub window: u32,
    pub state: State,
    pub firmware_transfer: bool,
    pub input: VecDeque<u8>,
    pub consumed: usize,
}

impl Channel {
    pub(super) fn new(destination: u16) -> Self {
        Self {
            destination,
            seq: 0,
            ack: 0,
            peer_ack: 0,
            window: 0,
            state: State::Opening,
            firmware_transfer: false,
            input: VecDeque::new(),
            consumed: 0,
        }
    }

    pub(super) fn tcp_header(&self, source: u16, flags: u8) -> [u8; 20] {
        let mut tcp = [0; 20];
        tcp[..2].copy_from_slice(&source.to_be_bytes());
        tcp[2..4].copy_from_slice(&self.destination.to_be_bytes());
        tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        let window = ((RECEIVE_WINDOW - self.input.len()) >> 8) as u16;
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        tcp
    }

    /// Apply a checked packet and report whether the link must send an ACK.
    pub(super) fn receive(&mut self, packet: &TcpPacket<'_>) -> Result<bool> {
        let TcpPacket {
            source: peer_port,
            destination: source,
            seq,
            ack,
            flags,
            window,
            data,
        } = *packet;
        ensure!(self.destination == peer_port, "mux TCP peer port mismatch");
        if self.state == State::Closed {
            return Ok(false);
        }
        self.window = window;
        if flags & RST != 0 {
            crate::log!(
                Debug,
                "usbmux",
                "RST {peer_port} -> {source}: {}",
                String::from_utf8_lossy(&data[..data.len().min(256)])
            );
            crate::logging::bytes(
                "usbmux:tcp",
                format_args!("RST {peer_port} -> {source}"),
                data,
            );
            self.state = State::Closed;
            return Ok(false);
        }
        if self.state == State::Opening {
            ensure!(
                flags == SYN | ACK && ack == 1 && data.is_empty(),
                "invalid mux TCP handshake"
            );
            self.seq = 1;
            self.peer_ack = 1;
            self.ack = seq.wrapping_add(1);
            self.state = State::Open;
            return Ok(true);
        }
        ensure!(
            flags & ACK != 0 && flags & SYN == 0,
            "invalid mux TCP flags {flags:#x}"
        );
        ensure!(
            self.seq.wrapping_sub(ack) <= self.seq.wrapping_sub(self.peer_ack),
            "invalid mux TCP acknowledgement"
        );
        self.peer_ack = ack;
        let acknowledge = !data.is_empty() || flags & 1 != 0;
        if acknowledge {
            ensure!(
                seq == self.ack,
                "out-of-order mux TCP data on {peer_port} -> {source}: expected={}, got={seq}, bytes={}, flags={flags:#x}",
                self.ack,
                data.len()
            );
        }
        if !data.is_empty() {
            ensure!(
                self.input.len() + data.len() <= RECEIVE_WINDOW,
                "device exceeded mux receive window"
            );
            self.input.extend(data);
            self.ack = self.ack.wrapping_add(data.len() as u32);
        }
        if flags & 1 != 0 {
            crate::log!(
                Debug,
                "usbmux",
                "FIN {peer_port} -> {source}: buffered={} B",
                self.input.len()
            );
            self.ack = self.ack.wrapping_add(1);
            self.state = State::Closed;
        }
        Ok(acknowledge)
    }
}
