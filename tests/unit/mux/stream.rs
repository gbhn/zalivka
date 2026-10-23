use super::*;
use crate::mux::{InputReady, Link, PacketTransport, SYN, decode_packet, encode_packet};
use anyhow::ensure;
use std::sync::Weak;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy)]
enum Completion {
    Wake,
    TimeoutThenWake,
    Cancel,
    Fail,
}

#[derive(Default)]
struct State {
    input: VecDeque<Vec<u8>>,
    output: Vec<Vec<u8>>,
    ack: Option<Vec<u8>>,
    link: Weak<Mutex<Link>>,
    waits: usize,
    empty_reads: usize,
}

struct EventUsb(Arc<Mutex<State>>, InputReady);

fn tcp(ack: u32, flags: u8) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..2].copy_from_slice(&12345u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&1u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&u32::from(flags != (SYN | ACK)).to_be_bytes());
    bytes[8..12].copy_from_slice(&ack.to_be_bytes());
    bytes[12] = 0x50;
    bytes[13] = flags;
    bytes[14..16].copy_from_slice(&1u16.to_be_bytes()); // 256-byte window.
    encode_packet(6, 2, 0, 0, &bytes).unwrap()
}

impl PacketTransport for EventUsb {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.output.push(bytes.to_vec());
        if let Ok(packet) = decode_packet(bytes, 2)
            && packet.protocol == 6
            && packet.payload.len() > 20
        {
            let seq = u32::from_be_bytes(packet.payload[4..8].try_into()?);
            state.ack = Some(tcp(seq + (packet.payload.len() - 20) as u32, ACK));
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut state = self.0.lock().unwrap();
        if let Some(packet) = state.input.pop_front() {
            return Ok(packet);
        }
        state.empty_reads += 1;
        // Fails promptly if the writer never uses its completion notifier.
        ensure!(state.empty_reads == 1, "ACK notification was not awaited");
        Ok(Vec::new())
    }

    fn input_ready(&self) -> Option<InputReady> {
        Some(self.1.clone())
    }
}

#[test]
fn window_event_wait_releases_link_and_rechecks_ack_timeout_cancel_and_error() {
    for completion in [
        Completion::Wake,
        Completion::TimeoutThenWake,
        Completion::Cancel,
        Completion::Fail,
    ] {
        let state = Arc::new(Mutex::new(State::default()));
        state.lock().unwrap().input = [
            encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tcp(1, SYN | ACK),
        ]
        .into();
        let waiting = state.clone();
        let ready = InputReady::new(move |timeout| {
            assert_eq!(timeout, Duration::from_millis(1));
            let mut state = waiting.lock().unwrap();
            let link = state.link.upgrade().unwrap();
            let guard = link
                .try_lock()
                .expect("notification waited under mux mutex");
            if matches!(completion, Completion::Cancel) {
                guard.cancelled.store(true, Ordering::Release);
            }
            drop(guard);
            state.waits += 1;
            state.empty_reads = 0;
            match completion {
                Completion::Fail => anyhow::bail!("injected event wait failure"),
                Completion::Cancel => return Ok(true),
                Completion::TimeoutThenWake if state.waits == 1 => return Ok(false),
                _ => {}
            }
            let ack = state.ack.take().unwrap();
            state.input.push_back(ack);
            Ok(true)
        });
        let session = Session::new(EventUsb(state.clone(), ready)).unwrap();
        state.lock().unwrap().link = Arc::downgrade(&session.0);
        let mut stream = session.connect(12345).unwrap();
        let data: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let result = stream.write_all(&data);
        match completion {
            Completion::Wake | Completion::TimeoutThenWake => {
                result.unwrap();
                let packets = state.lock().unwrap().output.clone();
                let sent: Vec<_> = packets
                    .iter()
                    .skip(2)
                    .filter_map(|b| {
                        let p = decode_packet(b, 2).unwrap();
                        (p.protocol == 6).then_some(&p.payload[20..])
                    })
                    .flatten()
                    .copied()
                    .collect();
                assert_eq!(sent, data);
                assert_eq!(stream.profile.event_wakeups, 2);
                assert_eq!(
                    stream.profile.event_waits,
                    if matches!(completion, Completion::Wake) {
                        2
                    } else {
                        3
                    }
                );
            }
            Completion::Cancel => {
                assert!(result.unwrap_err().to_string().contains("cancelled"));
                assert_eq!(stream.profile.bytes, 256);
            }
            Completion::Fail => {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("injected event wait failure")
                );
                assert_eq!(stream.profile.bytes, 256);
            }
        }
    }
}
