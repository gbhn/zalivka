use super::*;

#[test]
fn cancelled_or_expired_connects_do_not_allocate_channels_or_write_syn() {
    let state = Arc::new(Mutex::new(State::default()));
    state
        .lock()
        .unwrap()
        .input
        .push_back(crate::test_mux::version_packet());
    let session = Session::new(EventUsb(state.clone(), InputReady::new(|_| Ok(false)))).unwrap();
    let writes = state.lock().unwrap().output.len();
    assert!(session.connect_until(12345, Instant::now()).is_err());
    session.cancel();
    assert!(session.connect(12345).is_err());
    assert_eq!(state.lock().unwrap().output.len(), writes);
    let link = session.lock().unwrap();
    assert!(link.channels.is_empty());
    assert_eq!(link.next_port, 1);
}

#[test]
fn mux_header_rejects_usize_overflow_without_touching_the_buffer() {
    let mut bytes = vec![42];
    assert!(crate::mux::packet::encode_header(&mut bytes, 6, 2, 0, 0, usize::MAX).is_err());
    assert_eq!(bytes, [42]);
}
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

#[test]
fn version_handshake_waits_for_fragmented_input_and_propagates_wait_errors() {
    for fail in [false, true] {
        let state = Arc::new(Mutex::new(State::default()));
        let waiting = state.clone();
        let ready = InputReady::new(move |timeout| {
            assert_eq!(timeout, Duration::from_millis(1));
            let mut state = waiting.lock().unwrap();
            state.empty_reads = 0;
            state.waits += 1;
            ensure!(!fail, "injected handshake wait failure");
            let packet = crate::test_mux::version_packet();
            let fragment = if state.waits == 1 {
                &packet[..5]
            } else {
                &packet[5..]
            };
            state.input.push_back(fragment.to_vec());
            Ok(true)
        });
        let result = Session::new(EventUsb(state.clone(), ready));
        if fail {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("injected handshake wait failure")
            );
            assert_eq!(state.lock().unwrap().waits, 1);
        } else {
            let session = result.unwrap();
            assert_eq!(session.lock().unwrap().version, 2);
            assert_eq!(state.lock().unwrap().waits, 2);
            assert_eq!(state.lock().unwrap().output.len(), 2);
        }
    }
}

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

#[test]
fn fatal_input_errors_cancel_all_services_and_fin_requires_the_expected_sequence() {
    use crate::test_mux::{tcp as packet, version_packet};
    for bad in [
        vec![0; 8],
        packet(12345, 1, 99, 1, ACK | 1, &[]),
        packet(12345, 1, 99, 1, ACK, b"out of order"),
    ] {
        let state = Arc::new(Mutex::new(State::default()));
        state.lock().unwrap().input = [
            version_packet(),
            packet(12345, 1, 0, 1, SYN | ACK, &[]),
            bad,
        ]
        .into();
        let session = Session::new(EventUsb(state, InputReady::new(|_| Ok(false)))).unwrap();
        let mut stream = session.connect(12345).unwrap();
        assert!(stream.read(&mut [0]).is_err());
        assert!(session.1.load(Ordering::Acquire));
        assert!(stream.write_all(b"must not continue").is_err());
    }
}

#[test]
fn closed_mux_channels_cannot_accept_payload_after_eof() {
    use crate::test_mux::{tcp as packet, version_packet};
    let state = Arc::new(Mutex::new(State::default()));
    state.lock().unwrap().input = [
        version_packet(),
        packet(12345, 1, 0, 1, SYN | ACK, &[]),
        packet(12345, 1, 1, 1, ACK | 1, &[]),
        packet(12345, 1, 2, 1, ACK, b"late data"),
    ]
    .into();
    let session = Session::new(EventUsb(state, InputReady::new(|_| Ok(false)))).unwrap();
    let mut stream = session.connect(12345).unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert!(session.lock().unwrap().pump().unwrap());
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    assert!(!session.1.load(Ordering::Acquire));
}

#[test]
fn a_failed_window_ack_does_not_discard_bytes_already_read() {
    use crate::test_mux::{tcp as packet, version_packet};
    struct FailingAck {
        packets: VecDeque<Vec<u8>>,
        writes: usize,
    }
    impl PacketTransport for FailingAck {
        fn write_packet(&mut self, _: &[u8]) -> Result<()> {
            self.writes += 1;
            ensure!(self.writes != 6, "injected window ACK failure");
            Ok(())
        }
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            Ok(self.packets.pop_front().unwrap_or_default())
        }
    }
    let payload = vec![0x5a; 16384];
    let session = Session::new(FailingAck {
        packets: [
            version_packet(),
            packet(12345, 1, 0, 1, SYN | ACK, &[]),
            packet(12345, 1, 1, 1, ACK, &payload),
        ]
        .into(),
        writes: 0,
    })
    .unwrap();
    let mut stream = session.connect(12345).unwrap();
    let mut output = vec![0; payload.len()];
    assert_eq!(stream.read(&mut output).unwrap(), payload.len());
    assert_eq!(output, payload);
    assert!(stream.read(&mut [0]).is_err());
    assert!(session.1.load(Ordering::Acquire));
}
