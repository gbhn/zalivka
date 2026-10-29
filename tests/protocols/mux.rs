use super::*;

#[test]
fn mux_tcp_options_preserve_payload_boundaries_and_only_required_acks_are_sent() {
    let payload = b"payload across wrap";
    let initial = u32::MAX - 3;
    for options in [0, 4, 40] {
        let packet = |frame: Vec<u8>| {
            let mut body = frame[16..].to_vec();
            body[12] = (((20 + options) / 4) as u8) << 4;
            body.splice(20..20, vec![0xa5; options]);
            test_mux::encode_packet(6, 2, 1, 0, &body).unwrap()
        };
        let (usb, output) = mock_mux(vec![
            version_packet(),
            packet(tcp(12345, 1, initial, 1, 0x12, &[])),
            packet(tcp(12345, 1, 1234567, 1, 0x10, &[])),
            packet(tcp(54321, 65000, 1, 1, 0x10, b"unrelated channel")),
            packet(tcp(12345, 1, initial.wrapping_add(1), 1, 0x10, payload)),
            packet(tcp(
                12345,
                1,
                initial.wrapping_add(1 + payload.len() as u32),
                1,
                0x11,
                &[],
            )),
        ]);
        let session = Session::new(usb).unwrap();
        let mut stream = session.connect(12345).unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(received, payload);
        assert_eq!(
            stream.write(b"closed").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let sent = output.lock().unwrap();
        let acknowledgements: Vec<_> = sent
            .iter()
            .skip(2)
            .filter_map(|bytes| {
                let packet = mux::decode_packet(bytes, 2).unwrap();
                (packet.payload[13] == 0x10)
                    .then(|| u32::from_be_bytes(packet.payload[8..12].try_into().unwrap()))
            })
            .collect();
        assert_eq!(
            acknowledgements,
            [
                initial.wrapping_add(1),
                initial.wrapping_add(1 + payload.len() as u32),
                initial.wrapping_add(2 + payload.len() as u32),
            ]
        );
        assert_eq!(sent.len(), 6); // version, setup, SYN, and three ACKs.
    }
}

#[test]
fn mux_reset_preserves_buffered_bytes_and_does_not_close_other_services() {
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(12345, 1, 0, 1, 0x12, &[]),
        tcp(54321, 2, 0, 1, 0x12, &[]),
        tcp(12345, 1, 1, 1, 0x10, b"before reset"),
        tcp(12345, 1, 13, 1, 0x04, b"service stopped"),
        tcp(54321, 2, 1, 1, 0x10, b"OK"),
    ]);
    let session = Session::new(usb).unwrap();
    let mut first = session.connect(12345).unwrap();
    let mut second = session.connect(54321).unwrap();
    // This reader routes the other service's data and reset before that
    // service consumes its buffer.
    second.read_exact(&mut [0; 2]).unwrap();
    let mut received = Vec::new();
    first.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"before reset");
    assert_eq!(
        first.write(b"closed").unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    second.write_all(b"still open").unwrap();
    assert_eq!(mux_output(&output, 54321).into_inner(), b"still open");
    let acknowledgements = output
        .lock()
        .unwrap()
        .iter()
        .skip(2)
        .filter(|bytes| {
            let packet = mux::decode_packet(bytes, 2).unwrap();
            packet.payload[2..4] == 12345u16.to_be_bytes() && packet.payload[13] == 0x10
        })
        .count();
    assert_eq!(acknowledgements, 2); // SYN and data; never answer RST with ACK.
}

#[test]
fn malformed_tcp_headers_cancel_all_services_even_for_an_unknown_channel() {
    for destination in [1, 65000] {
        for malformed in 0..3 {
            let mut body = tcp(12345, destination, 1, 1, 0x10, &[])[16..].to_vec();
            match malformed {
                0 => {
                    body.pop();
                }
                1 => body[12] = 0x40,
                2 => body[12] = 0x60,
                _ => unreachable!(),
            }
            let (usb, output) = mock_mux(vec![
                version_packet(),
                tcp(12345, 1, 0, 1, 0x12, &[]),
                tcp(54321, 2, 0, 1, 0x12, &[]),
                test_mux::encode_packet(6, 2, 1, 0, &body).unwrap(),
            ]);
            let session = Session::new(usb).unwrap();
            let mut first = session.connect(12345).unwrap();
            let mut second = session.connect(54321).unwrap();
            assert!(
                first
                    .read(&mut [0])
                    .unwrap_err()
                    .to_string()
                    .contains("mux TCP")
            );
            let sent = output.lock().unwrap().len();
            assert!(
                second
                    .write_all(b"must not continue")
                    .unwrap_err()
                    .to_string()
                    .contains("cancelled")
            );
            assert_eq!(output.lock().unwrap().len(), sent);
        }
    }
}

#[test]
fn mux_coalesced_frames_survive_fragmentation_sequence_wrap_and_final_close() {
    let first = vec![0xa5; 4097];
    let last = b"final bytes";
    let initial = u32::MAX - 4;
    let next = initial.wrapping_add(1);
    let end = next.wrapping_add(first.len() as u32);
    let incoming = [
        version_packet(),
        tcp(62078, 1, initial, 1, 0x12, &[]),
        tcp(62078, 1, next, 1, 0x10, &first),
        tcp(62078, 1, end, 1, 0x11, last),
    ]
    .concat();
    for fragment in [1, 7, 8, 15, 16, 20, 36, 37, 65536] {
        let (usb, output) = mock_mux(incoming.chunks(fragment).map(<[u8]>::to_vec).collect());
        let session = Session::new(usb).unwrap();
        let mut stream = session.connect(62078).unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(
            received,
            [first.as_slice(), last].concat(),
            "fragment {fragment}"
        );
        let sent = output.lock().unwrap();
        let reply = mux::decode_packet(sent.last().unwrap(), 2).unwrap();
        assert_eq!(
            u32::from_be_bytes(reply.payload[8..12].try_into().unwrap()),
            end.wrapping_add(last.len() as u32 + 1),
        );
    }
}

#[test]
fn mux_accepts_the_recorded_device_magic_and_preserves_outgoing_host_magic() {
    // Captured on the physical Mac after negotiating mux v2. The TCP payload
    // is synthetic; the 16-byte device header is independent of our encoder.
    let mut incoming = vec![
        0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x24, 0xfa, 0xce, 0xfa, 0xce, 0x00, 0x00, 0x00,
        0x01,
    ];
    incoming.extend_from_slice(&[0; 20]);
    let packet = mux::decode_packet(&incoming, 2).unwrap();
    assert_eq!(packet.protocol, 6);
    assert_eq!(packet.rx, 1);
    assert_eq!(packet.payload, &[0; 20]);

    let outgoing = test_mux::encode_packet(6, 2, 1, 0xffff, packet.payload).unwrap();
    assert_eq!(&outgoing[8..12], &[0xfe, 0xed, 0xfa, 0xce]);
    assert!(mux::decode_packet(&outgoing, 2).is_ok());
    for invalid in [0u32, 0xcefaedfe, 0xcefacefa, 0xdeadbeef] {
        let mut bad = incoming.clone();
        bad[8..12].copy_from_slice(&invalid.to_be_bytes());
        assert!(mux::decode_packet(&bad, 2).is_err());
    }
}

#[test]
fn mux_device_magic_frames_connect_and_reassemble_across_usb_reads() {
    let mut handshake = tcp(62078, 1, 0, 1, 0x12, &[]);
    handshake[8..12].copy_from_slice(&[0xfa, 0xce, 0xfa, 0xce]);
    let mut data = tcp(62078, 1, 1, 1, 0x10, b"hello");
    data[8..12].copy_from_slice(&[0xfa, 0xce, 0xfa, 0xce]);
    let (usb, output) = mock_mux(vec![
        version_packet(),
        handshake[..10].to_vec(),
        handshake[10..].to_vec(),
        data[..5].to_vec(),
        data[5..].to_vec(),
    ]);
    let session = Session::new(usb).unwrap();
    let mut stream = session.connect(62078).unwrap();
    let mut reply = [0; 5];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"hello");
    stream.write_all(b"query").unwrap();
    let sent = output.lock().unwrap();
    for packet in sent.iter().skip(1) {
        assert_eq!(&packet[8..12], &[0xfe, 0xed, 0xfa, 0xce]);
    }
    assert_eq!(
        mux::decode_packet(sent.last().unwrap(), 2).unwrap().payload[20..],
        *b"query"
    );
}

#[test]
fn mux_v2_negotiates_and_reassembles_split_tcp_packets() {
    let data = tcp(62078, 1, 1, 1, 0x10, b"hello");
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        data[..5].to_vec(),
        data[5..].to_vec(),
    ]);
    let session = Session::new(usb).unwrap();
    let mut stream = session.connect(62078).unwrap();
    let mut b = [0; 5];
    stream.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"hello");
    stream.write_all(b"request").unwrap();
    let sent = output.lock().unwrap();
    assert_eq!(mux::decode_packet(&sent[0], 0).unwrap().protocol, 0);
    assert_eq!(&sent[1][12..14], &0u16.to_be_bytes());
    assert_eq!(mux::decode_packet(&sent[1], 2).unwrap().payload, &[7]);
    let last = mux::decode_packet(sent.last().unwrap(), 2).unwrap();
    assert_eq!(&last.payload[20..], b"request");
}

#[test]
fn mux_batched_write_all_obeys_small_zero_and_reopened_windows() {
    for window in [512u32, 262144] {
        let size = window as usize * 2 + 77;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let batch = if window as usize >= 49152 - 37 {
            window / (49152 - 37) * (49152 - 37)
        } else {
            window
        };
        let packet = |ack, flags, open: bool| {
            let mut bytes = tcp(12345, 1, if flags == 0x12 { 0 } else { 1 }, ack, flags, &[]);
            bytes[30..32]
                .copy_from_slice(&if open { (window >> 8) as u16 } else { 0 }.to_be_bytes());
            bytes
        };
        let (usb, output) = mock_mux(vec![
            version_packet(),
            packet(1, 0x12, true),
            packet(batch + 1, 0x10, false),
            packet(batch + 1, 0x10, true),
            packet(batch * 2 + 1, 0x10, true),
        ]);
        let session = Session::new(usb).unwrap();
        let mut stream = session.connect(12345).unwrap();
        stream.write_all(&data).unwrap();
        assert_eq!(mux_output(&output, 12345).into_inner(), data);
        let mut expected_seq = 1u32;
        for bytes in output.lock().unwrap().iter().skip(2) {
            let p = mux::decode_packet(bytes, 2).unwrap();
            if p.protocol != 6 || p.payload.len() == 20 {
                continue;
            }
            let seq = u32::from_be_bytes(p.payload[4..8].try_into().unwrap());
            let length = (p.payload.len() - 20) as u32;
            assert_eq!(seq, expected_seq);
            assert!(length <= 49152 - 37);
            assert!(length <= window);
            expected_seq += length;
        }
        assert_eq!(expected_seq, data.len() as u32 + 1);
    }
}

#[test]
fn mux_drains_ready_acks_without_fragmenting_frames_or_waiting_for_large_windows() {
    struct AckUsb {
        input: VecDeque<Vec<u8>>,
        output: Arc<Mutex<Vec<Vec<u8>>>>,
        window: u16,
        burst_packets: Arc<Mutex<Vec<usize>>>,
    }
    impl PacketTransport for AckUsb {
        fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
            self.output.lock().unwrap().push(bytes.to_vec());
            let protocol = u32::from_be_bytes(bytes[..4].try_into()?);
            let mut reply = if protocol == 0 {
                version_packet()
            } else if protocol == 6 {
                let packet = mux::decode_packet(bytes, 2)?;
                let t = packet.payload;
                let local = u16::from_be_bytes(t[..2].try_into()?);
                let port = u16::from_be_bytes(t[2..4].try_into()?);
                let seq = u32::from_be_bytes(t[4..8].try_into()?);
                if t[13] == 2 {
                    tcp(port, local, 0, 1, 0x12, &[])
                } else if t.len() > 20 {
                    tcp(
                        port,
                        local,
                        1,
                        seq.wrapping_add((t.len() - 20) as u32),
                        0x10,
                        &[],
                    )
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            };
            if protocol == 6 {
                reply[30..32].copy_from_slice(&self.window.to_be_bytes());
            }
            self.input.push_back(reply);
            Ok(())
        }
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            Ok(self.input.pop_front().unwrap_or_default())
        }
        fn write_packets(
            &mut self,
            packets: &[Vec<u8>],
            _cancelled: &std::sync::atomic::AtomicBool,
        ) -> Result<()> {
            self.burst_packets.lock().unwrap().push(packets.len());
            for packet in packets {
                self.write_packet(packet)?;
            }
            Ok(())
        }
    }
    for window in [1, 1024] {
        let output = Arc::new(Mutex::new(vec![]));
        let burst_packets = Arc::new(Mutex::new(vec![]));
        let session = Session::new(AckUsb {
            input: VecDeque::new(),
            output: output.clone(),
            window,
            burst_packets: burst_packets.clone(),
        })
        .unwrap();
        let mut stream = session.connect(12345).unwrap();
        let frame: Vec<u8> = (0..8258).map(|i| (i % 251) as u8).collect();
        for _ in 0..256 {
            stream.write_all(&frame).unwrap();
        }
        let mut expected = frame.repeat(256);
        if window == 1024 {
            let bulk = vec![0xa5; 1024 * 1024];
            stream.write_all(&bulk).unwrap();
            expected.extend_from_slice(&bulk);
            let batched_packets: usize = burst_packets.lock().unwrap().iter().sum();
            assert!(
                batched_packets * (49152 - 37) >= bulk.len() * 4 / 5,
                "ready ACKs failed to fill USB bursts"
            );
        }
        assert_eq!(mux_output(&output, 12345).into_inner(), expected);
        let mut sequence = 1u32;
        let mut packets = 0;
        for bytes in output.lock().unwrap().iter().skip(2) {
            let p = mux::decode_packet(bytes, 2).unwrap();
            if p.protocol == 6 && p.payload.len() > 20 {
                assert_eq!(
                    u32::from_be_bytes(p.payload[4..8].try_into().unwrap()),
                    sequence
                );
                let n = p.payload.len() - 20;
                assert!(n <= 49152 - 37 && n <= usize::from(window) * 256);
                sequence += n as u32;
                packets += 1;
            }
        }
        if window == 1024 {
            assert!(
                packets <= 300,
                "queued ACKs caused {packets} fragmented writes"
            );
        }
    }
}

#[test]
fn mux_batched_write_all_stops_on_partial_failure_or_cancellation_without_replay() {
    struct FaultUsb {
        packets: VecDeque<Vec<u8>>,
        attempts: Arc<Mutex<Vec<u32>>>,
        cancel: Arc<Mutex<std::sync::Weak<Session>>>,
        cancel_first: bool,
    }
    impl PacketTransport for FaultUsb {
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            Ok(self.packets.pop_front().unwrap())
        }
        fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
            if let Ok(p) = mux::decode_packet(bytes, 2)
                && p.protocol == 6
                && p.payload.len() > 20
            {
                let mut attempts = self.attempts.lock().unwrap();
                attempts.push(u32::from_be_bytes(p.payload[4..8].try_into().unwrap()));
                if self.cancel_first {
                    self.cancel.lock().unwrap().upgrade().unwrap().cancel();
                } else if attempts.len() == 2 {
                    anyhow::bail!("injected second packet failure");
                }
            }
            Ok(())
        }
    }
    for cancel_first in [false, true] {
        let attempts = Arc::new(Mutex::new(vec![]));
        let cancel = Arc::new(Mutex::new(std::sync::Weak::new()));
        let session = Arc::new(
            Session::new(FaultUsb {
                packets: VecDeque::from([version_packet(), tcp(12345, 1, 0, 1, 0x12, &[])]),
                attempts: attempts.clone(),
                cancel: cancel.clone(),
                cancel_first,
            })
            .unwrap(),
        );
        *cancel.lock().unwrap() = Arc::downgrade(&session);
        let mut stream = session.connect(12345).unwrap();
        let error = stream.write_all(&vec![0xa5; 131092]).unwrap_err();
        if cancel_first {
            assert!(error.to_string().contains("cancelled"));
            assert_eq!(*attempts.lock().unwrap(), vec![1]);
        } else {
            assert!(error.to_string().contains("injected second packet failure"));
            assert_eq!(*attempts.lock().unwrap(), vec![1, 49116]);
        }
        let before = attempts.lock().unwrap().clone();
        assert!(stream.write_all(b"must not replay a failed burst").is_err());
        assert_eq!(*attempts.lock().unwrap(), before);
    }
}

#[test]
fn mux_submits_bounded_bursts_with_individual_frames_and_continuous_sequences() {
    struct BurstUsb {
        usb: MockMux,
        bursts: Arc<Mutex<Vec<Vec<usize>>>>,
    }
    impl PacketTransport for BurstUsb {
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            self.usb.read_packet()
        }
        fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
            self.usb.write_packet(bytes)
        }
        fn write_packets(
            &mut self,
            packets: &[Vec<u8>],
            cancelled: &std::sync::atomic::AtomicBool,
        ) -> Result<()> {
            assert!(!cancelled.load(std::sync::atomic::Ordering::Acquire));
            self.bursts
                .lock()
                .unwrap()
                .push(packets.iter().map(Vec::len).collect());
            for packet in packets {
                self.write_packet(packet)?;
            }
            Ok(())
        }
    }
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(12345, 1, 0, 1, 0x12, &[]),
        tcp(12345, 1, 1, 245576, 0x10, &[]),
    ]);
    let bursts = Arc::new(Mutex::new(vec![]));
    let session = Session::new(BurstUsb {
        usb,
        bursts: bursts.clone(),
    })
    .unwrap();
    let mut stream = session.connect(12345).unwrap();
    let data: Vec<u8> = (0..400_000).map(|i| (i % 251) as u8).collect();
    stream.write_all(&data).unwrap();
    stream.write_all(b"tail").unwrap();
    let mut expected = data.clone();
    expected.extend_from_slice(b"tail");
    assert_eq!(mux_output(&output, 12345).into_inner(), expected);
    for burst in bursts.lock().unwrap().iter() {
        assert!(burst.len() > 1 && burst.len() <= 6);
        assert!(burst.iter().all(|&size| size <= 49151));
        assert!(burst[..burst.len() - 1].iter().all(|&size| size == 49151));
        assert!(burst.iter().map(|size| size - 36).sum::<usize>() <= 256 * 1024);
    }
    assert_eq!(bursts.lock().unwrap().len(), 2);
    let sent = output.lock().unwrap();
    let mut sequence = 1u32;
    for (index, bytes) in sent.iter().skip(1).enumerate() {
        assert_eq!(
            u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
            index as u16
        );
        let packet = mux::decode_packet(bytes, 2).unwrap();
        if packet.protocol == 6 && packet.payload.len() > 20 {
            assert_eq!(
                u32::from_be_bytes(packet.payload[4..8].try_into().unwrap()),
                sequence
            );
            sequence += (packet.payload.len() - 20) as u32;
        }
    }
    assert_eq!(sequence, expected.len() as u32 + 1);
}

#[test]
fn mux_reset_refuses_connection_and_bad_frames_fail() {
    let (usb, _) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 0, 4, &[])]);
    let session = Session::new(usb).unwrap();
    assert!(session.connect(62078).is_err());
    let mut bad = test_mux::encode_packet(6, 2, 0, 0, &[0; 20]).unwrap();
    bad[8] = 0;
    assert!(mux::decode_packet(&bad, 2).is_err());
    assert!(mux::decode_packet(&bad[..4], 2).is_err());
}

#[test]
fn mux_retries_explicit_service_refusal_but_not_bad_handshakes() {
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(12345, 1, 0, 0, 4, &[]),
        tcp(12345, 2, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut stream = session
        .connect_retry(12345, Duration::from_secs(2))
        .unwrap();
    stream.write_all(b"image").unwrap();
    let syns = output
        .lock()
        .unwrap()
        .iter()
        .skip(2)
        .filter(|bytes| {
            let packet = mux::decode_packet(bytes, 2).unwrap();
            packet.protocol == 6 && packet.payload[13] == 2
        })
        .count();
    assert_eq!(syns, 2);
    let (usb, output) = mock_mux(vec![version_packet(), tcp(12345, 1, 0, 9, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let error = session
        .connect_retry(12345, Duration::from_secs(2))
        .err()
        .unwrap();
    assert!(error.to_string().contains("invalid mux TCP handshake"));
    assert_eq!(output.lock().unwrap().len(), 3); // version, setup, SYN; corrupt session sends no RST
    assert!(session.connect(12345).is_err());
}

#[test]
fn mux_retry_timeout_cleans_up_the_failed_channel() {
    let (input, incoming) = mpsc::channel();
    let (output, _outgoing) = mpsc::channel();
    input.send(version_packet()).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    assert!(
        session
            .connect_retry(12345, Duration::from_millis(20))
            .is_err()
    );
    input.send(tcp(12345, 2, 0, 1, 0x12, &[])).unwrap();
    assert!(session.connect(12345).is_ok());
}

#[test]
fn mux_routes_other_channels_while_reading_and_honors_cancellation() {
    let (usb, _) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        tcp(1082, 2, 0, 1, 0x12, &[]),
        tcp(1082, 2, 1, 1, 0x10, b"FDR"),
        tcp(62078, 1, 1, 1, 0x10, b"OK"),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let mut fdr = session.connect(1082).unwrap();
    let mut b = [0; 2];
    main.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"OK");
    let mut b = [0; 3];
    fdr.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"FDR");
    session.cancel();
    assert!(main.write_all(b"no").is_err());
    assert!(main.read(&mut b).is_err());
}

#[test]
fn pending_mux_connection_allows_other_writes_and_session_cancellation() {
    let (input, incoming) = mpsc::channel();
    let (output, outgoing) = mpsc::channel();
    input.send(version_packet()).unwrap();
    input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    let mut main = session.connect(62078).unwrap();
    while outgoing.try_recv().is_ok() {}
    let pending_session = session.clone();
    let pending = std::thread::spawn(move || pending_session.connect(1082).is_err());
    let syn = outgoing.recv_timeout(Duration::from_secs(2));
    let (done_tx, done_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = main.write_all(b"request");
        let _ = done_tx.send(result.is_ok());
    });
    let written = done_rx.recv_timeout(Duration::from_secs(2));
    // A pending connect must neither starve the writer nor block cancellation.
    session.cancel();
    writer.join().unwrap();
    let cancelled = pending.join().unwrap();
    assert!(syn.is_ok());
    assert_eq!(written, Ok(true));
    assert!(cancelled);
    assert!(outgoing.try_iter().any(|bytes| {
        let packet = mux::decode_packet(&bytes, 2).unwrap();
        packet.protocol == 6 && packet.payload.get(20..) == Some(b"request".as_slice())
    }));
}

#[test]
fn mux_single_packet_failure_prevents_reuse_by_any_channel() {
    struct FaultUsb(MockMux);
    impl PacketTransport for FaultUsb {
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            self.0.read_packet()
        }
        fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
            // Record the bytes before reporting failure, as a USB completion can
            // fail after the device has already received part or all of a frame.
            self.0.write_packet(bytes)?;
            if let Ok(packet) = mux::decode_packet(bytes, 2)
                && packet.protocol == 6
                && packet.payload.len() > 20
            {
                anyhow::bail!("injected uncertain USB completion");
            }
            Ok(())
        }
    }
    for write_all in [false, true] {
        let (usb, output) = mock_mux(vec![
            version_packet(),
            tcp(12345, 1, 0, 1, 0x12, &[]),
            tcp(54321, 2, 0, 1, 0x12, &[]),
        ]);
        let session = Session::new(FaultUsb(usb)).unwrap();
        let mut first = session.connect(12345).unwrap();
        let mut second = session.connect(54321).unwrap();
        let error = if write_all {
            first.write_all(b"payload").unwrap_err()
        } else {
            first.write(b"payload").unwrap_err()
        };
        assert!(
            error
                .to_string()
                .contains("injected uncertain USB completion")
        );
        let sent = output.lock().unwrap().len();
        assert!(first.write(b"retry").is_err());
        assert!(second.write(b"different channel").is_err());
        assert!(session.connect(1000).is_err());
        drop(first);
        drop(second);
        assert_eq!(output.lock().unwrap().len(), sent);
        assert!(
            !session.disconnected(),
            "a write failure is not device removal"
        );
    }
}
