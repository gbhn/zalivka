use super::*;

fn frame(value: &Value) -> Vec<u8> {
    let mut body = vec![];
    value.to_writer_binary(&mut body).unwrap();
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend(body);
    bytes
}

#[test]
fn stopped_fdr_does_not_cancel_the_main_channels_final_response() {
    let (input, incoming) = mpsc::channel();
    let (output, _outgoing) = mpsc::channel();
    let framed = frame(&wire::dict([("ConnPort", 45678u64.into())]));
    input.send(version_packet()).unwrap();
    input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 2, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 2, 1, 1, 0x10, &framed)).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    let mut main = session.connect(62078).unwrap();
    let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
    fdr.stop();
    input
        .send(tcp(1082, 2, framed.len() as u32 + 1, 1, 0x14, &[]))
        .unwrap();
    main.write_all(b"ack").unwrap();
    input.send(tcp(62078, 1, 1, 4, 0x10, b"OK")).unwrap();
    let mut response = [0; 2];
    main.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"OK");
    fdr.check().unwrap();
}

#[test]
fn fdr_proxy_answers_short_socks_greeting_before_waiting_for_connect() {
    let (input, incoming) = mpsc::channel();
    let (output, outgoing) = mpsc::channel();
    let port = 45678u16;
    let mut control = frame(&wire::dict([("ConnPort", u64::from(port).into())]));
    control.extend([1, 0, 0, 0]);
    input.send(version_packet()).unwrap();
    input.send(tcp(1082, 1, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 1, 1, 1, 0x10, &control)).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
    let hello = frame(&wire::dict([("Command", "HelloConn".into())]));
    let mut response = vec![];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline && response.len() < 2 {
        let Ok(bytes) = outgoing.recv_timeout(Duration::from_millis(100)) else {
            continue;
        };
        if let Ok(packet) = mux::decode_packet(&bytes, 2)
            && packet.protocol == 6
            && packet.payload[2..4] == port.to_be_bytes()
        {
            if packet.payload[13] == 2 {
                input.send(tcp(port, 2, 0, 1, 0x12, &[])).unwrap();
            }
            let data = &packet.payload[20..];
            if data == b"HelloConn\0" {
                input.send(tcp(port, 2, 1, 1, 0x10, &hello)).unwrap();
                // A SOCKS client sends CONNECT only after receiving 05 00.
                // Fragment the greeting: USB reads are not message boundaries.
                for (i, byte) in [5, 1, 0].into_iter().enumerate() {
                    input
                        .send(tcp(
                            port,
                            2,
                            hello.len() as u32 + 1 + i as u32,
                            1,
                            0x10,
                            &[byte],
                        ))
                        .unwrap();
                }
            } else {
                response.extend_from_slice(data);
            }
        }
    }
    let result = fdr.check();
    drop(fdr);
    result.unwrap();
    assert_eq!(
        response,
        [5, 0],
        "CONNECT must not be needed to acknowledge the greeting"
    );
}

#[test]
fn fdr_child_closure_and_errors_preserve_main_channel_and_device_failure_status() {
    // Cover EOF before a command, truncated command/header, bad handshake,
    // and a refused child connection. None may cancel restored's channel.
    for case in 0..5 {
        let (input, incoming) = mpsc::channel();
        let (output, outgoing) = mpsc::channel();
        let port = 45678u16;
        let mut control = frame(&wire::dict([("ConnPort", u64::from(port).into())]));
        control.extend([1, 0, 0, 0]);
        input.send(version_packet()).unwrap();
        input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
        input.send(tcp(1082, 2, 0, 1, 0x12, &[])).unwrap();
        input.send(tcp(1082, 2, 1, 1, 0x10, &control)).unwrap();
        let session = Session::new(LiveMux {
            input: incoming,
            output,
        })
        .unwrap();
        let mut main = session.connect(62078).unwrap();
        let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
        // Device responses must follow a real host SYN/HelloConn, so another
        // worker cannot consume replies for a channel that does not exist yet.
        loop {
            let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
            if let Ok(packet) = mux::decode_packet(&bytes, 2)
                && packet.protocol == 6
                && packet.payload[2..4] == port.to_be_bytes()
                && packet.payload[13] == 2
            {
                input
                    .send(tcp(port, 3, 0, 1, if case == 4 { 4 } else { 0x12 }, &[]))
                    .unwrap();
                break;
            }
        }
        if case != 4 {
            loop {
                let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
                if let Ok(packet) = mux::decode_packet(&bytes, 2)
                    && packet.protocol == 6
                    && packet.payload[2..4] == port.to_be_bytes()
                    && packet.payload.get(20..) == Some(b"HelloConn\0".as_slice())
                {
                    break;
                }
            }
            let mut data = frame(&wire::dict([(
                "Command",
                if case == 3 { "Invalid" } else { "HelloConn" }.into(),
            )]));
            if case == 1 {
                data.push(0xaa); // Only half of the two-byte command.
            } else if case == 2 {
                data.extend(0x105u16.to_le_bytes());
                data.push(0); // Proxy header stops before address type/length.
            }
            input.send(tcp(port, 3, 1, 1, 0x10, &data)).unwrap();
            input
                .send(tcp(port, 3, data.len() as u32 + 1, 1, 4, &[]))
                .unwrap();
        }
        // Wait until the child is actually torn down, rather than racing the
        // error handler by checking Fdr immediately after it starts.
        loop {
            let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
            if let Ok(packet) = mux::decode_packet(&bytes, 2)
                && packet.protocol == 6
                && packet.payload[2..4] == port.to_be_bytes()
                && packet.payload[13] & 4 != 0
            {
                break;
            }
        }
        let status = wire::dict([
            ("MsgType", "StatusMsg".into()),
            ("Status", 10u64.into()),
            ("AMRError", 10u64.into()),
            ("Log", "device failure after FDR connection closed".into()),
        ]);
        let mut bytes = vec![];
        wire::send(&mut bytes, &status).unwrap();
        input.send(tcp(62078, 1, 1, 1, 0x10, &bytes)).unwrap();
        fdr.check().unwrap();
        assert_eq!(wire::receive(&mut main).unwrap(), status, "case {case}");
        fdr.check().unwrap();
        let error = restore::validate_final_status(&status).unwrap_err();
        assert!(error.to_string().contains("device failure after FDR"));
        main.write_all(b"ack").unwrap();
        fdr.stop();
    }
}

#[test]
fn fdr_command_boundary_eof_is_local_but_truncated_control_remains_fatal() {
    for tail in [&[][..], &[1][..], &[1, 0][..]] {
        let (input, incoming) = mpsc::channel();
        let (output, outgoing) = mpsc::channel();
        let mut control = frame(&wire::dict([("ConnPort", 45678u64.into())]));
        control.extend(tail);
        input.send(version_packet()).unwrap();
        input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
        input.send(tcp(1082, 2, 0, 1, 0x12, &[])).unwrap();
        input.send(tcp(1082, 2, 1, 1, 0x10, &control)).unwrap();
        input
            .send(tcp(1082, 2, control.len() as u32 + 1, 1, 4, &[]))
            .unwrap();
        let session = Session::new(LiveMux {
            input: incoming,
            output,
        })
        .unwrap();
        let mut main = session.connect(62078).unwrap();
        let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
        if tail.is_empty() {
            loop {
                let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
                if let Ok(packet) = mux::decode_packet(&bytes, 2)
                    && packet.protocol == 6
                    && packet.payload[2..4] == 1082u16.to_be_bytes()
                    && packet.payload[13] & 4 != 0
                {
                    break;
                }
            }
            fdr.check().unwrap();
            main.write_all(b"continue").unwrap();
        } else {
            main.set_read_timeout(Duration::from_secs(3));
            let cancelled = main.read(&mut [0]).unwrap_err();
            assert!(cancelled.to_string().contains("cancelled"));
            let error = fdr.check().unwrap_err();
            assert!(error.to_string().contains("FDR control failed"));
            assert!(main.write_all(b"continue").is_err());
        }
    }
}

#[test]
fn fdr_sync_waits_for_hello_before_connecting_the_next_child() {
    let (input, incoming) = mpsc::channel();
    let (output, outgoing) = mpsc::channel();
    let port = 45678u16;
    let mut control = frame(&wire::dict([("ConnPort", u64::from(port).into())]));
    control.extend([1, 0, 0, 0, 1, 0, 0, 0]); // Two Sync requests arrive together.
    input.send(version_packet()).unwrap();
    input.send(tcp(1082, 1, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 1, 1, 1, 0x10, &control)).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
    let mut hello = frame(&wire::dict([("Command", "HelloConn".into())]));
    hello.extend(0xbbaau16.to_le_bytes());
    hello.extend(frame(&wire::dict([("Command", "Ping".into())])));
    let mut next = 2u16;
    let mut pongs = 0;
    let expected_pong = [
        b"HelloConn\0".as_slice(),
        &frame(&wire::dict([("Pong", true.into())])),
    ]
    .concat();
    let mut replies = [Vec::new(), Vec::new()];
    while next < 4 || pongs < 2 {
        let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
        let Ok(packet) = mux::decode_packet(&bytes, 2) else {
            continue;
        };
        if packet.protocol != 6 || packet.payload[2..4] != port.to_be_bytes() {
            continue;
        }
        let source = u16::from_be_bytes(packet.payload[..2].try_into().unwrap());
        if packet.payload[13] == 2 {
            assert_eq!(source, next);
            input.send(tcp(port, source, 0, 1, 0x12, &[])).unwrap();
        }
        if packet.payload.get(20..) == Some(b"HelloConn\0".as_slice()) {
            assert_eq!(source, next);
            if source == 2 {
                // Hold back the first HelloConn reply. A second child SYN now
                // would prove that the Sync handshakes are being reordered.
                let until = std::time::Instant::now() + Duration::from_millis(80);
                while std::time::Instant::now() < until {
                    let Ok(b) = outgoing.recv_timeout(Duration::from_millis(10)) else {
                        continue;
                    };
                    if let Ok(p) = mux::decode_packet(&b, 2)
                        && p.protocol == 6
                        && p.payload[2..4] == port.to_be_bytes()
                    {
                        assert_ne!(
                            p.payload[13], 2,
                            "second Sync connected before first HelloConn reply"
                        );
                    }
                }
            }
            input.send(tcp(port, source, 1, 1, 0x10, &hello)).unwrap();
            next += 1;
        }
        if packet.payload.len() > 20 {
            let reply = &mut replies[usize::from(source - 2)];
            reply.extend_from_slice(&packet.payload[20..]);
            if reply == &expected_pong {
                pongs += 1;
            }
        }
    }
    fdr.check().unwrap();
    fdr.stop();
}

#[test]
fn fdr_v2_and_v1_fallback_open_sync_channels_and_answer_ping() {
    for version in [2, 1] {
        let (input, incoming) = mpsc::channel();
        let (output, outgoing) = mpsc::channel();
        input.send(version_packet()).unwrap();
        input.send(tcp(1082, 1, 0, 1, 0x12, &[])).unwrap();
        let control = if version == 1 {
            input.send(tcp(1082, 1, 1, 1, 4, &[])).unwrap();
            input.send(tcp(1082, 2, 0, 1, 0x12, &[])).unwrap();
            2
        } else {
            1
        };
        // A zero low byte in the port must not be mistaken for an extra NUL.
        let port = 0x4300u16;
        let mut response = if version == 2 {
            frame(&wire::dict([("ConnPort", u64::from(port).into())]))
        } else {
            let mut bytes = b"HelloCtrl\0".to_vec();
            bytes.extend(port.to_le_bytes());
            bytes
        };
        response.extend([1, 0, 0, 0]); // Sync command, then its two reserved bytes.
        input
            .send(tcp(1082, control, 1, 1, 0x10, &response))
            .unwrap();
        let mut hello = if version == 2 {
            frame(&wire::dict([("Command", "HelloConn".into())]))
        } else {
            b"HelloConn\0".to_vec()
        };
        hello.extend(0xbbaau16.to_le_bytes());
        hello.extend(frame(&wire::dict([("Command", "Ping".into())])));
        hello.extend(0xbbaau16.to_le_bytes());
        hello.extend(frame(&wire::dict([("Command", "Ping".into())])));
        let session = Session::new(LiveMux {
            input: incoming,
            output,
        })
        .unwrap();
        let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
        let mut payload = vec![];
        let expected = [
            b"HelloConn\0".as_slice(),
            &frame(&wire::dict([("Pong", true.into())])),
            &frame(&wire::dict([("Pong", true.into())])),
        ]
        .concat();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while payload.len() < expected.len() && std::time::Instant::now() < deadline {
            let Ok(bytes) = outgoing.recv_timeout(Duration::from_millis(100)) else {
                continue;
            };
            if let Ok(packet) = mux::decode_packet(&bytes, 2)
                && packet.protocol == 6
                && packet.payload.len() >= 20
                && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == port
            {
                if packet.payload[13] == 2 {
                    input.send(tcp(port, control + 1, 0, 1, 0x12, &[])).unwrap();
                }
                if packet.payload.get(20..) == Some(b"HelloConn\0".as_slice()) {
                    input
                        .send(tcp(port, control + 1, 1, 1, 0x10, &hello))
                        .unwrap();
                }
                payload.extend_from_slice(&packet.payload[20..]);
            }
        }
        let result = fdr.check();
        drop(fdr);
        result.unwrap();
        assert_eq!(payload, expected, "FDR version {version}");
    }
}

#[test]
fn closing_fdr_control_retires_idle_children_without_cancelling_restored() {
    let (input, incoming) = mpsc::channel();
    let (output, outgoing) = mpsc::channel();
    let port = 45678u16;
    let mut control = frame(&wire::dict([("ConnPort", u64::from(port).into())]));
    control.extend([1, 0, 0, 0]);
    input.send(version_packet()).unwrap();
    input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 2, 0, 1, 0x12, &[])).unwrap();
    input.send(tcp(1082, 2, 1, 1, 0x10, &control)).unwrap();
    let session = Session::new(LiveMux {
        input: incoming,
        output,
    })
    .unwrap();
    let mut main = session.connect(62078).unwrap();
    let fdr = zalivka::fdr::Fdr::start(&session).unwrap();
    loop {
        let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
        let Ok(packet) = mux::decode_packet(&bytes, 2) else {
            continue;
        };
        if packet.protocol != 6 || packet.payload[2..4] != port.to_be_bytes() {
            continue;
        }
        if packet.payload[13] == 2 {
            input.send(tcp(port, 3, 0, 1, 0x12, &[])).unwrap();
        }
        if packet.payload.get(20..) == Some(b"HelloConn\0".as_slice()) {
            let hello = frame(&wire::dict([("Command", "HelloConn".into())]));
            input.send(tcp(port, 3, 1, 1, 0x10, &hello)).unwrap();
            input
                .send(tcp(1082, 2, control.len() as u32 + 1, 1, 4, &[]))
                .unwrap();
            break;
        }
    }
    loop {
        let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
        if let Ok(packet) = mux::decode_packet(&bytes, 2)
            && packet.protocol == 6
            && packet.payload[2..4] == port.to_be_bytes()
            && packet.payload[13] & 4 != 0
        {
            break;
        }
    }
    fdr.check().unwrap();
    main.write_all(b"restored remains available").unwrap();
}
