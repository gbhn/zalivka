use super::*;

#[test]
fn asr_oob_and_checksummed_payload_work_with_fragmentation() {
    let image = vec![0xa5; 131079];
    let commands = [
        wire::dict([
            ("Command", "Initiate".into()),
            ("Checksum Chunks", true.into()),
        ]),
        wire::dict([
            ("Command", "OOBData".into()),
            ("OOB Offset", 131070u64.into()),
            ("OOB Length", 7u64.into()),
        ]),
        wire::dict([("Command", "Payload".into())]),
    ];
    let incoming = commands
        .iter()
        .flat_map(|c| wire::xml(c).unwrap())
        .collect();
    let mut stream = Duplex::new(incoming, 3);
    asr::transfer(&mut stream, &mut Cursor::new(&image), image.len() as u64).unwrap();
    let end = stream
        .output
        .windows(8)
        .position(|w| w == b"</plist>")
        .unwrap()
        + 8;
    let output = &stream.output[end..];
    assert_eq!(&output[..7], &image[131070..131077]);
    assert_eq!(output.len(), 7 + image.len() + 40);
    assert_eq!(
        &output[7 + 131072..7 + 131072 + 20],
        sha1::Sha1::digest(&image[..131072]).as_slice()
    );
    assert_eq!(
        &output[output.len() - 20..],
        sha1::Sha1::digest(&image[131072..]).as_slice()
    );
}

#[test]
fn asr_keeps_checksums_in_payload_packets_instead_of_tiny_mux_writes() {
    let image: Vec<u8> = (0..131079).map(|i| (i % 251) as u8).collect();
    let commands = [
        wire::dict([
            ("Command", "Initiate".into()),
            ("Checksum Chunks", true.into()),
        ]),
        wire::dict([("Command", "Payload".into())]),
    ];
    let incoming: Vec<u8> = commands
        .iter()
        .flat_map(|m| wire::xml(m).unwrap())
        .collect();
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(12345, 1, 0, 1, 0x12, &[]),
        tcp(12345, 1, 1, 1, 0x10, &incoming),
    ]);
    let session = Session::new(usb).unwrap();
    let mut stream = session.connect(12345).unwrap();
    asr::transfer(&mut stream, &mut Cursor::new(&image), image.len() as u64).unwrap();
    let mut sent = mux_output(&output, 12345);
    wire::receive_xml(&mut sent).unwrap();
    let mut expected = image[..131072].to_vec();
    expected.extend(sha1::Sha1::digest(&image[..131072]));
    expected.extend(&image[131072..]);
    expected.extend(sha1::Sha1::digest(&image[131072..]));
    let mut payload = vec![];
    sent.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, expected);
    let frames: Vec<_> = output
        .lock()
        .unwrap()
        .iter()
        .skip(2)
        .filter_map(|b| {
            let p = mux::decode_packet(b, 2).unwrap();
            (p.protocol == 6 && p.payload.len() > 20).then_some(p.payload.len() - 20)
        })
        .collect();
    // One XML response and three packets spanning both checksum blocks.
    assert_eq!(frames.len(), 4);
    assert!(!frames.contains(&20));
}

#[test]
fn asr_batches_keep_every_checksum_boundary_and_final_partial_block() {
    for checksum in [false, true] {
        for size in [0, 131072 - 1, 131072, 4 * 131072, 5 * 131072 + 17] {
            let image: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let incoming: Vec<u8> = [
                wire::dict([
                    ("Command", "Initiate".into()),
                    ("Checksum Chunks", checksum.into()),
                ]),
                wire::dict([("Command", "Payload".into())]),
            ]
            .iter()
            .flat_map(|m| wire::xml(m).unwrap())
            .collect();
            let mut stream = Duplex::new(incoming, 3);
            asr::transfer(&mut stream, &mut Cursor::new(&image), size as u64).unwrap();
            let mut sent = Cursor::new(&stream.output);
            wire::receive_xml(&mut sent).unwrap();
            let mut payload = vec![];
            sent.read_to_end(&mut payload).unwrap();
            let mut expected = vec![];
            for block in image.chunks(131072) {
                expected.extend_from_slice(block);
                if checksum {
                    expected.extend(sha1::Sha1::digest(block));
                }
            }
            assert_eq!(payload, expected, "size={size}, checksum={checksum}");
        }
    }
}

#[test]
fn asr_rejects_out_of_bounds_oob_before_sending_image() {
    let messages = [
        wire::dict([("Command", "Initiate".into())]),
        wire::dict([
            ("Command", "OOBData".into()),
            ("OOB Offset", u64::MAX.into()),
            ("OOB Length", 2u64.into()),
        ]),
    ];
    let mut stream = Duplex::new(
        messages
            .iter()
            .flat_map(|c| wire::xml(c).unwrap())
            .collect(),
        512,
    );
    assert!(asr::transfer(&mut stream, &mut Cursor::new(vec![1; 10]), 10).is_err());
}

#[test]
fn asr_repeated_initiate_preserves_or_updates_checksum_mode() {
    let image = vec![0xa5; 33];
    for change in [None, Some(false), Some(true)] {
        let first = wire::dict([
            ("Command", "Initiate".into()),
            ("Checksum Chunks", true.into()),
        ]);
        let mut second = wire::dict([("Command", "Initiate".into())]);
        if let Some(mode) = change {
            second
                .as_dictionary_mut()
                .unwrap()
                .insert("Checksum Chunks".into(), mode.into());
        }
        let messages = [first, second, wire::dict([("Command", "Payload".into())])];
        let mut stream = Duplex::new(
            messages
                .iter()
                .flat_map(|m| wire::xml(m).unwrap())
                .collect(),
            1,
        );
        asr::transfer(&mut stream, &mut Cursor::new(&image), image.len() as u64).unwrap();
        let mut output = Cursor::new(stream.output);
        let first = wire::receive_xml(&mut output).unwrap();
        assert!(wire::get(&first, &["Checksum Chunk Size"]).is_ok());
        let second = wire::receive_xml(&mut output).unwrap();
        let checksum = change.unwrap_or(true);
        assert_eq!(
            wire::get(&second, &["Checksum Chunk Size"]).is_ok(),
            checksum
        );
        let mut payload = vec![];
        output.read_to_end(&mut payload).unwrap();
        assert!(payload.starts_with(&image));
        assert_eq!(payload.len(), image.len() + if checksum { 20 } else { 0 });
        if checksum {
            assert_eq!(
                &payload[image.len()..],
                sha1::Sha1::digest(&image).as_slice()
            );
        }
    }
}

#[test]
fn asr_uses_default_for_zero_port_and_rejects_invalid_port() {
    assert_eq!(
        wire::data_port(&wire::dict([("DataPort", 0u64.into())]), 12345).unwrap(),
        12345
    );
    assert_eq!(
        wire::data_port(&wire::dict([("DataPort", 4567u64.into())]), 12345).unwrap(),
        4567
    );
    assert!(wire::data_port(&wire::dict([("DataPort", 65536u64.into())]), 12345).is_err());
}

#[test]
fn asr_flushes_each_reply_before_waiting_for_another_command() {
    struct BufferedDuplex {
        input: VecDeque<Vec<u8>>,
        pending: Vec<u8>,
        flushed: Vec<Vec<u8>>,
    }
    impl Read for BufferedDuplex {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                self.pending.is_empty(),
                "ASR waited with an unflushed reply"
            );
            let Some(command) = self.input.front_mut() else {
                return Ok(0);
            };
            let n = out.len().min(command.len());
            out[..n].copy_from_slice(&command[..n]);
            command.drain(..n);
            if command.is_empty() {
                self.input.pop_front();
            }
            Ok(n)
        }
    }
    impl Write for BufferedDuplex {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.pending.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed.push(std::mem::take(&mut self.pending));
            Ok(())
        }
    }
    let commands = [
        wire::dict([("Command", "Initiate".into())]),
        wire::dict([
            ("Command", "OOBData".into()),
            ("OOB Offset", 1u64.into()),
            ("OOB Length", 2u64.into()),
        ]),
        wire::dict([("Command", "Payload".into())]),
    ];
    let mut stream = BufferedDuplex {
        input: commands
            .iter()
            .map(|message| wire::xml(message).unwrap())
            .collect(),
        pending: vec![],
        flushed: vec![],
    };
    asr::transfer(&mut stream, &mut Cursor::new(b"image"), 5).unwrap();
    assert_eq!(stream.flushed[1], b"ma");
    assert_eq!(stream.flushed[2], b"image");
}
