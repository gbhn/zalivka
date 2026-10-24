use super::*;

#[test]
fn unframed_xml_uses_element_boundaries_and_preserves_following_messages_and_binary_data() {
    for xml in [
        &b"<plist><!-- </plist> --><dict><key>Command</key><string>Payload</string></dict></plist>"[..],
        b"<plist><dict><key>Command</key><string>Pay<![CDATA[</plist>]]>load</string></dict></plist>",
        b"<plist><?marker </plist>?><dict><key>Command</key><string>Payload</string></dict></plist>",
        b"<plist><dict><key>Command</key><string>Payload</string></dict></plist >",
        b"<plist><string>&lt;/plist&gt;</string></plist>",
    ] {
        let expected = Value::from_reader_xml(xml).unwrap();
        let next = wire::dict([("next", true.into())]);
        let tail = b"\0\xffraw\r\n</plist>";
        let bytes = [xml, &wire::xml(&next).unwrap(), tail].concat();
        for fragment in [1, 3, 4096] {
            let mut input = std::io::BufReader::with_capacity(128, Duplex::new(bytes.clone(), fragment));
            assert_eq!(wire::receive_xml(&mut input).unwrap(), expected);
            assert_eq!(wire::receive_xml(&mut input).unwrap(), next);
            let mut remaining = Vec::new();
            input.read_to_end(&mut remaining).unwrap();
            assert_eq!(remaining, tail);
        }
    }
}

#[test]
fn unframed_xml_rejects_every_truncated_prefix_and_malformed_document() {
    let xml = b"<plist><dict><key>Command</key><string>Payload</string></dict></plist>";
    for length in 0..xml.len() {
        assert!(
            wire::receive_xml(&mut Cursor::new(&xml[..length])).is_err(),
            "prefix {length}"
        );
    }
    for malformed in [
        &b"<other><plist><dict/></plist></other>"[..],
        b"<plist><dict></array></plist>",
        b"<plist><dict><!-- </plist>",
        b"<plist><string><![CDATA[</plist>",
        b"<plist/>",
    ] {
        assert!(
            wire::receive_xml(&mut Cursor::new(malformed)).is_err(),
            "{malformed:?}"
        );
    }
}

#[test]
fn unframed_xml_reads_buffered_blocks_instead_of_one_byte_at_a_time() {
    struct Input {
        bytes: Cursor<Vec<u8>>,
        reads: usize,
    }
    impl Read for Input {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.bytes.read(out)
        }
    }
    let value = wire::dict([("data", Value::Data(vec![42; 32768]))]);
    let input = Input {
        bytes: Cursor::new(wire::xml(&value).unwrap()),
        reads: 0,
    };
    let mut input = std::io::BufReader::new(input);
    assert_eq!(wire::receive_xml(&mut input).unwrap(), value);
    assert!(input.get_ref().reads < 16);
}

#[test]
fn framed_plists_handle_fragmented_reads() {
    let value = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0u64.into())]);
    let mut bytes = Vec::new();
    wire::send(&mut bytes, &value).unwrap();
    let mut fragmented = Duplex::new(bytes, 1);
    assert_eq!(wire::receive(&mut fragmented).unwrap(), value);
    for bytes in [vec![0xff; 4], vec![0; 4], vec![0, 0, 0, 9, 1, 2, 3]] {
        assert!(wire::receive(&mut Cursor::new(&bytes)).is_err());
        assert!(wire::try_receive(&mut Cursor::new(&bytes)).is_err());
    }
}

#[test]
fn plist_length_and_body_share_one_write_and_still_allow_short_writes() {
    struct Output {
        bytes: Vec<u8>,
        writes: usize,
        limit: usize,
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let n = bytes.len().min(self.limit);
            self.bytes.extend_from_slice(&bytes[..n]);
            self.writes += 1;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let value = wire::dict([
        ("FileData", Value::Data(vec![3; 8192])),
        ("Status", (-1i64).into()),
    ]);
    for binary in [false, true] {
        for limit in [usize::MAX, 7] {
            let mut out = Output {
                bytes: Vec::new(),
                writes: 0,
                limit,
            };
            if binary {
                wire::send_binary(&mut out, &value).unwrap();
            } else {
                wire::send(&mut out, &value).unwrap();
            }
            assert_eq!(
                u32::from_be_bytes(out.bytes[..4].try_into().unwrap()) as usize,
                out.bytes.len() - 4
            );
            if limit == usize::MAX {
                assert_eq!(out.writes, 1);
            } else {
                assert!(out.writes > 1);
            }
            assert_eq!(wire::receive(&mut Cursor::new(out.bytes)).unwrap(), value);
        }
    }
}

#[test]
fn binary_plist_and_optional_frames_preserve_framing() {
    let value = wire::dict([("Data", Value::Data(vec![1, 2, 3]))]);
    let mut bytes = vec![];
    wire::send_binary(&mut bytes, &value).unwrap();
    assert_eq!(&bytes[4..12], b"bplist00");
    assert_eq!(wire::receive(&mut Cursor::new(&bytes)).unwrap(), value);
    assert_eq!(
        wire::try_receive(&mut Cursor::new(bytes)).unwrap(),
        Some(value)
    );
    struct Timeout;
    impl Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))
        }
    }
    assert!(wire::try_receive(&mut Timeout).unwrap().is_none());
    assert!(wire::try_receive(&mut Cursor::new(vec![0, 0])).is_err());
}

#[test]
fn optional_plists_retry_interrupted_reads_and_preserve_partial_frame_timeouts() {
    struct Interrupted {
        input: Cursor<Vec<u8>>,
        interrupt: bool,
    }
    impl Read for Interrupted {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.input.read(&mut out[..1])
        }
    }
    let value = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0u64.into())]);
    let mut bytes = Vec::new();
    wire::send(&mut bytes, &value).unwrap();
    assert_eq!(
        wire::try_receive(&mut Interrupted {
            input: Cursor::new(bytes.clone()),
            interrupt: false,
        })
        .unwrap(),
        Some(value)
    );

    struct Timeout;
    impl Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }
    for received in [0, 1, 2, 3, 4, 8] {
        let mut input = (&bytes[..received]).chain(Timeout);
        let result = wire::try_receive(&mut input);
        if received == 0 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(
                result.is_err(),
                "timeout after {received} bytes was ignored"
            );
        }
    }
}
