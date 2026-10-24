use super::*;

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
