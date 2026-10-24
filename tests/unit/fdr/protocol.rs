use super::*;
use std::{
    collections::VecDeque,
    io::{self, Cursor},
};

#[test]
fn idle_control_preserves_partial_command_and_can_stop() {
    struct Input(VecDeque<io::Result<Vec<u8>>>);
    impl Read for Input {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let data = self.0.pop_front().unwrap()?;
            bytes[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }
    }
    let mut input = Input(VecDeque::from([
        Ok(vec![1]),
        Err(io::ErrorKind::TimedOut.into()),
        Err(io::ErrorKind::Interrupted.into()),
        Ok(vec![0]),
    ]));
    let stop = AtomicBool::new(false);
    let mut command = [0xff; 2];
    assert!(read_exact_idle(&mut input, &mut command, &stop).unwrap());
    assert_eq!(command, [1, 0]);
    assert_eq!(
        read_exact_idle(&mut Cursor::new([1]), &mut command, &stop)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(!read_exact_idle(&mut Cursor::new([]), &mut command, &stop).unwrap());

    struct StopOnRead<'a>(&'a AtomicBool);
    impl Read for StopOnRead<'_> {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.store(true, Ordering::Relaxed);
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    assert!(!read_exact_idle(&mut StopOnRead(&stop), &mut command, &stop).unwrap());
}

#[test]
fn fdr_frames_use_binary_plist_and_little_endian_lengths() {
    struct Output {
        bytes: Vec<u8>,
        limit: usize,
        writes: usize,
        flushes: usize,
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let n = bytes.len().min(self.limit);
            self.bytes.extend_from_slice(&bytes[..n]);
            self.writes += 1;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let value = wire::dict([("Command", "HelloConn".into())]);
    for limit in [usize::MAX, 3] {
        let mut out = Output {
            bytes: vec![],
            limit,
            writes: 0,
            flushes: 0,
        };
        wire::send_binary_le(&mut out, &value).unwrap();
        assert_eq!(&out.bytes[4..12], b"bplist00");
        assert_eq!(
            u32::from_le_bytes(out.bytes[..4].try_into().unwrap()) as usize,
            out.bytes.len() - 4
        );
        assert_eq!(out.writes, out.bytes.len().div_ceil(limit));
        assert_eq!(out.flushes, 1);
        assert_eq!(receive(&mut Cursor::new(out.bytes)).unwrap(), value);
    }
    assert!(receive(&mut Cursor::new(0u32.to_le_bytes())).is_err());
    assert!(receive(&mut Cursor::new(u32::MAX.to_le_bytes())).is_err());
}

struct ProxyPeer {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    greeting: bool,
}
impl Read for ProxyPeer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // Model a client that will not send more until it receives ACK.
        if self.greeting && self.input.position() == 1 {
            assert_eq!(self.output, [5, 0]);
        }
        self.input.read(&mut bytes[..1])
    }
}
impl Write for ProxyPeer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn proxy_handshake_accepts_greeting_and_direct_connect_with_fragmented_bytes() {
    for greeting in [false, true] {
        let host = b"tbsc.apple.com";
        let mut address = vec![0, 3, host.len() as u8];
        address.extend(host);
        address.extend(443u16.to_be_bytes());
        // handle_connection has already consumed the first 05 01.
        let mut input = if greeting { vec![0, 5, 1] } else { vec![] };
        input.extend_from_slice(&address);
        input.extend(b"TLS payload must not be read as part of CONNECT");
        let mut peer = ProxyPeer {
            input: Cursor::new(input),
            output: vec![],
            greeting,
        };
        assert_eq!(
            proxy_handshake(&mut peer).unwrap(),
            ("tbsc.apple.com".into(), 443)
        );
        let mut expected = if greeting {
            vec![5, 0, 5, 0]
        } else {
            vec![5, 0]
        };
        expected.extend(&address);
        assert_eq!(peer.output, expected);
        assert_eq!(
            peer.input.position() as usize,
            address.len() + if greeting { 3 } else { 0 }
        );
    }
}

#[test]
fn proxy_handshake_rejects_invalid_and_truncated_requests_before_echoing_an_address() {
    let mut invalid = vec![
        vec![],
        vec![2],
        vec![0],
        vec![0, 5],
        vec![0, 5, 1],
        vec![0, 5, 1, 2],
        vec![0, 1, 4],
        vec![0, 3, 0],
        vec![0, 3, 8, b'a'],
    ];
    for (host, port) in [("localhost", 443u16), ("tbsc.apple.com", 22u16)] {
        let mut bytes = vec![0, 3, host.len() as u8];
        bytes.extend(host.as_bytes());
        bytes.extend(port.to_be_bytes());
        invalid.push(bytes);
    }
    for input in invalid {
        let mut peer = ProxyPeer {
            input: Cursor::new(input),
            output: vec![],
            greeting: false,
        };
        assert!(proxy_handshake(&mut peer).is_err());
        assert!(peer.output.is_empty() || peer.output == [5, 0]);
    }
}
