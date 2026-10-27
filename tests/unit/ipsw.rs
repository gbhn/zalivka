use super::{STREAM_CHUNK, copy_prefetched};
use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

#[test]
fn prefetch_preserves_short_reads_interruptions_and_final_partial_blocks() {
    struct Fragmented<'a> {
        bytes: &'a [u8],
        interrupt: bool,
    }
    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = out.len().min(777);
            self.bytes.read(&mut out[..n])
        }
    }
    for size in [0, 1, STREAM_CHUNK, 3 * STREAM_CHUNK + 123] {
        let expected: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut output = Vec::new();
        let input = Fragmented {
            bytes: &expected,
            interrupt: false,
        };
        assert_eq!(
            copy_prefetched(input, &mut output).unwrap(),
            expected.len() as u64
        );
        assert_eq!(output, expected);
    }
}

#[test]
fn prefetch_overlaps_reads_with_writes_bounds_read_ahead_and_joins_on_output_failure() {
    struct AheadReader {
        reads: usize,
        notify: mpsc::Sender<usize>,
        dropped: Arc<AtomicBool>,
    }
    impl Read for AheadReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            out.fill(self.reads as u8);
            self.notify.send(self.reads).unwrap();
            Ok(out.len())
        }
    }
    impl Drop for AheadReader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }
    struct PartialWriter {
        calls: usize,
        reads: mpsc::Receiver<usize>,
    }
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                // While this write is blocked, the next block is queued and
                // one more can be read. A fourth read must wait for output.
                for expected in 1..=3 {
                    assert_eq!(
                        self.reads.recv_timeout(Duration::from_secs(5)).unwrap(),
                        expected
                    );
                }
                assert!(matches!(
                    self.reads.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
                assert_eq!(bytes, vec![1; STREAM_CHUNK]);
                return Ok(17);
            }
            assert_eq!(bytes.len(), STREAM_CHUNK - 17);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original output failure",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (notify, reads) = mpsc::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let input = AheadReader {
        reads: 0,
        notify,
        dropped: dropped.clone(),
    };
    let mut output = PartialWriter { calls: 0, reads };
    let error = copy_prefetched(input, &mut output).unwrap_err();
    assert_eq!(output.calls, 2);
    assert_eq!(error.to_string(), "original output failure");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn prefetch_propagates_input_failure_after_queued_data() {
    struct BrokenReader(Cursor<Vec<u8>>);
    impl Read for BrokenReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            match self.0.read(out)? {
                0 => Err(io::Error::new(io::ErrorKind::InvalidData, "input failed")),
                n => Ok(n),
            }
        }
    }
    let mut output = Vec::new();
    let error = copy_prefetched(
        BrokenReader(Cursor::new(vec![7; STREAM_CHUNK + 123])),
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "input failed");
    assert_eq!(output, vec![7; STREAM_CHUNK]);
}

#[test]
fn prefetch_returns_a_worker_panic_as_an_error() {
    struct PanickingReader;
    impl Read for PanickingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("simulated decoder panic");
        }
    }
    let error = copy_prefetched(PanickingReader, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "IPSW reader panicked");
}
