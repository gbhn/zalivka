use super::*;

#[test]
fn records_keep_their_level_and_source_through_the_elevated_pipe() {
    for level in [
        Level::Trace,
        Level::Debug,
        Level::Info,
        Level::Warning,
        Level::Error,
    ] {
        let mut record = Record::new(level, "restore", "Подготовка macOS");
        record.elapsed_ms = 3_723_004;
        let event = crate::progress::Event::Log(record.clone());
        let mut pipe = Vec::new();
        event.write_to(&mut pipe).unwrap();
        assert_eq!(
            crate::progress::Event::parse(std::str::from_utf8(&pipe).unwrap()),
            Some(event)
        );
        let text = record.to_string();
        assert!(text.starts_with("01:02:03.004 "));
        assert!(text.contains(level.label()));
        assert!(text.contains("restore"));
        assert!(text.ends_with("Подготовка macOS"));
    }
}

#[test]
fn external_diagnostics_cannot_break_rows_or_inject_terminal_controls() {
    let record = Record::new(
        Level::Error,
        "usb",
        "one\r\ntwo\tthree\u{00b7}four\u{1b}[31m",
    );
    assert_eq!(record.message, "one  / two three,four\\u{1b}[31m");
    let mut output = Vec::new();
    record.write_to(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains('\u{00b7}'));
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn firmware_trace_suppression_is_scoped_and_preserves_parallel_fdr_and_errors() {
    use std::sync::{Arc, Mutex};
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = records.clone();
    crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            output.lock().unwrap().push(record);
        }
    })
    .run(|| {
        let mut formatted = false;
        let result = (|| -> anyhow::Result<()> {
            let _transfer = firmware_transfer();
            {
                let _nested = firmware_transfer();
                assert!(!enabled(Level::Trace));
            }
            assert!(!enabled(Level::Trace));
            crate::log!(Trace, "plist", "{}", {
                formatted = true;
                "firmware payload"
            });
            bytes("usbmux:io", format_args!("TX"), b"firmware payload");
            crate::log!(Debug, "transfer", "Transfer progress");
            std::thread::spawn(crate::progress::inherit(|| {
                crate::log!(Trace, "fdr:conn", "Parallel FDR");
                bytes("fdr:conn", format_args!("RX"), b"FDR");
            }))
            .join()
            .unwrap();
            crate::log!(Error, "restore", "Transfer failed");
            anyhow::bail!("injected transfer failure")
        })();
        assert!(result.is_err());
        assert!(!formatted);
        assert!(enabled(Level::Trace));
        crate::log!(Trace, "restore", "Control tracing resumed");
    });
    let records = records.lock().unwrap();
    assert!(
        !records
            .iter()
            .any(|record| matches!(record.source.as_str(), "plist" | "usbmux:io"))
    );
    for message in [
        "Transfer progress",
        "Transfer failed",
        "Parallel FDR",
        "Control tracing resumed",
    ] {
        assert!(records.iter().any(|record| record.message == message));
    }
    assert!(
        records
            .iter()
            .any(|record| record.source == "fdr:conn" && record.message.ends_with("464452"))
    );
}

#[test]
fn queued_dumps_do_not_wait_for_the_sink_and_keep_owned_data_and_timestamps() {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = records.clone();
    let (entered_tx, entered) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let context = crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            if record.message == "Pause sink" {
                entered_tx.send(()).unwrap();
                released.lock().unwrap().recv().unwrap();
            }
            output.lock().unwrap().push(record);
        }
    })
    .with_async_logs(|| {})
    .unwrap();
    let worker = context.clone();
    let (done_tx, done) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        worker.run(|| {
            crate::log!(Info, "test", "Pause sink");
            let mut data: Vec<_> = (0..256 * 1024).map(|index| index as u8).collect();
            bytes("fdr:conn", format_args!("RX offset=0"), &data);
            data.fill(0);
            let mut value = crate::wire::dict([("Data", plist::Value::Data(vec![1, 2, 3]))]);
            plist("plist", "TX binary LE", &value);
            value.as_dictionary_mut().unwrap().clear();
            {
                let _transfer = firmware_transfer();
                bytes("firmware", format_args!("TX"), &data);
                plist("plist", "Firmware", &value);
            }
            crate::log!(Info, "test", "Final record");
            done_tx.send(elapsed_ms()).unwrap();
        })
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    // The sink stays blocked until the producer has queued the complete dump.
    let produced = done.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    producer.join().unwrap();
    let produced_at = produced.expect("TRACE waited for the blocked sink");
    context.flush_logs().unwrap();
    let records = records.lock().unwrap();
    assert_eq!(records.first().unwrap().message, "Pause sink");
    assert_eq!(records.last().unwrap().message, "Final record");
    assert!(
        records
            .iter()
            .all(|record| record.elapsed_ms <= produced_at)
    );
    let received: Vec<_> = records
        .iter()
        .filter(|record| record.source == "fdr:conn")
        .flat_map(|record| hex::decode(record.message.split_once("]: ").unwrap().1).unwrap())
        .collect();
    assert_eq!(
        received,
        (0..256 * 1024).map(|index| index as u8).collect::<Vec<_>>()
    );
    assert!(
        records
            .iter()
            .any(|record| record.source == "plist" && record.message.contains("[1, 2, 3]"))
    );
    assert!(
        !records
            .iter()
            .any(|record| record.source == "firmware" || record.message.starts_with("Firmware"))
    );
}

#[test]
fn background_journal_flushes_while_the_producer_is_idle() {
    use std::{sync::mpsc, time::Duration};
    let (flushed, rx) = mpsc::channel();
    let queue = Queue::new(move |record| {
        if record.is_none() {
            let _ = flushed.send(());
        }
    })
    .unwrap();
    queue
        .record(Record::new(Level::Info, "test", "Buffered record"))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    queue.flush().unwrap();
}

#[test]
#[ignore = "manual TRACE producer benchmark with temporary disk journals"]
fn trace_producer_benchmark() {
    use std::{
        io::BufWriter,
        sync::{Arc, Mutex},
    };
    let payload = vec![0xa5; 32 * 1024];
    for mode in ["disabled", "synchronous", "queued"] {
        let file = tempfile::tempfile().unwrap();
        let output = Arc::new(Mutex::new(BufWriter::with_capacity(256 * 1024, file)));
        let records = output.clone();
        let context = crate::progress::Context::new(move |event| {
            if let crate::progress::Event::Log(record) = event {
                record.write_to(&mut *records.lock().unwrap()).unwrap();
            }
        });
        let context = if mode == "queued" {
            let output = output.clone();
            context
                .with_async_logs(move || output.lock().unwrap().flush().unwrap())
                .unwrap()
        } else {
            context
        };
        let started = Instant::now();
        context.run(|| {
            let _disabled = (mode == "disabled").then(firmware_transfer);
            for offset in 0..256 {
                bytes(
                    "fdr:conn",
                    format_args!("RX offset={}", offset * payload.len()),
                    &payload,
                );
            }
        });
        let producer = started.elapsed();
        context.flush_logs().unwrap();
        let mut output = output.lock().unwrap();
        output.flush().unwrap();
        let disk_bytes = output.get_ref().metadata().unwrap().len();
        eprintln!(
            "{mode}: raw=8 MiB; producer={producer:?}; including drain={:?}; journal={disk_bytes} B",
            started.elapsed()
        );
        assert_eq!(disk_bytes == 0, mode == "disabled");
    }
}

#[test]
fn trace_subprocess() {
    let Ok(level) = std::env::var("ZALIVKA_TEST_TRACE_LEVEL") else {
        return;
    };
    init(match level.as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        _ => Level::Info,
    });
    let native = std::env::var_os("ZALIVKA_TEST_TRACE_NATIVE").is_some();
    let _background = (!native).then(|| background().unwrap());
    let run = || {
        let mut formatted = false;
        crate::log!(Trace, "test", "{}", {
            formatted = true;
            "trace formatting"
        });
        assert_eq!(formatted, level == "trace" || native);
        crate::log!(Debug, "test", "debug record");
        crate::log!(Info, "test", "info record");

        use crate::{
            mux::{PacketTransport, Session},
            test_mux::{tcp, version_packet},
        };
        use std::{
            collections::VecDeque,
            io::{Cursor, Read},
            sync::{Arc, Mutex, atomic::AtomicBool},
        };
        struct Usb(VecDeque<Vec<u8>>);
        impl PacketTransport for Usb {
            fn write_packet(&mut self, _: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }
            fn read_packet(&mut self) -> anyhow::Result<Vec<u8>> {
                Ok(self.0.pop_front().unwrap_or_default())
            }
        }
        // Control negotiation must be visible before a connection port is known.
        let mut frame = Vec::new();
        crate::wire::send_binary_le(
            &mut frame,
            &crate::wire::dict([("ConnPort", 45678u64.into())]),
        )
        .unwrap();
        let session = Session::new(Usb(VecDeque::from([
            version_packet(),
            tcp(1082, 1, 0, 1, 0x12, &[]),
            tcp(1082, 1, 1, 1, 0x10, &frame),
        ])))
        .unwrap();
        drop(crate::fdr::Fdr::start(&session).unwrap());

        // A complete SOCKS request and binary payload arrive in one USB packet,
        // but the parser consumes them through several reads of different sizes.
        let payload: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let reply: Vec<u8> = (0..333).map(|i| (255 - i % 256) as u8).collect();
        let host = b"tbsc.apple.com";
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend(host);
        request.extend(443u16.to_be_bytes());
        request.extend(&payload);
        let session = Session::new(Usb(VecDeque::from([
            version_packet(),
            tcp(45678, 1, 0, 1, 0x12, &[]),
            tcp(45678, 1, 1, 1, 0x10, &request),
        ])))
        .unwrap();
        struct Peer(Cursor<Vec<u8>>, Arc<Mutex<Vec<u8>>>);
        impl Read for Peer {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0.read(out)
            }
        }
        impl Write for Peer {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let n = data.len().min(13);
                self.1.lock().unwrap().extend_from_slice(&data[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sent = Arc::new(Mutex::new(Vec::new()));
        crate::fdr::handle_connection(
            session.connect(45678).unwrap(),
            &AtomicBool::new(false),
            |host, port| {
                assert_eq!((host, port), ("tbsc.apple.com", 443));
                Ok(Peer(Cursor::new(reply.clone()), sent.clone()))
            },
        )
        .unwrap();
        assert_eq!(*sent.lock().unwrap(), payload);
    };
    if native {
        let context =
            crate::progress::Context::new(|event| event.write_to(io::stdout().lock()).unwrap())
                .with_async_logs(|| {})
                .unwrap();
        context.run(run);
        context.flush_logs().unwrap();
    } else {
        run();
    }
}

#[test]
fn native_operations_always_trace_and_fdr_dumps_preserve_all_bytes_in_both_directions() {
    use crate::progress::Event;
    for native in [false, true] {
        for level in ["info", "debug", "trace"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "logging::tests::trace_subprocess",
                    "--nocapture",
                    "--format=terse",
                ])
                .env("ZALIVKA_TEST_TRACE_LEVEL", level);
            if native {
                command.env("ZALIVKA_TEST_TRACE_NATIVE", "1");
            } else {
                command.env_remove("ZALIVKA_TEST_TRACE_NATIVE");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let records: Vec<_> = stdout
                .lines()
                .filter_map(|line| match Event::parse(line) {
                    Some(Event::Log(record)) => Some(record),
                    _ => None,
                })
                .collect();
            if !native {
                assert_eq!(stderr.contains("TRACE"), level == "trace");
                assert_eq!(stderr.contains("DEBUG"), level != "info");
                assert!(stderr.contains("info record"));
                continue;
            }
            assert!(stderr.is_empty());
            assert!(records.iter().any(|r| r.message == "debug record"));
            assert!(records.iter().any(|r| r.level == Level::Trace));
            assert!(
                records
                    .iter()
                    .any(|r| r.source == "fdr:control" && r.message == "Stopped")
            );
            let dump = |source, direction| -> Vec<u8> {
                records
                    .iter()
                    .filter(|r| r.source == source && r.message.contains(direction))
                    .flat_map(|r| {
                        let (_, hex) = r.message.split_once("]: ").unwrap();
                        let bytes = hex::decode(hex).unwrap();
                        assert!(bytes.len() <= 64);
                        bytes
                    })
                    .collect()
            };
            let control = dump("fdr:control", " TX offset=");
            assert!(control.starts_with(b"BeginCtrl\0"));
            assert_eq!(&control[14..22], b"bplist00");
            let received = dump("fdr:conn", " RX offset=");
            assert_eq!(&received[..5], &[5, 1, 0, 3, 14]);
            assert_eq!(
                &received[21..],
                &(0..400).map(|i| i as u8).collect::<Vec<_>>()
            );
            assert_eq!(
                dump("fdr:proxy", " TX offset="),
                (0..400).map(|i| i as u8).collect::<Vec<_>>()
            );
            let reply: Vec<u8> = (0..333).map(|i| (255 - i % 256) as u8).collect();
            assert_eq!(dump("fdr:proxy", " RX offset="), reply);
            let sent = dump("fdr:conn", " TX offset=");
            assert!(sent.starts_with(&[5, 0, 0, 3, 14]));
            assert_eq!(&sent[21..], reply);
        }
    }
}
