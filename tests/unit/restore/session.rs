//! Complete restored/FDR/request lifecycle over a reactive device-side mux.
use super::*;
use crate::progress::{Context as Progress, Event};
use crate::restore::attestation::Attestation;

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Close,
    RemoveOnReply,
    FailStart,
    FailFdr,
    FailAck,
    FailClose,
    RemoveAfterAck,
}

struct Attempt {
    messages: Vec<Value>,
    resumed: bool,
    end: End,
    version: u64,
}

impl Attempt {
    fn new(messages: Vec<Value>, end: End) -> Self {
        Self {
            messages,
            resumed: false,
            end,
            version: 17,
        }
    }

    fn resumed(mut self) -> Self {
        self.resumed = true;
        self
    }
}

struct Device {
    attempt: Attempt,
    input: VecDeque<Vec<u8>>,
    output: Arc<Mutex<Vec<Vec<u8>>>>,
    main_local: u16,
    main_seq: u32,
    main_frame: Vec<u8>,
    removed: bool,
    close_failed: bool,
    deadline: Instant,
}

impl Device {
    fn messages(&mut self) -> Result<()> {
        let mut bytes = Vec::new();
        for message in self.attempt.messages.drain(..) {
            wire::send(&mut bytes, &message)?;
        }
        if !bytes.is_empty() {
            self.input.push_back(tcp_on(
                RESTORED_PORT,
                self.main_local,
                self.main_seq,
                0x10,
                &bytes,
            ));
            self.main_seq += bytes.len() as u32;
        }
        Ok(())
    }

    fn disconnect<T>(&mut self) -> Result<T> {
        self.removed = true;
        Err(nusb::transfer::TransferError::Disconnected.into())
    }
}

impl PacketTransport for Device {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.lock().unwrap().push(bytes.to_vec());
        match u32::from_be_bytes(bytes[..4].try_into()?) {
            0 => {
                self.input.push_back(version_packet());
                return Ok(());
            }
            6 => {}
            _ => return Ok(()),
        }
        let packet = mux::decode_packet(bytes, 2)?;
        let header = packet.payload;
        let local = u16::from_be_bytes(header[..2].try_into()?);
        let port = u16::from_be_bytes(header[2..4].try_into()?);
        if header[13] == 2 {
            if port == RESTORED_PORT {
                self.main_local = local;
            }
            self.input.push_back(tcp_on(port, local, 0, 0x12, &[]));
        }
        let data = &header[20..];
        if port == 1082 && data == b"BeginCtrl\0" {
            if self.attempt.end == End::FailFdr {
                return self.disconnect();
            }
            let mut response = Vec::new();
            wire::send_binary_le(&mut response, &wire::dict([("ConnPort", 45678u64.into())]))?;
            self.input
                .push_back(tcp_on(port, local, 1, 0x10, &response));
            if self.attempt.resumed {
                self.messages()?;
            }
        }
        if port != RESTORED_PORT || data.is_empty() {
            return Ok(());
        }
        // USB can report removal after an OUT transfer reached the device.
        // The host must not replay StartRestore on the next connection.
        if self.attempt.end == End::FailStart {
            return self.disconnect();
        }
        self.main_frame.extend_from_slice(data);
        while self.main_frame.len() >= 4 {
            let length = u32::from_be_bytes(self.main_frame[..4].try_into()?) as usize + 4;
            if self.main_frame.len() < length {
                break;
            }
            let message = wire::receive(&mut &self.main_frame[..length])?;
            self.main_frame.drain(..length);
            if wire::string(&message, &["Request"]).ok() == Some("StartRestore") {
                self.messages()?;
            } else if wire::string(&message, &["MsgType"]).ok() == Some("ReceivedFinalStatusMsg") {
                match self.attempt.end {
                    End::FailAck => return self.disconnect(),
                    End::FailClose => self.close_failed = true,
                    End::RemoveAfterAck => self.removed = true,
                    _ => self
                        .input
                        .push_back(tcp_on(port, local, self.main_seq, 0x11, &[])),
                }
            } else if self.attempt.end == End::RemoveOnReply {
                // A data reply proves earlier checkpoints were processed before
                // another thread can observe removal on the shared USB link.
                self.removed = true;
            }
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        if let Some(packet) = self.input.pop_front() {
            return Ok(packet);
        }
        if self.removed {
            return self.disconnect();
        }
        ensure!(!self.close_failed, "synthetic channel closure failure");
        ensure!(Instant::now() < self.deadline, "synthetic device stalled");
        Ok(Vec::new())
    }
}

struct Run {
    result: Result<()>,
    output: Vec<Arc<Mutex<Vec<Vec<u8>>>>>,
    events: Arc<Mutex<Vec<Event>>>,
}

fn run(attempts: Vec<Attempt>, attestation_mode: u64, log: Option<File>) -> Run {
    let mut identity = j313_identity();
    identity.value.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .insert("RestoreAttestationMode".into(), attestation_mode.into());
    let device = DeviceInfo::parse(
        "CPID:8103 BDID:26 ECID:000123456789abcd SDOM:01 CPFM:03",
        Mode::Dfu,
    )
    .unwrap();
    let ticket = wire::dict([(
        "ApImg4Ticket",
        Value::Data(b"synthetic restore ticket".to_vec()),
    )]);
    let attestation = Attestation::new(&identity, &device, &ticket).unwrap();
    let mut archive = tempfile::NamedTempFile::new().unwrap();
    {
        let mut zip = zip::ZipWriter::new(archive.as_file_mut());
        zip.start_file(
            "BuildManifest.plist",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        wire::dict([
            (
                "BuildIdentities",
                Value::Array(vec![identity.value.clone()]),
            ),
            (
                "SupportedProductTypes",
                Value::Array(vec!["MacBookAir10,1".into()]),
            ),
        ])
        .to_writer_xml(&mut zip)
        .unwrap();
        zip.finish().unwrap();
    }
    let mut state = RestoreSession {
        ipsw: Ipsw::open(archive.path()).unwrap(),
        context: Arc::new(RestoreContext {
            restore: SignedIdentity { identity, ticket },
            recovery: None,
            device,
            assets: net::AssetClient::default(),
        }),
    };
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = events.clone();
    let progress = Progress::new(move |event| captured.lock().unwrap().push(event));
    let mut attempts = attempts.into_iter();
    let mut output = Vec::new();
    let result = progress.run(|| {
        crate::restore::session::run(&mut state, None, log, attestation, |_| {
            let attempt = attempts.next().context("unexpected extra reconnection")?;
            let version = attempt.version;
            let packets = Arc::new(Mutex::new(Vec::new()));
            output.push(packets.clone());
            let session = Session::new(Device {
                attempt,
                input: VecDeque::new(),
                output: packets,
                main_local: 0,
                main_seq: 1,
                main_frame: Vec::new(),
                removed: false,
                close_failed: false,
                deadline: Instant::now() + Duration::from_secs(5),
            })?;
            let main = session.connect(RESTORED_PORT)?;
            Ok((session, main, version))
        })
    });
    // No background request may retain the archive context after the loop exits.
    assert_eq!(Arc::strong_count(&state.context), 1);
    // The transport belongs to the mux shared by FDR and request threads.
    // Releasing it proves those threads also released every connection attempt.
    for packets in &output {
        assert_eq!(Arc::strong_count(packets), 1);
    }
    Run {
        result,
        output,
        events,
    }
}

fn status(code: i64) -> Value {
    wire::dict([("MsgType", "StatusMsg".into()), ("Status", code.into())])
}

fn request(asynchronous: bool, kind: &str) -> Value {
    let mut message = wire::dict([
        (
            "MsgType",
            if asynchronous {
                "AsyncDataRequestMsg"
            } else {
                "DataRequestMsg"
            }
            .into(),
        ),
        ("DataType", kind.into()),
    ]);
    if asynchronous {
        message
            .as_dictionary_mut()
            .unwrap()
            .insert("DataPort".into(), 23456u64.into());
    }
    message
}

fn replies(run: &Run, attempt: usize, port: u16) -> Vec<Value> {
    let bytes = bytes_on(&run.output[attempt], port);
    let mut input = bytes.as_slice();
    let mut messages = Vec::new();
    while !input.is_empty() {
        messages.push(wire::receive(&mut input).unwrap());
    }
    messages
}

fn has_success(run: &Run) -> bool {
    run.events.lock().unwrap().iter().any(|event| {
        matches!(event,
        Event::Log(record) if record.source == "restore" && record.message.starts_with("Success;"))
    })
}

#[test]
fn service_lifecycle_serves_requests_joins_workers_and_records_every_message() {
    let messages = vec![
        wire::dict([
            ("MsgType", "RestoreProtocol".into()),
            (
                "Arguments",
                wire::dict([("RestoreProtocol", "MuxSocket".into())]),
            ),
        ]),
        wire::dict([
            ("MsgType", "ProgressMsg".into()),
            ("Operation", 14u64.into()),
            ("Progress", (-1i64).into()),
        ]),
        request(false, "RootTicket"),
        request(true, "RootTicket"),
        status(0),
    ];
    let transcript = tempfile::NamedTempFile::new().unwrap();
    let run = run(
        vec![Attempt::new(messages.clone(), End::Close)],
        0,
        Some(transcript.reopen().unwrap()),
    );
    run.result.as_ref().unwrap();
    let sent = replies(&run, 0, RESTORED_PORT);
    assert_eq!(
        wire::string(&sent[0], &["Request"]).unwrap(),
        "StartRestore"
    );
    assert_eq!(
        wire::number(wire::get(&sent[0], &["RestoreProtocolVersion"]).unwrap()).unwrap(),
        17
    );
    assert_eq!(
        wire::get(&sent[0], &["RestoreOptions"]).unwrap(),
        &options(&j313_identity()).unwrap()
    );
    assert_eq!(
        wire::get(&sent[1], &["RootTicketData"]).unwrap().as_data(),
        Some(b"synthetic restore ticket".as_slice())
    );
    assert_eq!(
        wire::string(&sent[2], &["MsgType"]).unwrap(),
        "ReceivedFinalStatusMsg"
    );
    assert_eq!(replies(&run, 0, 23456), vec![sent[1].clone()]);
    let recorded: Vec<Value> = std::fs::read_to_string(transcript.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(recorded, messages);
    assert!(has_success(&run));
}

#[test]
fn physical_reconnection_keeps_provisioning_warnings_and_does_not_restart_restore() {
    let mut messages: Vec<Value> =
        include_str!("../../fixtures/restored-ucrt-offline-26B123.jsonl")
            .lines()
            .take(2)
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    messages.push(request(false, "DeviceRestoreInfoPreflight"));
    let run = run(
        vec![
            Attempt::new(messages, End::RemoveOnReply),
            Attempt::new(vec![status(0)], End::Close).resumed(),
        ],
        0,
        None,
    );
    run.result.as_ref().unwrap();
    assert_eq!(run.output.len(), 2);
    assert_eq!(replies(&run, 0, RESTORED_PORT).len(), 2); // StartRestore, data reply
    let sent = replies(&run, 1, RESTORED_PORT);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        wire::string(&sent[0], &["MsgType"]).unwrap(),
        "ReceivedFinalStatusMsg"
    );
    assert_eq!(
        run.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Event::ProvisioningWarning { .. }))
            .count(),
        1
    );
}

#[test]
fn uncertain_start_write_is_not_replayed_but_fdr_failure_before_start_can_retry() {
    for end in [End::FailStart, End::FailFdr] {
        let second = Attempt::new(vec![status(0)], End::Close);
        let second = if end == End::FailStart {
            second.resumed()
        } else {
            second
        };
        let run = run(vec![Attempt::new(vec![], end), second], 0, None);
        run.result.as_ref().unwrap();
        let first = bytes_on(&run.output[0], RESTORED_PORT);
        assert_eq!(first.is_empty(), end == End::FailFdr);
        let sent = replies(&run, 1, RESTORED_PORT);
        assert_eq!(sent.len(), if end == End::FailFdr { 2 } else { 1 });
        assert_eq!(
            wire::string(sent.last().unwrap(), &["MsgType"]).unwrap(),
            "ReceivedFinalStatusMsg"
        );
    }
}

#[test]
fn protocol_changes_and_four_physical_failures_end_reconnection() {
    let mut changed = Attempt::new(vec![], End::FailFdr);
    changed.version = 18;
    let run = run(vec![Attempt::new(vec![], End::FailFdr), changed], 0, None);
    assert!(
        run.result
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("protocol changed")
    );
    assert_eq!(run.output.len(), 2);
    assert!(bytes_on(&run.output[1], 1082).is_empty());
    let run = self::run(
        (0..5).map(|_| Attempt::new(vec![], End::FailFdr)).collect(),
        0,
        None,
    );
    assert!(run.result.is_err());
    assert_eq!(run.output.len(), 4);
}

#[test]
fn final_status_failures_acknowledge_once_and_never_reconnect_or_report_success() {
    for (code, mode, end, expected) in [
        (10, 0, End::FailAck, "Status=10"),
        (0, 0, End::FailAck, "acknowledging final restore status"),
        (0, 0, End::FailClose, "waiting for device to close"),
        (0, 6, End::RemoveAfterAck, "without a verified attestation"),
    ] {
        let run = run(vec![Attempt::new(vec![status(code)], end)], mode, None);
        let error = format!("{:#}", run.result.as_ref().unwrap_err());
        assert!(error.contains(expected), "{error}");
        assert_eq!(run.output.len(), 1);
        let sent = replies(&run, 0, RESTORED_PORT);
        assert_eq!(sent.len(), 2);
        assert_eq!(
            wire::string(&sent[1], &["MsgType"]).unwrap(),
            "ReceivedFinalStatusMsg"
        );
        assert!(!has_success(&run));
    }
    let run = run(
        vec![Attempt::new(vec![status(0)], End::RemoveAfterAck)],
        0,
        None,
    );
    run.result.as_ref().unwrap();
    assert!(has_success(&run));
}

#[test]
fn worker_error_wakes_blocked_main_read_with_original_cause_and_joins_workers() {
    let mut message = request(true, "SourceBootObjectV5");
    message.as_dictionary_mut().unwrap().insert(
        "Arguments".into(),
        wire::dict([("ImageName", "MissingComponent".into())]),
    );
    let run = run(vec![Attempt::new(vec![message], End::Close)], 0, None);
    let error = format!("{:#}", run.result.as_ref().unwrap_err());
    assert!(
        error.contains("asynchronous SourceBootObjectV5 on DataPort 23456 failed"),
        "{error}"
    );
    assert!(error.contains("MissingComponent"), "{error}");
    assert_eq!(run.output.len(), 1);
    assert!(!has_success(&run));
}

#[test]
fn unwritable_transcript_does_not_interrupt_restore_protocol() {
    let transcript = tempfile::NamedTempFile::new().unwrap();
    let run = run(
        vec![Attempt::new(vec![status(0)], End::Close)],
        0,
        Some(File::open(transcript.path()).unwrap()),
    );
    run.result.as_ref().unwrap();
    assert!(has_success(&run));
    assert_eq!(run.events.lock().unwrap().iter().filter(|event| matches!(event,
        Event::Log(record) if record.source == "transcript" && record.message.contains("recording disabled"))).count(), 1);
}
