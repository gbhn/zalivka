use super::boot::{IBootStep, diagnostic_boot_command, iboot_stage, reconnect_after_ibss};
use super::file_data::{FILE_DATA_BATCH, FileDataWriter, send_file_data};
use super::*;
use crate::dfu;
use crate::mux::{self, PacketTransport};
use std::collections::{HashSet, VecDeque};
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::thread;

fn j313_identity() -> Identity {
    Identity {
        index: 3,
        value: serde_json::from_str(include_str!("../fixtures/j313-26A434-iboot.json")).unwrap(),
    }
}

fn stage_transcript(id: &Identity, stage1: bool) -> Vec<String> {
    iboot_stage(id, stage1)
        .unwrap()
        .into_iter()
        .map(|step| match step {
            IBootStep::Component(name) => format!("upload {name}"),
            IBootStep::Command(command) => command.into(),
        })
        .collect()
}

#[test]
fn j313_bootstrap_order_matches_macos_host_on_both_stages() {
    // The fixture is the flags/paths of identity 3 in the real 26A434 IPSW.
    // Expected ordering comes from MobileDevice 1860.2.5.100.2, not Manifest order.
    let id = j313_identity();
    assert_eq!(
        stage_transcript(&id, true),
        [
            "upload RestoreANS",
            "firmware",
            "setenv auto-boot false",
            "saveenv",
            "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore",
            "upload RestoreDCP",
            "firmware",
            "upload RestoreLogo",
            "setpicture 4",
            "bgcolor 0 0 0",
            "upload Ap,RestoreCIO",
            "firmware",
            "upload Ap,RestoreTMU",
            "firmware",
        ]
    );
    assert_eq!(
        stage_transcript(&id, false),
        [
            "upload RestoreLogo",
            "setpicture 4",
            "bgcolor 0 0 0",
            "setenv auto-boot false",
            "saveenv",
            "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore",
            "upload iBootData",
            "firmware",
            "upload ANE",
            "firmware",
            "upload AOP",
            "firmware",
            "upload AVE",
            "firmware",
            "upload Ap,RestoreDCP2",
            "firmware",
            "upload Ap,RestoreSecurePageTableMonitor",
            "firmware",
            "upload Ap,RestoreTrustedExecutionMonitor",
            "firmware",
            "upload GFX",
            "firmware",
            "upload ISP",
            "firmware",
            "upload PMP",
            "firmware",
            "upload RestoreTrustCache",
            "firmware",
            "upload SIO",
            "firmware",
        ]
    );
    for stage1 in [true, false] {
        let steps = stage_transcript(&id, stage1);
        let names: Vec<_> = steps.iter().filter(|s| s.starts_with("upload ")).collect();
        let unique: HashSet<_> = names.iter().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "a priority component was sent twice"
        );
        assert!(
            !steps
                .iter()
                .any(|s| s.contains("iBEC") || s.contains("RestoreKernelCache"))
        );
    }
}

#[test]
fn update_boot_args_are_repeated_without_enabling_reformat() {
    let mut id = j313_identity();
    id.value.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .insert("RestoreBehavior".into(), "Update".into());
    for stage1 in [true, false] {
        let steps = stage_transcript(&id, stage1);
        assert!(
            steps
                .iter()
                .any(|s| s == "setenvnp boot-args rd=md0 -progress -restore")
        );
        assert!(!steps.iter().any(|s| s.contains("reformat")));
    }
}

#[test]
fn bootstrap_respects_stage_flags_and_defers_logo_until_present_dcp() {
    let mut id = j313_identity();
    let manifest = id.value.as_dictionary_mut().unwrap()["Manifest"]
        .as_dictionary_mut()
        .unwrap();
    for name in ["RestoreANS", "RestoreDCP"] {
        let info = manifest[name].as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.insert("IsLoadedByiBootStage1".into(), false.into());
        info.insert("IsLoadedByiBoot".into(), true.into());
    }
    let first = stage_transcript(&id, true);
    assert!(!first.iter().any(|s| matches!(
        s.as_str(),
        "upload RestoreANS" | "upload RestoreDCP" | "upload RestoreLogo"
    )));
    let second = stage_transcript(&id, false);
    assert_eq!(
        &second[..12],
        [
            "upload RestoreANS",
            "firmware",
            "setenv auto-boot false",
            "saveenv",
            "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore",
            "upload iBootData",
            "firmware",
            "upload RestoreDCP",
            "firmware",
            "upload RestoreLogo",
            "setpicture 4",
            "bgcolor 0 0 0",
        ]
    );
    id.value.as_dictionary_mut().unwrap()["Manifest"]
        .as_dictionary_mut()
        .unwrap()
        .remove("RestoreLogo");
    assert!(
        !stage_transcript(&id, false)
            .iter()
            .any(|s| s.contains("RestoreLogo")
                || s.starts_with("setpicture")
                || s.starts_with("bgcolor"))
    );
}

#[test]
fn diagnostic_stages_never_persist_settings_or_enable_reformatting() {
    for behavior in ["Erase", "Update"] {
        let mut id = j313_identity();
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("RestoreBehavior".into(), behavior.into());
        for first in [true, false] {
            let commands: Vec<_> = iboot_stage(&id, first)
                .unwrap()
                .into_iter()
                .filter_map(|step| match step {
                    IBootStep::Command(command) => diagnostic_boot_command(command),
                    IBootStep::Component(_) => None,
                })
                .collect();
            assert!(commands.contains(&"setenvnp auto-boot false"));
            assert!(commands.contains(&"setenvnp boot-args rd=md0 -progress -restore"));
            for command in commands {
                assert!(!command.starts_with("setenv "), "{command}");
                assert!(!command.contains("saveenv"), "{command}");
                assert!(!command.contains("reformat"), "{command}");
            }
        }
    }
}

#[test]
fn attestation_declines_only_the_initial_question() {
    let message = |state: Value| {
        wire::dict([
            ("MsgType", "RestoreAttestation".into()),
            ("RestoreAttestationState", state),
        ])
    };
    assert_eq!(
        attestation_reply(&message("RestoreShouldAttest".into())).unwrap(),
        wire::dict([("RestoreShouldAttest", false.into())])
    );
    for state in [
        "AttestationIssued".into(),
        "AttestationError".into(),
        "unknown".into(),
        false.into(),
    ] {
        assert!(attestation_reply(&message(state)).is_err());
    }
    assert!(attestation_reply(&wire::dict([] as [(&str, Value); 0])).is_err());
}

#[test]
fn signed_progress_survives_xml_and_binary_plist_framing() {
    for progress in [-1i64, 0, 50, 100] {
        let message = wire::dict([
            ("MsgType", "ProgressMsg".into()),
            ("Operation", 28u64.into()),
            ("Progress", progress.into()),
        ]);
        for binary in [false, true] {
            let mut framed = Vec::new();
            if binary {
                wire::send_binary(&mut framed, &message).unwrap();
            } else {
                wire::send(&mut framed, &message).unwrap();
            }
            let received = wire::receive(&mut std::io::Cursor::new(framed)).unwrap();
            let mut output = Vec::new();
            log_progress(&received, &mut output).unwrap();
            let expected = if progress == -1 {
                "Operation 28: progress unavailable (-1)\n".to_owned()
            } else {
                format!("Operation 28: {progress}%\n")
            };
            assert_eq!(String::from_utf8(output).unwrap(), expected);
            assert!(validate_final_status(&received).is_err());
        }
    }
    // Device IDs still reject negative integers.
    assert!(wire::number(&(-1i64).into()).is_err());
}

#[test]
fn malformed_progress_reports_the_field_without_inventing_a_percentage() {
    let message = wire::dict([("Operation", 28u64.into()), ("Progress", (-1i64).into())]);
    for key in ["Operation", "Progress"] {
        for value in [None, Some(true.into()), Some(0.5f64.into())] {
            let mut malformed = message.clone();
            let dict = malformed.as_dictionary_mut().unwrap();
            if let Some(value) = value {
                dict.insert(key.into(), value);
            } else {
                dict.remove(key);
            }
            let mut output = Vec::new();
            let error = log_progress(&malformed, &mut output).unwrap_err();
            assert!(format!("{error:#}").contains(key), "{error:#}");
            assert!(output.is_empty());
        }
    }
}

#[test]
fn checkpoint_results_do_not_replace_final_restore_status() {
    for complete in [false, true] {
        for result in [0i64, 10, -1] {
            let checkpoint = wire::dict([
                ("MsgType", "CheckpointMsg".into()),
                ("CHECKPOINT_ID", 0x123u64.into()),
                ("CHECKPOINT_RESULT", result.into()),
                ("CHECKPOINT_COMPLETE", complete.into()),
            ]);
            let mut output = Vec::new();
            log_checkpoint(&checkpoint, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(if complete { "completed" } else { "started" }));
            assert!(output.contains(&format!("result={result}")));
            assert!(validate_final_status(&checkpoint).is_err());
        }
    }
    let status = |code| {
        wire::dict([
            ("MsgType", "StatusMsg".into()),
            ("Status", Value::Integer(code)),
        ])
    };
    validate_final_status(&status(0u64.into())).unwrap();
    assert!(validate_final_status(&status(10u64.into())).is_err());
}

#[test]
fn checkpoint_log_preserves_step_and_device_diagnostics() {
    let checkpoint = wire::dict([
        ("CHECKPOINT_ID", 0x123u64.into()),
        ("CHECKPOINT_NAME", "test_step".into()),
        ("CHECKPOINT_RESULT", 10i64.into()),
        ("CHECKPOINT_COMPLETE", true.into()),
        ("CHECKPOINT_WARNING", "test warning".into()),
        ("CHECKPOINT_ERROR", "test error details".into()),
    ]);
    let mut output = Vec::new();
    log_checkpoint(&checkpoint, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();
    for expected in [
        "Checkpoint completed: id=0x123, name=test_step, result=10",
        "Checkpoint warning: id=0x123, test warning",
        "Checkpoint error: id=0x123, test error details",
    ] {
        assert!(output.contains(expected), "{output}");
    }
}

#[test]
fn malformed_checkpoints_are_still_rejected() {
    let checkpoint = wire::dict([
        ("CHECKPOINT_ID", 0x123u64.into()),
        ("CHECKPOINT_RESULT", 10i64.into()),
    ]);
    for key in ["CHECKPOINT_ID", "CHECKPOINT_RESULT"] {
        let mut missing = checkpoint.clone();
        missing.as_dictionary_mut().unwrap().remove(key);
        assert!(log_checkpoint(&missing, Vec::new()).is_err());
        let mut malformed = checkpoint.clone();
        malformed
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), true.into());
        assert!(log_checkpoint(&malformed, Vec::new()).is_err());
    }
}

fn bootx_error() -> anyhow::Error {
    anyhow::Error::from(std::io::Error::from_raw_os_error(2))
        .context("Apple USB IOCTL 0x2200a0")
        .context("sending iBoot command \"bootx\"")
}

#[test]
fn bootx_usb_failure_requires_a_confirmed_restore_service() {
    let mut attempts = 0;
    let service = confirm_restore_service(Some(bootx_error()), || {
        attempts += 1;
        Ok("validated restored")
    })
    .unwrap();
    assert_eq!(service, "validated restored");
    assert_eq!(attempts, 1);
}

#[test]
fn bootx_failure_preserves_the_usb_error_if_the_service_is_missing_or_wrong() {
    for failure in [
        "no USB multiplex interface found",
        "not the restored service",
        "restore service ECID mismatch",
        "restore service chip mismatch",
        "restore service board mismatch",
    ] {
        let error = confirm_restore_service(Some(bootx_error()), || {
            Err::<(), _>(anyhow::anyhow!(failure))
        })
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(2)
        );
        let message = format!("{error:#}");
        for text in [failure, "bootx", "0x2200a0", "re-enter DFU"] {
            assert!(message.contains(text), "{message}");
        }
    }
}

#[test]
fn accepted_bootx_still_requires_the_restore_service() {
    confirm_restore_service(None, || Ok(())).unwrap();
    let error = confirm_restore_service(None, || {
        Err::<(), _>(anyhow::anyhow!("restore service ECID mismatch"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "restore service ECID mismatch");
}

fn ibss_reset_error() -> anyhow::Error {
    anyhow::Error::from(std::io::Error::from_raw_os_error(2))
        .context("Apple USB IOCTL 0x22000c")
        .context(dfu::ResetFailure)
        .context("uploading iBSS")
}

#[test]
fn ibss_reset_error_continues_only_after_confirmed_recovery() {
    for initial_mode in [None, Some(Mode::Recovery)] {
        let mut attempts = 0;
        let usb = reconnect_after_ibss(Err(ibss_reset_error()), initial_mode, |mode| {
            attempts += 1;
            assert_eq!(mode, Some(Mode::Recovery));
            Ok("connected")
        })
        .unwrap();
        assert_eq!(usb, "connected");
        assert_eq!(attempts, 1);
    }
}

#[test]
fn ibss_missing_recovery_preserves_the_reset_failure() {
    let error = reconnect_after_ibss(Err(ibss_reset_error()), None, |mode| {
        assert_eq!(mode, Some(Mode::Recovery));
        Err::<(), _>(anyhow::anyhow!("device did not reconnect after boot stage"))
    })
    .unwrap_err();
    assert!(error.is::<dfu::ResetFailure>());
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(2)
    );
    let message = format!("{error:#}");
    for text in [
        "re-enter DFU",
        "did not reconnect",
        "uploading iBSS",
        "0x22000c",
    ] {
        assert!(message.contains(text), "{message}");
    }
}

#[test]
fn ibss_transfer_failure_stops_without_waiting_for_recovery() {
    let error = reconnect_after_ibss(
        Err(anyhow::anyhow!("short DFU control write")),
        None,
        |_| -> Result<()> { panic!("must not reconnect after an incomplete upload") },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "short DFU control write");
}

#[test]
fn ibss_success_preserves_the_expected_mode_and_connection_error() {
    for mode in [None, Some(Mode::Recovery)] {
        reconnect_after_ibss(Ok(()), mode, |expected| {
            assert_eq!(expected, mode);
            Ok(())
        })
        .unwrap();
    }
    let error = reconnect_after_ibss(Ok(()), None, |_| {
        Err::<(), _>(anyhow::anyhow!("connection failed"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "connection failed");
    assert!(!error.is::<dfu::ResetFailure>());
}

struct Usb {
    input: VecDeque<Vec<u8>>,
    output: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl PacketTransport for Usb {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
    fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.input.pop_front().context("unexpected packet read")
    }
}
fn tcp(seq: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    tcp_on(1234, 1, seq, flags, data)
}
fn tcp_on(port: u16, local: u16, seq: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut tcp = vec![0; 20];
    tcp[..2].copy_from_slice(&port.to_be_bytes());
    tcp[2..4].copy_from_slice(&local.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&1024u16.to_be_bytes());
    tcp.extend(data);
    mux::encode_packet(6, 2, 1, 0, &tcp).unwrap()
}

fn bytes_on(output: &Arc<Mutex<Vec<Vec<u8>>>>, port: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    for packet in output.lock().unwrap().iter().skip(2) {
        let packet = mux::decode_packet(packet, 2).unwrap();
        if packet.protocol == 6
            && packet.payload.len() > 20
            && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == port
        {
            bytes.extend_from_slice(&packet.payload[20..]);
        }
    }
    bytes
}

struct FileDataUsb {
    input: VecDeque<Vec<u8>>,
    output: Arc<Mutex<Vec<Vec<u8>>>>,
    delay: Duration,
    fail_at: Option<usize>,
    data_packets: usize,
}

impl PacketTransport for FileDataUsb {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.lock().unwrap().push(bytes.to_vec());
        if u32::from_be_bytes(bytes[..4].try_into()?) != 6 {
            return Ok(());
        }
        let packet = mux::decode_packet(bytes, 2)?;
        let tcp = packet.payload;
        let local = u16::from_be_bytes(tcp[..2].try_into()?);
        let port = u16::from_be_bytes(tcp[2..4].try_into()?);
        let seq = u32::from_be_bytes(tcp[4..8].try_into()?);
        if tcp[13] == 2 {
            self.input.push_back(tcp_on(port, local, 0, 0x12, &[]));
        } else if tcp.len() > 20 {
            self.data_packets += 1;
            ensure!(
                self.fail_at != Some(self.data_packets),
                "simulated USB failure"
            );
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            let mut ack = tcp_on(port, local, 1, 0x10, &[]);
            ack[24..28].copy_from_slice(&seq.wrapping_add((tcp.len() - 20) as u32).to_be_bytes());
            self.input.push_back(ack);
        }
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        Ok(self.input.pop_front().unwrap_or_default())
    }
}

fn file_data_session(
    delay: Duration,
    fail_at: Option<usize>,
) -> (Session, Arc<Mutex<Vec<Vec<u8>>>>) {
    let output = Arc::new(Mutex::new(vec![]));
    let session = Session::new(FileDataUsb {
        input: vec![mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()]
            .into(),
        output: output.clone(),
        delay,
        fail_at,
        data_packets: 0,
    })
    .unwrap();
    (session, output)
}

fn verify_file_data(output: &Arc<Mutex<Vec<Vec<u8>>>>, image: &[u8]) -> usize {
    let bytes = bytes_on(output, 1234);
    let mut input = Cursor::new(&bytes);
    let mut offset = 0;
    let mut frames = 0;
    loop {
        let message = wire::receive(&mut input).unwrap();
        if wire::boolean(&message, &["FileDataDone"]) {
            break;
        }
        let data = wire::get(&message, &["FileData"])
            .unwrap()
            .as_data()
            .unwrap();
        assert!(!data.is_empty() && data.len() <= 8192);
        assert_eq!(data, &image[offset..offset + data.len()]);
        offset += data.len();
        frames += 1;
    }
    assert_eq!(offset, image.len());
    assert_eq!(input.position(), bytes.len() as u64);
    frames
}

#[test]
fn file_data_batches_preserve_frames_flush_tails_and_finish_once() {
    for size in [0, 3, 8192, 256 * 1024 + 123] {
        let image: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (session, output) = file_data_session(Duration::ZERO, None);
        let mut stream = session.connect(1234).unwrap();
        let assets = net::AssetClient::default();
        let mut writer =
            FileDataWriter::new(&mut stream, &session, &assets, "test", Some(size as u64));
        if size != 0 {
            let first = size.min(3);
            writer.write_all(&image[..first]).unwrap();
            assert!(!bytes_on(&output, 1234).is_empty());
            writer.write_all(&image[first..]).unwrap();
        }
        writer.flush().unwrap();
        assert!(writer.pending.is_empty());
        let before = bytes_on(&output, 1234);
        writer.flush().unwrap();
        assert_eq!(bytes_on(&output, 1234), before);
        writer.finish().unwrap();
        verify_file_data(&output, &image);
    }
}

#[test]
fn file_data_coalesces_batch_tails_without_changing_frames_or_progress_total() {
    let image: Vec<u8> = (0..2 * 1024 * 1024 + 123)
        .map(|i| (i % 251) as u8)
        .collect();
    let (session, output) = file_data_session(Duration::ZERO, None);
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(
        &mut stream,
        &session,
        &assets,
        "test",
        Some(image.len() as u64),
    );
    writer.write_all(&image).unwrap();
    assert!(!writer.pending.is_empty());
    assert!(writer.pending.len() < FILE_DATA_BATCH);
    assert_eq!(
        writer.profile.bytes + writer.pending_payload,
        image.len() as u64
    );
    assert!(writer.pending_payload <= writer.pending.len() as u64);
    writer.flush().unwrap();
    assert!(writer.pending.is_empty());
    assert_eq!(writer.profile.bytes, image.len() as u64);
    writer.finish().unwrap();
    verify_file_data(&output, &image);

    let packets: Vec<_> = output
        .lock()
        .unwrap()
        .iter()
        .skip(2)
        .filter_map(|bytes| {
            let packet = mux::decode_packet(bytes, 2).unwrap();
            (packet.protocol == 6 && packet.payload.len() > 20).then_some(packet.payload.len() - 20)
        })
        .collect();
    // Full frames terminate with a short USB packet at all supported endpoint
    // sizes, instead of issuing an additional zero-length OUT request.
    for packet_size in [64, 512, 1024] {
        assert!(
            packets[1..packets.len() - 2]
                .iter()
                .all(|&n| !(n + 36).is_multiple_of(packet_size))
        );
    }
    // Only the immediately delivered prefix, the final tail and FileDataDone
    // may be short. Intermediate buffer boundaries create no extra USB calls.
    assert_eq!(
        packets
            .iter()
            .filter(|&&n| n < crate::mux::MAX_PAYLOAD)
            .count(),
        3
    );
    assert!(
        packets[1..packets.len() - 2]
            .iter()
            .all(|&n| n == crate::mux::MAX_PAYLOAD)
    );
}

#[test]
fn aea_key_request_flushes_retained_plist_tail_before_reading_request() {
    let mut request = Vec::new();
    wire::send(&mut request, &wire::dict([("MsgType", "StatusMsg".into())])).unwrap();
    let mut handshake = tcp(0, 0x12, &[]);
    let mut request_packet = tcp(1, 0x10, &request);
    // Leave enough receive window to inspect flushing a retained partial frame
    // without needing a separate simulated ACK producer.
    handshake[30..32].copy_from_slice(&u16::MAX.to_be_bytes());
    request_packet[30..32].copy_from_slice(&u16::MAX.to_be_bytes());
    let output = Arc::new(Mutex::new(Vec::new()));
    let session = Session::new(Usb {
        input: vec![
            mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            handshake,
            request_packet,
            tcp_on(23456, 2, 0, 0x12, &[]),
        ]
        .into(),
        output: output.clone(),
    })
    .unwrap();
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    let image = vec![0x5a; 320 * 1024];
    writer.write_all(&image).unwrap();
    assert!(!writer.pending.is_empty());
    // Another service pumps a late request into this channel. Treat the AEA
    // prefix as already negotiated; no actual key client/network is involved.
    writer.aea = true;
    let _other = session.connect(23456).unwrap();
    assert!(writer.stream.has_pending_input().unwrap());
    // Reject an unrelated request after flushing, so the test observes exactly
    // where a real key exchange starts without mocking the asset client.
    let error = writer.write_all(b"tail").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unexpected AEA message StatusMsg")
    );
    assert!(writer.pending.is_empty());
    assert_eq!(writer.profile.bytes, image.len() as u64 + 4);
    let mut expected = Vec::new();
    for block in image.chunks(8192).chain([b"tail".as_slice()]) {
        wire::send_binary(
            &mut expected,
            &wire::dict([("FileData", Value::Data(block.to_vec()))]),
        )
        .unwrap();
    }
    assert_eq!(bytes_on(&output, 1234), expected);
}

#[test]
fn file_data_failed_batch_is_not_replayed_or_followed_by_done() {
    let (session, output) = file_data_session(Duration::ZERO, Some(3));
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    // First frame succeeds; the following batch fails on its second mux packet.
    writer.write_all(&[0; 8192]).unwrap();
    assert!(writer.write_all(&[0; FILE_DATA_BATCH]).is_err());
    assert!(writer.pending.is_empty());
    let count = output.lock().unwrap().len();
    writer.flush().unwrap();
    assert_eq!(output.lock().unwrap().len(), count);
    drop(writer);
    let bytes = bytes_on(&output, 1234);
    assert!(
        !bytes
            .windows(b"FileDataDone".len())
            .any(|part| part == b"FileDataDone")
    );
}

#[test]
#[ignore = "synthetic FileData benchmark; does not access physical USB or network"]
fn file_data_throughput() {
    let image: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    for readers in [0, 2] {
        let (session, output) = file_data_session(Duration::from_micros(250), None);
        let mut stream = session.connect(1234).unwrap();
        let assets = net::AssetClient::default();
        let mut threads = vec![];
        for port in [62078, 1082].into_iter().take(readers) {
            let mut idle = session.connect(port).unwrap();
            threads.push(thread::spawn(move || {
                let mut byte = [0];
                while idle.read(&mut byte).is_ok() {}
            }));
        }
        let started = Instant::now();
        send_file_data(&mut stream, &session, &assets, "benchmark", &image).unwrap();
        let elapsed = started.elapsed().as_secs_f64();
        session.cancel();
        for thread in threads {
            thread.join().unwrap();
        }
        let frames = verify_file_data(&output, &image);
        let packets = output
            .lock()
            .unwrap()
            .iter()
            .filter(|bytes| {
                if u32::from_be_bytes(bytes[..4].try_into().unwrap()) != 6 {
                    return false;
                }
                let packet = mux::decode_packet(bytes, 2).unwrap();
                packet.protocol == 6
                    && packet.payload.len() > 20
                    && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == 1234
            })
            .count();
        let zlp = output
            .lock()
            .unwrap()
            .iter()
            .skip(2)
            .filter(|bytes| {
                u32::from_be_bytes(bytes[..4].try_into().unwrap()) == 6
                    && bytes.len() > 36
                    && bytes.len().is_multiple_of(512)
            })
            .count();
        println!(
            "FILEDATA_BENCH {}",
            serde_json::json!({
                "idle_readers": readers, "write_delay_microseconds": 250,
                "image_bytes": image.len(), "seconds": elapsed,
                "MiB_per_second": image.len() as f64 / 1048576.0 / elapsed,
                "mux_data_packets": packets, "file_data_frames": frames,
                "modeled_usb_writes": packets + zlp, "modeled_zlp_writes": zlp,
                "modeled_endpoint_packet_size": 512,
                "delays_include_zlp": false,
                "payload_and_frames_verified": true, "real_usb": false,
            })
        );
    }
}

#[test]
fn recorded_final_status_does_not_advertise_socket_eof_on_raw_usb_mux() {
    let captured: Value = serde_json::from_str(include_str!(
        "../fixtures/restored-final-status-26A434.json"
    ))
    .unwrap();
    validate_final_status(&captured).unwrap();
    let output = Arc::new(Mutex::new(vec![]));
    let session = Session::new(Usb {
        input: vec![
            mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tcp_on(RESTORED_PORT, 1, 0, 0x12, &[]),
        ]
        .into(),
        output: output.clone(),
    })
    .unwrap();
    let mut main = session.connect(RESTORED_PORT).unwrap();
    acknowledge_final_status(&mut main).unwrap();
    assert_eq!(
        wire::receive(&mut Cursor::new(bytes_on(&output, RESTORED_PORT))).unwrap(),
        wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())])
    );
    drop(main);
    let sent = output.lock().unwrap();
    assert!(sent.iter().skip(2).all(|b| {
        let p = mux::decode_packet(b, 2).unwrap();
        p.protocol != 6 || p.payload[13] & 1 == 0
    }));
}

#[test]
fn final_ack_waits_for_peer_close_and_drains_trailing_bytes_without_fin() {
    let output = Arc::new(Mutex::new(vec![]));
    let session = Session::new(Usb {
        input: vec![
            mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tcp_on(RESTORED_PORT, 1, 0, 0x12, &[]),
            tcp_on(RESTORED_PORT, 1, 1, 0x10, b"tail"),
            tcp_on(RESTORED_PORT, 1, 5, 0x04, &[]),
        ]
        .into(),
        output: output.clone(),
    })
    .unwrap();
    let mut main = session.connect(RESTORED_PORT).unwrap();
    let previous_timeout = main.read_timeout();
    acknowledge_final_status(&mut main).unwrap();
    wait_for_restore_close(&mut main, &session, Duration::from_secs(1)).unwrap();
    assert_eq!(main.read_timeout(), previous_timeout);
    assert_eq!(main.read(&mut [0; 1]).unwrap(), 0);
    let sent = output.lock().unwrap();
    // No host FIN or RST is sent before we have observed the device close.
    assert!(sent.iter().skip(2).all(|b| {
        let packet = mux::decode_packet(b, 2).unwrap();
        packet.protocol != 6 || packet.payload[13] & 5 == 0
    }));
}

#[test]
fn restore_close_requires_peer_close_or_physical_usb_removal() {
    struct ClosingUsb {
        input: VecDeque<Vec<u8>>,
        removed: bool,
    }
    impl PacketTransport for ClosingUsb {
        fn write_packet(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn read_packet(&mut self) -> Result<Vec<u8>> {
            if let Some(packet) = self.input.pop_front() {
                return Ok(packet);
            }
            if self.removed {
                return Err(nusb::transfer::TransferError::Disconnected.into());
            }
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "device stayed connected").into())
        }
    }
    for removed in [false, true] {
        let session = Session::new(ClosingUsb {
            input: vec![
                mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                tcp_on(RESTORED_PORT, 1, 0, 0x12, &[]),
            ]
            .into(),
            removed,
        })
        .unwrap();
        let mut main = session.connect(RESTORED_PORT).unwrap();
        acknowledge_final_status(&mut main).unwrap();
        let previous_timeout = main.read_timeout();
        let result = wait_for_restore_close(&mut main, &session, Duration::from_secs(1));
        assert_eq!(result.is_ok(), removed, "{result:?}");
        assert_eq!(session.disconnected(), removed);
        assert_eq!(main.read_timeout(), previous_timeout);
    }
}

#[test]
fn aea_public_key_reply_is_local_to_one_fragmented_image_transfer() {
    use base64::Engine;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/fcs-synthetic.json")).unwrap();
    let prefix = base64::engine::general_purpose::STANDARD
        .decode(fixture["prefix"].as_str().unwrap())
        .unwrap();
    let key: [u8; 32] = crate::device::decode_hex(fixture["archive_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut frames = vec![];
    for index in 0..2 {
        let mut request = wire::dict([
            (
                "MsgType",
                if index == 0 {
                    "DataRequestMsg"
                } else {
                    "AsyncDataRequestMsg"
                }
                .into(),
            ),
            ("DataType", "StreamedImageDecryptionKey".into()),
            (
                "Arguments",
                wire::dict([
                    ("ArchiveIdentifier", "ab".repeat(32).into()),
                    ("RequestMethod", "POST".into()),
                    ("RequestURL", "https://wkms.sd.apple.com/key".into()),
                ]),
            ),
        ]);
        if index == 1 {
            request
                .as_dictionary_mut()
                .unwrap()
                .insert("DataPort".into(), 23456u64.into());
        }
        wire::send(&mut frames, &request).unwrap();
    }
    let output = Arc::new(Mutex::new(vec![]));
    let usb = Usb {
        input: vec![
            mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tcp(0, 0x12, &[]),
            tcp(1, 0x10, &frames),
            tcp_on(23456, 2, 0, 0x12, &[]),
        ]
        .into(),
        output: output.clone(),
    };
    let session = Session::new(usb).unwrap();
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    // Simulate a key fetched and authenticated earlier in this transfer.
    // The public metadata still has to be assembled from fragmented data.
    writer.public_key = Some(key);
    writer.write_all(&prefix[..2]).unwrap();
    // Do not attempt an exchange until the AEA header has been received.
    // Network requests are not needed when this transfer's key is cached.
    writer.write_all(&prefix[2..]).unwrap();
    assert_eq!(writer.key_requests, 2);
    assert!(writer.public_fcs.is_some());
    let mut input = Cursor::new(bytes_on(&output, 1234));
    assert_eq!(
        wire::get(&wire::receive(&mut input).unwrap(), &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
        &prefix[..2]
    );
    assert_eq!(
        wire::get(&wire::receive(&mut input).unwrap(), &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
        &prefix[2..]
    );
    for input in [&mut input, &mut Cursor::new(bytes_on(&output, 23456))] {
        let reply = wire::receive(&mut *input).unwrap();
        assert_eq!(
            wire::string(&reply, &["KeySource"]).unwrap(),
            "LocalUnwrapped"
        );
        assert_eq!(
            wire::get(&reply, &["KeyData"]).unwrap().as_data().unwrap(),
            key
        );
        assert_eq!(input.position(), input.get_ref().len() as u64);
    }
    let next_image = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    assert!(next_image.public_key.is_none() && next_image.public_fcs.is_none());
}

#[test]
fn aea_async_asset_replies_use_the_requested_ports_and_image_transfer_continues() {
    let mut frames = Vec::new();
    for (kind, port) in [
        ("URLAsset", 23456u64),
        ("StreamedImageDecryptionKey", 23457),
    ] {
        wire::send_binary(
            &mut frames,
            &wire::dict([
                ("MsgType", "AsyncDataRequestMsg".into()),
                ("DataType", kind.into()),
                ("DataPort", port.into()),
            ]),
        )
        .unwrap();
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let session = Session::new(Usb {
        input: vec![
            mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            tcp(0, 0x12, &[]),
            tcp(1, 0x10, &frames),
            tcp_on(23456, 2, 0, 0x12, &[]),
            tcp_on(23457, 3, 0, 0x12, &[]),
        ]
        .into(),
        output: output.clone(),
    })
    .unwrap();
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    // The AEA prefix has already been sent when these requests arrive.
    let prefix = b"AEA1already transferred prefix";
    wire::send_binary(
        writer.stream,
        &wire::dict([("FileData", Value::Data(prefix.to_vec()))]),
    )
    .unwrap();
    writer.aea = true;
    writer.first = false;
    writer.collecting_prefix = false;
    let responses = [
        wire::dict([
            ("ResponseStatus", 200u64.into()),
            ("ResponseBody", Value::Data(vec![1, 2, 3])),
        ]),
        wire::dict([
            ("KeySource", "Remote".into()),
            ("KeyData", Value::Data(vec![4, 5, 6])),
        ]),
    ];
    let mut count = 0;
    writer
        .key_exchange(|request| {
            assert_eq!(
                wire::string(request, &["DataType"])?,
                if count == 0 {
                    "URLAsset"
                } else {
                    "StreamedImageDecryptionKey"
                }
            );
            let reply = responses[count].clone();
            count += 1;
            Ok(reply)
        })
        .unwrap();
    assert_eq!(count, 2);
    writer.write_all(b"remaining archive bytes").unwrap();
    writer.finish().unwrap();
    for (port, expected) in [23456, 23457].into_iter().zip(responses) {
        let bytes = bytes_on(&output, port);
        assert_eq!(&bytes[4..12], b"bplist00");
        let mut input = Cursor::new(bytes);
        assert_eq!(wire::receive(&mut input).unwrap(), expected);
        assert_eq!(input.position(), input.get_ref().len() as u64);
    }
    let mut input = Cursor::new(bytes_on(&output, 1234));
    for expected in [prefix.as_slice(), b"remaining archive bytes"] {
        let message = wire::receive(&mut input).unwrap();
        assert_eq!(
            wire::get(&message, &["FileData"])
                .unwrap()
                .as_data()
                .unwrap(),
            expected
        );
    }
    assert!(wire::boolean(
        &wire::receive(&mut input).unwrap(),
        &["FileDataDone"]
    ));
    assert_eq!(input.position(), input.get_ref().len() as u64);
}

#[test]
fn aea_rejects_unrelated_or_invalid_async_requests_before_replying() {
    for (kind, port) in [
        ("KernelCache", Some(23456u64.into())),
        ("URLAsset", None),
        ("URLAsset", Some(0u64.into())),
        ("URLAsset", Some(u64::from(RESTORED_PORT).into())),
        ("StreamedImageDecryptionKey", Some(65536u64.into())),
        ("StreamedImageDecryptionKey", Some(true.into())),
    ] {
        let mut request = wire::dict([
            ("MsgType", "AsyncDataRequestMsg".into()),
            ("DataType", kind.into()),
        ]);
        if let Some(port) = port {
            request
                .as_dictionary_mut()
                .unwrap()
                .insert("DataPort".into(), port);
        }
        let mut frame = Vec::new();
        wire::send(&mut frame, &request).unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let session = Session::new(Usb {
            input: vec![
                mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                tcp(0, 0x12, &[]),
                tcp(1, 0x10, &frame),
            ]
            .into(),
            output: output.clone(),
        })
        .unwrap();
        let mut stream = session.connect(1234).unwrap();
        let assets = net::AssetClient::default();
        let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
        let error = writer
            .key_exchange(|_| panic!("invalid request must not call the asset client"))
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains(if kind == "KernelCache" {
                "KernelCache"
            } else {
                "DataPort"
            }),
            "{error}"
        );
        assert!(bytes_on(&output, 1234).is_empty());
        let opened = output
            .lock()
            .unwrap()
            .iter()
            .skip(2)
            .filter(|packet| {
                let packet = mux::decode_packet(packet, 2).unwrap();
                packet.protocol == 6 && packet.payload.len() >= 20 && packet.payload[13] & 2 != 0
            })
            .count();
        assert_eq!(opened, 1); // Only the existing image connection.
    }
}

#[test]
fn aea_handles_multiple_key_requests_and_rejects_unrelated_messages() {
    for kind in ["URLAsset", "StreamedImageDecryptionKey", "StatusMsg"] {
        let mut frames = vec![];
        for index in 0..2u64 {
            wire::send(
                &mut frames,
                &wire::dict([("MsgType", kind.into()), ("index", index.into())]),
            )
            .unwrap();
        }
        let output = Arc::new(Mutex::new(vec![]));
        let usb = Usb {
            input: vec![
                mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
                tcp(0, 0x12, &[]),
                tcp(1, 0x10, &frames),
            ]
            .into(),
            output: output.clone(),
        };
        let session = Session::new(usb).unwrap();
        let mut stream = session.connect(1234).unwrap();
        let assets = net::AssetClient::default();
        let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
        let mut count = 0u64;
        let result = writer.key_exchange(|request| {
            assert_eq!(wire::number(wire::get(request, &["index"])?)?, count);
            count += 1;
            Ok(wire::dict([("ResponseStatus", 200u64.into())]))
        });
        if kind == "StatusMsg" {
            assert!(result.is_err());
            assert_eq!(count, 0);
        } else {
            result.unwrap();
            assert_eq!(count, 2);
            let mut replies = vec![];
            for packet in output.lock().unwrap().iter().skip(2) {
                let decoded = mux::decode_packet(packet, 2).unwrap();
                if decoded.protocol == 6 && decoded.payload.len() > 20 {
                    replies.extend_from_slice(&decoded.payload[20..]);
                }
            }
            let mut replies = Cursor::new(replies);
            for _ in 0..2 {
                assert_eq!(
                    wire::number(
                        wire::get(&wire::receive(&mut replies).unwrap(), &["ResponseStatus"])
                            .unwrap()
                    )
                    .unwrap(),
                    200
                );
            }
        }
    }
}
