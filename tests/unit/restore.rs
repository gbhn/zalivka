use super::boot::{IBootStep, iboot_stage, reconnect_after_ibss};
use super::connection::confirm_restore_service;
use super::file_data::{FILE_DATA_BATCH, FileDataWriter, send_file_data};
use super::keys::{ImagePrefix, key_exchange};
use super::session::{
    acknowledge_final_status, finish_final_status, log_checkpoint, log_progress, operation_weights,
    provisioning_failed, record_message, wait_for_restore_close,
};
use super::*;

#[test]
fn reconnection_rechecks_hardware_and_security_before_sending_firmware() {
    let device =
        DeviceInfo::parse("ECID:1234 CPID:8103 BDID:0a SDOM:01 CPFM:03", Mode::Dfu).unwrap();
    super::boot::validate_reconnected_device(&device, &device).unwrap();
    for changed in [
        "ECID:1235 CPID:8103 BDID:0a SDOM:01 CPFM:03",
        "ECID:1234 CPID:8104 BDID:0a SDOM:01 CPFM:03",
        "ECID:1234 CPID:8103 BDID:0b SDOM:01 CPFM:03",
        "ECID:1234 CPID:8103 BDID:0a SDOM:02 CPFM:03",
        "ECID:1234 CPID:8103 BDID:0a SDOM:01 CPFM:01",
    ] {
        let changed = DeviceInfo::parse(changed, Mode::Recovery).unwrap();
        assert!(super::boot::validate_reconnected_device(&device, &changed).is_err());
    }
}
use crate::dfu;
use crate::mux::Session;
use crate::mux::{self, PacketTransport};
use crate::test_mux::{self, version_packet};
use std::collections::{HashSet, VecDeque};
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::thread;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

#[test]
fn transcript_write_or_flush_failure_does_not_block_final_status_acknowledgement() {
    struct BrokenLog {
        on_flush: bool,
    }
    impl Write for BrokenLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.on_flush {
                Ok(bytes.len())
            } else {
                Err(std::io::Error::other("disk write failed"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("disk flush failed"))
        }
    }
    let status = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0u64.into())]);
    for on_flush in [false, true] {
        let mut log = Some(BrokenLog { on_flush });
        let warning = record_message(&mut log, &status).unwrap();
        assert_eq!(warning.level, crate::logging::Level::Warning);
        assert!(warning.message.contains(if on_flush {
            "disk flush failed"
        } else {
            "disk write failed"
        }));
        assert!(log.is_none());
        assert!(record_message(&mut log, &status).is_none());
        let mut output = Vec::new();
        finish_final_status(&mut output, &status, || Ok(())).unwrap();
        let ack = wire::receive(&mut output.as_slice()).unwrap();
        assert_eq!(
            wire::string(&ack, &["MsgType"]).unwrap(),
            "ReceivedFinalStatusMsg"
        );
    }
    let mut log = Some(Vec::new());
    for _ in 0..2 {
        assert!(record_message(&mut log, &status).is_none());
    }
    let text = String::from_utf8(log.unwrap()).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        assert_eq!(serde_json::from_str::<Value>(line).unwrap(), status);
    }
}

#[test]
fn data_ports_require_explicit_asr_ports_and_keep_all_bounds() {
    use super::data_type::DataType;
    for kind in [
        DataType::Asr,
        DataType::RecoveryAsr,
        DataType::Asset,
        DataType::BuildIdentity,
    ] {
        for port in [
            None,
            Some(0u64.into()),
            Some(23456u64.into()),
            Some(65535u64.into()),
        ] {
            let mut message = wire::dict([] as [(&str, Value); 0]);
            if let Some(port) = port {
                message
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("DataPort".into(), port);
            }
            let explicit = wire::data_port(&message, 0).unwrap();
            let required = matches!(kind, DataType::Asr | DataType::RecoveryAsr);
            if required && explicit == 0 {
                assert!(kind.data_port(&message, false).is_err());
            } else {
                assert_eq!(kind.data_port(&message, false).unwrap(), explicit);
            }
            assert_eq!(kind.data_port(&message, true).is_ok(), explicit != 0);
        }
        for port in [
            (-1i64).into(),
            65536u64.into(),
            true.into(),
            "invalid".into(),
        ] {
            let message = wire::dict([("DataPort", port)]);
            for asynchronous in [false, true] {
                assert!(
                    format!("{:#}", kind.data_port(&message, asynchronous).unwrap_err())
                        .contains("DataPort")
                );
            }
        }
        assert!(
            kind.data_port(
                &wire::dict([("DataPort", u64::from(RESTORED_PORT).into())]),
                true
            )
            .is_err()
        );
    }
}

fn j313_identity() -> Identity {
    Identity::new(
        3,
        serde_json::from_str(include_str!("../fixtures/j313-26A434-iboot.json")).unwrap(),
    )
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
fn global_manifest_paths_preserve_namespaces_from_the_request() {
    let id = j313_identity();
    for (args, expected) in [
        (
            wire::dict([("Variant", "macOS Customer".into())]),
            "Firmware/Manifests/restore/macOS Customer/apticket.j313ap.im4m",
        ),
        (
            wire::dict([("Variant", "cryptex1/macOS Customer".into())]),
            "Firmware/Manifests/restore/cryptex1/macOS Customer/apticket.j313ap.im4m",
        ),
        (
            wire::dict([
                ("Variant", "macOS Customer".into()),
                ("GlobalManifestPrefix", "centauri/centauri".into()),
            ]),
            "Firmware/Manifests/restore/macOS Customer/centauri/centauri.j313ap.im4m",
        ),
    ] {
        let message = wire::dict([("Arguments", args)]);
        assert_eq!(
            images::boot_object_path(&id, "__GlobalManifest__", &message).unwrap(),
            expected
        );
    }
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
fn iboot_steps_depend_on_declared_types_instead_of_component_names() {
    let mut id = j313_identity();
    let before = [stage_transcript(&id, true), stage_transcript(&id, false)];
    let entries = id
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Manifest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    let names = entries.keys().cloned().collect::<Vec<_>>();
    let mut renamed = std::collections::BTreeMap::new();
    for (index, name) in names.into_iter().enumerate() {
        let value = entries.remove(&name).unwrap();
        let new = format!("UnlistedComponent{index:02}");
        entries.insert(new.clone(), value);
        renamed.insert(name, new);
    }
    for (stage1, expected) in [true, false].into_iter().zip(before) {
        let expected = expected
            .into_iter()
            .map(|step| {
                step.strip_prefix("upload ")
                    .map(|name| format!("upload {}", renamed[name]))
                    .unwrap_or(step)
            })
            .collect::<Vec<_>>();
        assert_eq!(stage_transcript(&id, stage1), expected);
    }
    let entries = id
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Manifest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    let dcp = renamed["RestoreDCP"].clone();
    entries
        .get_mut(&dcp)
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("Img4PayloadType");
    assert!(iboot_stage(&id, true).is_err());
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
fn restore_options_reject_unknown_or_malformed_behaviors() {
    let mut id = j313_identity();
    for value in ["".into(), "Unknown".into(), true.into()] {
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("RestoreBehavior".into(), value);
        assert!(id.behavior().is_err());
        assert!(options(&id).is_err());
        assert!(boot_arguments(&id).is_err());
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
            let event = log_progress(&received, |record| output.push(record)).unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].level, crate::logging::Level::Debug);
            assert!(output[0].message.contains("28"));
            assert_eq!(
                event,
                crate::progress::Event::OperationProgress {
                    operation: 28,
                    progress
                }
            );
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
            let error = log_progress(&malformed, |record| output.push(record)).unwrap_err();
            assert!(format!("{error:#}").contains(key), "{error:#}");
            assert!(output.is_empty());
        }
    }
}

#[test]
fn optional_operation_weights_preserve_the_device_ids_without_blocking_restore() {
    let message: Value =
        serde_json::from_str(include_str!("../fixtures/restored-operation-weights.json")).unwrap();
    for binary in [false, true] {
        let mut framed = Vec::new();
        if binary {
            wire::send_binary(&mut framed, &message).unwrap();
        } else {
            wire::send(&mut framed, &message).unwrap();
        }
        let received = wire::receive(&mut std::io::Cursor::new(framed)).unwrap();
        assert_eq!(
            operation_weights(&received).unwrap(),
            crate::progress::Event::OperationWeights {
                weights: vec![
                    (12, 300),
                    (13, 1800),
                    (14, 10),
                    (15, 100),
                    (18, 200),
                    (55, 1000),
                    (81, 225),
                ],
                progresses: vec![],
            }
        );
    }
    let mut missing = message.clone();
    missing
        .as_dictionary_mut()
        .unwrap()
        .remove("OperationWeights");
    assert!(operation_weights(&missing).is_none());
    assert!(log_progress(&missing, |_| {}).is_ok());
    for invalid in [true.into(), (-1i64).into(), "invalid".into()] {
        let mut malformed = message.clone();
        malformed
            .as_dictionary_mut()
            .unwrap()
            .get_mut("OperationWeights")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .get_mut("operation_weights")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("id_13".into(), invalid);
        assert!(operation_weights(&malformed).is_none());
        assert!(log_progress(&malformed, |_| {}).is_ok());
    }
}

#[test]
fn operation_weight_snapshots_preserve_completed_units_and_cap_them_to_the_weight() {
    let mut message: Value =
        serde_json::from_str(include_str!("../fixtures/restored-operation-weights.json")).unwrap();
    message.as_dictionary_mut().unwrap()["OperationWeights"]
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "operation_progresses".into(),
            wire::dict([("id_13", 450u64.into()), ("id_18", 999u64.into())]),
        );
    for binary in [false, true] {
        let mut framed = Vec::new();
        if binary {
            wire::send_binary(&mut framed, &message).unwrap();
        } else {
            wire::send(&mut framed, &message).unwrap();
        }
        let received = wire::receive(&mut std::io::Cursor::new(framed)).unwrap();
        let Some(crate::progress::Event::OperationWeights { progresses, .. }) =
            operation_weights(&received)
        else {
            panic!("missing progress snapshot");
        };
        assert_eq!(progresses, vec![(13, 450), (18, 200)]);
    }
    for value in [
        true.into(),
        wire::dict([("id_13", (-1i64).into())]),
        wire::dict([("unknown_id", 1u64.into())]),
    ] {
        let mut malformed = message.clone();
        malformed.as_dictionary_mut().unwrap()["OperationWeights"]
            .as_dictionary_mut()
            .unwrap()
            .insert("operation_progresses".into(), value);
        assert!(operation_weights(&malformed).is_none());
        assert!(log_progress(&malformed, |_| {}).is_ok());
    }
}

#[test]
fn malformed_checkpoint_completion_is_rejected_before_emitting_progress() {
    let message = wire::dict([
        ("CHECKPOINT_ID", 1u64.into()),
        ("CHECKPOINT_RESULT", 0i64.into()),
        ("CHECKPOINT_COMPLETE", "false".into()),
    ]);
    let mut records = Vec::new();
    let error = log_checkpoint(&message, |record| records.push(record)).unwrap_err();
    assert!(error.to_string().contains("CHECKPOINT_COMPLETE"));
    assert!(records.is_empty());
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
            let event = log_checkpoint(&checkpoint, |record| output.push(record)).unwrap();
            assert_eq!(
                event,
                crate::progress::Event::Checkpoint {
                    name: "unknown".into(),
                    complete,
                }
            );
            let output = output
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
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
    log_checkpoint(&checkpoint, |record| output.push(record)).unwrap();
    assert_eq!(
        output.iter().map(|record| record.level).collect::<Vec<_>>(),
        vec![
            crate::logging::Level::Warning,
            crate::logging::Level::Warning,
            crate::logging::Level::Error
        ]
    );
    let output = output
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Checkpoint completed: id=0x123, name=test_step, result=10",
        "test_step (0x123): test warning",
        "test_step (0x123): test error details",
    ] {
        assert!(output.contains(expected), "{output}");
    }
}

#[test]
fn device_warnings_keep_their_text_and_level_for_every_checkpoint() {
    use crate::logging::Level;
    let checkpoint = wire::dict([
        ("CHECKPOINT_ID", 0x1504u64.into()),
        ("CHECKPOINT_NAME", "update_fdr_ean".into()),
        ("CHECKPOINT_RESULT", 0i64.into()),
        ("CHECKPOINT_COMPLETE", true.into()),
        (
            "CHECKPOINT_WARNING",
            "update_fdr_ean missing data for eCfg.".into(),
        ),
    ]);
    let mut output = Vec::new();
    log_checkpoint(&checkpoint, |record| output.push(record)).unwrap();
    assert_eq!(output[1].level, Level::Warning);
    assert_eq!(
        output[1].message,
        "update_fdr_ean (0x1504): update_fdr_ean missing data for eCfg."
    );

    for (key, value) in [
        ("CHECKPOINT_ID", 0x131au64.into()),
        ("CHECKPOINT_NAME", "another_step".into()),
        ("CHECKPOINT_RESULT", (-1i64).into()),
        ("CHECKPOINT_COMPLETE", false.into()),
        ("CHECKPOINT_ERROR", "FDR validation failed".into()),
        (
            "CHECKPOINT_WARNING",
            "update_fdr_ean missing data for trst.".into(),
        ),
        ("CHECKPOINT_WARNING", "unrecognized FDR warning".into()),
    ] {
        let mut message = checkpoint.clone();
        message
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), value);
        let mut output = Vec::new();
        log_checkpoint(&message, |record| output.push(record)).unwrap();
        assert_eq!(output[1].level, Level::Warning, "{message:?}");
        assert_eq!(
            output[1].message,
            format!(
                "{} (0x{:x}): {}",
                wire::string(&message, &["CHECKPOINT_NAME"]).unwrap(),
                wire::number(wire::get(&message, &["CHECKPOINT_ID"]).unwrap()).unwrap(),
                wire::string(&message, &["CHECKPOINT_WARNING"]).unwrap(),
            )
        );
        if key == "CHECKPOINT_ERROR" {
            assert_eq!(output[2].level, Level::Error);
        }
    }
}

#[test]
fn offline_ucrt_warns_even_when_checkpoints_and_final_status_report_success() {
    let messages: Vec<Value> = include_str!("../fixtures/restored-ucrt-offline-26B123.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for checkpoint in &messages[..2] {
        log_checkpoint(checkpoint, |_| {}).unwrap();
        assert!(provisioning_failed(checkpoint));
        assert_eq!(
            wire::get(checkpoint, &["CHECKPOINT_RESULT"])
                .unwrap()
                .as_signed_integer(),
            Some(0)
        );
    }
    let status = &messages[2];
    let mut output = Vec::new();
    finish_final_status(&mut output, status, || Ok(())).unwrap();
    assert_eq!(
        wire::string(
            &wire::receive(&mut output.as_slice()).unwrap(),
            &["MsgType"]
        )
        .unwrap(),
        "ReceivedFinalStatusMsg"
    );

    let original = &messages[0];
    for (key, value, expected) in [
        ("CHECKPOINT_NAME", "other_step".into(), false),
        ("CHECKPOINT_COMPLETE", false.into(), false),
        ("CHECKPOINT_ERROR", " ".into(), false),
        ("CHECKPOINT_RESULT", (-1i64).into(), true),
    ] {
        let mut checkpoint = original.clone();
        checkpoint
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), value);
        assert_eq!(provisioning_failed(&checkpoint), expected, "{checkpoint:?}");
    }
    let healthy = wire::dict([
        ("CHECKPOINT_NAME", "create_production_dcrt".into()),
        ("CHECKPOINT_COMPLETE", true.into()),
        ("CHECKPOINT_RESULT", 0i64.into()),
    ]);
    assert!(!provisioning_failed(&healthy));
    let mut failed = healthy;
    failed
        .as_dictionary_mut()
        .unwrap()
        .insert("CHECKPOINT_RESULT".into(), (-1i64).into());
    assert!(provisioning_failed(&failed));
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
        assert!(log_checkpoint(&missing, |_| {}).is_err());
        let mut malformed = checkpoint.clone();
        malformed
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), true.into());
        assert!(log_checkpoint(&malformed, |_| {}).is_err());
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
    test_mux::tcp(port, local, seq, 1, flags, data)
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
        input: vec![version_packet()].into(),
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
        if crate::test_support::boolean(&message, &["FileDataDone"]) {
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
            version_packet(),
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
    writer.prefix = ImagePrefix::Aea;
    let _other = session.connect(23456).unwrap();
    assert!(writer.stream.has_pending_input().unwrap());
    // Reject an unrelated request after flushing, so the test observes exactly
    // where a real key exchange starts without mocking the asset client.
    let error = writer.write_all(b"tail").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unexpected AEA data type StatusMsg")
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
    let count = output.lock().unwrap().len();
    assert!(writer.write_all(b"retry").is_err());
    assert!(writer.flush().is_err());
    assert!(writer.finish().is_err());
    assert_eq!(output.lock().unwrap().len(), count);
}

#[test]
fn file_data_failed_batch_is_not_replayed_or_followed_by_done() {
    // Cover both a failed first frame and a partially written batch. The first
    // failure does not cancel the mux session, so the writer must prevent Done.
    for fail_at in [1, 3] {
        let (session, output) = file_data_session(Duration::ZERO, Some(fail_at));
        let mut stream = session.connect(1234).unwrap();
        let assets = net::AssetClient::default();
        let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
        assert!(writer.write_all(&[0; FILE_DATA_BATCH + 8192]).is_err());
        assert!(writer.pending.is_empty());
        let count = output.lock().unwrap().len();
        assert!(writer.write_all(b"retry").is_err());
        assert!(writer.flush().is_err());
        assert!(writer.finish().is_err());
        assert_eq!(output.lock().unwrap().len(), count);
        let bytes = bytes_on(&output, 1234);
        assert!(
            !bytes
                .windows(b"FileDataDone".len())
                .any(|part| part == b"FileDataDone")
        );
    }
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
        input: vec![version_packet(), tcp_on(RESTORED_PORT, 1, 0, 0x12, &[])].into(),
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
fn final_status_attempts_ack_after_worker_failure_and_preserves_the_original_error() {
    let status = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0i64.into())]);
    let mut output = Vec::new();
    let error = finish_final_status(&mut output, &status, || {
        Err(anyhow::anyhow!("asynchronous image transfer failed"))
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "asynchronous image transfer failed");
    assert_eq!(
        wire::receive(&mut Cursor::new(output)).unwrap(),
        wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())])
    );

    for code in [0i64, 6] {
        let status = wire::dict([("MsgType", "StatusMsg".into()), ("Status", code.into())]);
        let mut attempted = false;
        struct BrokenAck<'a>(&'a mut bool);
        impl Write for BrokenAck<'_> {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                *self.0 = true;
                Err(std::io::Error::other("acknowledgement failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = finish_final_status(&mut BrokenAck(&mut attempted), &status, || {
            assert_eq!(code, 0, "failed final status must not wait for workers");
            Err(anyhow::anyhow!("asynchronous image transfer failed"))
        })
        .unwrap_err();
        assert!(attempted);
        assert!(error.to_string().contains(if code == 0 {
            "asynchronous image transfer failed"
        } else {
            "restored failed"
        }));
    }
}

#[test]
fn successful_final_status_requires_workers_and_acknowledgement() {
    let status = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0i64.into())]);
    let mut finished = false;
    let mut output = Vec::new();
    finish_final_status(&mut output, &status, || {
        finished = true;
        Ok(())
    })
    .unwrap();
    assert!(finished);
    assert_eq!(
        wire::receive(&mut Cursor::new(output)).unwrap(),
        wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())])
    );
    assert!(
        finish_final_status(
            &mut std::io::Cursor::new(&mut [0u8; 0][..]),
            &status,
            || Ok(())
        )
        .is_err()
    );
}

#[test]
fn final_ack_waits_for_peer_close_and_drains_trailing_bytes_without_fin() {
    let output = Arc::new(Mutex::new(vec![]));
    let session = Session::new(Usb {
        input: vec![
            version_packet(),
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
            input: vec![version_packet(), tcp_on(RESTORED_PORT, 1, 0, 0x12, &[])].into(),
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

fn public_fcs_fixture() -> (Vec<u8>, [u8; 32]) {
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
    (prefix, key)
}

#[test]
fn aea_fragmented_prefix_collects_metadata_before_caching_a_key() {
    let (prefix, _) = public_fcs_fixture();
    let (session, output) = file_data_session(Duration::ZERO, None);
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    writer.write_all(&prefix[..2]).unwrap();
    assert!(matches!(&writer.prefix, ImagePrefix::Collecting(bytes) if bytes == &prefix[..2]));
    for chunk in prefix[2..].chunks(7) {
        writer.write_all(chunk).unwrap();
    }
    assert!(matches!(
        writer.prefix,
        ImagePrefix::Public { key: None, .. }
    ));
    assert_eq!(writer.key_requests, 0);
    writer.finish().unwrap();
    verify_file_data(&output, &prefix);
}

#[test]
fn aea_public_key_reply_is_bound_to_one_image_transfer() {
    let (prefix, key) = public_fcs_fixture();
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
            version_packet(),
            tcp(0, 0x12, &[]),
            tcp(1, 0x10, &frames),
            tcp_on(23457, 2, 0, 0x12, &[]),
            tcp_on(23456, 3, 0, 0x12, &[]),
        ]
        .into(),
        output: output.clone(),
    };
    let session = Session::new(usb).unwrap();
    let mut stream = session.connect(1234).unwrap();
    let assets = net::AssetClient::default();
    let mut writer = FileDataWriter::new(&mut stream, &session, &assets, "test", None);
    writer.write_all(&prefix[..2]).unwrap();
    assert!(matches!(&writer.prefix, ImagePrefix::Collecting(bytes) if bytes == &prefix[..2]));
    // Simulate already authenticated metadata and its key. A key can only be
    // cached together with this image's public FCS metadata, never on its own.
    let crate::aea::Prefix::Public(fcs) = crate::aea::PublicFcs::from_prefix(&prefix).unwrap()
    else {
        panic!("fixture has no public FCS metadata")
    };
    writer.prefix = ImagePrefix::Public {
        fcs,
        key: Some(key),
    };
    // A second channel receives the queued requests while the file continues.
    let _other = session.connect(23457).unwrap();
    writer.write_all(&prefix[2..]).unwrap();
    assert_eq!(writer.key_requests, 2);
    assert!(matches!(
        writer.prefix,
        ImagePrefix::Public { key: Some(_), .. }
    ));
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
    assert!(matches!(next_image.prefix, ImagePrefix::Collecting(_)));
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
            version_packet(),
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
    writer.prefix = ImagePrefix::Aea;
    writer.profile.bytes = prefix.len() as u64;
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
    key_exchange(
        writer.stream,
        &session,
        &mut writer.key_requests,
        |request| {
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
        },
    )
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
    assert!(crate::test_support::boolean(
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
            input: vec![version_packet(), tcp(0, 0x12, &[]), tcp(1, 0x10, &frame)].into(),
            output: output.clone(),
        })
        .unwrap();
        let mut stream = session.connect(1234).unwrap();
        let error = key_exchange(&mut stream, &session, &mut 0, |_| {
            panic!("invalid request must not call the asset client")
        })
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
            input: vec![version_packet(), tcp(0, 0x12, &[]), tcp(1, 0x10, &frames)].into(),
            output: output.clone(),
        };
        let session = Session::new(usb).unwrap();
        let mut stream = session.connect(1234).unwrap();
        let mut count = 0u64;
        let result = key_exchange(&mut stream, &session, &mut 0, |request| {
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
