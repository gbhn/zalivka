use super::*;

#[test]
fn ftab_roundtrip_preserves_entries_and_rejects_bad_offsets() {
    use zalivka::firmware::Ftab;
    let mut header = [0; 48];
    header[..4].copy_from_slice(&1u32.to_le_bytes());
    header[4..8].fill(255);
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let table = Ftab {
        header,
        entries: vec![(*b"rkos", vec![1, 2, 3], 0), (*b"rrko", vec![4, 5], 7)],
    };
    let bytes = table.encode().unwrap();
    let parsed = Ftab::parse(&bytes).unwrap();
    assert_eq!(parsed.entries, table.entries);
    assert_eq!(parsed.encode().unwrap(), bytes);
    // A streaming reader has the complete index, without the payload bytes.
    assert_eq!(
        zalivka::firmware::payload_ranges(&bytes[..80], bytes.len() as u64).unwrap(),
        [80..83, 83..85]
    );
    let rejects = |bad: &[u8]| {
        assert!(Ftab::parse(bad).is_err());
        assert!(zalivka::firmware::payload_ranges(bad, bad.len() as u64).is_err());
    };
    let mut bad = bytes.clone();
    bad[52..56].copy_from_slice(&u32::MAX.to_le_bytes());
    rejects(&bad);
    let mut bad = bytes.clone();
    bad[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    rejects(&bad);
    let mut bad = bytes.clone();
    let first_offset = u32::from_le_bytes(bad[52..56].try_into().unwrap());
    bad[68..72].copy_from_slice(&(first_offset + 1).to_le_bytes());
    rejects(&bad);
    let mut bad = bytes;
    bad[64..68].copy_from_slice(b"rkos");
    rejects(&bad);
}

#[test]
fn container_indexes_must_fit_the_declared_file_even_without_payloads() {
    use zalivka::firmware::{Ftab, payload_ranges};
    let mut header = [0; 48];
    header[36..40].copy_from_slice(b"ftab");
    let mut table = Ftab {
        header,
        entries: vec![],
    };
    let bytes = table.encode().unwrap();
    assert!(payload_ranges(&bytes, 48).unwrap().is_empty());
    assert!(payload_ranges(&bytes, 47).is_err());
    table.header[36..40].fill(0);
    assert!(table.encode().is_err());

    let mut uarp = vec![0; 44];
    uarp[..4].copy_from_slice(&3u32.to_be_bytes());
    uarp[4..8].copy_from_slice(&44u32.to_be_bytes());
    uarp[36..40].copy_from_slice(&44u32.to_be_bytes());
    assert!(payload_ranges(&uarp, 44).unwrap().is_empty());
    assert!(payload_ranges(&uarp, 43).is_err());
    uarp[36..40].copy_from_slice(&43u32.to_be_bytes());
    assert!(payload_ranges(&uarp, 44).is_err());
    uarp[36..40].copy_from_slice(&44u32.to_be_bytes());
    uarp[40..44].copy_from_slice(&40u32.to_be_bytes());
    assert!(payload_ranges(&uarp, 84).is_err()); // The index is not in the prefix yet.
}

#[test]
fn nested_payloads_keep_their_parsed_tags_when_layout_entries_change_order() {
    use zalivka::firmware::payload_ranges;
    let mut layout = centauri_table(vec![(*b"msww", vec![], 0)]);
    layout[52..56].copy_from_slice(&640u32.to_le_bytes());
    layout[56..60].copy_from_slice(&0x20_0000u32.to_le_bytes());
    let nested = centauri_table(vec![(*b"rkos", vec![1, 2, 3], 0)]);
    for entries in [
        vec![(*b"2ftb", layout.clone(), 0), (*b"FIRM", nested.clone(), 0)],
        vec![(*b"FIRM", nested.clone(), 0), (*b"2ftb", layout.clone(), 0)],
    ] {
        let nested_index = entries
            .iter()
            .position(|entry| entry.0 == *b"FIRM")
            .unwrap();
        let bytes = centauri_table(entries);
        let mut expected = payload_ranges(&bytes[..80], bytes.len() as u64).unwrap();
        let start = expected[nested_index].start + 64;
        expected.push(start..start + 3);
        assert_eq!(
            payload_ranges(&bytes, bytes.len() as u64).unwrap(),
            expected
        );
    }
}

#[test]
fn se_update_selects_production_hashes_and_requires_the_requested_ticket() {
    let fixture = fixture(None, false);
    let mut ipsw = Ipsw::open(fixture.path()).unwrap();
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "SE,UpdatePayload".into(),
        wire::dict([
            ("ProductionCMAC", Value::Data(vec![1])),
            ("DevelopmentCMAC", Value::Data(vec![2])),
            ("Info", wire::dict([("Path", "Firmware/iBSS".into())])),
        ]),
    );
    let args = updater_args(
        "SE",
        wire::dict([
            ("SE,ChipID", 0x73u64.into()),
            ("SE,ID", Value::Data(vec![1])),
            ("SE,Nonce", Value::Data(vec![2])),
            ("SE,RootKeyIdentifier", Value::Data(vec![3])),
        ]),
        &["SE,Ticket", "FirmwareData"],
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert!(wire::get(&update.request, &["SE,UpdatePayload", "DevelopmentCMAC"]).is_err());
    assert!(wire::get(&update.request, &["SE,UpdatePayload", "ProductionCMAC"]).is_ok());
    let response = update
        .finish(wire::dict([("SE,Ticket", Value::Data(vec![1]))]))
        .unwrap();
    assert_eq!(
        wire::get(&response, &["FirmwareData"])
            .unwrap()
            .as_data()
            .unwrap(),
        im4p(b"test")
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert!(
        update
            .finish(wire::dict([("OtherTicket", true.into())]))
            .is_err()
    );
}

#[test]
fn rose_update_merges_restore_rtkit_and_preserves_device_request() {
    use zalivka::firmware::Ftab;
    let mut header = [0; 48];
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let base = Ftab {
        header,
        entries: vec![(*b"rkos", vec![1, 2], 0), (*b"rrko", vec![3], 0)],
    }
    .encode()
    .unwrap();
    let restore = Ftab {
        header,
        entries: vec![(*b"rrko", vec![4, 5, 6], 9)],
    }
    .encode()
    .unwrap();
    let mut id = identity();
    let manifest = manifest_mut(&mut id);
    manifest.insert(
        "Rap,RTKitOS".into(),
        component_entry("Firmware/rose", &base),
    );
    manifest.insert(
        "Rap,RestoreRTKitOS".into(),
        component_entry("Firmware/rose-restore", &restore),
    );
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[
            ("Firmware/rose", &base),
            ("Firmware/rose-restore", &restore),
        ],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = updater_args(
        "Rose",
        wire::dict([
            ("Rap,ECID", 123u64.into()),
            ("Rap,Nonce", Value::Data(vec![1, 2, 3])),
        ]),
        &["Rap,Ticket", "FirmwareData"],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("Rap,ECID", 456u64.into())]),
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert_eq!(
        wire::get(&update.request, &["Rap,ECID"]).unwrap(),
        &456u64.into()
    );
    assert!(wire::get(&update.request, &["Rap,RTKitOS", "Info"]).is_err());
    assert!(wire::boolean(&update.request, &["@Rap,Ticket"]));
    let response = update
        .finish(wire::dict([("Rap,Ticket", Value::Data(vec![42]))]))
        .unwrap();
    let payload = wire::get(&response, &["FirmwareData"])
        .unwrap()
        .as_data()
        .unwrap();
    let table = Ftab::parse(payload).unwrap();
    assert_eq!(
        table.entries,
        [(*b"rkos", vec![1, 2], 0), (*b"rrko", vec![4, 5, 6], 9)]
    );
}

#[test]
fn bmu_update_serializes_firmware_map_with_manifest_digest() {
    let map = wire::dict([("controller", "test-bmu".into())]);
    let bytes = wire::xml(&map).unwrap();
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("BMU,BoardID".into(), 9u64.into());
    manifest_mut(&mut id).insert(
        "BMU,FirmwareMap".into(),
        component_entry("Firmware/bmu", &bytes),
    );
    let file = fixture_files(Some(id.clone()), false, &[("Firmware/bmu", &bytes)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let args = updater_args(
        "T200",
        wire::dict([
            ("ChipID", 0x42u64.into()),
            ("Nonce", Value::Data(vec![1, 2])),
            ("ProductionMode", true.into()),
            ("UniqueID", 1234u64.into()),
        ]),
        &["BMU,Ticket", "FirmwareData"],
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert!(wire::boolean(&update.request, &["@BMU,Ticket"]));
    assert_eq!(
        wire::get(&update.request, &["BMU,ChipID"]).unwrap(),
        &0x42u64.into()
    );
    assert_eq!(
        wire::get(&update.request, &["BMU,BoardID"]).unwrap(),
        &9u64.into()
    );
    let response = update
        .finish(wire::dict([("BMU,Ticket", Value::Data(vec![42]))]))
        .unwrap();
    let payload = wire::get(&response, &["FirmwareData"])
        .unwrap()
        .as_data()
        .unwrap();
    assert!(payload.starts_with(b"bplist00"));
    let map = Value::from_reader(Cursor::new(payload)).unwrap();
    assert_eq!(wire::string(&map, &["controller"]).unwrap(), "test-bmu");
    assert_eq!(
        wire::get(&map, &["fw_map_digest"])
            .unwrap()
            .as_data()
            .unwrap(),
        Sha384::digest(&bytes).as_slice()
    );
}

#[test]
fn se2_request_does_not_also_request_se1_ticket() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = updater_args(
        "SE",
        wire::dict([
            ("SE,ChipID", 0x73u64.into()),
            ("SE,ID", Value::Data(vec![1])),
            ("SE,Nonce", Value::Data(vec![2])),
            ("SE,RootKeyIdentifier", Value::Data(vec![3])),
        ]),
        &["SE2,Ticket"],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("@SE2,Ticket", true.into())]),
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(wire::boolean(&update.request, &["@SE2,Ticket"]));
    assert!(wire::get(&update.request, &["@SE,Ticket"]).is_err());
}

#[test]
fn cryptex_request_keeps_device_generated_personalization_tags() {
    let fixture = fixture(None, false);
    let mut ipsw = Ipsw::open(fixture.path()).unwrap();
    let mut args = updater_args(
        "Cryptex1",
        wire::dict([("Cryptex1,Nonce", Value::Data(vec![1, 2, 3]))]),
        &["Cryptex1,Ticket"],
    );
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Cryptex1,Version".into(), 3u64.into());
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(wire::boolean(&update.request, &["@Cryptex1,Ticket"]));
    assert_eq!(
        wire::get(&update.request, &["Cryptex1,Version"]).unwrap(),
        &3u64.into()
    );
    assert_eq!(
        wire::number(wire::get(&update.request, &["ApChipID"]).unwrap()).unwrap(),
        0x8103
    );
    assert!(
        update
            .finish(wire::dict([("Cryptex1,Ticket", Value::Data(vec![42]))]))
            .is_ok()
    );
}

#[test]
fn updater_v2_validates_signing_requests_and_v3_is_a_capability_marker() {
    let file = fixture(None, false);
    let mut state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let mut args = modern_updater_args("NewController");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("ResponseTags");
    // Neither version may submit an incomplete signing request or send any
    // firmware. The V2 request must reach the same schema validation as V1.
    for kind in ["FirmwareUpdaterData", "FirmwareUpdaterDataV2"] {
        assert!(wire::get(&restore::supported_data_types(), &[kind]).is_ok());
        let message = wire::dict([("DataType", kind.into()), ("Arguments", args.clone())]);
        let error = state.serve(&session, &mut main, &message).unwrap_err();
        assert_eq!(error.to_string(), "modern updater has no ResponseTags");
    }
    assert!(mux_output(&output, 62078).get_ref().is_empty());
    assert!(wire::boolean(
        &restore::supported_data_types(),
        &["FirmwareUpdaterDataV3"]
    ));
    let message = wire::dict([
        ("DataType", "FirmwareUpdaterDataV3".into()),
        ("Arguments", modern_updater_args("NewController")),
    ]);
    assert!(
        state
            .serve(&session, &mut main, &message)
            .unwrap_err()
            .to_string()
            .contains("unsupported restored DataType FirmwareUpdaterDataV3")
    );
}

#[test]
fn modern_updaters_use_requested_manifest_tags_and_device_generated_fields_without_legacy_requirements()
 {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("RequiresUIDMode".into(), true.into());
    for name in [
        "SE",
        "AppleTCON",
        "AppleTypeCRetimer",
        "PS190",
        "Ace3",
        "Centauri",
        "NewController",
    ] {
        let args = modern_updater_args(name);
        let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
        assert!(wire::boolean(&update.request, &["@Controller,Ticket"]));
        assert!(wire::boolean(&update.request, &["@BBTicket"]));
        assert!(!wire::boolean(&update.request, &["ApProductionMode"]));
        assert_eq!(
            wire::number(wire::get(&update.request, &["ApECID"]).unwrap()).unwrap(),
            123
        );
        assert_eq!(
            wire::number(wire::get(&update.request, &["ApChipID"]).unwrap()).unwrap(),
            0x8112
        );
        assert!(
            wire::get(&update.request, &["ApBoardID"])
                .unwrap()
                .as_unsigned_integer()
                .is_some()
        );
        assert_eq!(
            wire::get(&update.request, &["UniqueBuildID"]).unwrap(),
            wire::get(&id.value, &["UniqueBuildID"]).unwrap()
        );
        for excluded in [
            "RequiresUIDMode",
            "Manifest",
            "Info",
            "UnrequestedInfo",
            "@SE,Ticket",
            "@Baobab,Ticket",
        ] {
            assert!(
                wire::get(&update.request, &[excluded]).is_err(),
                "{name}: {excluded}"
            );
        }
        assert!(update.firmware.is_none());
        update
            .finish(wire::dict([("Controller,Ticket", Value::Data(vec![42]))]))
            .unwrap();
    }
}

#[test]
fn canary_v3_self_test_roundtrips_both_loops_without_tss_or_binary_chunking() {
    for query in [true, false] {
        for modern in [true, false] {
            let file = fixture(None, false);
            let mut state = restore_state(file.path());
            let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
            let session = Session::new(usb).unwrap();
            let mut stream = session.connect(62078).unwrap();
            let mut args = wire::dict([
                ("MessageArgType", "FirmwareResponseData".into()),
                ("MessageArgUpdaterName", "Canary".into()),
                ("MessageArgInfo", wire::dict([("QueryLoop0", query.into())])),
                ("DataChunkSize", 1u64.into()),
            ]);
            if modern {
                args.as_dictionary_mut().unwrap().extend(
                    wire::dictionary(&wire::dict([
                        (
                            "DeviceGeneratedRequest",
                            wire::dict([("QueryLoop0", query.into())]),
                        ),
                        (
                            "DeviceGeneratedTags",
                            wire::dict([
                                (
                                    "BuildIdentityTags",
                                    Value::Array(vec!["TestFirmware".into()]),
                                ),
                                (
                                    "ResponseTags",
                                    Value::Array(vec![
                                        "Test,Ticket,1".into(),
                                        "Test,Ticket,2".into(),
                                    ]),
                                ),
                                (
                                    "LoopInstance",
                                    if query { "InstanceA" } else { "InstanceB" }.into(),
                                ),
                            ]),
                        ),
                    ]))
                    .unwrap()
                    .clone(),
                );
            }
            state
                .serve(
                    &session,
                    &mut stream,
                    &wire::dict([
                        ("DataType", "FirmwareUpdaterData".into()),
                        ("Arguments", args),
                    ]),
                )
                .unwrap();
            let mut wire_data = mux_output(&output, 62078);
            let response = wire::receive(&mut wire_data).unwrap();
            let test = [if query { 1 } else { 2 }; 4];
            assert_eq!(
                wire::get(
                    &response,
                    &["FirmwareResponseData", "Test,Ticket,1", "Test,Ticket,1"]
                )
                .unwrap()
                .as_data()
                .unwrap(),
                test
            );
            assert_eq!(
                wire::get(&response, &["FirmwareResponseData", "Test,Ticket,2"])
                    .unwrap()
                    .as_data()
                    .unwrap(),
                test
            );
            for name in ["FirmwareEntry1", "FirmwareEntry2"] {
                assert_eq!(
                    wire::string(&response, &["FirmwareResponseData", "FirmwareData", name])
                        .unwrap(),
                    "PlaceholderData"
                );
            }
            assert_eq!(wire_data.position(), wire_data.get_ref().len() as u64);
        }
    }
}

#[test]
fn canary_cannot_return_test_tickets_under_production_tag_names() {
    let mut args = updater_args(
        "Canary",
        wire::dict([("QueryLoop0", true.into())]),
        &["ApImg4Ticket"],
    );
    assert!(zalivka::firmware::canary_response(&args).is_err());
    args.as_dictionary_mut()
        .unwrap()
        .remove("DeviceGeneratedTags");
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("QueryLoop0", false.into())]),
    );
    assert!(zalivka::firmware::canary_response(&args).is_err());
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("QueryLoop0", "not a boolean".into())]),
    );
    assert!(zalivka::firmware::canary_response(&args).is_err());
}

#[test]
fn ps190_builds_structured_payload_for_the_selected_controller() {
    let mut id = identity();
    for n in [1, 2] {
        manifest_mut(&mut id).insert(
            format!("PCON{n},Firmware"),
            component_entry(&format!("pcon{n}.bin"), &[n]),
        );
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(format!("PCON{n},BoardID"), (100u64 + n as u64).into());
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(format!("PCON{n},SecurityDomain"), 1u64.into());
    }
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("pcon1.bin", &[1]), ("pcon2.bin", &[2])],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = updater_args(
        "PS190",
        wire::dict([(
            "InfoArray",
            Value::Array(vec![
                wire::dict([
                    ("TagNumber", 1u64.into()),
                    ("TicketName", "PCON1,Ticket".into()),
                ]),
                wire::dict([
                    ("TagNumber", 2u64.into()),
                    ("TicketName", "PCON2,Ticket".into()),
                ]),
            ]),
        )]),
        &["PCON2,Ticket", "FirmwareData"],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([
            ("PCON1,Firmware", wire::dict([] as [(&str, Value); 0])),
            ("PCON2,Firmware", wire::dict([] as [(&str, Value); 0])),
        ]),
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    let response = update
        .finish(wire::dict([("PCON2,Ticket", Value::Data(vec![42]))]))
        .unwrap();
    assert_eq!(
        wire::get(&response, &["FirmwareData", "FirmwareData"])
            .unwrap()
            .as_data()
            .unwrap(),
        &[2]
    );
    assert_eq!(
        wire::number(wire::get(&response, &["FirmwareData", "BoardID"]).unwrap()).unwrap(),
        102
    );
    assert_eq!(
        wire::number(wire::get(&response, &["FirmwareData", "SecurityDomain"]).unwrap()).unwrap(),
        1
    );
    let mut output = Vec::new();
    zalivka::firmware::send_response(
        &mut output,
        response.clone(),
        &wire::dict([("DataChunkSize", 1u64.into())]),
    )
    .unwrap();
    let mut cursor = Cursor::new(output);
    assert_eq!(
        wire::get(
            &wire::receive(&mut cursor).unwrap(),
            &["FirmwareResponseData"]
        )
        .unwrap(),
        &response
    );
    assert_eq!(cursor.position(), cursor.get_ref().len() as u64);
    let mut fallback = args.clone();
    fallback.as_dictionary_mut().unwrap().insert(
        "MessageArgInfo".into(),
        wire::dict([] as [(&str, Value); 0]),
    );
    // Without InfoArray, exactly one known PCON component must be requested.
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &fallback).is_err());
    fallback.as_dictionary_mut().unwrap()["DeviceGeneratedRequest"]
        .as_dictionary_mut()
        .unwrap()
        .remove("PCON1,Firmware");
    let payload = zalivka::firmware::prepare(&mut ipsw, &id, &fallback)
        .unwrap()
        .firmware
        .unwrap();
    assert_eq!(
        wire::get(&payload, &["FirmwareData"]).unwrap().as_data(),
        Some(&[2][..])
    );
    fallback.as_dictionary_mut().unwrap()["DeviceGeneratedRequest"]
        .as_dictionary_mut()
        .unwrap()
        .remove("PCON2,Firmware");
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &fallback).is_err());
    id.value
        .as_dictionary_mut()
        .unwrap()
        .remove("PCON2,BoardID");
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
}

#[test]
fn ace3_manifest_prefix_selects_one_controller_and_rejects_ambiguous_prefixes() {
    let mut id = identity();
    for n in [1, 2] {
        manifest_mut(&mut id).insert(
            format!("USBPortController{n},USBFirmware"),
            component_entry(&format!("usbc{n}.bin"), &[n]),
        );
    }
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("usbc1.bin", &[1]), ("usbc2.bin", &[2])],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = updater_args(
        "Ace3",
        wire::dict([("ManifestPrefix", "USBPortController2,".into())]),
        &["USBPortController2,Ticket", "FirmwareData"],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([
            (
                "USBPortController1,USBFirmware",
                wire::dict([] as [(&str, Value); 0]),
            ),
            (
                "USBPortController2,USBFirmware",
                wire::dict([] as [(&str, Value); 0]),
            ),
        ]),
    );
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert_eq!(update.firmware.unwrap().as_data().unwrap(), &[2]);
    for prefix in ["USBPortController", "USBPortController3,"] {
        args.as_dictionary_mut().unwrap().insert(
            "MessageArgInfo".into(),
            wire::dict([("ManifestPrefix", prefix.into())]),
        );
        assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
    }
}

#[test]
fn modern_updaters_reject_malformed_tags_and_honor_explicit_production_overrides() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let id = identity();
    for mode in [Value::Boolean(false), true.into(), 0u64.into(), 1u64.into()] {
        let mut args = modern_updater_args("SE");
        args.as_dictionary_mut()
            .unwrap()
            .get_mut("MessageArgInfo")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Controller,ProductionMode".into(), mode.clone());
        let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
        assert_eq!(
            wire::boolean(&update.request, &["ApProductionMode"]),
            mode.as_boolean()
                .unwrap_or(mode.as_unsigned_integer() == Some(1))
        );
    }
    for invalid in [Value::Boolean(true), Value::Array(vec![true.into()])] {
        let mut args = modern_updater_args("SE");
        args.as_dictionary_mut()
            .unwrap()
            .get_mut("DeviceGeneratedTags")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("BuildIdentityTags".into(), invalid);
        assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
    }
    let mut args = modern_updater_args("SE");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("MessageArgInfo")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Another,ProductionMode".into(), true.into());
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("ApProductionMode".into(), false.into());
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    assert!(!wire::boolean(&update.request, &["ApProductionMode"]));
    args.as_dictionary_mut()
        .unwrap()
        .remove("DeviceGeneratedRequest");
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
    let mut args = modern_updater_args("SE");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("ResponseTags");
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &args).is_err());
}

#[test]
fn centauri_layout_index_is_hashable_without_treating_device_addresses_as_file_offsets() {
    let mut layout = centauri_table(vec![(*b"msww", vec![], 0)]);
    layout[52..56].copy_from_slice(&640u32.to_le_bytes());
    layout[56..60].copy_from_slice(&0x20_0000u32.to_le_bytes());
    let original = centauri_table(vec![(*b"rkos", vec![1, 2, 3], 0), (*b"2ftb", layout, 0)]);
    let ranges = zalivka::firmware::payload_ranges(&original, original.len() as u64).unwrap();
    assert_eq!(ranges.len(), 2);
    let firmware = &original[ranges[0].start as usize..ranges[0].end as usize];
    assert_eq!(firmware, &[1, 2, 3]);
    // Exercise the same component digest path used with the actual IPSW.
    let mut id = identity();
    let mut entry = component_entry("centauri.bin", &original);
    entry.as_dictionary_mut().unwrap().insert(
        "Digest".into(),
        Value::Data(Sha384::digest(firmware).to_vec()),
    );
    manifest_mut(&mut id).insert("Wireless1,RTKitOS".into(), entry);
    let file = fixture_files(Some(id.clone()), false, &[("centauri.bin", &original)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(ipsw.component(&id, "Wireless1,RTKitOS").unwrap(), original);
}

#[test]
fn centauri_response_patches_only_nonce_and_validity_and_uses_chunk_framing() {
    let mut original = centauri_table(vec![(*b"rkos", vec![0, 1, 2, 255], 7)]);
    // Preserve intentional alignment padding, trailing bytes, index metadata,
    // and every byte of the actual firmware payload.
    original.splice(64..64, [0x5a; 7]);
    original[52..56].copy_from_slice(&71u32.to_le_bytes());
    original.extend_from_slice(b"trailing-data");
    let nonce = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let response = centauri_response(
        &original,
        wire::dict([
            ("Wireless1,ChipRev", Value::Data(vec![0x11, 0])),
            ("Wireless1,RestoreBootNonce", Value::Data(nonce.to_vec())),
        ]),
    )
    .unwrap();
    let mut expected = original;
    expected[4..8].copy_from_slice(&1u32.to_le_bytes());
    expected[8..16].copy_from_slice(&nonce);
    assert_eq!(
        wire::get(&response, &["FirmwareData"])
            .unwrap()
            .as_data()
            .unwrap(),
        expected
    );
    let mut output = Vec::new();
    zalivka::firmware::send_response(
        &mut output,
        response,
        &wire::dict([("DataChunkSize", 9u64.into())]),
    )
    .unwrap();
    let mut input = Cursor::new(output);
    let first = wire::receive(&mut input).unwrap();
    assert_eq!(
        wire::number(wire::get(&first, &["DataSize"]).unwrap()).unwrap(),
        expected.len() as u64
    );
    assert_eq!(
        wire::get(&first, &["FirmwareResponseData", "Wireless1,Ticket"])
            .unwrap()
            .as_data()
            .unwrap(),
        &[42]
    );
    let mut received = Vec::new();
    loop {
        let message = wire::receive(&mut input).unwrap();
        let data = wire::get(&message, &["FirmwareResponseData"])
            .unwrap()
            .as_data()
            .unwrap();
        assert!(data.len() <= 9);
        if wire::boolean(&message, &["DataDone"]) {
            assert!(data.is_empty());
            break;
        }
        received.extend_from_slice(data);
    }
    assert_eq!(received, expected);
    assert_eq!(input.position(), input.get_ref().len() as u64);
}

#[test]
fn centauri_selects_exact_embedded_revision_then_family_then_outer_table() {
    let exact = centauri_table(vec![(*b"rkos", vec![1], 0)]);
    let family = centauri_table(vec![(*b"rkos", vec![2], 0)]);
    let outer = centauri_table(vec![
        (*b"rkos", vec![3], 0),
        (*b"_b1f", exact, 0),
        (*b"_bxf", family, 0),
    ]);
    for (revision, expected) in [
        (0x11u16, 1),
        (0x0111, 1),
        (0x10, 2),
        (0x15, 2),
        (0x20, 3),
        (0xffff, 3),
        (0x40, 3),
        (0x1f, 3),
    ] {
        let response = centauri_response(
            &outer,
            wire::dict([
                (
                    "Wireless1,ChipRev",
                    Value::Data(revision.to_le_bytes().to_vec()),
                ),
                ("Wireless1,RestoreBootNonce", Value::Data(vec![7; 8])),
            ]),
        )
        .unwrap();
        let table = zalivka::firmware::Ftab::parse(
            wire::get(&response, &["FirmwareData"])
                .unwrap()
                .as_data()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(table.entries[0].1, [expected]);
        assert_eq!(&table.header[8..16], &[7; 8]);
    }
}

#[test]
fn centauri_keeps_existing_boot_nonce_when_device_does_not_replace_it() {
    let mut bytes = centauri_table(vec![(*b"rkos", vec![3], 0)]);
    bytes[8..16].copy_from_slice(&[9; 8]);
    for nonce in [
        None,
        Some(Value::Data(vec![0; 8])),
        Some(Value::Data(vec![5; 8])),
    ] {
        let mut info = wire::dict([("Wireless1,ChipRev", Value::Data(vec![0xff; 2]))]);
        if let Some(nonce) = nonce.clone() {
            info.as_dictionary_mut()
                .unwrap()
                .insert("Wireless1,RestoreBootNonce".into(), nonce);
        }
        let response = centauri_response(&bytes, info).unwrap();
        let out = wire::get(&response, &["FirmwareData"])
            .unwrap()
            .as_data()
            .unwrap();
        assert_eq!(
            &out[8..16],
            if nonce == Some(Value::Data(vec![5; 8])) {
                &[5; 8]
            } else {
                &[9; 8]
            }
        );
    }
}

#[test]
fn centauri_rejects_bad_revision_nonce_and_embedded_firmware() {
    let good = centauri_table(vec![(*b"rkos", vec![3], 0)]);
    for revision in [
        None,
        Some(true.into()),
        Some(Value::Data(vec![0])),
        Some(Value::Data(vec![0; 3])),
    ] {
        let mut info = wire::dict([("Wireless1,RestoreBootNonce", Value::Data(vec![7; 8]))]);
        if let Some(revision) = revision {
            info.as_dictionary_mut()
                .unwrap()
                .insert("Wireless1,ChipRev".into(), revision);
        }
        assert!(centauri_response(&good, info).is_err());
    }
    for nonce in [
        None,
        Some(true.into()),
        Some(Value::Data(vec![0; 8])),
        Some(Value::Data(vec![7; 7])),
        Some(Value::Data(vec![7; 9])),
    ] {
        let mut info = wire::dict([("Wireless1,ChipRev", Value::Data(vec![0x11, 0]))]);
        if let Some(nonce) = nonce {
            info.as_dictionary_mut()
                .unwrap()
                .insert("Wireless1,RestoreBootNonce".into(), nonce);
        }
        assert!(centauri_response(&good, info).is_err());
    }
    let info = wire::dict([
        ("Wireless1,ChipRev", Value::Data(vec![0x11, 0])),
        ("Wireless1,RestoreBootNonce", Value::Data(vec![7; 8])),
    ]);
    for bad in [
        vec![0; 48],
        centauri_table(vec![(*b"rrko", vec![1], 0)]),
        centauri_table(vec![(*b"rkos", vec![1], 0), (*b"_b1f", vec![0; 64], 0)]),
    ] {
        assert!(centauri_response(&bad, info.clone()).is_err());
    }
}

#[test]
fn updater_response_can_supply_a_multi_component_payload_and_missing_payload_is_an_error() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = modern_updater_args("NewController");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "ResponseTags".into(),
            Value::Array(vec!["Controller,Ticket".into(), "FirmwareData".into()]),
        );
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .extend(
            wire::dictionary(&wire::dict([
                ("iBSS", wire::dict([] as [(&str, Value); 0])),
                ("iBEC", wire::dict([] as [(&str, Value); 0])),
            ]))
            .unwrap()
            .clone(),
        );
    let response = wire::dict([
        ("Controller,Ticket", Value::Data(vec![42])),
        ("FirmwareData", Value::Data(vec![9, 8, 7])),
    ]);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(update.firmware.is_none());
    assert_eq!(update.finish(response.clone()).unwrap(), response);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(
        update
            .finish(wire::dict([("Controller,Ticket", Value::Data(vec![42]))]))
            .is_err()
    );
    // A complete service response takes precedence over an optional local payload.
    let update = zalivka::firmware::Update {
        request: wire::dict([] as [(&str, Value); 0]),
        response_tags: vec!["FirmwareData".into()],
        firmware: Some(Value::Data(vec![1])),
    };
    assert_eq!(update.finish(response.clone()).unwrap(), response);
}

#[test]
fn legacy_updaters_without_device_generated_tags_still_return_their_ticket_and_firmware() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut id = identity();
    let manifest = manifest_mut(&mut id);
    manifest.insert(
        "SE,UpdatePayload".into(),
        component_entry("Firmware/iBSS", &im4p(b"test")),
    );
    manifest.insert(
        "Baobab,TCON".into(),
        component_entry("Firmware/iBSS", &im4p(b"test")),
    );
    for (name, ticket_name, info) in [
        (
            "SE",
            "SE,Ticket",
            wire::dict([
                ("SE,ChipID", 0x73u64.into()),
                ("SE,ID", Value::Data(vec![1])),
                ("SE,Nonce", Value::Data(vec![2])),
                ("SE,RootKeyIdentifier", Value::Data(vec![3])),
            ]),
        ),
        (
            "AppleTCON",
            "Baobab,Ticket",
            wire::dict([("Baobab,ProductionMode", true.into())]),
        ),
    ] {
        let args = wire::dict([
            ("MessageArgType", "FirmwareResponseData".into()),
            ("MessageArgUpdaterName", name.into()),
            ("MessageArgInfo", info),
        ]);
        let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
        let response = update
            .finish(wire::dict([(ticket_name, Value::Data(vec![42]))]))
            .unwrap();
        assert_eq!(
            wire::get(&response, &["FirmwareData"])
                .unwrap()
                .as_data()
                .unwrap(),
            im4p(b"test")
        );
    }
}

#[test]
fn firmware_chunk_stream_sends_tickets_size_bounded_chunks_and_an_explicit_end() {
    let payload: Vec<u8> = (0..(512 * 1024 + 17)).map(|n| n as u8).collect();
    for requested in [131072u64, 262144, u64::MAX] {
        let response = wire::dict([
            ("Controller,Ticket", Value::Data(vec![42])),
            ("FirmwareData", Value::Data(payload.clone())),
        ]);
        let mut bytes = vec![];
        zalivka::firmware::send_response(
            &mut bytes,
            response,
            &wire::dict([("DataChunkSize", requested.into())]),
        )
        .unwrap();
        let mut stream = Cursor::new(bytes);
        let header = wire::receive(&mut stream).unwrap();
        assert_eq!(
            wire::number(wire::get(&header, &["DataSize"]).unwrap()).unwrap(),
            payload.len() as u64
        );
        assert_eq!(
            wire::get(&header, &["FirmwareResponseData", "Controller,Ticket"])
                .unwrap()
                .as_data()
                .unwrap(),
            &[42]
        );
        assert!(wire::get(&header, &["FirmwareResponseData", "FirmwareData"]).is_err());
        let mut received = vec![];
        loop {
            let frame = wire::receive(&mut stream).unwrap();
            let data = wire::get(&frame, &["FirmwareResponseData"])
                .unwrap()
                .as_data()
                .unwrap();
            if wire::boolean(&frame, &["DataDone"]) {
                assert!(data.is_empty());
                break;
            }
            assert!(!data.is_empty() && data.len() <= requested.min(262144) as usize);
            received.extend_from_slice(data);
        }
        assert_eq!(received, payload);
        assert_eq!(stream.position(), stream.get_ref().len() as u64);
    }
}

#[test]
fn firmware_chunk_compatibility_covers_legacy_structured_and_empty_payloads() {
    for size in [None, Some(0), Some(3)] {
        for data in [
            None,
            Some(Value::Data(vec![1, 2, 3])),
            Some(wire::dict([("YonkersFirmware", Value::Data(vec![1]))])),
        ] {
            let mut response = wire::dict([("Controller,Ticket", Value::Data(vec![42]))]);
            if let Some(data) = data.clone() {
                response
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("FirmwareData".into(), data);
            }
            let args = wire::dict(size.map(|n| ("DataChunkSize", (n as u64).into())));
            let mut bytes = vec![];
            zalivka::firmware::send_response(&mut bytes, response.clone(), &args).unwrap();
            if size == Some(3) && data.as_ref().is_some_and(|d| d.as_data().is_some()) {
                continue;
            }
            let mut stream = Cursor::new(bytes);
            assert_eq!(
                wire::get(
                    &wire::receive(&mut stream).unwrap(),
                    &["FirmwareResponseData"]
                )
                .unwrap(),
                &response
            );
            assert_eq!(stream.position(), stream.get_ref().len() as u64);
        }
    }
    let mut bytes = vec![];
    zalivka::firmware::send_response(
        &mut bytes,
        wire::dict([("FirmwareData", Value::Data(vec![]))]),
        &wire::dict([("DataChunkSize", 1u64.into())]),
    )
    .unwrap();
    let mut stream = Cursor::new(bytes);
    assert_eq!(
        wire::number(wire::get(&wire::receive(&mut stream).unwrap(), &["DataSize"]).unwrap())
            .unwrap(),
        0
    );
    assert!(wire::boolean(
        &wire::receive(&mut stream).unwrap(),
        &["DataDone"]
    ));
    assert_eq!(stream.position(), stream.get_ref().len() as u64);
    for invalid in [Value::Boolean(true), (-1i64).into(), "invalid".into()] {
        let mut bytes = vec![];
        assert!(
            zalivka::firmware::send_response(
                &mut bytes,
                wire::dict([] as [(&str, Value); 0]),
                &wire::dict([("DataChunkSize", invalid)])
            )
            .is_err()
        );
        assert!(bytes.is_empty());
    }
}

#[test]
fn firmware_chunk_failure_does_not_emit_a_successful_end_marker() {
    struct FailedWriter {
        bytes: Vec<u8>,
        frames_left: usize,
    }
    impl Write for FailedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.frames_left == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.frames_left -= 1;
            Ok(())
        }
    }
    let mut out = FailedWriter {
        bytes: vec![],
        frames_left: 2,
    }; // Header and first chunk, independent of write boundaries.
    assert!(
        zalivka::firmware::send_response(
            &mut out,
            wire::dict([("FirmwareData", Value::Data(vec![1, 2]))]),
            &wire::dict([("DataChunkSize", 1u64.into())])
        )
        .is_err()
    );
    let mut stream = Cursor::new(out.bytes);
    assert!(wire::get(&wire::receive(&mut stream).unwrap(), &["DataSize"]).is_ok());
    assert_eq!(
        wire::get(
            &wire::receive(&mut stream).unwrap(),
            &["FirmwareResponseData"]
        )
        .unwrap()
        .as_data()
        .unwrap(),
        &[1]
    );
    assert_eq!(stream.position(), stream.get_ref().len() as u64);
}

#[test]
fn retimer_update_uses_hardware_tag_and_requested_ticket() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let info = wire::dict([(
        "InfoArray",
        Value::Array(vec![wire::dict([
            ("TagNumber", 1u64.into()),
            ("TicketName", "Timer,Ticket,1".into()),
            (
                "HardwareID",
                wire::dict([
                    ("ChipID", 22u64.into()),
                    ("BoardID", 2u64.into()),
                    ("ECID", 44u64.into()),
                    ("Nonce", Value::Data(vec![1, 2])),
                    ("SecurityMode", true.into()),
                    ("SecurityDomain", 1u64.into()),
                    ("ProductionStatus", true.into()),
                ]),
            ),
        ])]),
    )]);
    let args = updater_args("AppleTypeCRetimer", info, &["Timer,Ticket,1"]);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(wire::boolean(&update.request, &["@Timer,Ticket,1"]));
    assert_eq!(
        wire::number(wire::get(&update.request, &["Timer,ECID,1"]).unwrap()).unwrap(),
        44
    );
}

#[test]
fn retimer_uarp_v3_assembles_nested_ftab_and_separate_restore_payload() {
    use zalivka::firmware::{Ftab, payload_ranges};
    let mut header = [0; 48];
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let normal = b"RTKit executable";
    let phy = b"Type-C PHY executable";
    let restore = b"restore RTKit executable";
    let table = Ftab {
        header,
        entries: vec![(*b"rkos", normal.to_vec(), 0), (*b"cphy", phy.to_vec(), 0)],
    }
    .encode()
    .unwrap();
    let mut uarp = vec![0; 124];
    uarp[..4].copy_from_slice(&3u32.to_be_bytes());
    uarp[4..8].copy_from_slice(&44u32.to_be_bytes());
    uarp[36..40].copy_from_slice(&44u32.to_be_bytes());
    uarp[40..44].copy_from_slice(&80u32.to_be_bytes());
    for (index, (tag, data)) in [(b"FIRM", table.as_slice()), (b"RRKO", restore.as_slice())]
        .into_iter()
        .enumerate()
    {
        let row = 44 + index * 40;
        let offset = uarp.len() as u32;
        uarp[row..row + 4].copy_from_slice(&40u32.to_be_bytes());
        uarp[row + 4..row + 8].copy_from_slice(tag);
        uarp[row + 32..row + 36].copy_from_slice(&offset.to_be_bytes());
        uarp[row + 36..row + 40].copy_from_slice(&(data.len() as u32).to_be_bytes());
        uarp.extend_from_slice(data);
    }
    assert!(payload_ranges(&uarp, uarp.len() as u64).unwrap().len() > 2);
    let mut id = identity();
    let entries = manifest_mut(&mut id);
    for (name, data) in [
        ("Timer,RTKitOS,1", normal.as_slice()),
        ("Timer,RestoreRTKitOS,1", restore.as_slice()),
        ("Timer,AppleTypeCPhyFirmware,1", phy.as_slice()),
    ] {
        entries.insert(name.into(), component_entry("rt15.uarp", data));
    }
    let file = fixture_files(Some(id.clone()), false, &[("rt15.uarp", &uarp)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    ipsw.verify_all().unwrap();
    let args = wire::dict([
        ("MessageArgType", "FirmwareResponseData".into()),
        ("MessageArgUpdaterName", "AppleTypeCRetimer".into()),
        (
            "MessageArgInfo",
            wire::dict([(
                "InfoArray",
                Value::Array(vec![wire::dict([
                    ("TagNumber", 1u64.into()),
                    ("TicketName", "Timer,Ticket,1".into()),
                ])]),
            )]),
        ),
        (
            "DeviceGeneratedTags",
            wire::dict([
                (
                    "BuildIdentityTags",
                    Value::Array(vec!["UniqueBuildID".into(), "ApSecurityDomain".into()]),
                ),
                (
                    "ResponseTags",
                    Value::Array(vec!["Timer,Ticket,1".into(), "FirmwareData".into()]),
                ),
            ]),
        ),
        (
            "DeviceGeneratedRequest",
            wire::dict([
                ("@Timer,Ticket,1", true.into()),
                ("Timer,Nonce,1", Value::Data(vec![1; 16])),
            ]),
        ),
    ]);
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &args).unwrap();
    let result = update
        .finish(wire::dict([("Timer,Ticket,1", Value::Data(vec![42]))]))
        .unwrap();
    let payload = Ftab::parse(
        wire::get(&result, &["FirmwareData"])
            .unwrap()
            .as_data()
            .unwrap(),
    )
    .unwrap();
    for (tag, expected) in [
        (b"rkos", normal.as_slice()),
        (b"cphy", phy.as_slice()),
        (b"rrko", restore.as_slice()),
    ] {
        assert_eq!(
            payload
                .entries
                .iter()
                .find(|entry| &entry.0 == tag)
                .unwrap()
                .1,
            expected
        );
    }
}

#[test]
fn retimer_selects_the_requested_ticket_instead_of_the_first_info_array_entry() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let item = |tag: u64| {
        wire::dict([
            ("TagNumber", tag.into()),
            ("TicketName", format!("Timer,Ticket,{tag}").into()),
            (
                "HardwareID",
                wire::dict([
                    ("ChipID", 22u64.into()),
                    ("BoardID", 2u64.into()),
                    ("ECID", (40 + tag).into()),
                    ("Nonce", Value::Data(vec![tag as u8])),
                    ("SecurityMode", true.into()),
                    ("SecurityDomain", 1u64.into()),
                    ("ProductionStatus", true.into()),
                ]),
            ),
        ])
    };
    let info = wire::dict([("InfoArray", Value::Array(vec![item(1), item(2)]))]);
    let args = updater_args("AppleTypeCRetimer", info.clone(), &["Timer,Ticket,2"]);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &args).unwrap();
    assert!(wire::boolean(&update.request, &["@Timer,Ticket,2"]));
    assert_eq!(
        wire::number(wire::get(&update.request, &["Timer,ECID,2"]).unwrap()).unwrap(),
        42
    );
    assert!(wire::get(&update.request, &["Timer,ECID,1"]).is_err());
    for requested in [
        vec!["Timer,Ticket,1", "Timer,Ticket,2"],
        vec!["Timer,Ticket,3"],
    ] {
        let args = updater_args("AppleTypeCRetimer", info.clone(), &requested);
        assert!(zalivka::firmware::prepare(&mut ipsw, &identity(), &args).is_err());
    }
}

fn updater_args(name: &str, info: Value, tags: &[&str]) -> Value {
    wire::dict([
        ("MessageArgType", "FirmwareResponseData".into()),
        ("MessageArgUpdaterName", name.into()),
        ("MessageArgInfo", info),
        (
            "DeviceGeneratedRequest",
            wire::dict([("@Test,Ticket", true.into())]),
        ),
        (
            "DeviceGeneratedTags",
            wire::dict([(
                "ResponseTags",
                Value::Array(tags.iter().map(|t| (*t).into()).collect()),
            )]),
        ),
    ])
}

fn modern_updater_args(name: &str) -> Value {
    let mut args = updater_args(
        name,
        wire::dict([
            ("ApECID", 123u64.into()),
            ("Controller,ProductionMode", false.into()),
            ("UnrequestedInfo", "do not forward".into()),
        ]),
        &["Controller,Ticket"],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([
            ("@Controller,Ticket", true.into()),
            ("Controller,Nonce", Value::Data(vec![1, 2])),
            ("ApChipID", 0x8112u64.into()),
        ]),
    );
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "BuildIdentityTags".into(),
            Value::Array(vec![
                "UniqueBuildID".into(),
                "ApSecurityDomain".into(),
                "RequiresUIDMode".into(),
                "AbsentOptionalTag".into(),
            ]),
        );
    args
}

fn centauri_table(entries: Vec<([u8; 4], Vec<u8>, u32)>) -> Vec<u8> {
    let mut header = [0; 48];
    header[..4].copy_from_slice(&0x1a00_0000u32.to_le_bytes());
    header[4..8].fill(255);
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    zalivka::firmware::Ftab { header, entries }
        .encode()
        .unwrap()
}

fn centauri_response(bytes: &[u8], info: Value) -> anyhow::Result<Value> {
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "Wireless1,RTKitOS".into(),
        component_entry("centauri.bin", bytes),
    );
    let file = fixture_files(Some(id.clone()), false, &[("centauri.bin", bytes)]);
    let mut ipsw = Ipsw::open(file.path())?;
    let mut args = updater_args("Centauri", info, &["Wireless1,Ticket", "FirmwareData"]);
    let fields = args.as_dictionary_mut().unwrap();
    fields
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "BuildIdentityTags".into(),
            Value::Array(vec!["UniqueBuildID".into()]),
        );
    fields.insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("@Wireless1,Ticket", true.into())]),
    );
    zalivka::firmware::prepare(&mut ipsw, &id, &args)?
        .finish(wire::dict([("Wireless1,Ticket", Value::Data(vec![42]))]))
}
