use super::*;

#[test]
fn firmware_plist_payloads_and_chunks_are_transferred_without_trace_dumps() {
    for chunk in [0u64, 8192] {
        let records = Arc::new(Mutex::new(Vec::new()));
        let output = records.clone();
        let payload = vec![0xa5; 512 * 1024];
        let mut sent = Vec::new();
        zalivka::progress::Context::new(move |event| {
            if let zalivka::progress::Event::Log(record) = event {
                output.lock().unwrap().push(record);
            }
        })
        .run(|| {
            zalivka::firmware::send_response(
                &mut sent,
                wire::dict([("FirmwareData", Value::Data(payload.clone()))]),
                &wire::dict([("DataChunkSize", chunk.into())]),
            )
        })
        .unwrap();
        assert!(records.lock().unwrap().is_empty());
        let mut input = Cursor::new(sent);
        let mut received = Vec::new();
        while input.position() < input.get_ref().len() as u64 {
            let message = wire::receive(&mut input).unwrap();
            let response = wire::get(&message, &["FirmwareResponseData"]).unwrap();
            if let Some(bytes) = response.as_data() {
                received.extend_from_slice(bytes);
            } else if let Ok(value) = wire::get(response, &["FirmwareData"]) {
                received.extend_from_slice(value.as_data().unwrap());
            }
        }
        assert_eq!(received, payload);
    }
}

#[test]
fn metadata_updater_cannot_contradict_connected_ap_fields() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for (key, value) in [
        ("ApChipID", 0xffffu64.into()),
        ("ApBoardID", 0xffu64.into()),
        ("ApProductionMode", false.into()),
        ("ApSecurityMode", false.into()),
    ] {
        let mut args = modern_updater_args("UnknownController");
        args.as_dictionary_mut()
            .unwrap()
            .get_mut("DeviceGeneratedRequest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), value);
        assert!(
            zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).is_err(),
            "accepted conflicting {key}"
        );
    }
    let mut args = modern_updater_args("UnknownController");
    let generated = args
        .as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    generated.insert("ApChipID".into(), "0X8103".into());
    generated.insert("ApBoardID".into(), "0x0A".into());
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
    assert_eq!(
        wire::string(&update.request, &["ApChipID"]).unwrap(),
        "0X8103"
    );
    assert_eq!(
        wire::string(&update.request, &["ApBoardID"]).unwrap(),
        "0x0A"
    );
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("ApChipID");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "BuildIdentityTags".into(),
            Value::Array(vec!["ApChipID".into()]),
        );
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("ApChipID".into(), 0xffffu64.into());
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_err());
}

#[test]
fn all_updaters_forward_explicit_requests_and_preserve_complete_service_payloads() {
    let id = identity();
    let mut device = device_info();
    device.chip_fuse_mode = Some(1);
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for name in [
        "SE",
        "AppleTCON",
        "PS190",
        "Rose",
        "T200",
        "Centauri",
        "Cryptex1",
        "FutureController",
    ] {
        let mut args = modern_updater_args(name);
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
        fields
            .get_mut("DeviceGeneratedTags")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "ResponseTags".into(),
                Value::Array(vec!["Controller,Ticket".into(), "FirmwareData".into()]),
            );
        let generated = fields
            .get_mut("DeviceGeneratedRequest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        generated.insert("Future,OpaqueParameter".into(), "preserve me".into());
        generated.insert("ApProductionMode".into(), false.into());
        for payload in [
            Value::Data(vec![1, 2, 3]),
            wire::dict([("new payload shape", true.into())]),
        ] {
            let update = zalivka::firmware::prepare(&mut ipsw, &id, &device, &args).unwrap();
            let request = wire::dictionary(&update.request).unwrap();
            assert_eq!(
                request["UniqueBuildID"],
                id.value.as_dictionary().unwrap()["UniqueBuildID"]
            );
            for (key, value) in
                wire::dictionary(wire::get(&args, &["DeviceGeneratedRequest"]).unwrap()).unwrap()
            {
                assert_eq!(&request[key], value);
            }
            for absent in ["@BBTicket", "UnrequestedInfo", "RequiresUIDMode"] {
                assert!(
                    !request.contains_key(absent),
                    "{name}: unexpected default {absent}"
                );
            }
            let response = wire::dict([
                ("Controller,Ticket", Value::Data(vec![42])),
                ("FirmwareData", payload),
            ]);
            assert_eq!(update.finish(response.clone()).unwrap(), response);
        }
        let update = zalivka::firmware::prepare(&mut ipsw, &id, &device, &args).unwrap();
        let error = update
            .finish(wire::dict([("Controller,Ticket", Value::Data(vec![42]))]))
            .unwrap_err();
        assert!(format!("{error:#}").contains("FirmwareData"));
    }
}

#[test]
fn absent_selected_identity_fields_are_omitted_without_defaults() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = modern_updater_args("FutureController");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "BuildIdentityTags".into(),
            Value::Array(vec!["MissingTag".into()]),
        );
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
    assert!(wire::get(&update.request, &["MissingTag"]).is_err());
    for (key, value) in
        wire::dictionary(wire::get(&args, &["DeviceGeneratedRequest"]).unwrap()).unwrap()
    {
        assert_eq!(wire::get(&update.request, &[key]).unwrap(), value);
    }
}

#[test]
fn device_generated_fields_override_selected_identity_fields_without_type_changes() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = modern_updater_args("UnknownController");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .extend([
            ("ApSecurityDomain".into(), "0x02".into()),
            ("UniqueBuildID".into(), Value::Data(vec![0x37; 20])),
        ]);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
    assert_eq!(
        wire::get(&update.request, &["ApSecurityDomain"]).unwrap(),
        &Value::String("0x02".into())
    );
    assert_eq!(
        wire::get(&update.request, &["UniqueBuildID"])
            .unwrap()
            .as_data()
            .unwrap(),
        &[0x37; 20]
    );
    // With the override absent, the selected, existing identity field is copied.
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("UniqueBuildID");
    let id = identity();
    let update = zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).unwrap();
    assert_eq!(
        wire::get(&update.request, &["UniqueBuildID"]).unwrap(),
        wire::get(&id.value, &["UniqueBuildID"]).unwrap()
    );
    assert_eq!(
        wire::number(wire::get(&update.request, &["ApBoardID"]).unwrap()).unwrap(),
        u64::from(device_info().board_id)
    );
}

#[test]
fn common_updater_fields_use_actual_hardware_and_fuses_without_ap_ticket_defaults() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = modern_updater_args("UnlistedUpdater");
    args.as_dictionary_mut()
        .unwrap()
        .get_mut("DeviceGeneratedRequest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("ApChipID");
    let mut device = device_info();
    device.chip_id = 0x9912;
    device.board_id = 0x78;
    device.ap_nonce.clear();
    device.security_domain = None;
    for fuse in 0..4 {
        device.chip_fuse_mode = Some(fuse);
        let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device, &args).unwrap();
        assert_eq!(
            wire::number(wire::get(&update.request, &["ApChipID"]).unwrap()).unwrap(),
            0x9912
        );
        assert_eq!(
            wire::number(wire::get(&update.request, &["ApBoardID"]).unwrap()).unwrap(),
            0x78
        );
        assert_eq!(
            wire::get(&update.request, &["ApProductionMode"])
                .unwrap()
                .as_boolean(),
            Some(fuse & 2 != 0)
        );
        assert_eq!(
            wire::get(&update.request, &["ApSecurityMode"])
                .unwrap()
                .as_boolean(),
            Some(fuse & 1 != 0)
        );
        for absent in ["@ApImg4Ticket", "@BBTicket", "ApNonce", "ApECID"] {
            assert!(wire::get(&update.request, &[absent]).is_err());
        }
    }
    device.chip_fuse_mode = None;
    let error = zalivka::firmware::prepare(&mut ipsw, &identity(), &device, &args)
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("CPFM"));
}

#[test]
fn captured_cryptex_request_preserves_optional_absence_and_returns_ticket_without_payload() {
    let message = Value::from_reader(Cursor::new(include_bytes!(
        "../fixtures/restored-26A434-cryptex.plist"
    )))
    .unwrap();
    let mut args = wire::get(&message, &["Arguments"]).unwrap().clone();
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let generated = wire::get(&args, &["DeviceGeneratedRequest"])
        .unwrap()
        .clone();
    for name in ["Cryptex1", "UnlistedFutureUpdater"] {
        args.as_dictionary_mut()
            .unwrap()
            .insert("MessageArgUpdaterName".into(), name.into());
        let update =
            zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
        let mut actual = update.request.clone();
        actual.as_dictionary_mut().unwrap().retain(|key, _| {
            ![
                "@HostPlatformInfo",
                "@VersionInfo",
                "ApChipID",
                "ApBoardID",
                "ApProductionMode",
                "ApSecurityMode",
            ]
            .contains(&key.as_str())
        });
        assert_eq!(actual, generated);
        for absent in [
            "Cryptex1,UseProductClass",
            "Cryptex1,FakeRoot",
            "Cryptex1,GenericDmg",
            "Cryptex1,ExclaveNonceDomain",
        ] {
            assert!(wire::get(&update.request, &[absent]).is_err());
        }
        assert_eq!(
            wire::get(&update.request, &["Cryptex1,Nonce"])
                .unwrap()
                .as_data()
                .unwrap()
                .len(),
            32
        );
        let response = wire::dict([("Cryptex1,Ticket", Value::Data(ticket()))]);
        let response = update.finish(response).unwrap();
        let mut bytes = vec![];
        zalivka::firmware::send_response(&mut bytes, response.clone(), &args).unwrap();
        let mut stream = Cursor::new(bytes);
        let frame = wire::receive(&mut stream).unwrap();
        assert_eq!(
            wire::get(&frame, &["FirmwareResponseData"]).unwrap(),
            &response
        );
        assert!(wire::get(&frame, &["DataSize"]).is_err());
        assert_eq!(stream.position(), stream.get_ref().len() as u64);
    }
}

#[test]
fn complete_device_requests_do_not_depend_on_controller_names_or_unused_info() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut args = modern_updater_args("FutureController");
    let fields = args.as_dictionary_mut().unwrap();
    fields.remove("MessageArgUpdaterName");
    fields.remove("MessageArgInfo");
    fields
        .get_mut("DeviceGeneratedTags")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("BuildIdentityTags".into(), Value::Array(vec![]));
    assert!(zalivka::firmware::canary_response(&args).unwrap().is_none());
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
    let response = wire::dict([("Controller,Ticket", Value::Data(vec![42]))]);
    assert_eq!(update.finish(response.clone()).unwrap(), response);
}

#[test]
fn requested_tickets_require_nonempty_data_and_structured_firmware_is_preserved() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let args = modern_updater_args("UnlistedUpdater");
    for invalid in [
        Value::Data(vec![]),
        true.into(),
        "invalid".into(),
        wire::dict([("unexpected", true.into())]),
    ] {
        let update =
            zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
        let error = update
            .finish(wire::dict([("Controller,Ticket", invalid)]))
            .unwrap_err();
        assert!(format!("{error:#}").contains("Controller,Ticket"));
    }
    let response = wire::dict([
        ("Controller,Ticket", Value::Data(vec![42])),
        (
            "FirmwareData",
            wire::dict([("FuturePayload", Value::Data(vec![1]))]),
        ),
    ]);
    let update = zalivka::firmware::prepare(&mut ipsw, &identity(), &device_info(), &args).unwrap();
    assert_eq!(update.finish(response.clone()).unwrap(), response);
}

#[test]
fn ftab_index_preserves_payload_ranges_and_rejects_bad_offsets() {
    use crate::test_support::Ftab;
    let mut header = [0; 48];
    header[..4].copy_from_slice(&1u32.to_le_bytes());
    header[4..8].fill(255);
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let table = Ftab {
        header,
        entries: vec![(*b"rkos", vec![1, 2, 3], 0), (*b"rrko", vec![4, 5], 7)],
    };
    let bytes = table.encode();
    // A streaming reader has the complete index, without the payload bytes.
    assert_eq!(
        zalivka::firmware::payload_ranges(&bytes[..80], bytes.len() as u64).unwrap(),
        [80..83, 83..85]
    );
    let rejects = |bad: &[u8]| {
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
    use crate::test_support::Ftab;
    use zalivka::firmware::payload_ranges;
    let mut header = [0; 48];
    header[36..40].copy_from_slice(b"ftab");
    let table = Ftab {
        header,
        entries: vec![],
    };
    let bytes = table.encode();
    assert!(payload_ranges(&bytes, 48).unwrap().is_empty());
    assert!(payload_ranges(&bytes, 47).is_err());

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
        assert!(format!("{error:#}").contains("ResponseTags"));
    }
    assert!(mux_output(&output, 62078).get_ref().is_empty());
    assert!(crate::test_support::boolean(
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
            if crate::test_support::boolean(&frame, &["DataDone"]) {
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
    assert!(crate::test_support::boolean(
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
            ("ApChipID", u64::from(device_info().chip_id).into()),
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
            ]),
        );
    args
}

fn namespace_bundle(namespace: &str) -> (Identity, Value, Vec<u8>) {
    let payload = vec![0x51; 140000];
    let digest = sha2::Sha256::digest(&payload).to_vec();
    let bundle = wire::xml(&wire::dict([(
        "arbitrary wrapper",
        wire::dict([
            ("Payload", Value::Data(payload)),
            ("Digest", Value::Data(digest.clone())),
        ]),
    )]))
    .unwrap();
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert(format!("{namespace},BoardID"), 7u64.into());
    manifest_mut(&mut id).insert(
        format!("{namespace},ArbitraryComponent"),
        wire::dict([
            ("Digest", Value::Data(digest)),
            (
                "Info",
                wire::dict([("Path", "arbitrary/path.plist".into())]),
            ),
        ]),
    );
    let args = wire::dict([
        ("MessageArgType", "FirmwareResponseData".into()),
        ("DataChunkSize", 131072u64.into()),
        (
            "MessageArgInfo",
            wire::dict([
                (format!("{namespace},ProductionMode"), false.into()),
                (format!("{namespace},SecurityDomain"), 1u64.into()),
                (format!("{namespace},ECID"), Value::Data(vec![0x32; 16])),
                (
                    format!("{namespace},UpdateNonce"),
                    Value::Data(vec![0x57; 32]),
                ),
                (
                    format!("{namespace},FutureParameter"),
                    "forward unchanged".into(),
                ),
            ]),
        ),
    ]);
    (id, args, bundle)
}

#[test]
fn namespace_bundles_bind_metadata_and_stream_original_bytes_without_updater_names() {
    for namespace in ["Baobab", "UnlistedNamespace"] {
        let (id, args, bundle) = namespace_bundle(namespace);
        let file = fixture_files(
            Some(id.clone()),
            false,
            &[("arbitrary/path.plist", &bundle)],
        );
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(ipsw.verify_all().is_ok());
        for name in [None, Some("AppleTCON"), Some("UnknownUpdater")] {
            let mut args = args.clone();
            if let Some(name) = name {
                args.as_dictionary_mut()
                    .unwrap()
                    .insert("MessageArgUpdaterName".into(), name.into());
            }
            let update = zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).unwrap();
            let request = wire::dictionary(&update.request).unwrap();
            assert!(crate::test_support::boolean(
                &update.request,
                &[&format!("@{namespace},Ticket")]
            ));
            assert!(crate::test_support::boolean(
                &update.request,
                &["@BBTicket"]
            ));
            assert_eq!(request[&format!("{namespace},BoardID")], 7u64.into());
            for (key, value) in
                wire::dictionary(wire::get(&args, &["MessageArgInfo"]).unwrap()).unwrap()
            {
                assert_eq!(&request[key], value);
            }
            let entry = wire::get(
                &update.request,
                &[&format!("{namespace},ArbitraryComponent")],
            )
            .unwrap();
            assert_eq!(
                wire::get(entry, &["EPRO"]).unwrap().as_boolean(),
                Some(false)
            );
            assert!(wire::get(entry, &["Info"]).is_err());
            let ticket = format!("{namespace},Ticket");
            let response = update
                .finish(wire::dict([(ticket.as_str(), Value::Data(vec![42]))]))
                .unwrap();
            let mut bytes = vec![];
            zalivka::firmware::send_response(&mut bytes, response, &args).unwrap();
            let mut stream = Cursor::new(bytes);
            let header = wire::receive(&mut stream).unwrap();
            assert_eq!(
                wire::get(&header, &["FirmwareResponseData", &ticket])
                    .unwrap()
                    .as_data()
                    .unwrap(),
                &[42]
            );
            assert_eq!(
                wire::number(wire::get(&header, &["DataSize"]).unwrap()).unwrap(),
                bundle.len() as u64
            );
            let mut received = vec![];
            loop {
                let frame = wire::receive(&mut stream).unwrap();
                let data = wire::get(&frame, &["FirmwareResponseData"])
                    .unwrap()
                    .as_data()
                    .unwrap();
                assert!(data.len() <= 131072);
                received.extend_from_slice(data);
                if crate::test_support::boolean(&frame, &["DataDone"]) {
                    assert!(data.is_empty());
                    break;
                }
            }
            assert_eq!(received, bundle);
            assert_eq!(stream.position(), stream.get_ref().len() as u64);
        }
    }
}

#[test]
fn namespace_inference_refuses_missing_conflicting_ambiguous_or_partial_metadata() {
    let (id, args, bundle) = namespace_bundle("New");
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("arbitrary/path.plist", &bundle)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for case in 0..11 {
        let mut id = id.clone();
        let mut args = args.clone();
        let fields = args.as_dictionary_mut().unwrap();
        match case {
            0 => {
                fields
                    .get_mut("MessageArgInfo")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .remove("New,ProductionMode");
            }
            1 => {
                fields
                    .get_mut("MessageArgInfo")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("Other,Nonce".into(), 1u64.into());
            }
            2 => {
                fields
                    .get_mut("MessageArgInfo")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("New,BoardID".into(), 8u64.into());
            }
            3 => {
                let entry = manifest_mut(&mut id)["New,ArbitraryComponent"].clone();
                manifest_mut(&mut id).insert("New,SecondComponent".into(), entry);
            }
            4 => {
                id.value.as_dictionary_mut().unwrap().remove("New,BoardID");
            }
            5 => {
                fields.insert("DeviceGeneratedRequest".into(), true.into());
            }
            6 => {
                fields.insert("DeviceGeneratedTags".into(), true.into());
            }
            7 => {
                fields
                    .get_mut("MessageArgInfo")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("Unnamespaced".into(), true.into());
            }
            8 => {
                manifest_mut(&mut id)
                    .get_mut("New,ArbitraryComponent")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("EPRO".into(), true.into());
            }
            9 => {
                manifest_mut(&mut id)
                    .get_mut("New,ArbitraryComponent")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .remove("Digest");
            }
            10 => {
                manifest_mut(&mut id)
                    .get_mut("New,ArbitraryComponent")
                    .unwrap()
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("Digest".into(), Value::Data(vec![]));
            }
            _ => unreachable!(),
        }
        assert!(
            zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn namespace_payloads_require_a_valid_ticket_and_verified_bundle() {
    let (id, args, bundle) = namespace_bundle("New");
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("arbitrary/path.plist", &bundle)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for response in [
        wire::dict([] as [(&str, Value); 0]),
        wire::dict([("New,Ticket", Value::Data(vec![]))]),
        wire::dict([("New,Ticket", true.into())]),
        wire::dict([
            ("New,Ticket", Value::Data(vec![42])),
            ("FirmwareData", Value::Data(vec![1])),
        ]),
    ] {
        assert!(
            zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args)
                .unwrap()
                .finish(response)
                .is_err()
        );
    }
    let mut corrupt = Value::from_reader(Cursor::new(&bundle)).unwrap();
    corrupt
        .as_dictionary_mut()
        .unwrap()
        .get_mut("arbitrary wrapper")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Payload".into(), Value::Data(vec![0; 140000]));
    let corrupt = wire::xml(&corrupt).unwrap();
    for bytes in [corrupt.as_slice(), b"opaque unknown format".as_slice()] {
        let file = fixture_files(Some(id.clone()), false, &[("arbitrary/path.plist", bytes)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(ipsw.component(&id, "New,ArbitraryComponent").is_err());
        assert!(ipsw.verify_all().is_err());
        assert!(zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_err());
    }
    // Even a valid raw-file digest does not describe how to package it for Mac.
    let mut id = id;
    manifest_mut(&mut id)
        .get_mut("New,ArbitraryComponent")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "Digest".into(),
            Value::Data(sha2::Sha256::digest(b"raw").to_vec()),
        );
    let file = fixture_files(Some(id.clone()), false, &[("arbitrary/path.plist", b"raw")]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.component(&id, "New,ArbitraryComponent").is_ok());
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_err());
}

#[test]
fn namespace_bundle_integrity_checks_agree_even_when_the_outer_hash_is_valid() {
    let (mut id, args, bundle) = namespace_bundle("New");
    let mut corrupt = Value::from_reader(Cursor::new(&bundle)).unwrap();
    corrupt.as_dictionary_mut().unwrap()["arbitrary wrapper"]
        .as_dictionary_mut()
        .unwrap()
        .insert("Payload".into(), Value::Data(b"changed".to_vec()));
    let corrupt = wire::xml(&corrupt).unwrap();
    manifest_mut(&mut id)["New,ArbitraryComponent"]
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "Digest".into(),
            Value::Data(sha2::Sha256::digest(&corrupt).to_vec()),
        );
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("arbitrary/path.plist", &corrupt)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.component(&id, "New,ArbitraryComponent").is_err());
    assert!(ipsw.verify_all().is_err());
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_err());
}

#[test]
fn namespace_bundle_limit_is_checked_before_reading_and_raw_manifest_hashes_are_supported() {
    let (mut id, args, bundle) = namespace_bundle("New");
    manifest_mut(&mut id)["New,ArbitraryComponent"]
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "Digest".into(),
            Value::Data(sha2::Sha256::digest(&bundle).to_vec()),
        );
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("arbitrary/path.plist", &bundle)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args).is_ok());
    assert!(ipsw.component(&id, "New,ArbitraryComponent").is_ok());
    assert!(ipsw.verify_all().is_ok());

    let mut oversized = vec![0; 32 * 1024 * 1024 + 1];
    oversized[..8].copy_from_slice(b"bplist00");
    let file = fixture_compression(
        Some(id.clone()),
        false,
        &[("arbitrary/path.plist", &oversized)],
        zip::CompressionMethod::Deflated,
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let error = ipsw.verify_all().unwrap_err();
    assert!(format!("{error:#}").contains("exceeds memory limit"));
    let error = zalivka::firmware::prepare(&mut ipsw, &id, &device_info(), &args)
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("exceeds memory limit"));
}

fn centauri_table(entries: Vec<([u8; 4], Vec<u8>, u32)>) -> Vec<u8> {
    let mut header = [0; 48];
    header[..4].copy_from_slice(&0x1a00_0000u32.to_le_bytes());
    header[4..8].fill(255);
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    crate::test_support::Ftab { header, entries }.encode()
}

#[test]
fn canary_rejects_duplicate_firmware_data_response_tags() {
    let mut args = updater_args(
        "Canary",
        wire::dict([("QueryLoop0", true.into())]),
        &[
            "Test,Ticket,1",
            "Test,Ticket,2",
            "FirmwareData",
            "FirmwareData",
        ],
    );
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("QueryLoop0", true.into())]),
    );
    assert!(zalivka::firmware::canary_response(&args).is_err());
}
