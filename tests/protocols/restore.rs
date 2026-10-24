use super::*;

#[test]
fn restore_capability_tables_match_26a434_compatibility_contract() {
    // Independently extracted from restored_update, including both comparisons
    // in is_host_compatible, rather than only the messages named in one failure.
    let contract: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/restored-26A434-capabilities.json"
    ))
    .unwrap();
    let compatible = |sender: &plist::Dictionary, receiver: &plist::Dictionary| {
        sender.iter().all(|(name, optional)| {
            receiver.contains_key(name) || optional.as_boolean() == Some(true)
        })
    };
    for behavior in ["Erase", "Update"] {
        let mut id = identity();
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("RestoreBehavior".into(), behavior.into());
        let request = wire::dict([
            ("Request", "StartRestore".into()),
            ("RestoreOptions", restore::options(&id).unwrap()),
        ]);
        let mut frame = Cursor::new(Vec::new());
        wire::send(&mut frame, &request).unwrap();
        frame.set_position(0);
        let request = wire::receive(&mut frame).unwrap();
        for table in ["SupportedMessageTypes", "SupportedDataTypes"] {
            let device = wire::dict(contract[table].as_object().unwrap().iter().map(
                |(name, optional)| (name.clone(), Value::Boolean(optional.as_bool().unwrap())),
            ));
            let device = device.as_dictionary().unwrap();
            assert_eq!(
                device.len(),
                if table == "SupportedMessageTypes" {
                    18
                } else {
                    68
                }
            );
            let host = wire::get(&request, &["RestoreOptions", table])
                .unwrap()
                .as_dictionary()
                .unwrap();
            assert!(
                compatible(device, host),
                "{behavior}: {table}, device to host"
            );
            assert!(
                compatible(host, device),
                "{behavior}: {table}, host to device"
            );
            for (name, optional) in host {
                if let Some(expected) = device.get(name) {
                    assert_eq!(expected, optional, "{behavior}: {table}.{name}");
                } else {
                    assert_eq!(optional.as_boolean(), Some(true), "{table}.{name}");
                }
            }
            // Every required device entry is checked, including FileData field
            // names and legacy vocabulary that must not enable async handlers.
            for (name, optional) in device {
                if optional.as_boolean() == Some(false) {
                    let mut missing = host.clone();
                    missing.remove(name);
                    assert!(!compatible(device, &missing), "{behavior}: {table}.{name}");
                }
            }
        }
        for name in ["FDRSubmit", "CrashLog"] {
            assert!(
                wire::get(&request, &["RestoreOptions", "SupportedMessageTypes", name]).is_err()
            );
        }
        for name in [
            "AuthInstallCACert",
            "RecoveryOSIBEC",
            "OverlayRootDataForKey",
        ] {
            assert!(wire::get(&request, &["RestoreOptions", "SupportedDataTypes", name]).is_err());
        }
    }
}

#[test]
fn revive_selects_only_upgrade_and_omits_formatting_options_and_boot_argument() {
    use zalivka::ipsw::Behavior;
    let mut upgrade = identity();
    upgrade
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .extend([
            ("RestoreBehavior".into(), "Update".into()),
            ("Variant".into(), "Customer Upgrade Install (IPSW)".into()),
        ]);
    let file = fixture(Some(upgrade.clone()), false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(
        ipsw.select_behavior(&device_info(), None, Behavior::Update)
            .unwrap()
            .index,
        1
    );
    assert!(
        ipsw.select_behavior(&device_info(), Some(0), Behavior::Update)
            .is_err()
    );
    let erase_only = fixture(None, false);
    assert!(
        Ipsw::open(erase_only.path())
            .unwrap()
            .select_behavior(&device_info(), None, Behavior::Update)
            .is_err()
    );
    let options = restore::options(&upgrade).unwrap();
    assert_eq!(
        wire::string(&options, &["AuthInstallRestoreBehavior"]).unwrap(),
        "Update"
    );
    assert!(!wire::boolean(&options, &["CreateFilesystemPartitions"]));
    assert!(!wire::boolean(&options, &["FormatForAPFS"]));
    assert!(
        !restore::boot_arguments(&upgrade)
            .unwrap()
            .contains("reformat")
    );
    assert!(
        restore::boot_arguments(&identity())
            .unwrap()
            .contains("nand-enable-reformat=1")
    );
}

#[test]
fn only_explicit_successful_final_status_counts() {
    let message = |status| {
        wire::dict([
            ("MsgType", "StatusMsg".into()),
            ("Status", Value::Integer(status)),
        ])
    };
    restore::validate_final_status(&message(0u64.into())).unwrap();
    assert!(restore::validate_final_status(&message(6u64.into())).is_err());
    assert!(
        restore::validate_final_status(&wire::dict([("MsgType", "StatusMsg".into())])).is_err()
    );
    let mut failed = message(0u64.into());
    failed
        .as_dictionary_mut()
        .unwrap()
        .insert("AMRError".into(), 53u64.into());
    assert!(restore::validate_final_status(&failed).is_err());
}

#[test]
fn signed_final_failures_preserve_the_device_error_after_plist_framing() {
    for (status, amr) in [(-1i64, -1i64), (0, -1), (-1, 0), (6, 53)] {
        let message = wire::dict([
            ("MsgType", "StatusMsg".into()),
            ("Status", status.into()),
            ("AMRError", amr.into()),
            ("Log", "ipd update failed with code 0x00000001".into()),
        ]);
        for binary in [false, true] {
            let mut bytes = Vec::new();
            if binary {
                wire::send_binary(&mut bytes, &message).unwrap();
            } else {
                wire::send(&mut bytes, &message).unwrap();
            }
            let received = wire::receive(&mut Cursor::new(bytes)).unwrap();
            let error = restore::validate_final_status(&received).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(&format!("Status={status}, AMRError={amr}")),
                "{error}"
            );
            assert!(error.contains("ipd update failed"), "{error}");
        }
    }
    for key in ["Status", "AMRError"] {
        for value in [true.into(), (-1.0f64).into(), "0".into()] {
            let mut message = wire::dict([
                ("MsgType", "StatusMsg".into()),
                ("Status", 0i64.into()),
                ("AMRError", 0i64.into()),
            ]);
            message
                .as_dictionary_mut()
                .unwrap()
                .insert(key.into(), value);
            let error = restore::validate_final_status(&message).unwrap_err();
            assert!(format!("{error:#}").contains(&format!("StatusMsg.{key}")));
        }
    }
}

#[test]
fn personalized_data_enables_early_iboot_dcp_and_keeps_ean_separate() {
    // restored's copy_ibfw_ean checks this key's presence before requesting
    // ImageType=IsiBootEANFirmware. Protocol compatibility alone permits its
    // absence because it is optional, silently skipping early DCP firmware.
    assert!(wire::boolean(
        &restore::supported_data_types(),
        &["PersonalizedData"]
    ));
    let dcp = im4p(b"dcpf");
    let restore_dcp = im4p(b"rdcp");
    let file = fixture_files(
        None,
        false,
        &[
            ("Firmware/dcp.im4p", &dcp),
            ("Firmware/rdcp.im4p", &restore_dcp),
        ],
    );
    let mut state = restore_state(file.path());
    let manifest = manifest_mut(&mut state.restore.identity);
    for (name, path, bytes, early, fud, stage1) in [
        ("DCP", "Firmware/dcp.im4p", &dcp, true, false, false),
        ("Ap,DCP2", "Firmware/dcp.im4p", &dcp, false, true, false),
        (
            "RestoreDCP",
            "Firmware/rdcp.im4p",
            &restore_dcp,
            false,
            false,
            true,
        ),
    ] {
        manifest.insert(
            name.into(),
            wire::dict([
                ("Trusted", true.into()),
                ("Digest", Value::Data(Sha384::digest(bytes).to_vec())),
                (
                    "Info",
                    wire::dict([
                        ("Path", path.into()),
                        ("IsiBootEANFirmware", early.into()),
                        ("IsFUDFirmware", fud.into()),
                        ("IsLoadedByiBootStage1", stage1.into()),
                    ]),
                ),
            ]),
        );
    }
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    for (kind, args) in [
        ("EANData", wire::dict([("EANImageList", true.into())])),
        (
            "PersonalizedData",
            wire::dict([
                ("ImageList", true.into()),
                ("ImageType", "IsiBootEANFirmware".into()),
            ]),
        ),
        (
            "PersonalizedBootObjectV3",
            wire::dict([("ImageName", "DCP".into()), ("IsRecoveryOS", false.into())]),
        ),
        (
            "PersonalizedData",
            wire::dict([
                ("ImageName", "DCP".into()),
                ("ImageType", "IsiBootEANFirmware".into()),
            ]),
        ),
    ] {
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into()), ("Arguments", args)]),
            )
            .unwrap();
    }
    let mut replies = mux_output(&output, 62078);
    assert_eq!(
        wire::get(&wire::receive(&mut replies).unwrap(), &["EANImageList"]).unwrap(),
        &Value::Array(vec![])
    );
    assert_eq!(
        wire::get(&wire::receive(&mut replies).unwrap(), &["ImageList"]).unwrap(),
        &Value::Array(vec!["DCP".into()])
    );
    let personalized = img4::personalize("DCP", &dcp, &ticket()).unwrap();
    let boot_object = wire::receive(&mut replies).unwrap();
    assert_eq!(
        wire::get(&boot_object, &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
        personalized
    );
    assert!(wire::boolean(
        &wire::receive(&mut replies).unwrap(),
        &["FileDataDone"]
    ));
    let named = wire::receive(&mut replies).unwrap();
    assert_eq!(wire::string(&named, &["ImageName"]).unwrap(), "DCP");
    assert_eq!(
        wire::get(&named, &["ImageData"])
            .unwrap()
            .as_data()
            .unwrap(),
        personalized
    );
}

#[test]
fn untrusted_input_device_uses_img4_for_fud_and_personalized_boot_objects() {
    let bytes = im4p(b"ipdf");
    let file = fixture_files(None, false, &[("Firmware/InputDevice.im4p", &bytes)]);
    let mut state = restore_state(file.path());
    manifest_mut(&mut state.restore.identity).insert(
        "InputDevice".into(),
        wire::dict([
            ("Trusted", false.into()),
            ("Digest", Value::Data(Sha384::digest(&bytes).to_vec())),
            (
                "Info",
                wire::dict([
                    ("Path", "Firmware/InputDevice.im4p".into()),
                    ("Personalize", true.into()),
                    ("IsFUDFirmware", true.into()),
                    ("RestoreRequestRules", Value::Array(vec![])),
                ]),
            ),
        ]),
    );
    // Preserve Trusted=false in signing metadata while wrapping the payload.
    assert_eq!(
        wire::get(
            &tss::request(&device_info(), &state.restore.identity).unwrap(),
            &["InputDevice", "Trusted"]
        )
        .unwrap()
        .as_boolean(),
        Some(false)
    );
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    for (kind, args) in [
        ("FUDData", Value::Dictionary(plist::Dictionary::new())),
        ("FUDData", wire::dict([("ImageName", "InputDevice".into())])),
        (
            "PersonalizedBootObjectV3",
            wire::dict([("ImageName", "InputDevice".into())]),
        ),
        (
            "SourceBootObjectV4",
            wire::dict([("ImageName", "InputDevice".into())]),
        ),
    ] {
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into()), ("Arguments", args)]),
            )
            .unwrap();
    }
    let assert_img4 = |data: &[u8]| {
        let (outer, rest) = img4::parse(data).unwrap();
        assert_eq!(outer.tag, 0x30);
        assert!(rest.is_empty());
        let (magic, fields) = img4::parse(outer.content).unwrap();
        assert_eq!(magic.content, b"IMG4");
        let (payload, fields) = img4::parse(fields).unwrap();
        assert_eq!(payload.encoded, bytes);
        let (manifest, rest) = img4::parse(fields).unwrap();
        assert_eq!(manifest.tag, 0xa0);
        assert_eq!(manifest.content, ticket());
        assert!(rest.is_empty());
    };
    let mut replies = mux_output(&output, 62078);
    let all = wire::receive(&mut replies).unwrap();
    assert_img4(
        wire::get(&all, &["FUDImageData", "InputDevice"])
            .unwrap()
            .as_data()
            .unwrap(),
    );
    let one = wire::receive(&mut replies).unwrap();
    assert_eq!(wire::string(&one, &["ImageName"]).unwrap(), "InputDevice");
    assert_img4(
        wire::get(&one, &["FUDImageData"])
            .unwrap()
            .as_data()
            .unwrap(),
    );
    let personalized = wire::receive(&mut replies).unwrap();
    assert_img4(
        wire::get(&personalized, &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
    );
    assert!(wire::boolean(
        &wire::receive(&mut replies).unwrap(),
        &["FileDataDone"]
    ));
    let source = wire::receive(&mut replies).unwrap();
    assert_eq!(
        wire::get(&source, &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
        bytes
    );
    assert!(wire::boolean(
        &wire::receive(&mut replies).unwrap(),
        &["FileDataDone"]
    ));
}

#[test]
fn cpio_header_matches_odc_wire_format() {
    let mut bytes = vec![];
    restore::cpio_header(&mut bytes, "boot.efi", 0o100755, 123).unwrap();
    assert_eq!(&bytes[..6], b"070707");
    assert_eq!(&bytes[18..24], b"100755");
    assert_eq!(&bytes[59..65], b"000011");
    assert_eq!(&bytes[65..76], b"00000000173");
    assert_eq!(&bytes[76..], b"boot.efi\0");
}

#[test]
fn restored_dispatch_transfers_identity_ticket_signed_boot_object_and_asr_image() {
    let file = fixture(None, false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    let mut state = restore::ContextState {
        ipsw,
        ..restore_state(file.path())
    };
    let initiate = wire::xml(&wire::dict([("Command", "Initiate".into())])).unwrap();
    let payload = wire::xml(&wire::dict([("Command", "Payload".into())])).unwrap();
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        tcp(12345, 2, 0, 1, 0x12, &[]),
        tcp(12345, 2, 1, 1, 0x10, &[initiate, payload].concat()),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    for kind in [
        "BuildIdentityDict",
        "BuildIdentityDictV2",
        "RootTicket",
        "PersonalizedBootObjectV3",
        "SystemImageData",
    ] {
        let message = wire::dict([
            ("MsgType", "DataRequestMsg".into()),
            ("DataType", kind.into()),
            ("Arguments", wire::dict([("ImageName", "iBSS".into())])),
        ]);
        state.serve(&session, &mut main, &message).unwrap();
    }
    let output = output.lock().unwrap();
    let mut control = Vec::new();
    let mut asr = Vec::new();
    for packet in output.iter().skip(2) {
        let packet = mux::decode_packet(packet, 2).unwrap();
        if packet.protocol != 6 || packet.payload.len() < 20 {
            continue;
        }
        let port = u16::from_be_bytes(packet.payload[2..4].try_into().unwrap());
        if port == 62078 {
            control.extend_from_slice(&packet.payload[20..]);
        }
        if port == 12345 {
            asr.extend_from_slice(&packet.payload[20..]);
        }
    }
    let mut control = Cursor::new(control);
    let id = wire::receive(&mut control).unwrap();
    assert!(wire::get(&id, &["BuildIdentityDict"]).is_ok());
    assert_eq!(wire::receive(&mut control).unwrap(), id);
    let root = wire::receive(&mut control).unwrap();
    assert_eq!(
        wire::get(&root, &["RootTicketData"])
            .unwrap()
            .as_data()
            .unwrap(),
        ticket()
    );
    let object = wire::receive(&mut control).unwrap();
    let data = wire::get(&object, &["FileData"])
        .unwrap()
        .as_data()
        .unwrap();
    assert!(data.windows(4).any(|w| w == b"IMG4"));
    assert!(wire::boolean(
        &wire::receive(&mut control).unwrap(),
        &["FileDataDone"]
    ));
    assert!(asr.ends_with(&im4p(b"test")));
}

#[test]
fn ticket_selection_uses_request_type_with_distinct_macos_identity() {
    let normal = ticket();
    let mut fields = img4::element(0x16, b"IM4M");
    fields.extend(img4::element(4, b"recovery-ticket"));
    let recovery = img4::element(0x30, &fields);
    let file = fixture(Some(recovery_identity()), false);
    let mut state = restore::ContextState {
        ipsw: Ipsw::open(file.path()).unwrap(),
        restore: restore::SignedIdentity {
            identity: identity(),
            ticket: wire::dict([("ApImg4Ticket", Value::Data(normal.clone()))]),
        },
        recovery: Some(restore::SignedIdentity {
            identity: recovery_identity(),
            ticket: wire::dict([("ApImg4Ticket", Value::Data(recovery.clone()))]),
        }),
        device: device_info(),
        assets: net::AssetClient::default(),
    };
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let request = |kind: &str, is_recovery| {
        wire::dict([
            ("MsgType", "DataRequestMsg".into()),
            ("DataType", kind.into()),
            (
                "Arguments",
                wire::dict([
                    ("IsRecoveryOS", Value::Boolean(is_recovery)),
                    ("ImageName", "KernelCache".into()),
                    ("FWOverrideKey", "RecoveryOSKernelCache".into()),
                ]),
            ),
        ])
    };
    let mut root_request = request("RootTicket", false);
    root_request
        .as_dictionary_mut()
        .unwrap()
        .insert("DataPort".into(), 0u64.into());
    state.serve(&session, &mut main, &root_request).unwrap();
    state
        .serve(&session, &mut main, &request("RootTicket", true))
        .unwrap();
    state
        .serve(
            &session,
            &mut main,
            &request("RecoveryOSRootTicketData", true),
        )
        .unwrap();
    state
        .serve(
            &session,
            &mut main,
            &request("PersonalizedBootObjectV3", true),
        )
        .unwrap();
    state
        .serve(
            &session,
            &mut main,
            &request("RecoveryOSFileAssetImage", true),
        )
        .unwrap();
    for (name, flag) in [
        ("KernelCache", "IsLoadedByiBoot"),
        ("iBSS", "IsLoadedByiBootStage1"),
    ] {
        manifest_mut(&mut state.recovery.as_mut().unwrap().identity)[name]
            .as_dictionary_mut()
            .unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert(flag.into(), true.into());
    }
    state
        .serve(
            &session,
            &mut main,
            &request("RecoveryOSIBootFWFilesImages", true),
        )
        .unwrap();
    state.recovery = None;
    assert!(
        state
            .serve(
                &session,
                &mut main,
                &request("RecoveryOSRootTicketData", true)
            )
            .is_err()
    );
    let mut data = vec![];
    for bytes in output.lock().unwrap().iter().skip(2) {
        let packet = mux::decode_packet(bytes, 2).unwrap();
        if packet.protocol == 6 {
            data.extend_from_slice(&packet.payload[20..]);
        }
    }
    let mut input = Cursor::new(data);
    let root = wire::receive(&mut input).unwrap();
    assert_eq!(
        wire::get(&root, &["RootTicketData"])
            .unwrap()
            .as_data()
            .unwrap(),
        normal
    );
    let root = wire::receive(&mut input).unwrap();
    assert_eq!(
        wire::get(&root, &["RootTicketData"])
            .unwrap()
            .as_data()
            .unwrap(),
        normal
    );
    let root = wire::receive(&mut input).unwrap();
    assert_eq!(
        wire::get(&root, &["RootTicketData"])
            .unwrap()
            .as_data()
            .unwrap(),
        recovery
    );
    let object = wire::receive(&mut input).unwrap();
    let data = wire::get(&object, &["FileData"])
        .unwrap()
        .as_data()
        .unwrap();
    let (root, _) = img4::parse(data).unwrap();
    let (_, fields) = img4::parse(root.content).unwrap();
    let (_, fields) = img4::parse(fields).unwrap();
    let (signed_ticket, _) = img4::parse(fields).unwrap();
    assert_eq!(signed_ticket.tag, 0xa0);
    assert_eq!(signed_ticket.content, normal);
    assert!(wire::boolean(
        &wire::receive(&mut input).unwrap(),
        &["FileDataDone"]
    ));
    let asset = wire::receive(&mut input).unwrap();
    let data = wire::get(&asset, &["AdditionalBootImages"])
        .unwrap()
        .as_data()
        .unwrap();
    let group = wire::receive(&mut input).unwrap();
    let images = wire::get(&group, &["AdditionalBootImages"])
        .unwrap()
        .as_dictionary()
        .unwrap();
    assert_eq!(images.len(), 2);
    for data in [
        data,
        images["KernelCache"].as_data().unwrap(),
        images["iBSS"].as_data().unwrap(),
    ] {
        let (root, _) = img4::parse(data).unwrap();
        let (_, fields) = img4::parse(root.content).unwrap();
        let (_, fields) = img4::parse(fields).unwrap();
        let (signed_ticket, _) = img4::parse(fields).unwrap();
        assert_eq!(signed_ticket.content, recovery);
    }
    assert_eq!(input.position(), input.get_ref().len() as u64);
}

#[test]
fn optional_global_manifest_completes_without_data_but_required_manifest_must_exist() {
    let file = fixture(None, false);
    let mut state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let request = |optional, suffix: &str| {
        wire::dict([
            ("DataType", "SourceBootObjectV4".into()),
            (
                "Arguments",
                wire::dict([
                    ("ImageName", "__GlobalManifest__".into()),
                    ("Variant", "macOS Customer".into()),
                    ("GlobalManifestOptional", Value::Boolean(optional)),
                    ("GlobalManifestSuffix", suffix.into()),
                ]),
            ),
        ])
    };
    state
        .serve(&session, &mut main, &request(false, ""))
        .unwrap();
    state
        .restore
        .identity
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("VariantSupportsGlobalSigning".into(), true.into());
    assert!(
        state
            .serve(&session, &mut main, &request(false, ""))
            .is_err()
    );
    state
        .serve(&session, &mut main, &request(true, ""))
        .unwrap();
    assert!(
        state
            .serve(&session, &mut main, &request(true, "/../../escape"))
            .is_err()
    );
    let global = ticket();
    let with_manifest = fixture_files(
        None,
        false,
        &[(
            "Firmware/Manifests/restore/macOS Customer/apticket.j313ap.im4m",
            &global,
        )],
    );
    state.ipsw = Ipsw::open(with_manifest.path()).unwrap();
    state
        .serve(&session, &mut main, &request(false, ""))
        .unwrap();
    let mut data = mux_output(&output, 62078);
    assert!(wire::boolean(
        &wire::receive(&mut data).unwrap(),
        &["FileDataDone"]
    ));
    assert!(wire::boolean(
        &wire::receive(&mut data).unwrap(),
        &["FileDataDone"]
    ));
    let file = wire::receive(&mut data).unwrap();
    assert_eq!(
        wire::get(&file, &["FileData"]).unwrap().as_data().unwrap(),
        global
    );
    assert!(wire::boolean(
        &wire::receive(&mut data).unwrap(),
        &["FileDataDone"]
    ));
}

#[test]
fn missing_optional_recovery_assets_are_reported_for_absent_or_unmatched_identities() {
    for recovery in [None, Some(recovery_identity())] {
        let file = fixture(None, false);
        let mut state = restore::ContextState {
            recovery: recovery.map(|identity| restore::SignedIdentity {
                identity,
                ticket: wire::dict([("ApImg4Ticket", Value::Data(ticket()))]),
            }),
            ..restore_state(file.path())
        };
        let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
        let session = Session::new(usb).unwrap();
        let mut main = session.connect(62078).unwrap();
        for (kind, key) in [
            ("RecoveryOSFileAssetImage", "RecoveryOSUnknownComponent"),
            ("RecoveryOSFileAssetImage", "OtherPrefix"),
            ("RecoveryOSIBootFWFilesImages", ""),
        ] {
            let request = wire::dict([
                ("DataType", kind.into()),
                (
                    "Arguments",
                    wire::dict([("IsRecoveryOS", true.into()), ("FWOverrideKey", key.into())]),
                ),
            ]);
            state.serve(&session, &mut main, &request).unwrap();
        }
        let mut data = mux_output(&output, 62078);
        for _ in 0..3 {
            let reply = wire::receive(&mut data).unwrap();
            assert!(wire::boolean(&reply, &["RecoveryOSNoAssetFound"]));
            assert!(wire::get(&reply, &["AdditionalBootImages"]).is_err());
        }
    }
}

#[test]
fn recovery_ticket_has_recovery_images_and_local_policy_uses_device_arguments() {
    let mut id = identity();
    manifest_mut(&mut id)
        .get_mut("OS")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Trusted".into(), false.into());
    assert!(wire::get(&tss::request(&device_info(), &id).unwrap(), &["OS"]).is_err());
    let recovery = tss::recovery_request(&device_info(), &id).unwrap();
    assert!(wire::get(&recovery, &["Ap,LocalBoot"]).is_err());
    assert!(wire::get(&recovery, &["OS"]).is_ok());
    assert!(wire::get(&recovery, &["iBSS"]).is_err());
    let args = wire::dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
        (
            "Ap,VolumeUUID",
            "00112233-4455-6677-8899-aabbccddeeff".into(),
        ),
    ]);
    let policy = tss::local_policy_request(&device_info(), &ticket(), Some(&args)).unwrap();
    assert!(wire::boolean(&policy, &["Ap,LocalBoot"]));
    assert!(wire::get(&policy, &["ApNonce"]).is_err());
    assert_eq!(
        wire::get(&policy, &["Ap,VolumeUUID"])
            .unwrap()
            .as_data()
            .unwrap()
            .len(),
        16
    );
}

#[test]
fn recovery_local_boot_is_only_used_as_a_rule_parameter() {
    let mut id = identity();
    manifest_mut(&mut id)
        .get_mut("OS")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "RestoreRequestRules".into(),
            Value::Array(vec![wire::dict([
                ("Conditions", wire::dict([("Ap,LocalBoot", false.into())])),
                ("Actions", wire::dict([("EPRO", false.into())])),
            ])]),
        );
    let device = device_info();
    let request = tss::recovery_request(&device, &id).unwrap();
    assert!(wire::get(&request, &["Ap,LocalBoot"]).is_err());
    assert_eq!(
        wire::get(&request, &["OS", "EPRO"]).unwrap(),
        &Value::Boolean(false)
    );
    assert_eq!(
        wire::get(&request, &["ApNonce"])
            .unwrap()
            .as_data()
            .unwrap(),
        device.ap_nonce
    );
    assert_eq!(
        wire::get(&request, &["UniqueBuildID"]).unwrap(),
        wire::get(&id.value, &["UniqueBuildID"]).unwrap()
    );
}

#[test]
fn system_image_metadata_requests_use_manifest_components_and_exact_file_keys() {
    let root_hash = b"root hash from fixture";
    let metadata = b"canonical metadata from fixture";
    let file = fixture_compression(
        None,
        false,
        &[("root.hash", root_hash), ("canonical.meta", metadata)],
        zip::CompressionMethod::Stored,
    );
    let mut state = restore_state(file.path());
    for (component, path, bytes) in [
        ("SystemVolume", "root.hash", root_hash.as_slice()),
        (
            "Ap,SystemVolumeCanonicalMetadata",
            "canonical.meta",
            metadata.as_slice(),
        ),
    ] {
        manifest_mut(&mut state.restore.identity).insert(
            component.into(),
            wire::dict([
                ("Trusted", false.into()),
                ("Digest", Value::Data(Sha384::digest(bytes).to_vec())),
                ("Info", wire::dict([("Path", path.into())])),
            ]),
        );
    }
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    for kind in ["SystemImageRootHash", "SystemImageCanonicalMetadata"] {
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into())]),
            )
            .unwrap();
    }
    let mut response = mux_output(&output, 62078);
    for (key, expected) in [
        ("SystemImageRootHashFile", root_hash.as_slice()),
        ("SystemImageCanonicalMetadataFile", metadata.as_slice()),
    ] {
        let message = wire::receive(&mut response).unwrap();
        assert_eq!(message.as_dictionary().unwrap().len(), 1);
        assert_eq!(
            wire::get(&message, &[key]).unwrap().as_data(),
            Some(expected)
        );
    }
    assert_eq!(response.position(), response.get_ref().len() as u64);
}

#[test]
fn both_bootability_requests_stream_both_archive_versions_as_cpio() {
    let mut previous = None;
    for (bundle, kind) in ["BootabilityBundle", "BootabilityBundleV2"]
        .into_iter()
        .flat_map(|bundle| ["BootabilityBundle", "BootabilityBundleV2"].map(|kind| (bundle, kind)))
    {
        let image = format!("{bundle}/Restore/Bootability/test.bin");
        let trustcache = format!("{bundle}/Restore/Firmware/Bootability.dmg.trustcache");
        let directory = format!("{bundle}/Restore/Bootability/");
        let file = fixture_compression(
            None,
            false,
            &[
                (image.as_str(), b"bootability fixture"),
                (trustcache.as_str(), b"trustcache fixture"),
                (directory.as_str(), b""),
                (
                    "BootabilityBundleV20/Restore/Bootability/ignored",
                    b"ignored",
                ),
            ],
            zip::CompressionMethod::Stored,
        );
        let mut state = restore_state(file.path());
        let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
        let session = Session::new(usb).unwrap();
        let mut main = session.connect(62078).unwrap();
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into())]),
            )
            .unwrap();
        let bytes = mux_output(&output, 62078).into_inner();
        let mut entries = std::collections::BTreeMap::new();
        let mut position = 0;
        loop {
            let header = &bytes[position..position + 76];
            assert_eq!(&header[..6], b"070707");
            let name_len =
                usize::from_str_radix(std::str::from_utf8(&header[59..65]).unwrap(), 8).unwrap();
            let size =
                usize::from_str_radix(std::str::from_utf8(&header[65..76]).unwrap(), 8).unwrap();
            position += 76;
            let name = std::str::from_utf8(&bytes[position..position + name_len - 1])
                .unwrap()
                .to_owned();
            assert_eq!(bytes[position + name_len - 1], 0);
            position += name_len;
            let data = bytes[position..position + size].to_vec();
            position += size;
            if name == "TRAILER!!!" {
                assert_eq!(size, 0);
                break;
            }
            assert!(entries.insert(name, data).is_none());
        }
        assert_eq!(position, bytes.len());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["test.bin"], b"bootability fixture");
        assert_eq!(entries["Bootability.trustcache"], b"trustcache fixture");
        if let Some(expected) = &previous {
            assert_eq!(&bytes, expected);
        }
        previous = Some(bytes);
    }
}

#[test]
fn macos_27_source_v5_and_device_info_preflight_use_their_service_ports() {
    let file = fixture(None, false);
    let mut state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        tcp(23456, 2, 0, 1, 0x12, &[]),
        tcp(23457, 3, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    state
        .serve(
            &session,
            &mut main,
            &wire::dict([
                ("DataType", "SourceBootObjectV5".into()),
                ("DataPort", 23456u64.into()),
                ("Arguments", wire::dict([("ImageName", "iBSS".into())])),
            ]),
        )
        .unwrap();
    state
        .serve(
            &session,
            &mut main,
            &wire::dict([
                ("DataType", "DeviceRestoreInfoPreflight".into()),
                ("DataPort", 23457u64.into()),
            ]),
        )
        .unwrap();
    let mut source = mux_output(&output, 23456);
    assert_eq!(
        wire::get(&wire::receive(&mut source).unwrap(), &["FileData"])
            .unwrap()
            .as_data()
            .unwrap(),
        im4p(b"test")
    );
    assert!(wire::boolean(
        &wire::receive(&mut source).unwrap(),
        &["FileDataDone"]
    ));
    assert_eq!(source.position(), source.get_ref().len() as u64);
    let mut preflight = mux_output(&output, 23457);
    assert!(
        wire::receive(&mut preflight)
            .unwrap()
            .as_dictionary()
            .unwrap()
            .is_empty()
    );
    assert!(mux_output(&output, 62078).get_ref().is_empty());
    let options = restore::options(&identity()).unwrap();
    for kind in ["SourceBootObjectV5", "DeviceRestoreInfoPreflight"] {
        assert!(wire::boolean(&options, &["SupportedDataTypes", kind]));
        assert!(wire::boolean(&options, &["SupportedAsyncDataTypes", kind]));
    }
}

#[test]
fn implemented_async_data_handlers_are_advertised() {
    let options = restore::options(&identity()).unwrap();
    for kind in [
        "URLAsset",
        "StreamedImageDecryptionKey",
        "SystemImageData",
        "RecoveryOSASRImage",
        "PersonalizedBootObjectV3",
        "FirmwareUpdaterData",
        "ReceiptManifest",
        "BuildIdentityDictV2",
        "BootabilityBundleV2",
        "SystemImageRootHash",
        "SystemImageCanonicalMetadata",
    ] {
        assert!(wire::boolean(&options, &["SupportedAsyncDataTypes", kind]));
    }
    assert!(wire::get(&options, &["SupportedAsyncDataTypes", "BasebandData"]).is_err());
    let file = fixture(None, false);
    let state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let _main = session.connect(62078).unwrap();
    let mut requests = restore::AsyncRequests::new(&session);
    for kind in [
        "BasebandData",
        "FileData",
        "FileDataDone",
        "ProvisioningData",
        "FDRMemoryCommit",
        "FirmwareUpdaterDataV3",
    ] {
        assert!(wire::get(&options, &["SupportedDataTypes", kind]).is_ok());
        assert!(wire::get(&options, &["SupportedAsyncDataTypes", kind]).is_err());
        let error = requests
            .spawn(
                &state,
                wire::dict([("DataType", kind.into()), ("DataPort", 23456u64.into())]),
            )
            .unwrap_err();
        assert!(error.to_string().contains("unsupported async data type"));
    }
    assert!(mux_output(&output, 23456).get_ref().is_empty());
}

#[test]
fn unsupported_data_requests_fail_before_opening_a_service_or_cancelling_control() {
    let file = fixture(None, false);
    let mut state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let writes = output.lock().unwrap().len();
    for kind in ["UnknownData", "FirmwareUpdaterDataV3", "FileData"] {
        let error = state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into()), ("DataPort", 23456u64.into())]),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("unsupported restored DataType {kind}"))
        );
        assert_eq!(output.lock().unwrap().len(), writes);
    }
    main.write_all(b"control still works").unwrap();
}

#[test]
fn async_asr_keeps_control_and_component_channels_responsive_with_independent_zip_readers() {
    for compression in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let file = fixture_compression(None, false, &[], compression);
        let mut state = restore_state(file.path());
        let (input, incoming) = mpsc::channel();
        let (output, outgoing) = mpsc::channel();
        input.send(version_packet()).unwrap();
        input.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
        let session = Session::new(LiveMux {
            input: incoming,
            output,
        })
        .unwrap();
        let mut main = session.connect(62078).unwrap();
        let mut requests = restore::AsyncRequests::new(&session);
        let asr_request = wire::dict([
            ("DataType", "SystemImageData".into()),
            ("DataPort", 12345u64.into()),
        ]);
        requests.spawn(&state, asr_request.clone()).unwrap();
        // Reserve the port until the first transfer completes.
        assert!(
            requests
                .spawn(&state, asr_request)
                .unwrap_err()
                .to_string()
                .contains("already in use")
        );
        input.send(tcp(12345, 2, 0, 1, 0x12, &[])).unwrap();
        let initiate = wire::xml(&wire::dict([
            ("Command", "Initiate".into()),
            ("Checksum Chunks", true.into()),
        ]))
        .unwrap();
        input.send(tcp(12345, 2, 1, 1, 0x10, &initiate)).unwrap();
        let info = receive_mux_data(&outgoing, 12345, 1);
        let info = Value::from_reader(Cursor::new(info)).unwrap();
        assert_eq!(
            wire::number(wire::get(&info, &["Payload", "Size"]).unwrap()).unwrap(),
            im4p(b"test").len() as u64
        );
        // ASR is still waiting for Payload. Control traffic must be handled now.
        let mut progress = vec![];
        wire::send(
            &mut progress,
            &wire::dict([("MsgType", "ProgressMsg".into())]),
        )
        .unwrap();
        input.send(tcp(62078, 1, 1, 1, 0x10, &progress)).unwrap();
        main.set_read_timeout(Duration::from_secs(2));
        assert_eq!(
            wire::string(&wire::receive(&mut main).unwrap(), &["MsgType"]).unwrap(),
            "ProgressMsg"
        );
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", "ReceiptManifest".into())]),
            )
            .unwrap();
        let mut expected_receipt = vec![];
        wire::send(
            &mut expected_receipt,
            &wire::dict([(
                "ReceiptManifest",
                Value::Dictionary(identity().manifest().unwrap().clone()),
            )]),
        )
        .unwrap();
        let control = receive_mux_data(&outgoing, 62078, expected_receipt.len());
        let receipt = wire::receive(&mut Cursor::new(control)).unwrap();
        assert_eq!(
            wire::get(&receipt, &["ReceiptManifest"])
                .unwrap()
                .as_dictionary()
                .unwrap(),
            identity().manifest().unwrap()
        );
        // A second worker reads a personalized component from the same IPSW.
        requests
            .spawn(
                &state,
                wire::dict([
                    ("DataType", "PersonalizedBootObjectV3".into()),
                    ("DataPort", 23456u64.into()),
                    ("Arguments", wire::dict([("ImageName", "iBSS".into())])),
                ]),
            )
            .unwrap();
        // The ASR reader can pump packets for every channel. Do not send the
        // SYN-ACK before the component worker has actually opened its channel.
        loop {
            let bytes = outgoing.recv_timeout(Duration::from_secs(3)).unwrap();
            let packet = mux::decode_packet(&bytes, 2).unwrap();
            if packet.protocol == 6
                && packet.payload[13] == 2
                && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == 23456
            {
                let source = u16::from_be_bytes(packet.payload[..2].try_into().unwrap());
                input.send(tcp(23456, source, 0, 1, 0x12, &[])).unwrap();
                break;
            }
        }
        let expected = state
            .ipsw
            .personalized(&identity(), "iBSS", &state.restore.ticket)
            .unwrap();
        let mut expected_frames = vec![];
        wire::send_binary(
            &mut expected_frames,
            &wire::dict([("FileData", Value::Data(expected))]),
        )
        .unwrap();
        wire::send(
            &mut expected_frames,
            &wire::dict([("FileDataDone", true.into())]),
        )
        .unwrap();
        assert_eq!(
            receive_mux_data(&outgoing, 23456, expected_frames.len()),
            expected_frames
        );
        // Complete ASR only after the other channels have both made progress.
        let payload = wire::xml(&wire::dict([("Command", "Payload".into())])).unwrap();
        input
            .send(tcp(12345, 2, 1 + initiate.len() as u32, 1, 0x10, &payload))
            .unwrap();
        let image = im4p(b"test");
        let expected = [image.as_slice(), sha1::Sha1::digest(&image).as_slice()].concat();
        assert_eq!(receive_mux_data(&outgoing, 12345, expected.len()), expected);
        requests.finish().unwrap();
    }
}

#[test]
fn async_ticket_requests_keep_restore_and_recovery_signatures_distinct() {
    let file = fixture(Some(recovery_identity()), false);
    let mut state = restore_state(file.path());
    let recovery_ticket = b"separate recoveryOS signature";
    state.recovery = Some(restore::SignedIdentity {
        identity: recovery_identity(),
        ticket: wire::dict([("ApImg4Ticket", Value::Data(recovery_ticket.to_vec()))]),
    });
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(23456, 1, 0, 1, 0x12, &[]),
        tcp(34567, 2, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut requests = restore::AsyncRequests::new(&session);
    for (kind, port, expected) in [
        (
            "RecoveryOSRootTicketData",
            23456,
            recovery_ticket.as_slice(),
        ),
        (
            "RootTicket",
            34567,
            tss::ticket(&state.restore.ticket).unwrap(),
        ),
    ] {
        requests
            .spawn(
                &state,
                wire::dict([
                    ("DataType", kind.into()),
                    ("DataPort", u64::from(port).into()),
                    ("Arguments", wire::dict([("IsRecoveryOS", true.into())])),
                ]),
            )
            .unwrap();
        requests.finish().unwrap();
        let reply = wire::receive(&mut mux_output(&output, port)).unwrap();
        assert_eq!(
            wire::get(&reply, &["RootTicketData"]).unwrap().as_data(),
            Some(expected)
        );
    }
}

#[test]
fn async_recovery_asr_selects_recovery_image_and_uses_its_explicit_port() {
    let image = b"separate recoveryOS image";
    let mut recovery = recovery_identity();
    manifest_mut(&mut recovery).insert("OS".into(), component_entry("recovery.dmg", image));
    let file = fixture_files(Some(recovery.clone()), false, &[("recovery.dmg", image)]);
    let mut state = restore_state(file.path());
    state.recovery = Some(restore::SignedIdentity {
        identity: recovery,
        ticket: wire::dict([("ApImg4Ticket", Value::Data(ticket()))]),
    });
    let initiate = wire::xml(&wire::dict([("Command", "Initiate".into())])).unwrap();
    let payload = wire::xml(&wire::dict([("Command", "Payload".into())])).unwrap();
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(34567, 1, 0, 1, 0x12, &[]),
        tcp(34567, 1, 1, 1, 0x10, &[initiate, payload].concat()),
    ]);
    let session = Session::new(usb).unwrap();
    let mut requests = restore::AsyncRequests::new(&session);
    requests
        .spawn(
            &state,
            wire::dict([
                ("DataType", "RecoveryOSASRImage".into()),
                ("DataPort", 34567u64.into()),
            ]),
        )
        .unwrap();
    requests.finish().unwrap();
    let mut data = mux_output(&output, 34567);
    let info = wire::receive_xml(&mut data).unwrap();
    assert_eq!(
        wire::number(wire::get(&info, &["Payload", "Size"]).unwrap()).unwrap(),
        image.len() as u64
    );
    let mut body = vec![];
    data.read_to_end(&mut body).unwrap();
    assert_eq!(body, image);
}

#[test]
fn async_requests_reject_invalid_ports_and_propagate_worker_failure_to_the_control_channel() {
    let file = fixture(None, false);
    let state = restore_state(file.path());
    let (usb, _) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        tcp(23456, 2, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let mut requests = restore::AsyncRequests::new(&session);
    for port in [0, 62078, 65536] {
        assert!(
            requests
                .spawn(
                    &state,
                    wire::dict([
                        ("DataType", "RootTicket".into()),
                        ("DataPort", (port as u64).into()),
                    ])
                )
                .is_err()
        );
    }
    assert!(
        requests
            .spawn(&state, wire::dict([("DataType", "RootTicket".into())]))
            .is_err()
    );
    assert!(
        requests
            .spawn(
                &state,
                wire::dict([
                    ("DataType", "Unknown".into()),
                    ("DataPort", 23456u64.into()),
                ])
            )
            .is_err()
    );
    main.write_all(b"still connected").unwrap();
    requests
        .spawn(
            &state,
            wire::dict([
                ("DataType", "PersonalizedBootObjectV3".into()),
                ("DataPort", 23456u64.into()),
                (
                    "Arguments",
                    wire::dict([("ImageName", "MissingFirmware".into())]),
                ),
            ]),
        )
        .unwrap();
    let error = requests.finish().unwrap_err();
    assert!(
        error.to_string().contains("PersonalizedBootObjectV3")
            && error.to_string().contains("23456")
    );
    assert!(
        error
            .chain()
            .skip(1)
            .any(|cause| cause.to_string().contains("MissingFirmware"))
    );
    assert!(main.write_all(b"session was cancelled").is_err());
}

#[test]
fn async_completion_releases_ports_and_leaves_the_control_channel_available() {
    let file = fixture(None, false);
    let state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(62078, 1, 0, 1, 0x12, &[]),
        tcp(23456, 2, 0, 1, 0x12, &[]),
        tcp(23456, 3, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    let mut requests = restore::AsyncRequests::new(&session);
    for _ in 0..2 {
        requests
            .spawn(
                &state,
                wire::dict([
                    ("DataType", "RootTicket".into()),
                    ("DataPort", 23456u64.into()),
                ]),
            )
            .unwrap();
        requests.finish().unwrap();
        requests.check().unwrap();
        main.write_all(b"control is still connected").unwrap();
    }
    requests.finish().unwrap();
    let mut replies = mux_output(&output, 23456);
    for _ in 0..2 {
        let reply = wire::receive(&mut replies).unwrap();
        assert_eq!(
            wire::get(&reply, &["RootTicketData"])
                .unwrap()
                .as_data()
                .unwrap(),
            tss::ticket(&state.restore.ticket).unwrap()
        );
    }
    assert_eq!(replies.position(), replies.get_ref().len() as u64);
}

#[test]
fn nor_formats_preserve_firmware_order_and_separate_llb_and_sep_images() {
    let bytes = im4p(b"test");
    let names = ["LLB", "Auxiliary", "iBoot", "RestoreSEP", "SEP"];
    let paths: Vec<_> = names
        .iter()
        .map(|name| format!("Firmware/{name}"))
        .collect();
    let files: Vec<_> = paths
        .iter()
        .map(|path| (path.as_str(), bytes.as_slice()))
        .collect();
    let file = fixture_files(None, false, &files);
    let mut state = restore_state(file.path());
    let manifest = manifest_mut(&mut state.restore.identity);
    for (name, path) in names.into_iter().zip(&paths) {
        let mut entry = component_entry(path, &bytes);
        entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("IsFirmwarePayload".into(), (name != "SEP").into());
        manifest.insert(name.into(), entry);
    }
    let id = state.restore.identity.clone();
    let mut expected = plist::Dictionary::new();
    for name in names {
        expected.insert(
            name.into(),
            Value::Data(
                state
                    .ipsw
                    .personalized(&id, name, &state.restore.ticket)
                    .unwrap(),
            ),
        );
    }
    let (usb, output) = mock_mux(vec![version_packet(), tcp(62078, 1, 0, 1, 0x12, &[])]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(62078).unwrap();
    for named in [false, true] {
        let args = if named {
            wire::dict([("FlashVersion1", true.into())])
        } else {
            Value::Dictionary(plist::Dictionary::new())
        };
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", "NORData".into()), ("Arguments", args)]),
            )
            .unwrap();
    }
    let mut output = mux_output(&output, 62078);
    for named in [false, true] {
        let reply = wire::receive(&mut output).unwrap();
        for (key, name) in [
            ("LlbImageData", "LLB"),
            ("RestoreSEPImageData", "RestoreSEP"),
            ("SEPImageData", "SEP"),
        ] {
            assert_eq!(wire::get(&reply, &[key]).unwrap(), &expected[name]);
        }
        let nor = wire::get(&reply, &["NorImageData"]).unwrap();
        if named {
            let nor = wire::dictionary(nor).unwrap();
            assert_eq!(
                nor.keys().map(String::as_str).collect::<Vec<_>>(),
                ["iBoot", "Auxiliary"]
            );
            assert_eq!(nor["iBoot"], expected["iBoot"]);
            assert_eq!(nor["Auxiliary"], expected["Auxiliary"]);
        } else {
            assert_eq!(
                nor.as_array().unwrap(),
                &[expected["iBoot"].clone(), expected["Auxiliary"].clone()]
            );
        }
    }
}

#[test]
fn large_nor_reply_crosses_mux_windows_and_allows_the_next_checkpoint() {
    let payload: Vec<u8> = (0..1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    let mut fields = img4::element(0x16, b"IM4P");
    fields.extend(img4::element(0x16, b"test"));
    fields.extend(img4::element(0x16, b"large NOR fixture"));
    fields.extend(img4::element(4, &payload));
    let bytes = img4::element(0x30, &fields);
    let names = ["LLB", "iBoot", "RestoreSEP", "SEP"];
    let paths: Vec<_> = names
        .iter()
        .map(|name| format!("Firmware/{name}"))
        .collect();
    let files: Vec<_> = paths
        .iter()
        .map(|path| (path.as_str(), bytes.as_slice()))
        .collect();
    let file = fixture_files(None, false, &files);
    let mut state = restore_state(file.path());
    for (name, path) in names.into_iter().zip(&paths) {
        let mut entry = component_entry(path, &bytes);
        entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("IsFirmwarePayload".into(), (name != "SEP").into());
        manifest_mut(&mut state.restore.identity).insert(name.into(), entry);
    }
    let id = state.restore.identity.clone();
    let mut expected = plist::Dictionary::new();
    for name in names {
        expected.insert(
            name.into(),
            Value::Data(
                state
                    .ipsw
                    .personalized(&id, name, &state.restore.ticket)
                    .unwrap(),
            ),
        );
    }
    let (to_device, peer_input) = mpsc::channel::<Vec<u8>>();
    let (peer_output, to_host) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let mut received = Vec::new();
        let mut sequence = 1u32;
        loop {
            let bytes = peer_input.recv_timeout(Duration::from_secs(5)).unwrap();
            if u32::from_be_bytes(bytes[..4].try_into().unwrap()) == 0 {
                peer_output.send(version_packet()).unwrap();
                continue;
            }
            let packet = mux::decode_packet(&bytes, 2).unwrap();
            if packet.protocol != 6 {
                continue;
            }
            let tcp_data = packet.payload;
            if tcp_data[13] == 2 {
                peer_output.send(tcp(62078, 1, 0, 1, 0x12, &[])).unwrap();
                continue;
            }
            if tcp_data.len() == 20 {
                continue;
            }
            assert_eq!(
                u32::from_be_bytes(tcp_data[4..8].try_into().unwrap()),
                sequence
            );
            sequence += (tcp_data.len() - 20) as u32;
            received.extend_from_slice(&tcp_data[20..]);
            peer_output
                .send(tcp(62078, 1, 1, sequence, 0x10, &[]))
                .unwrap();
            if received.len() >= 4 {
                let length = u32::from_be_bytes(received[..4].try_into().unwrap()) as usize;
                if received.len() >= length + 4 {
                    assert_eq!(received.len(), length + 4);
                    assert!(length > 4 * 1024 * 1024);
                    let reply = wire::receive(&mut Cursor::new(received)).unwrap();
                    let mut checkpoint = Cursor::new(Vec::new());
                    wire::send(
                        &mut checkpoint,
                        &wire::dict([
                            ("MsgType", "CheckpointMsg".into()),
                            ("CHECKPOINT_NAME", "load_sep_os".into()),
                            ("CHECKPOINT_COMPLETE", true.into()),
                            ("CHECKPOINT_RESULT", 0u64.into()),
                        ]),
                    )
                    .unwrap();
                    peer_output
                        .send(tcp(62078, 1, 1, sequence, 0x10, checkpoint.get_ref()))
                        .unwrap();
                    // Keep the duplex endpoint alive for host ACKs until the
                    // host closes the channel after receiving the checkpoint.
                    while let Ok(bytes) = peer_input.recv_timeout(Duration::from_secs(5)) {
                        let packet = mux::decode_packet(&bytes, 2).unwrap();
                        if packet.protocol == 6 && packet.payload[13] & 4 != 0 {
                            break;
                        }
                    }
                    return reply;
                }
            }
        }
    });
    let session = Session::new(LiveMux {
        input: to_host,
        output: to_device,
    })
    .unwrap();
    let mut main = session.connect(62078).unwrap();
    main.set_read_timeout(Duration::from_secs(5));
    state
        .serve(
            &session,
            &mut main,
            &wire::dict([
                ("DataType", "NORData".into()),
                ("Arguments", wire::dict([("FlashVersion1", "1".into())])),
            ]),
        )
        .unwrap();
    let checkpoint = wire::receive(&mut main).unwrap();
    assert_eq!(
        wire::string(&checkpoint, &["CHECKPOINT_NAME"]).unwrap(),
        "load_sep_os"
    );
    assert!(wire::boolean(&checkpoint, &["CHECKPOINT_COMPLETE"]));
    drop(main);
    drop(session);
    let reply = peer.join().unwrap();
    for (key, name) in [
        ("LlbImageData", "LLB"),
        ("RestoreSEPImageData", "RestoreSEP"),
        ("SEPImageData", "SEP"),
    ] {
        assert_eq!(wire::get(&reply, &[key]).unwrap(), &expected[name]);
    }
    assert_eq!(
        wire::get(&reply, &["NorImageData", "iBoot"]).unwrap(),
        &expected["iBoot"]
    );
}

#[test]
fn diagnostic_query_uses_the_existing_stream_and_does_not_start_a_restore() {
    let reply = wire::dict([(
        "HardwareInfo",
        wire::dict([("UniqueChipID", 123u64.into())]),
    )]);
    let mut frame = Vec::new();
    wire::send_binary(&mut frame, &reply).unwrap();
    let mut stream = Duplex::new(frame, 1);
    assert_eq!(
        restore::query_value(&mut stream, "HardwareInfo").unwrap(),
        reply
    );
    let mut request = Cursor::new(stream.output);
    assert_eq!(
        wire::receive(&mut request).unwrap(),
        wire::dict([
            ("Request", "QueryValue".into()),
            ("QueryKey", "HardwareInfo".into()),
            ("Label", "zalivka".into()),
        ])
    );
    assert_eq!(request.position(), request.get_ref().len() as u64);
}

fn outgoing_data(bytes: &[u8], port: u16) -> &[u8] {
    if bytes[..4] == 0u32.to_be_bytes() {
        return &[]; // The initial version packet still has the v1 header.
    }
    let packet = mux::decode_packet(bytes, 2).unwrap();
    if packet.protocol == 6
        && packet.payload.len() >= 20
        && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == port
    {
        &packet.payload[20..]
    } else {
        &[]
    }
}

fn receive_mux_data(output: &mpsc::Receiver<Vec<u8>>, port: u16, length: usize) -> Vec<u8> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut bytes = vec![];
    while bytes.len() < length {
        let packet = output
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .expect("restore worker stopped producing data");
        bytes.extend_from_slice(outgoing_data(&packet, port));
    }
    bytes
}

#[test]
fn identity_independent_requests_do_not_require_recovery_firmware() {
    let file = fixture(None, false);
    let mut state = restore_state(file.path());
    let (usb, output) = mock_mux(vec![
        version_packet(),
        tcp(restore::RESTORED_PORT, 1, 0, 1, 0x12, &[]),
    ]);
    let session = Session::new(usb).unwrap();
    let mut main = session.connect(restore::RESTORED_PORT).unwrap();
    let arguments = wire::dict([("IsRecoveryOS", true.into())]);
    for kind in [
        "FDRTrustData",
        "FirmwareUpdaterPreflight",
        "DeviceRestoreInfoPreflight",
        "RootTicket",
    ] {
        state
            .serve(
                &session,
                &mut main,
                &wire::dict([("DataType", kind.into()), ("Arguments", arguments.clone())]),
            )
            .unwrap();
    }
    let mut replies = mux_output(&output, restore::RESTORED_PORT);
    for _ in 0..3 {
        assert!(
            wire::dictionary(&wire::receive(&mut replies).unwrap())
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        wire::receive(&mut replies).unwrap(),
        wire::dict([("RootTicketData", Value::Data(ticket()))])
    );
    assert_eq!(replies.position(), replies.get_ref().len() as u64);

    // An invalid asset URL must reach the network decoder without requiring an
    // unrelated RecoveryOS identity. This test never performs a network request.
    for kind in ["URLAsset", "StreamedImageDecryptionKey"] {
        let error = state
            .serve(
                &session,
                &mut main,
                &wire::dict([
                    ("DataType", kind.into()),
                    (
                        "Arguments",
                        wire::dict([
                            ("IsRecoveryOS", true.into()),
                            ("RequestURL", "https://invalid.example/asset".into()),
                            ("RequestMethod", "GET".into()),
                        ]),
                    ),
                ]),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("Apple distribution host"),
            "{kind}: {error:#}"
        );
    }
    // Requests which actually consume recovery firmware must still fail.
    for kind in [
        "BuildIdentityDict",
        "ReceiptManifest",
        "KernelCache",
        "RecoveryOSRootTicketData",
    ] {
        assert!(
            state
                .serve(
                    &session,
                    &mut main,
                    &wire::dict([("DataType", kind.into()), ("Arguments", arguments.clone())]),
                )
                .is_err(),
            "{kind} accepted missing recovery firmware"
        );
    }
}
