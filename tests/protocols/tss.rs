use super::*;

#[test]
fn tss_requests_bind_hardware_nonce_and_component_digests() {
    let d = device_info();
    let id = identity();
    let request = tss::request(&d, &id).unwrap();
    assert_eq!(
        wire::number(wire::get(&request, &["ApECID"]).unwrap()).unwrap(),
        d.ecid
    );
    assert_eq!(
        wire::get(&request, &["ApNonce"])
            .unwrap()
            .as_data()
            .unwrap(),
        d.ap_nonce
    );
    assert!(wire::get(&request, &["iBSS", "Info"]).is_err());
    assert!(wire::boolean(&request, &["iBSS", "ESEC"]));
    assert_eq!(
        wire::get(&request, &["iBSS", "Digest"]).unwrap(),
        wire::get(&id.value, &["Manifest", "iBSS", "Digest"]).unwrap()
    );
    let local = tss::local_policy_request(&d, &ticket(), None).unwrap();
    assert_eq!(
        wire::get(&local, &["Ap,NextStageIM4MHash"])
            .unwrap()
            .as_data()
            .unwrap(),
        Sha384::digest(ticket()).as_slice()
    );
    let mut no_nonce = d;
    no_nonce.ap_nonce.clear();
    assert!(tss::request(&no_nonce, &id).is_err());
}

#[test]
fn shared_component_preparation_keeps_default_flags_specific_to_restore_requests() {
    for rules in [
        None,
        Some(Value::Array(vec![])),
        Some(Value::Array(vec![wire::dict([
            ("Conditions", wire::dict([] as [(&str, Value); 0])),
            ("Actions", wire::dict([("ESEC", false.into())])),
        ])])),
    ] {
        let mut id = identity();
        let mut info = wire::dict([("Path", "Firmware/extra".into())]);
        if let Some(rules) = &rules {
            info.as_dictionary_mut()
                .unwrap()
                .insert("RestoreRequestRules".into(), rules.clone());
        }
        manifest_mut(&mut id).insert(
            "Extra".into(),
            wire::dict([("Trusted", true.into()), ("Info", info)]),
        );
        let restore = tss::request(&device_info(), &id).unwrap();
        let recovery = tss::recovery_request(&device_info(), &id).unwrap();
        for request in [&restore, &recovery] {
            assert!(wire::get(request, &["Extra", "Info"]).is_err());
            assert_eq!(
                wire::get(request, &["Extra", "Digest"]).unwrap().as_data(),
                Some(&[][..])
            );
        }
        if rules.is_none() {
            assert!(wire::boolean(&restore, &["Extra", "EPRO"]));
            assert!(wire::boolean(&restore, &["Extra", "ESEC"]));
            assert!(wire::get(&recovery, &["Extra", "EPRO"]).is_err());
            assert!(wire::get(&recovery, &["Extra", "ESEC"]).is_err());
        } else {
            assert_eq!(
                wire::get(&restore, &["Extra"]).unwrap(),
                wire::get(&recovery, &["Extra"]).unwrap()
            );
            assert!(wire::get(&restore, &["Extra", "EPRO"]).is_err());
        }
    }
}

#[test]
fn signing_rejects_malformed_metadata_instead_of_skipping_components() {
    for entry in [
        true.into(),
        wire::dict([("Info", "invalid".into())]),
        wire::dict([
            ("Info", wire::dict([] as [(&str, Value); 0])),
            ("Trusted", "true".into()),
        ]),
        wire::dict([
            ("Trusted", true.into()),
            ("Info", wire::dict([("RestoreRequestRules", false.into())])),
        ]),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert("Extra".into(), entry);
        for build in [tss::request, tss::recovery_request] {
            let error = build(&device_info(), &id).unwrap_err();
            assert!(format!("{error:#}").contains("Extra"), "{error:#}");
        }
    }
    let mut id = identity();
    manifest_mut(&mut id).insert("SigningOnly".into(), wire::dict([("Trusted", true.into())]));
    for build in [tss::request, tss::recovery_request] {
        assert!(wire::get(&build(&device_info(), &id).unwrap(), &["SigningOnly"]).is_err());
    }
}

#[test]
fn component_rules_use_device_parameters_independently_of_manifest_order() {
    let first = wire::dict([
        ("Trusted", true.into()),
        ("Info", wire::dict([] as [(&str, Value); 0])),
    ]);
    for build in [tss::request, tss::recovery_request] {
        let mut id = identity();
        manifest_mut(&mut id).insert("First".into(), first.clone());
        let prepared = wire::get(&build(&device_info(), &id).unwrap(), &["First"])
            .unwrap()
            .clone();
        let second = wire::dict([
            ("Trusted", true.into()),
            (
                "Info",
                wire::dict([(
                    "RestoreRequestRules",
                    Value::Array(vec![wire::dict([
                        ("Conditions", wire::dict([("First", prepared)])),
                        ("Actions", wire::dict([("ESEC", false.into())])),
                    ])]),
                )]),
            ),
        ]);
        manifest_mut(&mut id).insert("Second".into(), second.clone());
        let forward = build(&device_info(), &id).unwrap();
        let entries = manifest_mut(&mut id);
        entries.remove("First");
        entries.remove("Second");
        entries.insert("Second".into(), second);
        entries.insert("First".into(), first.clone());
        let reverse = build(&device_info(), &id).unwrap();
        assert_eq!(
            wire::get(&forward, &["Second"]).unwrap(),
            wire::get(&reverse, &["Second"]).unwrap()
        );
        assert!(wire::get(&forward, &["Second", "ESEC"]).is_err());
    }
}

#[test]
fn local_policy_volume_uuid_preserves_byte_order_and_rejects_misplaced_hyphens() {
    for (valid, uuid) in [
        (true, "00112233-4455-6677-8899-aabbccddeeff"),
        (true, "00112233-4455-6677-8899-AABBCCDDEEFF"),
        (true, "00112233445566778899aabbccddeeff"),
        (false, "-00112233445566778899aabbccddeeff"),
        (false, "00112233445566778899aabbccddeeff-"),
        (false, "0011223344556677-8899aabbccddeeff"),
        (false, "00112233--4455-6677-8899-aabbccddeeff"),
        (false, "00112233-4455-6677-8899-aabbccddeezz"),
        (false, "00112233-4455-6677-8899-aabbccddee"),
    ] {
        let args = wire::dict([
            ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
            ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
            ("Ap,VolumeUUID", uuid.into()),
        ]);
        let policy = tss::local_policy_request(&device_info(), &ticket(), Some(&args));
        if valid {
            let policy = policy.unwrap();
            assert_eq!(
                wire::get(&policy, &["Ap,VolumeUUID"])
                    .unwrap()
                    .as_data()
                    .unwrap(),
                &[
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff
                ],
                "{uuid}"
            );
        } else {
            assert!(policy.is_err(), "accepted {uuid:?}");
        }
    }
}

#[test]
fn local_policy_omits_firmware_metadata_without_changing_firmware_requests() {
    let mut id = identity();
    let metadata = [
        "Ap,OSLongVersion",
        "Ap,OSReleaseType",
        "Ap,ProductMarketingVersion",
        "Ap,ProductType",
        "Ap,SDKPlatform",
        "Ap,Target",
        "Ap,TargetType",
        "Ap,Timestamp",
        "PearlCertificationRootPub",
        "NeRDEpoch",
        "AllowNeRDBoot",
        "PermitNeRDPivot",
    ];
    for key in metadata {
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), "firmware-only fixture".into());
    }
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("RequiresUIDMode".into(), true.into());
    let device = device_info();
    let firmware = tss::request(&device, &id).unwrap();
    let recovery = tss::recovery_request(&device, &id).unwrap();
    for request in [&firmware, &recovery] {
        for key in metadata {
            assert_eq!(
                wire::get(request, &[key]).unwrap(),
                wire::get(&id.value, &[key]).unwrap()
            );
        }
        assert!(wire::get(request, &["UniqueBuildID"]).is_ok());
        assert!(wire::get(request, &["SepNonce"]).is_ok());
        assert!(wire::get(request, &["UID_MODE"]).is_ok());
    }

    let args = wire::dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
        (
            "Ap,VolumeUUID",
            "00112233-4455-6677-8899-aabbccddeeff".into(),
        ),
    ]);
    for args in [None, Some(&args)] {
        let policy = tss::local_policy_request(&device, &ticket(), args).unwrap();
        let mut expected = vec![
            "@HostPlatformInfo",
            "@VersionInfo",
            "@ApImg4Ticket",
            "ApECID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
            "ApProductionMode",
            "ApSecurityMode",
            "Ap,LocalBoot",
            "Ap,LocalPolicy",
            "Ap,NextStageIM4MHash",
        ];
        if args.is_some() {
            expected.extend(["Ap,RecoveryOSPolicyNonceHash", "Ap,VolumeUUID"]);
        } else {
            expected.push("ApNonce");
            assert_eq!(
                wire::get(&policy, &["ApNonce"]).unwrap().as_data().unwrap(),
                device.ap_nonce
            );
        }
        expected.sort_unstable();
        let mut actual: Vec<&str> = wire::dictionary(&policy)
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        for key in [
            "ApECID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
            "ApProductionMode",
            "ApSecurityMode",
        ] {
            assert_eq!(
                wire::get(&policy, &[key]).unwrap(),
                wire::get(&firmware, &[key]).unwrap()
            );
        }
        assert_eq!(wire::boolean(&policy, &["Ap,LocalBoot"]), args.is_some());
    }
}

#[test]
fn tss_restore_rules_apply_only_when_conditions_match() {
    let mut entry = plist::Dictionary::new();
    let parameters = wire::dict([("ApProductionMode", true.into())]);
    let rules = Value::Array(vec![
        wire::dict([
            (
                "Conditions",
                wire::dict([
                    ("ApRawProductionMode", true.into()),
                    ("ApRequiresImage4", true.into()),
                ]),
            ),
            ("Actions", wire::dict([("EPRO", true.into())])),
        ]),
        wire::dict([
            (
                "Conditions",
                wire::dict([("UnknownCondition", true.into())]),
            ),
            ("Actions", wire::dict([("ESEC", false.into())])),
        ]),
    ]);
    tss::apply_rules(&mut entry, &rules, parameters.as_dictionary().unwrap()).unwrap();
    assert_eq!(entry.get("EPRO"), Some(&true.into()));
    assert!(!entry.contains_key("ESEC"));
}

#[test]
fn tss_never_accepts_rejection_or_malformed_success() {
    assert!(tss::parse_response(b"STATUS=94&MESSAGE=not eligible").is_err());
    assert!(tss::parse_response(b"STATUS=9&MESSAGE=FAIL&REQUEST_STRING=<plist/>").is_err());
    assert!(tss::parse_response(b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=bad").is_err());
    let response = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
    let bytes = [
        b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".as_slice(),
        &wire::xml(&response).unwrap(),
    ]
    .concat();
    assert_eq!(tss::parse_response(&bytes).unwrap(), response);
    for header in [
        "STATUS=94&STATUS=0",
        "STATUS=0&STATUS=94",
        "STATUS=0&STATUS=0",
        "MESSAGE=SUCCESS",
    ] {
        let bytes = [
            format!("{header}&REQUEST_STRING=").into_bytes(),
            wire::xml(&response).unwrap(),
        ]
        .concat();
        assert!(tss::parse_response(&bytes).is_err(), "{header}");
    }
}
