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
    assert!(crate::test_support::boolean(&request, &["iBSS", "ESEC"]));
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
fn signing_requires_device_security_metadata_and_never_defaults_to_production() {
    let mut device = device_info();
    for (fuse, production, security) in [
        (0, false, false),
        (1, false, true),
        (2, true, false),
        (3, true, true),
    ] {
        device.chip_fuse_mode = Some(fuse);
        let request = tss::request(&device, &identity()).unwrap();
        assert_eq!(
            wire::get(&request, &["ApProductionMode"]).unwrap(),
            &Value::Boolean(production)
        );
        assert_eq!(
            wire::get(&request, &["ApSecurityMode"]).unwrap(),
            &Value::Boolean(security)
        );
    }
    device.chip_fuse_mode = None;
    assert!(tss::request(&device, &identity()).is_err());
    device.chip_fuse_mode = Some(3);
    device.security_domain = None;
    assert!(tss::request(&device, &identity()).is_err());
    let mut id = identity();
    manifest_mut(&mut id)
        .get_mut("iBSS")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("Personalize");
    assert!(wire::get(&tss::request(&device_info(), &id).unwrap(), &["iBSS"]).is_ok());
}

#[test]
fn component_signing_uses_declared_trust_rules_and_actions() {
    for rules in [
        Value::Array(vec![]),
        Value::Array(vec![wire::dict([
            ("Conditions", wire::dict([] as [(&str, Value); 0])),
            (
                "Actions",
                wire::dict([
                    ("ESEC", false.into()),
                    ("FutureAction", Value::Data(vec![1, 2])),
                ]),
            ),
        ])]),
    ] {
        let mut id = identity();
        let entry = wire::dict([
            ("Trusted", true.into()),
            ("Digest", Value::Data(vec![])),
            (
                "Info",
                wire::dict([
                    ("Personalize", true.into()),
                    ("RestoreRequestRules", rules.clone()),
                ]),
            ),
        ]);
        manifest_mut(&mut id).insert("NewComponent".into(), entry);
        for build in [tss::request, tss::recovery_request] {
            let request = build(&device_info(), &id).unwrap();
            assert!(wire::get(&request, &["NewComponent", "Info"]).is_err());
            assert!(wire::get(&request, &["NewComponent", "EPRO"]).is_err());
            assert_eq!(
                wire::get(&request, &["NewComponent", "ESEC"]).is_ok(),
                !rules.as_array().unwrap().is_empty()
            );
        }
        manifest_mut(&mut id)["NewComponent"]
            .as_dictionary_mut()
            .unwrap()
            .remove("Digest");
        assert_eq!(
            wire::get(
                &tss::request(&device_info(), &id).unwrap(),
                &["NewComponent", "Digest"]
            )
            .unwrap(),
            &Value::Data(vec![])
        );
    }
}

#[test]
fn fileless_measurements_are_signed_even_with_personalize_false() {
    let manifest: Value =
        serde_json::from_str(include_str!("../fixtures/j313-26A434-fdr.json")).unwrap();
    for renamed in [false, true] {
        let mut id = identity();
        for (index, (name, value)) in manifest.as_dictionary().unwrap().iter().enumerate() {
            let name = if renamed {
                format!("new{index}")
            } else {
                name.clone()
            };
            manifest_mut(&mut id).insert(name, value.clone());
        }
        let original = id.value.clone();
        for build in [tss::request, tss::recovery_request] {
            let request = build(&device_info(), &id).unwrap();
            for (index, (name, _)) in manifest.as_dictionary().unwrap().iter().enumerate() {
                let name = if renamed {
                    format!("new{index}")
                } else {
                    name.clone()
                };
                assert_eq!(
                    wire::get(&request, &[&name]).unwrap(),
                    &wire::dict([
                        ("Trusted", true.into()),
                        ("EPRO", true.into()),
                        ("ESEC", true.into()),
                        ("Digest", Value::Data(vec![])),
                    ])
                );
            }
        }
        assert_eq!(id.value, original);
    }
}

#[test]
fn trusted_file_hashes_are_never_replaced_with_server_measurement_markers() {
    for digest in [None, Some(Value::Data(vec![])), Some("invalid".into())] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)["iBSS"].as_dictionary_mut().unwrap();
        entry.remove("Digest");
        if let Some(digest) = digest {
            entry.insert("Digest".into(), digest);
        }
        entry["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("Personalize".into(), false.into());
        for build in [tss::request, tss::recovery_request] {
            let error = build(&device_info(), &id).unwrap_err();
            assert!(format!("{error:#}").contains("iBSS"), "{error:#}");
        }
    }
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "newa".into(),
        wire::dict([
            ("Trusted", true.into()),
            ("Info", wire::dict([("Personalize", false.into())])),
        ]),
    );
    assert!(tss::request(&device_info(), &id).is_err());
}

fn measurement_property(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
    use asn1_rs::{Class, Header, Length, Tag, ToDer};
    let mut body = img4::element(0x16, name);
    body.extend_from_slice(value);
    let body = img4::element(0x30, &body);
    let header = Header::new(
        Class::Private,
        true,
        Tag(u32::from_be_bytes(*name)),
        Length::Definite(body.len()),
    );
    let mut encoded = Vec::new();
    header.write_der_header(&mut encoded).unwrap();
    encoded.extend(body);
    encoded
}

fn measurement_ticket(objects: &[u8]) -> Value {
    let mut fields = img4::element(0x16, b"IM4M");
    fields.extend(img4::element(0x02, &[0]));
    fields.extend(img4::element(
        0x31,
        &measurement_property(b"MANB", &img4::element(0x31, objects)),
    ));
    fields.extend(img4::element(0x04, b"synthetic-signature"));
    fields.extend(img4::element(0x30, &[]));
    wire::dict([("ApImg4Ticket", Value::Data(img4::element(0x30, &fields)))])
}

#[test]
fn server_generated_measurements_must_be_present_and_nonempty_in_the_returned_ticket() {
    let request = wire::dict([(
        "newa",
        wire::dict([("Trusted", true.into()), ("Digest", Value::Data(vec![]))]),
    )]);
    let digest = measurement_property(b"DGST", &img4::element(0x04, &[0xab; 32]));
    let object = measurement_property(b"newa", &img4::element(0x31, &digest));
    let valid = measurement_ticket(&object);
    assert_eq!(
        tss::validate_ticket(&request, &valid).unwrap(),
        tss::ticket(&valid).unwrap()
    );
    for objects in [
        vec![],
        measurement_property(b"newb", &img4::element(0x31, &digest)),
        measurement_property(b"newa", &img4::element(0x31, &[])),
        measurement_property(
            b"newa",
            &img4::element(
                0x31,
                &measurement_property(b"DGST", &img4::element(0x04, &[])),
            ),
        ),
        measurement_property(
            b"newa",
            &img4::element(
                0x31,
                &measurement_property(b"DGST", &img4::element(0x01, &[0xff])),
            ),
        ),
        measurement_property(
            b"newa",
            &img4::element(0x31, &[digest.clone(), digest].concat()),
        ),
        [object.clone(), object].concat(),
    ] {
        let error = tss::validate_ticket(&request, &measurement_ticket(&objects)).unwrap_err();
        assert!(format!("{error:#}").contains("newa"), "{error:#}");
    }
    for malformed in [
        b"invalid".to_vec(),
        tss::ticket(&valid).unwrap()[..12].to_vec(),
    ] {
        assert!(
            tss::validate_ticket(
                &request,
                &wire::dict([("ApImg4Ticket", Value::Data(malformed))])
            )
            .is_err()
        );
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
        let error = build(&device_info(), &id).unwrap_err();
        assert!(format!("{error:#}").contains("SigningOnly"));
    }
}

#[test]
fn trusted_signing_measurements_without_info_keep_their_declared_digest() {
    let entry = wire::dict([
        ("Trusted", true.into()),
        ("Digest", Value::Data(vec![0x36; 48])),
    ]);
    let mut id = identity();
    manifest_mut(&mut id).insert("FutureMeasurement".into(), entry.clone());
    for build in [tss::request, tss::recovery_request] {
        let request = build(&device_info(), &id).unwrap();
        assert_eq!(wire::get(&request, &["FutureMeasurement"]).unwrap(), &entry);
    }
}

#[test]
fn local_policy_rejects_missing_empty_or_nondata_hashes() {
    let valid = wire::dict([
        ("Ap,NextStageIM4MHash", Value::Data(vec![5; 48])),
        ("Ap,RecoveryOSPolicyNonceHash", Value::Data(vec![6; 48])),
        (
            "Ap,VolumeUUID",
            "00112233-4455-6677-8899-aabbccddeeff".into(),
        ),
    ]);
    for name in ["Ap,NextStageIM4MHash", "Ap,RecoveryOSPolicyNonceHash"] {
        for invalid in [
            None,
            Some(Value::Data(vec![])),
            Some("hash".into()),
            Some(false.into()),
        ] {
            let mut args = valid.clone();
            let fields = args.as_dictionary_mut().unwrap();
            fields.remove(name);
            if let Some(value) = invalid {
                fields.insert(name.into(), value);
            }
            let error =
                tss::local_policy_request(&device_info(), &ticket(), Some(&args)).unwrap_err();
            assert!(format!("{error:#}").contains(name), "{error:#}");
        }
    }
}

#[test]
fn component_rules_use_device_parameters_independently_of_manifest_order() {
    let first = wire::dict([
        ("Trusted", true.into()),
        ("Info", wire::dict([("Personalize", true.into())])),
        ("Digest", Value::Data(vec![])),
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
        let mut second = second;
        second
            .as_dictionary_mut()
            .unwrap()
            .insert("Digest".into(), Value::Data(vec![]));
        second
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Personalize".into(), true.into());
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
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("UID_MODE".into(), false.into());
    id.value
        .as_dictionary_mut()
        .unwrap()
        .insert("Ap,SikaFuse".into(), 0u64.into());
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
        assert_eq!(
            crate::test_support::boolean(&policy, &["Ap,LocalBoot"]),
            args.is_some()
        );
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

#[test]
fn unmatched_signing_rules_still_require_well_formed_actions() {
    for actions in [None, Some(true.into())] {
        let mut rule = wire::dict([(
            "Conditions",
            wire::dict([("UnavailableParameter", true.into())]),
        )]);
        if let Some(actions) = actions {
            rule.as_dictionary_mut()
                .unwrap()
                .insert("Actions".into(), actions);
        }
        let mut entry = plist::Dictionary::new();
        assert!(
            tss::apply_rules(
                &mut entry,
                &Value::Array(vec![rule]),
                &plist::Dictionary::new()
            )
            .is_err()
        );
        assert!(entry.is_empty());
    }
}
#[test]
fn signing_rules_validate_the_resulting_trust_and_digest() {
    for (trusted, digest) in [
        ("yes".into(), Value::Data(vec![1; 48])),
        (true.into(), Value::Data(vec![])),
        (true.into(), Value::Data(vec![1; 17])),
    ] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)
            .get_mut("iBSS")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        entry.insert("Trusted".into(), false.into());
        entry
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "RestoreRequestRules".into(),
                Value::Array(vec![wire::dict([
                    ("Conditions", wire::dict([] as [(&str, Value); 0])),
                    (
                        "Actions",
                        wire::dict([("Trusted", trusted), ("Digest", digest)]),
                    ),
                ])]),
            );
        assert!(tss::request(&device_info(), &id).is_err());
    }
}

#[test]
fn manifest_components_cannot_replace_device_signing_fields() {
    for name in ["ApNonce", "ApECID", "@ApImg4Ticket", "@FutureTicket"] {
        let mut id = identity();
        let entry = manifest_mut(&mut id)["iBSS"].clone();
        manifest_mut(&mut id).insert(name.into(), entry);
        assert!(tss::request(&device_info(), &id).is_err(), "{name}");
    }
}

#[test]
fn signing_rejects_an_identity_for_other_hardware_or_security_domain() {
    for key in ["ApChipID", "ApBoardID", "ApSecurityDomain"] {
        let mut id = identity();
        id.value
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), 0xffffu64.into());
        for request in [tss::request, tss::recovery_request] {
            assert!(request(&device_info(), &id).is_err(), "{key}");
        }
    }
}
