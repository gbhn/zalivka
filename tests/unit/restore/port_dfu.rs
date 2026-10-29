use super::*;
use crate::{device::DeviceInfo, wire};

fn archive(value: Value) -> Value {
    fn add(value: Value, objects: &mut Vec<Value>) -> Value {
        let value = match value {
            Value::Dictionary(fields) => {
                let (keys, values): (Vec<_>, Vec<_>) = fields
                    .into_iter()
                    .map(|(k, v)| (add(k.into(), objects), add(v, objects)))
                    .unzip();
                wire::dict([
                    ("NS.keys", Value::Array(keys)),
                    ("NS.objects", Value::Array(values)),
                ])
            }
            Value::Array(values) => wire::dict([(
                "NS.objects",
                Value::Array(values.into_iter().map(|v| add(v, objects)).collect()),
            )]),
            value => value,
        };
        let uid = plist::Uid::new(objects.len() as u64);
        objects.push(value);
        Value::Uid(uid)
    }
    let mut objects = vec!["$null".into()];
    let root = add(value, &mut objects);
    wire::dict([
        ("$archiver", "NSKeyedArchiver".into()),
        ("$objects", Value::Array(objects)),
        ("$top", wire::dict([("root", root)])),
    ])
}

fn uarp(board: u64, revision_min: u64, revision_max: u64) -> Vec<u8> {
    let metadata = wire::dict([(
        "SuperBinary Payloads",
        Value::Array(vec![wire::dict([
            ("Payload 4CC", "DL99".into()),
            (
                "Payload MetaData",
                wire::dict([
                    (
                        "Personalization Manifest Prefix",
                        "USBPortController".into(),
                    ),
                    ("Personalization Board ID (64 bits)", board.into()),
                    (
                        "Personalization Matching Data",
                        Value::Array(vec![wire::dict([
                            (
                                "Personalization Matching Data Product Revision Minimum",
                                revision_min.into(),
                            ),
                            (
                                "Personalization Matching Data Product Revision Maximum",
                                revision_max.into(),
                            ),
                            (
                                "Personalization Matching Data Payload Tags",
                                "PT99,AC99".into(),
                            ),
                        ])]),
                    ),
                ]),
            ),
        ])]),
    )]);
    let mut plist = Vec::new();
    archive(metadata).to_writer_binary(&mut plist).unwrap();
    let mut out = vec![0; 164];
    for (offset, value) in [(0, 2u32), (4, 44), (8, 173), (36, 44), (40, 120)] {
        out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    for (i, (tag, bytes)) in [(b"PT99", b"ABC"), (b"AC99", b"DEF"), (b"DL99", b"GHI")]
        .iter()
        .enumerate()
    {
        let offset = 44 + i * 40;
        out[offset..offset + 4].copy_from_slice(&40u32.to_be_bytes());
        out[offset + 4..offset + 8].copy_from_slice(*tag);
        for (field, value) in [
            (8, 2u32),
            (12, 66),
            (16, 40),
            (32, (164 + i * 3) as u32),
            (36, 3),
        ] {
            out[offset + field..offset + field + 4].copy_from_slice(&value.to_be_bytes());
        }
        out.extend(*bytes);
    }
    out.extend(plist);
    out
}

#[test]
fn ace3_selects_by_board_and_revision_and_encodes_the_controller_image() {
    let firmware = uarp(0xf081fa00, 32, 63);
    let selected = payloads(&firmware, 0xf081fa00, 32).unwrap();
    let image = binary(selected, b"ticket").unwrap();
    assert_eq!(&image[64..], b"ABCDEFticketGHI");
    let words: Vec<_> = image[..40]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|v| u32::from_le_bytes(*v))
        .collect();
    assert_eq!(
        &words[..9],
        &[0xace00003, 0x00206640, 0x2800, 64, 3, 3, 70, 9, 15]
    );
    assert_eq!(&image[40..64], &[0xff; 24]);
    // Independent bit-at-a-time reference, including bit order and no final XOR.
    let mut crc = u32::MAX;
    for byte in &image[64..] {
        for bit in 0..8 {
            let xor = (crc >> 31) ^ u32::from((byte >> bit) & 1);
            crc <<= 1;
            if xor != 0 {
                crc ^= 0x04c11db7;
            }
        }
    }
    assert_eq!(words[9], crc);
    assert!(payloads(&firmware, 0xf081fa00, 63).is_ok());
    assert!(payloads(&firmware, 0xf081fa00, 31).is_err());
    assert!(payloads(&firmware, 0xf081fa00, 64).is_err());
    assert!(payloads(&firmware, 0xf081fa01, 32).is_err());
}

#[test]
fn ace3_rejects_truncation_bad_offsets_cycles_and_oversized_images() {
    let firmware = uarp(9, 0, 255);
    for length in 0..firmware.len() {
        assert!(
            payloads(&firmware[..length], 9, 0).is_err(),
            "length {length}"
        );
    }
    for (offset, value) in [
        (4, 45u32),
        (8, u32::MAX),
        (36, u32::MAX),
        (40, u32::MAX),
        (44, 0),
        (76, 0),
        (80, u32::MAX),
    ] {
        let mut malformed = firmware.clone();
        malformed[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(payloads(&malformed, 9, 0).is_err(), "offset {offset}");
    }
    let mut cyclic = archive("value".into());
    cyclic.as_dictionary_mut().unwrap().insert(
        "$objects".into(),
        Value::Array(vec![
            Value::Uid(plist::Uid::new(1)),
            Value::Uid(plist::Uid::new(1)),
        ]),
    );
    assert!(
        unarchive(&cyclic)
            .unwrap_err()
            .to_string()
            .contains("cyclic")
    );
    assert!(
        binary(
            payloads(&firmware, 9, 0).unwrap(),
            &vec![1; 4 * 1024 * 1024]
        )
        .is_err()
    );
}

#[test]
fn port_ticket_uses_controller_identity_fuses_and_reversed_nonce() {
    let mut controller = DeviceInfo::parse(
        "ECID:2a CPID:22 BDID:22813200 SDOM:01 CPFM:03 PREV:20",
        Mode::PortDfu,
    )
    .unwrap();
    controller.ap_nonce = vec![1, 2, 3, 4];
    let identity = Identity::new(
        0,
        wire::dict([
            ("USBPortController1,ChipID", 0x22u64.into()),
            ("USBPortController1,BoardID", 0x22813200u64.into()),
            ("USBPortController1,SecurityDomain", 1u64.into()),
            (
                "Manifest",
                wire::dict([(
                    FIRMWARE,
                    wire::dict([
                        ("Digest", Value::Data(vec![1; 32])),
                        ("Info", wire::dict([("Path", "controller.uarp".into())])),
                    ]),
                )]),
            ),
        ]),
    );
    let ticket = request(&controller, &identity).unwrap();
    assert_eq!(
        wire::get(&ticket, &["USBPortController1,Nonce"])
            .unwrap()
            .as_data()
            .unwrap(),
        [4, 3, 2, 1]
    );
    assert_eq!(
        wire::number(wire::get(&ticket, &["USBPortController1,ECID"]).unwrap()).unwrap(),
        42
    );
    assert!(wire::get(&ticket, &["ApECID"]).is_err());
    assert!(wire::get(&ticket, &[FIRMWARE, "Info"]).is_err());
    controller.board_id += 1;
    assert!(request(&controller, &identity).is_err());
    controller.board_id -= 1;
    controller.security_domain = None;
    assert!(request(&controller, &identity).is_ok());
    controller.security_domain = Some(2);
    assert!(request(&controller, &identity).is_err());
}

#[test]
fn current_m4_m5_controller_metadata_builds_bound_tickets() {
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/m4-m5-metadata.json")).unwrap();
    let mut checked = 0;
    for model in snapshot["models"].as_array().unwrap() {
        for value in model["identities"].as_array().unwrap() {
            let value: Value = serde_json::from_value(value.clone()).unwrap();
            let mut identity = Identity::new(0, value);
            let chip =
                wire::number(wire::get(&identity.value, &["USBPortController1,ChipID"]).unwrap())
                    .unwrap();
            let board =
                wire::number(wire::get(&identity.value, &["USBPortController1,BoardID"]).unwrap())
                    .unwrap();
            let mut controller = DeviceInfo::parse(
                &format!("ECID:2A CPID:{chip:X} BDID:{board:X} CPFM:03 PREV:20"),
                Mode::PortDfu,
            )
            .unwrap();
            controller.ap_nonce = vec![1; 32];
            identity.value.as_dictionary_mut().unwrap()["Manifest"]
                .as_dictionary_mut()
                .unwrap()
                .insert(
                    FIRMWARE.into(),
                    wire::dict([("Digest", Value::Data(vec![1; 32]))]),
                );
            request(&controller, &identity).unwrap();
            checked += 1;
        }
    }
    assert_eq!(checked, 66);
}

#[test]
#[ignore = "read-only lab check; provide ZALIVKA_ACE3_UARP and ZALIVKA_BUILD_MANIFEST, no USB or TSS"]
fn apple_ace3_archive_matches_build_manifest() {
    let firmware =
        std::fs::read(std::env::var_os("ZALIVKA_ACE3_UARP").expect("UARP path required")).unwrap();
    let manifest = std::fs::read(
        std::env::var_os("ZALIVKA_BUILD_MANIFEST").expect("BuildManifest path required"),
    )
    .unwrap();
    let manifest = wire::decode_plist(&manifest).unwrap();
    let mut checked = 0;
    for value in wire::get(&manifest, &["BuildIdentities"])
        .unwrap()
        .as_array()
        .unwrap()
    {
        if wire::optional(value, &["Manifest", FIRMWARE])
            .unwrap()
            .is_none()
        {
            continue;
        }
        let Some(board) = wire::optional(value, &["USBPortController1,BoardID"]).unwrap() else {
            continue;
        };
        for revision in [0, 32, 64, 255] {
            let Ok(selected) = payloads(&firmware, wire::number(board).unwrap(), revision) else {
                continue;
            };
            crate::ipsw::verify_digest(
                selected.digest_list,
                wire::get(value, &["Manifest", FIRMWARE, "Digest"])
                    .unwrap()
                    .as_data()
                    .unwrap(),
            )
            .unwrap();
            let image = binary(selected, b"synthetic ticket, no signing request").unwrap();
            assert!(image.len() > 64);
            checked += 1;
        }
    }
    assert!(checked >= 4, "no matching real UARP/manifest identities");
    eprintln!("Validated {checked} Apple UARP/identity/revision combinations without USB or TSS");
}
