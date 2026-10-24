use super::*;

#[test]
fn der_roundtrip_and_reject_truncated_or_noncanonical_values() {
    for n in [0, 1, 127, 128, 255, 256, 65536] {
        let data = vec![0xab; n];
        let encoded = img4::element(4, &data);
        let (parsed, rest) = img4::parse(&encoded).unwrap();
        assert_eq!(parsed.content, data);
        assert!(rest.is_empty());
    }
    for bad in [
        &[4, 0x80][..],
        &[4, 0x81, 1, 0],
        &[4, 0x82, 0, 128],
        &[4, 4, 0],
        &[0xff, 0x80, 0],
        &[0x1f, 0x1e, 0],
        &[0xff, 0x01, 0],
        &[0xff, 0x80, 0x81, 0, 0],
        &[0xff, 0x90, 0x80, 0x80, 0x80, 0, 0], // Tag overflows u32.
        &[4, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert!(img4::parse(bad).is_err(), "{bad:?}");
    }
    for valid in [&[0x1f, 0x1f, 0][..], &[0xff, 0x81, 0x00, 0]] {
        assert!(img4::parse(valid).is_ok(), "{valid:?}");
    }
}

#[test]
fn der_length_headers_match_wire_fixtures() {
    for (length, header) in [
        (0, &b"\x04\x00"[..]),
        (127, b"\x04\x7f"),
        (128, b"\x04\x81\x80"),
        (255, b"\x04\x81\xff"),
        (256, b"\x04\x82\x01\x00"),
        (65535, b"\x04\x82\xff\xff"),
        (65536, b"\x04\x83\x01\x00\x00"),
    ] {
        let encoded = img4::element(4, &vec![0xab; length]);
        assert_eq!(&encoded[..header.len()], header, "length {length}");
        assert_eq!(encoded.len(), header.len() + length);
    }
}

#[test]
fn im4p_prefix_uses_canonical_headers_and_stays_inside_the_declared_sequence() {
    let payload = im4p(b"krnl");
    let offset = img4::type_offset(&payload).unwrap();
    for length in 0..=payload.len() {
        assert_eq!(
            img4::type_offset(&payload[..length]),
            (length >= offset + 4).then_some(offset),
            "prefix length {length}"
        );
    }
    let fields = &payload[2..];
    for header in [
        vec![0x30, 0],
        vec![0x30, 6], // Only the magic belongs to the sequence.
        vec![0x30, 0x80],
        vec![0x30, 0x81, fields.len() as u8],
        vec![0x30, 0x82, 0, 128],
        [
            vec![0x30, 0x80 | size_of::<usize>() as u8],
            vec![255; size_of::<usize>()],
        ]
        .concat(),
    ] {
        let malformed = [header, fields.to_vec()].concat();
        assert_eq!(img4::type_offset(&malformed), None, "{malformed:?}");
        assert!(img4::personalize("iBSS", &malformed, &ticket()).is_err());
    }
    // A large image can expose its type before the body has arrived.
    let prefix = [vec![0x30, 0x84, 0x40, 0, 0, 0], fields[..12].to_vec()].concat();
    assert_eq!(img4::type_offset(&prefix), Some(14));
    assert!(img4::parse(&prefix).is_err());
    // Header-only inspection must also support images larger than 4 GiB.
    if usize::BITS > 32 {
        let prefix = [vec![0x30, 0x85, 1, 0, 0, 0, 0], fields[..12].to_vec()].concat();
        assert_eq!(img4::type_offset(&prefix), Some(15));
        assert!(img4::parse(&prefix).is_err());
    }
}

#[test]
fn img4_preserves_payload_and_uses_restore_tag() {
    let payload = im4p(b"krnl");
    let image = img4::personalize("RestoreKernelCache", &payload, &ticket()).unwrap();
    let (sequence, _) = img4::parse(&image).unwrap();
    let (magic, rest) = img4::parse(sequence.content).unwrap();
    assert_eq!(magic.content, b"IMG4");
    let (p, rest) = img4::parse(rest).unwrap();
    let (_, fields) = img4::parse(p.content).unwrap();
    let (kind, _) = img4::parse(fields).unwrap();
    assert_eq!(kind.content, b"rkrn");
    let (manifest, rest) = img4::parse(rest).unwrap();
    assert_eq!(manifest.tag, 0xa0);
    assert_eq!(manifest.content, ticket());
    assert!(rest.is_empty());
    assert!(img4::personalize("iBSS", b"garbage", &ticket()).is_err());
    assert!(img4::personalize("iBSS", &payload, b"invalid ticket").is_err());
}

#[test]
fn img4_metadata_matches_the_existing_envelope_at_der_length_boundaries() {
    for size in [0, 1, 127, 128, 255, 256, 65536] {
        let mut fields = img4::element(0x16, b"IM4P");
        fields.extend(img4::element(0x16, b"sepi"));
        fields.extend(img4::element(0x16, b"test"));
        fields.extend(img4::element(4, &vec![0xab; size]));
        fields.extend(img4::element(0xa0, b"trailing metadata"));
        let payload = img4::element(0x30, &fields);
        for metadata in [false, true] {
            let mut id = identity();
            let info = id
                .value
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Info")
                .unwrap()
                .as_dictionary_mut()
                .unwrap();
            info.insert("RequiresNonceSlot".into(), metadata.into());
            info.insert("SepNonceSlotID".into(), 128u64.into());
            let mut tss = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
            if metadata {
                tss.as_dictionary_mut().unwrap().insert(
                    "SEP-TBM".into(),
                    wire::dict([
                        ("ucon", Value::Data(vec![1, 2])),
                        ("ucer", Value::Data(vec![3, 4])),
                    ]),
                );
            }
            // Construct the expected wire envelope independently of personalization.
            let mut expected = img4::element(0x16, b"IMG4");
            expected.extend_from_slice(&payload);
            expected.extend(img4::element(0xa0, &ticket()));
            assert_eq!(
                img4::personalize("SEP", &payload, &ticket()).unwrap(),
                img4::element(0x30, &expected)
            );
            if let Some(info) = img4::restore_info(&tss, "SEP", &id.value).unwrap() {
                expected.extend(info);
            }
            let actual = img4::personalize_with_metadata("SEP", &payload, &tss, &id.value).unwrap();
            assert_eq!(
                actual,
                img4::element(0x30, &expected),
                "size {size}, IM4R {metadata}"
            );
        }
    }
}

#[test]
fn nonce_slots_use_positive_der_integers_and_apple_private_tags() {
    for (slot, integer) in [
        (0, &b"\x02\x01\x00"[..]),
        (127, b"\x02\x01\x7f"),
        (128, b"\x02\x02\x00\x80"),
        (255, b"\x02\x02\x00\xff"),
        (256, b"\x02\x02\x01\x00"),
        (u64::MAX, b"\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    ] {
        let identity = wire::dict([(
            "Info",
            wire::dict([
                ("RequiresNonceSlot", true.into()),
                ("SepNonceSlotID", slot.into()),
                ("ApNonceSlotID", slot.into()),
            ]),
        )]);
        for (component, tag, name) in [
            ("SEP", b"\xff\x87\x9b\xb9\xd2\x64", b"snid"),
            ("SepStage1", b"\xff\x87\x9b\xb9\xd2\x64", b"snid"),
            ("LLB", b"\xff\x86\x8b\xb9\xd2\x64", b"anid"),
        ] {
            let info =
                img4::restore_info(&wire::dict([] as [(&str, Value); 0]), component, &identity)
                    .unwrap()
                    .unwrap();
            let (outer, _) = img4::parse(&info).unwrap();
            let (sequence, _) = img4::parse(outer.content).unwrap();
            let (_, fields) = img4::parse(sequence.content).unwrap();
            let (set, _) = img4::parse(fields).unwrap();
            let (property, rest) = img4::parse(set.content).unwrap();
            assert!(rest.is_empty());
            assert_eq!(&property.encoded[..6], tag);
            let (sequence, rest) = img4::parse(property.content).unwrap();
            assert!(rest.is_empty());
            let (actual_name, actual_integer) = img4::parse(sequence.content).unwrap();
            assert_eq!(actual_name.content, name);
            assert_eq!(actual_integer, integer, "{component}, slot {slot}");
        }
    }
}

#[test]
fn local_policy_and_im4r_nonce_slot_tbm_are_encoded() {
    assert_eq!(
        device::encode_hex(&img4::empty_local_policy()),
        "30141604494d345016046c706f6c1603312e30040100"
    );
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("RequiresNonceSlot".into(), true.into());
    let tss = wire::dict([
        ("ApImg4Ticket", Value::Data(ticket())),
        (
            "SEP-TBM",
            wire::dict([
                ("ucon", Value::Data(vec![1, 2])),
                ("ucer", Value::Data(vec![3, 4])),
            ]),
        ),
    ]);
    let info = img4::restore_info(&tss, "SEP", &id.value).unwrap().unwrap();
    let (outer, _) = img4::parse(&info).unwrap();
    assert_eq!(outer.tag, 0xa1);
    let (inner, _) = img4::parse(outer.content).unwrap();
    let (magic, rest) = img4::parse(inner.content).unwrap();
    assert_eq!(magic.content, b"IM4R");
    let (set, _) = img4::parse(rest).unwrap();
    let (private, rest) = img4::parse(set.content).unwrap();
    assert_eq!(private.tag, 0xff);
    assert!(!rest.is_empty());
    assert!(info.windows(4).any(|w| w == b"snid"));
    assert!(info.windows(4).any(|w| w == b"ucon"));
    assert!(info.windows(4).any(|w| w == b"ucer"));
}
