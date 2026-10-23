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
    ] {
        assert!(img4::parse(bad).is_err(), "{bad:?}");
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
            // Retain the previous composition as a byte compatibility check:
            // IMG4 body, followed by optional IM4R, inside one outer sequence.
            let base = img4::personalize("SEP", &payload, &ticket()).unwrap();
            let (outer, rest) = img4::parse(&base).unwrap();
            assert!(rest.is_empty());
            let mut expected = outer.content.to_vec();
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
