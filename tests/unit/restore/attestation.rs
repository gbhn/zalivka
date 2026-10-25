use super::*;
use asn1_rs::{Header, Length, Tag};
use std::time::Duration;

const SYNTHETIC_ROOT: &[u8] = include_bytes!("../../fixtures/attestation/synthetic-root.cer");
const SYNTHETIC_INTERMEDIATE: &[u8] =
    include_bytes!("../../fixtures/attestation/synthetic-intermediate.cer");
const SYNTHETIC_LEAF: &[u8] = include_bytes!("../../fixtures/attestation/synthetic-leaf.cer");

fn attestation(mode: u64) -> Attestation {
    let mut id = Identity::new(
        3,
        serde_json::from_str(include_str!("../../fixtures/j313-26A434-iboot.json")).unwrap(),
    );
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("RestoreAttestationMode".into(), mode.into());
    let device = DeviceInfo::parse(
        "CPID:8103 BDID:26 ECID:000123456789abcd SDOM:01 CPFM:03",
        crate::device::Mode::Dfu,
    )
    .unwrap();
    let ticket = wire::dict([(
        "ApImg4Ticket",
        Value::Data(b"synthetic iBSS restore ticket".to_vec()),
    )]);
    Attestation::new(&id, &device, &ticket).unwrap()
}

fn message(state: &str) -> Value {
    wire::dict([
        ("MsgType", "RestoreAttestation".into()),
        ("RestoreAttestationState", state.into()),
    ])
}

#[test]
fn supported_levels_request_attestation_and_cannot_finish_without_a_certificate() {
    assert!(attestation(6).finish().is_err());
    for mode in 0..=8 {
        let mut attest = attestation(mode);
        let reply = attest
            .handle(&message("RestoreShouldAttest"))
            .unwrap()
            .unwrap();
        assert_eq!(
            reply,
            wire::dict([("RestoreShouldAttest", (mode != 0).into())])
        );
        assert_eq!(attest.finish().is_ok(), mode == 0);
        assert!(attest.handle(&message("AttestationIssued")).is_err());
        assert_eq!(attest.finish().is_ok(), mode == 0);
    }
}

#[test]
fn successful_device_status_does_not_replace_a_missing_attestation_and_is_still_acknowledged() {
    let mut output = Vec::new();
    let status = wire::dict([("MsgType", "StatusMsg".into()), ("Status", 0i64.into())]);
    let proof = attestation(6);
    assert!(
        super::super::session::finish_final_status(&mut output, &status, || proof.finish())
            .is_err()
    );
    assert_eq!(
        wire::receive(&mut std::io::Cursor::new(output)).unwrap(),
        wire::dict([("MsgType", "ReceivedFinalStatusMsg".into())])
    );
}

#[test]
fn update_restore_declines_dfu_attestation_and_unknown_levels_fail_before_boot() {
    let mut id = Identity::new(
        3,
        serde_json::from_str(include_str!("../../fixtures/j313-26A434-iboot.json")).unwrap(),
    );
    let info = id
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    info.insert("RestoreBehavior".into(), "Update".into());
    let expected = attestation(6);
    let ticket = wire::dict([(
        "ApImg4Ticket",
        Value::Data(b"synthetic iBSS restore ticket".to_vec()),
    )]);
    let mut update = Attestation::new(&id, &expected.device, &ticket).unwrap();
    assert_eq!(
        update.handle(&message("RestoreShouldAttest")).unwrap(),
        Some(wire::dict([("RestoreShouldAttest", false.into())]))
    );
    update.finish().unwrap();
    for mode in [9u64.into(), true.into()] {
        id.value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("RestoreAttestationMode".into(), mode);
        assert!(Attestation::new(&id, &expected.device, &ticket).is_err());
    }
}

#[test]
fn attestation_errors_and_unknown_or_out_of_order_states_are_rejected() {
    for state in ["AttestationIssued", "AttestationError", "unknown"] {
        assert!(attestation(6).handle(&message(state)).is_err());
    }
    assert!(
        attestation(6)
            .handle(&wire::dict([] as [(&str, Value); 0]))
            .is_err()
    );
    let mut attest = attestation(6);
    attest.handle(&message("RestoreShouldAttest")).unwrap();
    for certificates in [
        Value::Array(vec![]),
        Value::Array(vec![false.into(); 2]),
        Value::Array(vec![Value::Data(vec![0; 16385]); 2]),
    ] {
        let mut issued = message("AttestationIssued");
        issued
            .as_dictionary_mut()
            .unwrap()
            .insert("Certificates".into(), certificates);
        assert!(attest.handle(&issued).is_err());
        assert!(attest.finish().is_err());
    }
}

#[test]
fn official_apple_baa_chains_verify_only_under_their_matching_pinned_root() {
    for (leaf, intermediate, root, other_root) in [
        (
            include_bytes!("../../fixtures/attestation/baa-scrt-leaf.cer").as_slice(),
            include_bytes!("../../fixtures/attestation/baa-system-subca.cer").as_slice(),
            SYSTEM_ROOT,
            USER_ROOT,
        ),
        (
            include_bytes!("../../fixtures/attestation/baa-ucrt-leaf.cer").as_slice(),
            include_bytes!("../../fixtures/attestation/baa-user-subca.cer").as_slice(),
            USER_ROOT,
            SYSTEM_ROOT,
        ),
    ] {
        let cert = certificate_from_der(leaf).unwrap();
        let when = cert.validity().not_before.timestamp() as u64 + 60;
        let now = UnixTime::since_unix_epoch(Duration::from_secs(when));
        verify_chain(leaf, intermediate, root, now).unwrap();
        assert!(verify_chain(leaf, intermediate, other_root, now).is_err());
        assert!(verify_chain(leaf, intermediate, root, UnixTime::now()).is_err());
        let mut corrupt = leaf.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(verify_chain(&corrupt, intermediate, root, now).is_err());
        assert!(verify_chain(leaf, root, root, now).is_err());
    }
}

#[test]
fn real_apple_device_identifier_encoding_is_parsed_without_claiming_it_is_a_restore_proof() {
    let leaf = include_bytes!("../../fixtures/attestation/baa-scrt-leaf.cer");
    assert_eq!(
        device_identifiers(leaf).unwrap()[&2],
        b"8010-844d838134126-5-a0000000"
    );
    assert!(attestation(6).verify_properties(leaf).is_err());
}

#[test]
fn synthetic_restore_proof_verifies_both_crypto_and_all_level_eight_bindings() {
    let when = UnixTime::since_unix_epoch(Duration::from_secs(1792886400));
    verify_chain(SYNTHETIC_LEAF, SYNTHETIC_INTERMEDIATE, SYNTHETIC_ROOT, when).unwrap();
    for mode in [1, 2, 3, 4, 5, 6, 7, 8] {
        attestation(mode).verify_properties(SYNTHETIC_LEAF).unwrap();
    }
    // An attacker cannot supply their own anchor through the restore protocol.
    let mut attest = attestation(8);
    attest.handle(&message("RestoreShouldAttest")).unwrap();
    let mut issued = message("AttestationIssued");
    issued.as_dictionary_mut().unwrap().extend([
        (
            "Certificates".into(),
            Value::Array(vec![
                Value::Data(SYNTHETIC_LEAF.to_vec()),
                Value::Data(SYNTHETIC_INTERMEDIATE.to_vec()),
            ]),
        ),
        ("AttestationUseSCRT".into(), true.into()),
    ]);
    assert!(attest.handle(&issued).is_err());
    assert!(attest.finish().is_err());
}

#[test]
fn wrong_ecid_ticket_boot_tag_security_domain_and_local_boot_measurements_fail() {
    let attest = attestation(8);
    let original = device_identifiers(SYNTHETIC_LEAF).unwrap();
    for (tag, bytes) in [
        (2, b"8103-123456789abce-d-a0000000".as_slice()),
        (2, b"8104-123456789abcd-d-a0000000".as_slice()),
        (2, b"8103-123456789abcd-e-a0000000".as_slice()),
        (2, b"8103-123456789abcd-5-a0000000".as_slice()),
        (2, b"8103-not-hex-d".as_slice()),
        (1002, &[0; 48]),
        (1007, b"ibec".as_slice()),
        (1010, &[0, 0, 0, 8]),
        (1011, &[0, 0, 0, 0]),
        (1011, &[0]),
    ] {
        let mut properties = original.clone();
        properties.insert(tag, bytes);
        assert!(attest.verify_identifiers(&properties).is_err(), "tag {tag}");
    }
    for tag in [2, 1002, 1007, 1010, 1011] {
        let mut properties = original.clone();
        properties.remove(&tag);
        assert!(
            attest.verify_identifiers(&properties).is_err(),
            "missing {tag}"
        );
    }
}

#[test]
fn attested_modes_must_match_both_actual_fuse_bits_without_defaults() {
    let original = device_identifiers(SYNTHETIC_LEAF).unwrap();
    for fuse in 0..4 {
        let mut proof = attestation(6);
        proof.device.chip_fuse_mode = Some(fuse);
        for reported in 0..4 {
            let identity = format!("8103-123456789abcd-{:x}-a0000000", 1 | (reported << 2));
            let mut properties = original.clone();
            properties.insert(2, identity.as_bytes());
            assert_eq!(
                proof.verify_identifiers(&properties).is_ok(),
                fuse == reported
            );
        }
    }
    let mut proof = attestation(6);
    proof.device.chip_fuse_mode = None;
    assert!(format!("{:#}", proof.verify_identifiers(&original).unwrap_err()).contains("CPFM"));
}

fn property(tag: u32, encoded: &[u8]) -> Vec<u8> {
    let header = Header::new(
        Class::ContextSpecific,
        true,
        Tag(tag),
        Length::Definite(encoded.len()),
    );
    let mut bytes = Vec::new();
    header.write_der_header(&mut bytes).unwrap();
    bytes.extend_from_slice(encoded);
    bytes
}

#[test]
fn duplicate_properties_wrong_types_and_noncanonical_der_are_rejected() {
    let field = property(1002, &img4::element(4, &[0; 48]));
    let mut duplicated = field.clone();
    duplicated.extend(&field);
    assert!(parse_identifiers(&img4::element(0x30, &duplicated)).is_err());
    assert!(
        parse_identifiers(&img4::element(
            0x30,
            &property(1002, &img4::element(2, &[1]))
        ))
        .is_err()
    );
    let mut noncanonical = field.clone();
    noncanonical.insert(1, 0x80);
    assert!(parse_identifiers(&img4::element(0x30, &noncanonical)).is_err());
    let mut trailing = img4::element(0x30, &field);
    trailing.push(0);
    assert!(parse_identifiers(&trailing).is_err());
}
