use super::*;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/fcs-synthetic.json")).unwrap();
    (
        STANDARD.decode(value["prefix"].as_str().unwrap()).unwrap(),
        value["pem"].as_str().unwrap().as_bytes().to_vec(),
        crate::device::decode_hex(value["archive_key"].as_str().unwrap()).unwrap(),
    )
}

fn parse(prefix: &[u8]) -> PublicFcs {
    match PublicFcs::from_prefix(prefix).unwrap() {
        Prefix::Public(fcs) => *fcs,
        _ => panic!("expected a complete FCS prefix"),
    }
}

#[test]
fn hpke_matches_the_independent_cfrg_p256_sha256_aes256_vector() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/hpke-p256-sha256-aes256.json")).unwrap();
    let field = |v: &serde_json::Value| crate::device::decode_hex(v.as_str().unwrap()).unwrap();
    let secret = SecretKey::from_slice(&field(&value["skRm"])).unwrap();
    let output = hpke_open(
        &secret,
        &field(&value["enc"]),
        &field(&value["encryption"]["ct"]),
        &field(&value["info"]),
        &field(&value["encryption"]["aad"]),
    )
    .unwrap();
    assert_eq!(output, field(&value["encryption"]["pt"]));
}

#[test]
fn public_fcs_unwraps_and_authenticates_an_independently_generated_image() {
    let (prefix, pem, expected) = fixture();
    for end in 0..prefix.len() {
        assert!(matches!(
            PublicFcs::from_prefix(&prefix[..end]).unwrap(),
            Prefix::Incomplete
        ));
    }
    assert_eq!(
        parse(&prefix).unwrap_key(&pem).unwrap().as_slice(),
        expected
    );
}

#[test]
fn fcs_rejects_wrong_keys_and_tampered_hpke_metadata_salt_or_root() {
    let (prefix, pem, _) = fixture();
    let mut fcs = parse(&prefix);
    fcs.fingerprint = URL_SAFE.encode([0; 32]);
    assert!(fcs.unwrap_key(&pem).is_err());
    for target in 0..5 {
        let mut fcs = parse(&prefix);
        match target {
            0 => fcs.wrapped[0] ^= 1,
            1 => fcs.sender[1] ^= 1,
            2 => fcs.auth[10] ^= 1,
            3 => fcs.salt[0] ^= 1,
            _ => fcs.root[32] ^= 1,
        }
        assert!(fcs.unwrap_key(&pem).is_err());
    }
    assert!(parse(&prefix).unwrap_key(b"not a PEM key").is_err());
    assert!(parse(&prefix).unwrap_key(&vec![0; 65537]).is_err());
}

#[test]
fn fcs_prefix_rejects_oversized_duplicate_and_truncated_metadata_fields() {
    let (prefix, _, _) = fixture();
    let mut bad = prefix.clone();
    bad[8..12].copy_from_slice(&(MAX_AUTH as u32 + 1).to_le_bytes());
    assert!(PublicFcs::from_prefix(&bad).is_err());
    for length in [0, 3, 4, u32::MAX] {
        let mut bad = prefix.clone();
        bad[12..16].copy_from_slice(&length.to_le_bytes());
        assert!(PublicFcs::from_prefix(&bad).is_err());
    }
    let auth = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
    let field = u32::from_le_bytes(prefix[12..16].try_into().unwrap()) as usize;
    let mut duplicate = prefix.clone();
    duplicate.splice(12..12, prefix[12..12 + field].iter().copied());
    duplicate[8..12].copy_from_slice(&((auth + field) as u32).to_le_bytes());
    assert!(PublicFcs::from_prefix(&duplicate).is_err());
    let mut unsupported = prefix;
    unsupported[4] = 2;
    assert!(matches!(
        PublicFcs::from_prefix(&unsupported).unwrap(),
        Prefix::Unsupported
    ));
}
