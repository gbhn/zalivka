use super::*;
use crate::wire;

fn record(payload: &[u8], digest: &[u8]) -> Value {
    wire::dict([
        ("Payload", Value::Data(payload.to_vec())),
        ("Digest", Value::Data(digest.to_vec())),
        ("Version", 123u64.into()),
    ])
}

#[test]
fn bundle_records_are_verified_recursively_and_metadata_alone_is_insufficient() {
    let data = b"arbitrary firmware";
    let digest = Sha256::digest(data).to_vec();
    let mut bundle = wire::dict([
        ("unknown product", record(data, &digest)),
        (
            "other configs",
            Value::Array(vec![record(b"config", &Sha256::digest(b"config"))]),
        ),
    ]);
    let check =
        |value: &Value, digest: &[u8]| verify_plist_bundle(&wire::xml(value).unwrap(), digest);
    let report = check(&bundle, &digest).unwrap();
    assert_eq!(report.payloads, 2);
    assert!(report.manifest_digest);
    let mut binary = vec![];
    bundle.to_writer_binary(&mut binary).unwrap();
    assert!(
        verify_plist_bundle(&binary, &digest)
            .unwrap()
            .manifest_digest
    );
    assert!(!check(&bundle, &[0; 32]).unwrap().manifest_digest);
    let fields = bundle.as_dictionary_mut().unwrap()["unknown product"]
        .as_dictionary_mut()
        .unwrap();
    fields.insert("Payload".into(), Value::Data(b"tampered firmware".to_vec()));
    assert!(check(&bundle, &digest).is_err());
    let metadata = wire::dict([("Digest", Value::Data(digest.clone()))]);
    assert!(!check(&metadata, &digest).unwrap().manifest_digest);
    assert_eq!(
        verify_plist_bundle(b"raw firmware", &digest)
            .unwrap()
            .payloads,
        0
    );
    assert!(verify_plist_bundle(b"<?xml invalid", &digest).is_err());
}

#[test]
fn bundle_verification_bounds_nesting_and_requires_payload_digests() {
    let mut nested = record(b"data", &Sha256::digest(b"data"));
    for _ in 0..34 {
        nested = Value::Array(vec![nested]);
    }
    assert!(verify_plist_bundle(&wire::xml(&nested).unwrap(), &[0; 32]).is_err());
    let missing_digest = wire::dict([("Payload", Value::Data(vec![1]))]);
    assert!(verify_plist_bundle(&wire::xml(&missing_digest).unwrap(), &[0; 32]).is_err());
}

#[test]
fn flash_image_codec_checks_banks_lengths_and_nested_configuration() {
    let mut image = vec![0; 0xf000];
    image[..4].copy_from_slice(&17u32.to_be_bytes());
    image[4..8].copy_from_slice(&23u32.to_be_bytes());
    image[0x1000..0x1011].fill(0x35);
    image[0x9000..0x9017].fill(0x7b);
    let input = [&image[..8], &image[0x1000..0x1011], &image[0x9000..0x9017]].concat();
    let digest = Sha256::digest(input).to_vec();
    assert!(verify_bundle_payload(&image, &digest).is_ok());
    for position in [0, 4, 0x1000, 0x1010, 0x9000, 0x9016] {
        let mut bad = image.clone();
        bad[position] ^= 1;
        assert!(verify_bundle_payload(&bad, &digest).is_err());
    }
    assert!(verify_bundle_payload(&image[..0xefff], &digest).is_err());
    for (code, data) in [(0u32, 23u32), (17, 0), (0x8001, 23), (17, 0x6001)] {
        let mut bad = image.clone();
        bad[..4].copy_from_slice(&code.to_be_bytes());
        bad[4..8].copy_from_slice(&data.to_be_bytes());
        assert!(verify_bundle_payload(&bad, &digest).is_err());
    }
    let bundle = wire::dict([
        ("firmware", record(&image, &digest)),
        ("config", record(b"changed", &Sha256::digest(b"original"))),
    ]);
    assert!(verify_plist_bundle(&wire::xml(&bundle).unwrap(), &digest).is_err());
}
