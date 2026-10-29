use super::*;
use crate::{img4, test_support::Ftab};
use sha2::{Digest, Sha256, Sha384};
use std::io::Cursor;

struct Fragmented<'a> {
    data: Cursor<&'a [u8]>,
    interrupted: bool,
}

#[test]
fn bundle_digests_survive_fragmented_streaming_and_reject_corrupted_payloads() {
    let digest = Sha256::digest(b"firmware").to_vec();
    let bundle = wire::dict([
        ("Payload", plist::Value::Data(b"firmware".to_vec())),
        ("Digest", plist::Value::Data(digest.clone())),
    ]);
    let requirements = EntryDigests {
        components: HashSet::from([ComponentDigest {
            tag: None,
            expected: digest,
        }]),
    };
    for corrupt in [false, true] {
        let mut value = bundle.clone();
        if corrupt {
            value
                .as_dictionary_mut()
                .unwrap()
                .insert("Payload".into(), plist::Value::Data(b"modified".to_vec()));
        }
        let bytes = wire::xml(&value).unwrap();
        let mut reader = Fragmented {
            data: Cursor::new(bytes.as_slice()),
            interrupted: false,
        };
        let result = requirements.verify(
            &mut reader,
            "arbitrary.plist",
            bytes.len() as u64,
            &mut [0; 64],
        );
        assert_eq!(result.is_ok(), !corrupt);
    }
}

#[test]
fn a_valid_outer_digest_does_not_hide_a_corrupt_bundle_payload() {
    for corrupt in [false, true] {
        let value = wire::dict([
            ("Payload", plist::Value::Data(b"firmware".to_vec())),
            (
                "Digest",
                plist::Value::Data(
                    Sha256::digest(if corrupt { b"modified" } else { b"firmware" }).to_vec(),
                ),
            ),
        ]);
        let bytes = wire::xml(&value).unwrap();
        let expected = Sha256::digest(&bytes).to_vec();
        let requirements = EntryDigests {
            components: HashSet::from([ComponentDigest {
                tag: None,
                expected: expected.clone(),
            }]),
        };
        let result = requirements.verify(
            &mut bytes.as_slice(),
            "bundle.plist",
            bytes.len() as u64,
            &mut [0; 64],
        );
        let prepared = firmware::verify_plist_bundle(&bytes);
        assert_eq!(result.is_ok(), prepared.is_ok(), "corrupt={corrupt}");
        assert_eq!(result.is_ok(), !corrupt);
    }
}

impl Read for Fragmented<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.interrupted = !self.interrupted;
        if self.interrupted {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = out.len().min(7);
        self.data.read(&mut out[..length])
    }
}

#[test]
fn fragmented_reads_and_interrupts_preserve_container_and_retagged_digests() {
    let payload = vec![0x35; 8193];
    let mut header = [0; 48];
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let ftab = Ftab {
        header,
        entries: vec![(*b"rkos", payload.clone(), 0)],
    }
    .encode();
    let mut fields = img4::element(0x16, b"IM4P");
    fields.extend(img4::element(0x16, b"krnl"));
    fields.extend(img4::element(0x16, b"test"));
    fields.extend(img4::element(4, &payload));
    let kernel = img4::element(0x30, &fields);
    let mut retagged = kernel.clone();
    let offset = img4::type_offset(&kernel).unwrap();
    retagged[offset..offset + 4].copy_from_slice(b"rkrn");

    for (bytes, tag, digest) in [
        (&ftab, None, Sha256::digest(&payload).to_vec()),
        (&kernel, Some(*b"rkrn"), Sha256::digest(&retagged).to_vec()),
    ] {
        let requirements = EntryDigests {
            components: HashSet::from([
                ComponentDigest {
                    tag,
                    expected: digest,
                },
                ComponentDigest {
                    tag: None,
                    expected: Sha384::digest(bytes).to_vec(),
                },
            ]),
        };
        let mut reader = Fragmented {
            data: Cursor::new(bytes.as_slice()),
            interrupted: false,
        };
        let result = requirements
            .verify(&mut reader, "image", bytes.len() as u64, &mut [0; 1024])
            .unwrap();
        assert_eq!(result.bytes, bytes.len() as u64);
        assert_eq!(result.digests, 2);
        assert!(!result.aea_deferred);
    }
}

#[test]
fn truncated_entries_and_read_failures_keep_the_entry_name_and_io_cause() {
    let requirements = EntryDigests::default();
    let error = requirements
        .verify(&mut b"short".as_slice(), "missing.dmg", 10, &mut [0; 64])
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("truncated ZIP entry missing.dmg")
    );

    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read denied",
            ))
        }
    }
    let error = requirements
        .verify(&mut Failed, "blocked.dmg", 10, &mut [0; 64])
        .err()
        .unwrap();
    assert!(error.to_string().contains("blocked.dmg"));
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn streamed_verification_matches_full_verification_for_nested_late_ftab() {
    let payload = vec![0x35; 1024];
    let mut header = [0; 48];
    header[36..40].copy_from_slice(b"ftab");
    let inner = Ftab {
        header,
        entries: vec![(*b"rkos", payload.clone(), 0)],
    }
    .encode();
    let bytes = Ftab {
        header,
        entries: vec![
            (*b"PAD0", vec![7; 3 * 1024 * 1024], 0),
            (*b"FIRM", inner.clone(), 0),
        ],
    }
    .encode();
    let offset = 84 + 3 * 1024 * 1024;
    let mut uarp = vec![0; offset + inner.len()];
    uarp[..4].copy_from_slice(&3u32.to_be_bytes());
    uarp[4..8].copy_from_slice(&44u32.to_be_bytes());
    uarp[36..40].copy_from_slice(&44u32.to_be_bytes());
    uarp[40..44].copy_from_slice(&40u32.to_be_bytes());
    uarp[44..48].copy_from_slice(&40u32.to_be_bytes());
    uarp[76..80].copy_from_slice(&(offset as u32).to_be_bytes());
    uarp[80..84].copy_from_slice(&(inner.len() as u32).to_be_bytes());
    uarp[offset..].copy_from_slice(&inner);
    for bytes in [bytes, uarp] {
        let expected = Sha256::digest(&payload).to_vec();
        let full = DigestInput::variants(&bytes, bytes.len() as u64, None).unwrap();
        verify_component_digest(full, |input| input.matches(&bytes, &expected)).unwrap();
        let requirements = EntryDigests {
            components: HashSet::from([ComponentDigest {
                tag: None,
                expected,
            }]),
        };
        requirements
            .verify(
                &mut bytes.as_slice(),
                "valid-nested.ftab",
                bytes.len() as u64,
                &mut vec![0; 2 * 1024 * 1024],
            )
            .unwrap();
    }
}
