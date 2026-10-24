use super::*;
use crate::{firmware::Ftab, img4};
use sha2::{Digest, Sha256, Sha384};
use std::io::Cursor;

struct Fragmented<'a> {
    data: Cursor<&'a [u8]>,
    interrupted: bool,
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
    .encode()
    .unwrap();
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
            tcon: false,
            components: HashSet::from([
                ComponentDigest {
                    tag,
                    tcon: false,
                    expected: digest,
                },
                ComponentDigest {
                    tag: None,
                    tcon: false,
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
        assert!(!result.tcon_deferred);
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
