use super::*;

#[test]
fn kis_packets_use_portals_arguments_and_word_counts() {
    assert_eq!(
        packet(1, 0x0a, &[0x21], &[], 1).unwrap(),
        [0, 0, 0xa0, 1, 1, 0x0a, 4, 0, 4, 0, 0, 0, 0x21, 0, 0, 0]
    );
    assert_eq!(
        packet(0x10, 0x100, &[], &[], 0xc0).unwrap(),
        [0, 0, 0xa0, 0x10, 0, 0, 1, 3, 0, 0, 0, 0]
    );
    let request = packet(0x10, 0x0d, &[0x4000, 0, 3], b"abc", 0).unwrap();
    assert_eq!(
        &request[..12],
        &[0, 0, 0xa0, 0x10, 3, 0x0d, 0, 0, 15, 0, 0, 0]
    );
    assert_eq!(
        &request[12..],
        &[0, 0x40, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, b'a', b'b', b'c']
    );
    assert!(packet(0x10, 1024, &[], &[], 0).is_err());
    assert!(packet(0x10, 0, &[], &[], 16384).is_err());
}

fn info_reply() -> Vec<u8> {
    let mut reply = vec![0; 788];
    let body = &mut reply[12..780];
    body[64..66].copy_from_slice(&[18, 1]);
    body[72..76].copy_from_slice(&[0xac, 5, 0x27, 0x12]);
    body[80] = 24; // KIS string indices are word offsets.
    body[24..28].copy_from_slice(&56u32.to_le_bytes());
    for (offset, text) in [
        (96, "ECID:2A CPID:8142 BDID:22 SDOM:01 CPFM:03"),
        (224, "NONC:01020304 SNON:05060708"),
    ] {
        let bytes: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        body[offset] = bytes.len() as u8;
        body[offset + 1] = 3;
        body[offset + 2..offset + 2 + bytes.len()].copy_from_slice(&bytes);
    }
    reply
}

#[test]
fn kis_device_info_reads_the_embedded_identity_and_nonces() {
    let reply = info_reply();
    let device = device_info(&reply).unwrap();
    assert_eq!(device.ecid, 42);
    assert_eq!(device.chip_id, 0x8142);
    assert_eq!(device.ap_nonce, [1, 2, 3, 4]);
    assert_eq!(device.sep_nonce, [5, 6, 7, 8]);
    for length in 0..reply.len() {
        assert!(device_info(&reply[..length]).is_err());
    }
    for offset in [12 + 64, 12 + 72, 12 + 74, 12 + 80, 12 + 24, 784] {
        let mut malformed = reply.clone();
        malformed[offset] = 0xff;
        assert!(device_info(&malformed).is_err(), "offset {offset}");
    }
}

#[test]
fn kis_rejects_short_acknowledgements_and_device_errors() {
    let good = vec![0; 20];
    check_reply(&good).unwrap();
    for length in 0..20 {
        assert!(check_reply(&good[..length]).is_err());
    }
    let mut error = good;
    error[16] = 1;
    assert!(check_reply(&error).is_err());
    assert!(string(&[0; 768], usize::MAX).is_err());
}
