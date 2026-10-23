use super::*;
#[test]
fn parses_the_macs_datagram_limit_including_unspecified_zero() {
    let mut bytes = vec![
        28, 0, 3, 0, 252, 127, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 252, 127, 0, 0, 4, 0, 0, 0, 4, 0, 0, 2,
    ];
    let params = Parameters::parse(&bytes).unwrap();
    assert_eq!(params.output_size, 32764);
    assert_eq!(params.max_datagrams, 128);
    for (value, expected) in [(0u16, 128), (1, 1), (2, 2), (40, 40)] {
        bytes[26..28].copy_from_slice(&value.to_le_bytes());
        assert_eq!(Parameters::parse(&bytes).unwrap().max_datagrams, expected);
    }
}
#[test]
fn batches_preserve_frames_and_all_negotiated_bounds_and_alignments() {
    let frames: Vec<Vec<u8>> = (0..257)
        .map(|index| {
            let length = [14, 60, 1514, 1499, 64, 54][index % 6];
            (0..length).map(|offset| (index ^ offset) as u8).collect()
        })
        .collect();
    for (output_size, divisor, remainder, alignment, max_datagrams) in [
        (32764, 4, 0, 4, 128),
        (2048, 4, 0, 4, 128),
        (32764, 512, 0, 512, 2),
        (65535, 512, 511, 512, 128),
        (2048, 1, 0, 1, 1),
        (32764, 16, 7, 8, 7),
    ] {
        let params = Parameters {
            input_size: 32768,
            output_size,
            divisor,
            remainder,
            alignment,
            max_datagrams,
        };
        let mut offset = 0;
        let mut sequence = u16::MAX;
        while offset < frames.len() {
            let (bytes, count) = params.encode(&frames[offset..], sequence).unwrap();
            assert!((1..=max_datagrams).contains(&count));
            assert!(bytes.len() <= output_size);
            assert_eq!(word(&bytes, 6).unwrap(), sequence as usize);
            assert_eq!(word(&bytes, 8).unwrap(), bytes.len());
            let table = word(&bytes, 10).unwrap();
            assert_eq!(table % alignment, 0);
            assert_eq!(word(&bytes, table + 4).unwrap(), 12 + 4 * count);
            for index in 0..count {
                let start = word(&bytes, table + 8 + 4 * index).unwrap();
                assert_eq!((start + 14) % divisor, remainder);
            }
            assert_eq!(decode(&bytes).unwrap(), frames[offset..offset + count]);
            offset += count;
            sequence = sequence.wrapping_add(1);
        }
    }
}
#[test]
fn exact_usb_packet_lengths_and_unencodable_frames() {
    let params = Parameters {
        input_size: 32768,
        output_size: 32764,
        divisor: 4,
        remainder: 0,
        alignment: 4,
        max_datagrams: 128,
    };
    for size in [64, 512, 1024] {
        let frame = vec![0x5a; size - 30];
        let (bytes, count) = params.encode(std::slice::from_ref(&frame), 0).unwrap();
        assert_eq!(count, 1);
        assert_eq!(bytes.len(), size);
        assert_eq!(decode(&bytes).unwrap(), [frame]);
    }
    assert!(params.encode(&[], 0).is_err());
    assert!(params.encode(&[vec![0; 13]], 0).is_err());
    assert!(params.encode(&[vec![0; MAX_FRAME + 1]], 0).is_err());
    let small = Parameters {
        output_size: 2048,
        ..params
    };
    assert!(small.encode(&[vec![0; 2048]], 0).is_err());
}
#[test]
fn known_ntb_and_malformed_tables() {
    let params = Parameters {
        input_size: 32768,
        output_size: 32768,
        divisor: 4,
        remainder: 0,
        alignment: 4,
        max_datagrams: 128,
    };
    let frame: Vec<_> = (0..64).collect();
    let (packet, count) = params.encode(std::slice::from_ref(&frame), 0xffff).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        &packet[..12],
        &[0x4e, 0x43, 0x4d, 0x48, 12, 0, 255, 255, 94, 0, 12, 0]
    );
    assert_eq!(
        &packet[12..28],
        &[
            0x4e, 0x43, 0x4d, 0x30, 16, 0, 0, 0, 30, 0, 64, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(decode(&packet).unwrap(), vec![frame.clone()]);
    let mut concatenated = packet.clone();
    concatenated.extend(&packet);
    assert_eq!(decode(&concatenated).unwrap(), vec![frame.clone(), frame]);
    for n in 1..packet.len() {
        assert!(decode(&packet[..n]).is_err());
    }
    let mut cycle = packet.clone();
    cycle[18] = 12;
    assert!(decode(&cycle).is_err());
    let mut bad = packet.clone();
    bad[20] = 250;
    assert!(decode(&bad).is_err());
    let mut bad = packet;
    bad[20] = 12;
    assert!(decode(&bad).is_err());
}
