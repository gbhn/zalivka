use super::*;
use nusb::descriptors::ConfigurationDescriptor;

#[test]
fn unusable_endpoint_numbers_do_not_hide_a_later_ncm_interface() {
    for address in [0x80, 0x91, 0xf1] {
        let mut bytes = configuration(0);
        let offset = bytes
            .windows(3)
            .position(|bytes| bytes == [7, 5, 0x81])
            .unwrap();
        bytes[offset + 2] = address;
        let selected = ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).unwrap();
        assert_eq!(selected.control, 2);
    }
}

fn configuration(first: u8) -> Vec<u8> {
    let mut bytes = vec![9, 2, 0, 0, 4, 1, 0, 0x80, 50];
    for (control, input, output) in [(first, 0x81, 0x02), (first + 2, 0x83, 0x04)] {
        bytes.extend([9, 4, control, 0, 0, 2, 0x0d, 0, 0]);
        bytes.extend([5, 0x24, 6, control, control + 1]);
        bytes.extend([9, 4, control + 1, 0, 0, 0x0a, 0, 0, 0]);
        bytes.extend([9, 4, control + 1, 3, 2, 0x0a, 0, 0, 0]);
        bytes.extend([7, 5, input, 2, 64, 0, 0]);
        bytes.extend([7, 5, output, 2, 0, 2, 0]);
    }
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

#[test]
fn ncm_selection_keeps_the_union_pair_alternate_and_output_packet_size() {
    // Apple NCM control needs no notification endpoint; data lives in alt 3.
    for control in [0, 4] {
        let bytes = configuration(control);
        let config = ConfigurationDescriptor::new(&bytes).unwrap();
        let selected = ncm_interface(config).unwrap();
        assert_eq!(
            selected,
            NcmInterface {
                control,
                data: control + 1,
                alternate: 3,
                input: 0x81,
                output: 0x02,
                packet_size: 512,
            }
        );
    }
}

#[test]
fn ncm_selection_skips_non_bulk_pairs_and_rejects_broken_unions_or_directions() {
    let mut bytes = configuration(0);
    let output = bytes.windows(3).position(|b| b == [7, 5, 0x02]).unwrap();
    bytes[output + 3] = 3; // The first pair has an interrupt endpoint.
    assert_eq!(
        ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap())
            .unwrap()
            .control,
        2
    );
    let output = bytes.windows(3).position(|b| b == [7, 5, 0x04]).unwrap();
    bytes[output + 3] = 3;
    assert!(ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).is_err());

    let mut bytes = configuration(0);
    for offset in 0..bytes.len() - 4 {
        if bytes[offset..offset + 3] == [5, 0x24, 6] {
            bytes[offset + 4] = 99; // No such data interface.
        }
    }
    assert!(ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).is_err());

    let mut bytes = configuration(0);
    let output = bytes.windows(3).position(|b| b == [7, 5, 0x02]).unwrap();
    bytes[output + 2] = 0x82; // Two IN pipes cannot supply an OUT pipe.
    assert_eq!(
        ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap())
            .unwrap()
            .control,
        2
    );
    let output = bytes.windows(3).position(|b| b == [7, 5, 0x04]).unwrap();
    bytes[output + 2] = 0x84;
    assert!(ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).is_err());
}

#[test]
fn ncm_selection_checks_later_alternates_of_the_same_data_interface() {
    let mut bytes = configuration(0);
    let alternate = bytes
        .windows(6)
        .position(|b| b == [9, 4, 1, 3, 2, 0x0a])
        .unwrap();
    let mut later = bytes[alternate..alternate + 23].to_vec();
    later[3] = 4;
    bytes[alternate + 12] = 3; // Alt 3 uses interrupt IN; alt 4 remains bulk.
    bytes.splice(alternate + 23..alternate + 23, later);
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    let selected = ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).unwrap();
    assert_eq!(selected.control, 0);
    assert_eq!(selected.data, 1);
    assert_eq!(selected.alternate, 4);
}

#[test]
fn unusable_ncm_directions_and_self_references_do_not_hide_later_pairs() {
    for self_reference in [false, true] {
        let mut bytes = configuration(0);
        if self_reference {
            let union = bytes.windows(3).position(|b| b == [5, 0x24, 6]).unwrap();
            bytes[union + 4] = 0;
            let data = bytes
                .windows(6)
                .position(|b| b == [9, 4, 1, 3, 2, 0x0a])
                .unwrap();
            bytes[data + 2] = 0;
        } else {
            let output = bytes.windows(3).position(|b| b == [7, 5, 0x02]).unwrap();
            bytes[output + 2] = 0x82;
        }
        let selected = ncm_interface(ConfigurationDescriptor::new(&bytes).unwrap()).unwrap();
        assert_eq!((selected.control, selected.data), (2, 3));
    }
}
