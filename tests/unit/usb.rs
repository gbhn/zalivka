use super::*;
use nusb::descriptors::ConfigurationDescriptor;

fn configuration(value: u8, protocol: u8) -> Vec<u8> {
    vec![
        9, 2, 32, 0, 1, value, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0xfe, protocol, 0, 7, 5, 0x81, 2,
        64, 0, 0, 7, 5, 0x04, 2, 64, 0, 0,
    ]
}

#[test]
fn multiplex_prefers_the_active_configuration_in_either_descriptor_order() {
    let first = configuration(1, 2);
    let last = configuration(5, 2);
    for buffers in [[&first, &last], [&last, &first]] {
        for active in [1, 5] {
            let selected = select_mux_interface(
                buffers
                    .iter()
                    .map(|b| ConfigurationDescriptor::new(b).unwrap()),
                Some(active),
            )
            .unwrap();
            assert_eq!(
                selected,
                MuxInterface {
                    configuration: active,
                    number: 0,
                    alternate: 0,
                    output: 0x04,
                    input: 0x81,
                    packet_size: 64
                }
            );
            // MuxUsb::open does not call set_configuration for this result.
            assert_eq!(Some(selected.configuration), Some(active));
        }
    }
}

#[test]
fn multiplex_selection_skips_other_protocols_and_retains_a_fallback() {
    let other = configuration(1, 1);
    let mux = configuration(2, 2);
    let buffers = [&other, &mux];
    for active in [None, Some(1), Some(2)] {
        let selected = select_mux_interface(
            buffers
                .iter()
                .map(|b| ConfigurationDescriptor::new(b).unwrap()),
            active,
        )
        .unwrap();
        assert_eq!(
            selected,
            MuxInterface {
                configuration: 2,
                number: 0,
                alternate: 0,
                output: 0x04,
                input: 0x81,
                packet_size: 64
            }
        );
    }
    assert!(
        select_mux_interface(
            [ConfigurationDescriptor::new(&other).unwrap()].into_iter(),
            Some(1)
        )
        .is_none()
    );
    assert!(select_mux_interface(std::iter::empty(), None).is_none());
}

#[test]
fn multiplex_skips_non_bulk_and_zero_packet_size_endpoints() {
    let valid = configuration(5, 2);
    for (offset, value) in [(21, 3), (28, 3), (22, 0), (29, 0)] {
        let mut invalid = configuration(1, 2);
        invalid[offset] = value;
        let descriptors = [&invalid, &valid];
        let selected = select_mux_interface(
            descriptors
                .iter()
                .map(|b| ConfigurationDescriptor::new(b).unwrap()),
            Some(1),
        )
        .unwrap();
        assert_eq!(selected.configuration, 5);
        assert!(
            select_mux_interface(
                [ConfigurationDescriptor::new(&invalid).unwrap()].into_iter(),
                Some(1),
            )
            .is_none()
        );
    }
}

#[test]
fn recovery_selects_its_actual_interface_and_alternate_without_a_zero_fallback() {
    let mut bytes = configuration(1, 1);
    bytes[11] = 3;
    bytes[12] = 2;
    assert_eq!(
        recovery_interface(ConfigurationDescriptor::new(&bytes).unwrap()).unwrap(),
        (3, 2)
    );
    for (offset, value) in [(27, 0x02), (28, 3), (29, 0)] {
        let mut invalid = bytes.clone();
        invalid[offset] = value;
        assert!(recovery_interface(ConfigurationDescriptor::new(&invalid).unwrap()).is_err());
    }
}
