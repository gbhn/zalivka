use super::*;

#[test]
fn usb_removal_is_distinct_from_protocol_timeout_and_cancel_errors() {
    assert!(mux::is_device_removal(
        &anyhow::Error::new(nusb::transfer::TransferError::Disconnected).context("USB read")
    ));
    for error in [
        anyhow::Error::new(nusb::transfer::TransferError::Cancelled),
        anyhow::Error::new(nusb::transfer::TransferError::Stall),
        anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        anyhow::anyhow!("malformed restored message"),
    ] {
        assert!(!mux::is_device_removal(&error));
    }
}

#[test]
fn driver_configuration_is_targeted_and_never_overwrites_existing_sources() {
    use zalivka::drivers;
    let inf = drivers::winusb_inf(0x1227, None).unwrap();
    assert!(inf.contains("USB\\VID_05AC&PID_1227"));
    assert!(inf.contains("CatalogFile=zalivka.cat"));
    assert!(!inf.contains("USB\\VID_05AC\n"));
    assert!(drivers::winusb_inf(0x12a8, None).is_err());
    assert!(
        drivers::winusb_inf(0x12a8, Some(2))
            .unwrap()
            .contains("PID_12A8&MI_02")
    );
    let dir = tempfile::tempdir().unwrap();
    drivers::export(dir.path(), 0x1227, None).unwrap();
    assert!(drivers::export(dir.path(), 0x1281, None).is_err());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("zalivka.inf")).unwrap(),
        inf
    );
    assert!(zalivka::storage::available(dir.path()).unwrap() > 0);
    assert!(zalivka::storage::require(dir.path(), u64::MAX).is_err());
}

#[test]
fn parse_dfu_serial_and_nonces() {
    let d = device_info();
    assert_eq!(d.chip_id, 0x8103);
    assert_eq!(d.board_id, 10);
    assert_eq!(d.ecid, 0x123456789abcd);
    assert_eq!(d.ap_nonce, [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    assert!(DeviceInfo::parse("CPID:8103 BDID:0A ECID:0", Mode::Dfu).is_err());
    assert!(DeviceInfo::parse("CPID:FFFFFFFFFF BDID:0A ECID:12", Mode::Dfu).is_err());
    assert!(DeviceInfo::parse("CPID:8103 BDID:0A", Mode::Dfu).is_err());
}

#[test]
fn metadata_usb_identifiers_reject_duplicates_and_share_hex_syntax_with_cli() {
    let serial = "CPID:8103 BDID:0A ECID:12 SDOM:1 CPFM:3 IBFL:10";
    for field in [
        "CPID:8103",
        "BDID:0A",
        "ECID:12",
        "SDOM:1",
        "CPFM:3",
        "IBFL:10",
    ] {
        assert!(
            DeviceInfo::parse(&format!("{serial} {field}"), Mode::Dfu).is_err(),
            "duplicate {field}"
        );
    }
    let parsed = DeviceInfo::parse("CPID:0X8103 BDID:0X0A ECID:0X12", Mode::Dfu).unwrap();
    assert_eq!(parsed.ecid, device::parse_ecid("0X12").unwrap());
    for invalid in ["+12", "0x0x12", "0X0X12"] {
        assert!(device::parse_ecid(invalid).is_err());
        assert!(
            DeviceInfo::parse(&format!("CPID:8103 BDID:0A ECID:{invalid}"), Mode::Dfu).is_err()
        );
    }
    let mut device = device_info();
    let before = device.clone();
    assert!(device.set_nonces("NONC:1122 NONC:3344 SNON:5566").is_err());
    assert_eq!(device, before);
}

#[test]
fn optional_usb_fields_default_only_when_absent() {
    let serial = "CPID:8103 BDID:0A ECID:12";
    let device = DeviceInfo::parse(serial, Mode::Dfu).unwrap();
    assert_eq!(device.security_domain, None);
    assert_eq!(device.iboot_flags, None);
    let device = DeviceInfo::parse(&format!("{serial} SDOM:2 IBFL:10"), Mode::Dfu).unwrap();
    assert_eq!(device.security_domain, Some(2));
    assert_eq!(device.iboot_flags, Some(0x10));
    for name in ["SDOM", "IBFL", "CPFM"] {
        for value in ["broken", "", "100000000", "10000000000000000"] {
            assert!(DeviceInfo::parse(&format!("{serial} {name}:{value}"), Mode::Dfu).is_err());
        }
    }
}

#[test]
fn hex_ecid_is_consistent() {
    assert_eq!(device::parse_ecid("10").unwrap(), 16);
    assert_eq!(device::parse_ecid("0x10").unwrap(), 16);
    assert!(device::parse_ecid("0").is_err());
    assert!(device::decode_hex("abc").is_err());
    assert!(device::decode_hex("€").is_err());
    assert_eq!(
        device::encode_hex(&device::decode_hex("aB01").unwrap()),
        "ab01"
    );
    assert!(device::decode_hex("").unwrap().is_empty());
    for value in ["+1", "0a+1", "-1", " 1", "1 ", "0x", "gg", "\0\0", "é"] {
        assert!(device::decode_hex(value).is_err(), "accepted {value:?}");
    }
}

#[test]
fn invalid_nonces_leave_both_previous_values_intact() {
    let mut device = device_info();
    let previous = device.clone();
    for value in ["NONC:zz SNON:1122", "NONC:1122 SNON:zz", "SNON:+1"] {
        assert!(device.set_nonces(value).is_err());
        assert_eq!(device, previous);
    }
    device.set_nonces("NONC:1122 SNON:aAbB").unwrap();
    assert_eq!(device.ap_nonce, [0x11, 0x22]);
    assert_eq!(device.sep_nonce, [0xaa, 0xbb]);
    device.set_nonces("").unwrap();
    assert!(device.ap_nonce.is_empty());
    assert!(device.sep_nonce.is_empty());
}

#[test]
fn dfu_crc_known_vector_and_packet_boundaries() {
    assert_eq!(dfu::crc32(b"123456789"), 0x340bc6d9);
    for len in [1, 2032, 2033, 2048, 2049, 4096] {
        let data = vec![0xaa; len];
        let packets = dfu::packets(&data).unwrap();
        assert!(packets.iter().all(|(_, p)| p.len() <= 2048));
        let joined: Vec<u8> = packets
            .iter()
            .flat_map(|(_, p)| p.iter().copied())
            .collect();
        assert_eq!(joined.len(), len + 16);
        assert_eq!(&joined[..len], data);
        let crc = u32::from_le_bytes(joined[joined.len() - 4..].try_into().unwrap());
        assert_eq!(crc, dfu::crc32(&joined[..joined.len() - 4]));
        assert_eq!(
            &joined[len..len + 12],
            &[255, 255, 255, 255, 0xac, 5, 0, 1, 0x55, 0x46, 0x44, 0x10]
        );
    }
    let p = dfu::packets(&vec![0; 2048]).unwrap();
    assert_eq!(p.iter().map(|p| p.0).collect::<Vec<_>>(), [0, 0]);
    assert!(dfu::packets(&[]).is_err());
}

#[test]
fn getenv_only_queries_the_named_variable_without_bulk_writes_or_reset() {
    let mut usb = MockUsb {
        reads: [b"true\0ignored".to_vec()].into(),
        ..Default::default()
    };
    assert_eq!(dfu::getenv(&mut usb, "auto-boot").unwrap(), "true");
    assert_eq!(
        usb.controls,
        vec![(0x40, 0, 0, b"getenv auto-boot\0".to_vec())]
    );
    assert_eq!(usb.requests, vec![(0x40, 0, 0), (0xc0, 0, 0)]);
    assert!(usb.bulk.is_empty());
    assert_eq!(usb.resets, 0);
}

#[test]
fn getenv_reads_persistent_boot_breadcrumbs_longer_than_255_bytes() {
    let breadcrumbs = "3000c(69626f74) 3000d ".repeat(48);
    let mut reply = breadcrumbs.as_bytes().to_vec();
    reply.push(0);
    let mut usb = MockUsb {
        reads: [reply].into(),
        ..Default::default()
    };
    assert_eq!(
        dfu::getenv(&mut usb, "boot-breadcrumbs").unwrap(),
        breadcrumbs
    );
}

#[test]
fn getenv_rejects_command_injection_and_reports_invalid_replies() {
    for name in [
        "",
        "auto-boot; saveenv",
        "boot-command\nreboot",
        "auto-boot\0",
    ] {
        let mut usb = MockUsb::default();
        assert!(dfu::getenv(&mut usb, name).is_err());
        assert!(usb.requests.is_empty());
    }
    let mut usb = MockUsb {
        reads: [vec![0xff]].into(),
        ..Default::default()
    };
    assert!(
        dfu::getenv(&mut usb, "boot-command")
            .unwrap_err()
            .to_string()
            .contains("UTF-8")
    );
}

#[test]
fn dfu_upload_checks_states_and_finishes() {
    let mut usb = MockUsb {
        reads: [
            vec![2],
            vec![0, 0, 0, 0, 3, 0],
            vec![0, 0, 0, 0, 5, 0],
            vec![0, 0, 0, 0, 6, 0],
            vec![0, 0, 0, 0, 7, 0],
        ]
        .into(),
        ..Default::default()
    };
    dfu::upload(&mut usb, Mode::Dfu, b"image", true).unwrap();
    assert_eq!(usb.controls.len(), 2);
    assert_eq!(usb.controls[1], (0x21, 1, 1, vec![]));
    assert_eq!(usb.resets, 1);
    assert!(usb.reads.is_empty());
}

#[test]
fn dfu_suffix_continuation_is_sent_before_getstatus() {
    for size in [2032usize, 2033, 2048, 2049, 4096] {
        let blocks = size.div_ceil(dfu::BLOCK_SIZE);
        let mut reads = VecDeque::from([vec![2]]);
        reads.extend((0..blocks).map(|_| vec![0, 0, 0, 0, 5, 0]));
        let mut usb = MockUsb {
            reads,
            ..Default::default()
        };
        dfu::upload(&mut usb, Mode::Dfu, &vec![0xaa; size], false).unwrap();
        let packets = dfu::packets(&vec![0xaa; size]).unwrap();
        assert_eq!(
            usb.controls
                .iter()
                .map(|(_, _, block, bytes)| (*block, bytes.clone()))
                .collect::<Vec<_>>(),
            packets
        );
        let mut expected = vec![(0xa1, 5, 0)];
        for (i, (block, _)) in packets.iter().enumerate() {
            expected.push((0x21, 1, *block));
            if packets.get(i + 1).is_none_or(|next| next.0 != *block) {
                expected.push((0xa1, 3, 0));
            }
        }
        assert_eq!(usb.requests, expected, "image size {size}");
        assert!(usb.reads.is_empty());
        // At this boundary the payload and suffix must be adjacent DNLOADs.
        if size == 2048 {
            assert_eq!(
                usb.requests,
                [(0xa1, 5, 0), (0x21, 1, 0), (0x21, 1, 0), (0xa1, 3, 0)]
            );
        }
    }
}

#[test]
fn dfu_upload_borrows_complete_blocks_and_preserves_the_suffix_bytes() {
    for size in [
        3 * dfu::BLOCK_SIZE + 2032,
        3 * dfu::BLOCK_SIZE + 2033,
        4 * dfu::BLOCK_SIZE,
    ] {
        let data: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
        let blocks = size.div_ceil(dfu::BLOCK_SIZE);
        let mut reads = VecDeque::from([vec![2]]);
        reads.extend((0..blocks).map(|_| vec![0, 0, 0, 0, 5, 0]));
        let mut usb = MockUsb {
            reads,
            ..Default::default()
        };
        dfu::upload(&mut usb, Mode::Dfu, &data, false).unwrap();
        // Observe what the transport actually receives; these buffers must
        // point into the original image rather than a second image-sized copy.
        for (i, address) in usb.control_buffers.iter().take(blocks - 1).enumerate() {
            assert_eq!(*address, data[i * dfu::BLOCK_SIZE..].as_ptr() as usize);
        }
        let actual: Vec<_> = usb
            .controls
            .into_iter()
            .map(|(_, _, block, bytes)| (block, bytes))
            .collect();
        assert_eq!(actual, dfu::packets(&data).unwrap());
        assert!(
            actual
                .iter()
                .all(|(_, bytes)| bytes.len() <= dfu::BLOCK_SIZE)
        );
        assert!(usb.reads.is_empty());
        assert_eq!(usb.resets, 0);
    }
}

#[test]
fn dfu_error_never_resets_or_sends_remaining_data() {
    let mut usb = MockUsb {
        reads: [vec![2], vec![7, 0, 0, 0, 10, 0]].into(),
        ..Default::default()
    };
    let error = dfu::upload(&mut usb, Mode::Dfu, &[0; 4096], true).unwrap_err();
    assert!(!error.is::<dfu::ResetFailure>());
    assert_eq!(usb.controls.len(), 1);
    assert_eq!(usb.resets, 0);
    assert!(dfu::Status::parse(&[0, 0, 0, 0, 5]).is_err());
}

#[test]
fn dfu_reset_failure_marks_a_completed_upload_and_preserves_the_os_error() {
    let mut usb = MockUsb {
        reads: [
            vec![2],
            vec![0, 0, 0, 0, 5, 0],
            vec![0, 0, 0, 0, 6, 0],
            vec![0, 0, 0, 0, 8, 0],
        ]
        .into(),
        reset_error: Some(2),
        ..Default::default()
    };
    let error = dfu::upload(&mut usb, Mode::Dfu, b"image", true).unwrap_err();
    assert!(error.is::<dfu::ResetFailure>());
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(2)
    );
    assert_eq!(usb.controls.len(), 2);
    assert_eq!(usb.controls[1], (0x21, 1, 1, vec![]));
    assert_eq!(usb.resets, 1);
    assert!(usb.reads.is_empty());
}

#[test]
fn dfu_waiting_for_reset_rejects_a_fresh_upload_without_writing() {
    let mut usb = MockUsb {
        reads: [vec![8]].into(),
        ..Default::default()
    };
    let error = dfu::upload(&mut usb, Mode::Dfu, b"image", true).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expected DFU idle state 2, got 8")
    );
    assert!(usb.controls.is_empty());
    assert!(usb.bulk.is_empty());
    assert_eq!(usb.resets, 0);
}

#[test]
fn recovery_bulk_and_nul_terminated_commands() {
    let mut usb = MockUsb::default();
    dfu::upload(&mut usb, Mode::Recovery, &[1; 512], false).unwrap();
    assert_eq!(usb.bulk.iter().map(Vec::len).collect::<Vec<_>>(), [512, 0]);
    dfu::command(&mut usb, "go", true).unwrap();
    assert_eq!(
        usb.controls.last().unwrap(),
        &(0x40, 1, 0, b"go\0".to_vec())
    );
    assert!(dfu::command(&mut usb, "go\0other", false).is_err());
}

#[test]
fn kernel_boot_attempts_bootx_once_even_when_the_transfer_notification_fails() {
    for notification_error in [None, Some(2)] {
        for bootx_error in [None, Some(2)] {
            let mut usb = MockUsb {
                control_errors: [notification_error, bootx_error].into(),
                ..Default::default()
            };
            let result = dfu::boot_kernel(&mut usb);
            assert_eq!(result.is_err(), bootx_error.is_some());
            if let Err(error) = result {
                assert_eq!(
                    error
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .raw_os_error(),
                    Some(2)
                );
                assert!(error.to_string().contains("bootx"));
            }
            assert_eq!(
                usb.controls,
                [(0x21, 1, 0, vec![]), (0x40, 1, 0, b"bootx\0".to_vec())]
            );
            assert!(usb.control_errors.is_empty());
            assert_eq!(usb.resets, 0);
            assert!(usb.bulk.is_empty());
        }
    }
}

#[derive(Default)]
struct MockUsb {
    reads: VecDeque<Vec<u8>>,
    controls: Vec<(u8, u8, u16, Vec<u8>)>,
    control_buffers: Vec<usize>,
    bulk: Vec<Vec<u8>>,
    resets: usize,
    reset_error: Option<i32>,
    control_errors: VecDeque<Option<i32>>,
    requests: Vec<(u8, u8, u16)>,
}
impl RecoveryTransport for MockUsb {
    fn control_in(&mut self, k: u8, r: u8, v: u16, _: u16, length: u16) -> Result<Vec<u8>> {
        self.requests.push((k, r, v));
        let reply = self
            .reads
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected USB read"))?;
        anyhow::ensure!(
            reply.len() <= usize::from(length),
            "USB response exceeds wLength"
        );
        Ok(reply)
    }
    fn control_out(&mut self, k: u8, r: u8, v: u16, _: u16, b: &[u8]) -> Result<()> {
        self.requests.push((k, r, v));
        self.control_buffers.push(b.as_ptr() as usize);
        self.controls.push((k, r, v, b.to_vec()));
        if let Some(Some(code)) = self.control_errors.pop_front() {
            return Err(std::io::Error::from_raw_os_error(code).into());
        }
        Ok(())
    }
    fn bulk_out(&mut self, b: &[u8]) -> Result<()> {
        self.bulk.push(b.to_vec());
        Ok(())
    }
    fn reset(&mut self) -> Result<()> {
        self.resets += 1;
        if let Some(code) = self.reset_error {
            return Err(std::io::Error::from_raw_os_error(code).into());
        }
        Ok(())
    }
}

#[test]
fn empty_firmware_is_rejected_before_any_usb_request_in_both_modes() {
    struct NoUsb;
    impl RecoveryTransport for NoUsb {
        fn control_in(&mut self, _: u8, _: u8, _: u16, _: u16, _: u16) -> Result<Vec<u8>> {
            panic!("USB request for empty firmware")
        }
        fn control_out(&mut self, _: u8, _: u8, _: u16, _: u16, _: &[u8]) -> Result<()> {
            panic!("USB request for empty firmware")
        }
        fn bulk_out(&mut self, _: &[u8]) -> Result<()> {
            panic!("USB write for empty firmware")
        }
        fn reset(&mut self) -> Result<()> {
            panic!("USB reset for empty firmware")
        }
    }
    for mode in [Mode::Dfu, Mode::Recovery] {
        assert!(dfu::upload(&mut NoUsb, mode, &[], true).is_err());
    }
}
