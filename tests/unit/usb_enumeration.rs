use super::*;

#[test]
fn target_selection_skips_unreadable_neighbours_and_cached_other_ecids() {
    let selected = find_ecid(
        42,
        [(Some(7), 0), (None, 1), (None, 2), (None, 3)].into_iter(),
        |candidate| match candidate {
            0 => panic!("known unrelated devices must not be opened"),
            1 => anyhow::bail!("neighbour disconnected"),
            2 => Ok((13, "another device")),
            _ => Ok((42, "target")),
        },
    )
    .unwrap();
    assert_eq!(selected, "target");
}

#[test]
fn target_errors_retain_the_original_io_cause() {
    let error = find_ecid(42, [(Some(42), ())].into_iter(), |_| {
        Err::<(u64, ()), _>(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "target denied").into(),
        )
    })
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(format!("{error:#}").contains("target denied"));
}

#[test]
fn scans_keep_healthy_devices_but_report_failure_when_none_can_be_read() {
    let info = DeviceInfo::parse("ECID:2a CPID:8103 BDID:26", Mode::Dfu).unwrap();
    let devices =
        collect_devices([Err(anyhow::anyhow!("gone")), Ok(info.clone())].into_iter()).unwrap();
    assert_eq!(devices, [info]);
    assert!(
        collect_devices([Err(anyhow::anyhow!("permission denied"))].into_iter())
            .unwrap_err()
            .to_string()
            .contains("permission denied")
    );
}
