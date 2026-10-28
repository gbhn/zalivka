use super::*;

fn catalog(checksum: &str) -> Value {
    wire::dict([
        (
            "MobileDeviceProductTypes",
            wire::dict([("DFU", wire::dict([("637567235", "MacBookAir10,1".into())]))]),
        ),
        (
            "MobileDeviceSoftwareVersionsByVersion",
            wire::dict([(
                "1",
                wire::dict([(
                    "MobileDeviceSoftwareVersions",
                    wire::dict([(
                        "MacBookAir10,1",
                        wire::dict([(
                            "Unknown",
                            wire::dict([(
                                "Universal",
                                wire::dict([(
                                    "Restore",
                                    wire::dict([
                                        (
                                            "FirmwareURL",
                                            "https://updates.cdn-apple.com/test.ipsw".into(),
                                        ),
                                        ("FirmwareSHA1", checksum.into()),
                                        ("BuildVersion", "26A434".into()),
                                        ("ProductVersion", "27.0".into()),
                                    ]),
                                )]),
                            )]),
                        )]),
                    )]),
                )]),
            )]),
        ),
    ])
}

fn device() -> DeviceInfo {
    DeviceInfo::parse("ECID:1234 CPID:8103 BDID:26", Mode::Dfu).unwrap()
}

#[test]
fn either_catalog_can_supply_a_release_when_the_other_fails() {
    for failed in [MACOS_CATALOG, BRIDGEOS_CATALOG] {
        let mut called = Vec::new();
        let selected = latest_with(&device(), |url| {
            called.push(url.to_owned());
            if url == failed {
                anyhow::bail!("server unavailable");
            }
            Ok(catalog(&"ab".repeat(20)))
        })
        .unwrap();
        assert_eq!(selected.build, "26A434");
        assert_eq!(called, [MACOS_CATALOG, BRIDGEOS_CATALOG]);
    }
}

#[test]
fn unavailable_catalogs_preserve_errors_and_available_conflicts_still_fail() {
    let error = latest_with(&device(), |url| anyhow::bail!("offline: {url}")).unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains(MACOS_CATALOG) && error.contains(BRIDGEOS_CATALOG));
    let error = latest_with(&device(), |url| {
        Ok(catalog(
            &if url == MACOS_CATALOG { "ab" } else { "cd" }.repeat(20),
        ))
    })
    .unwrap_err();
    assert!(error.to_string().contains("conflicting firmware"));
}

#[test]
fn malformed_catalog_metadata_does_not_hide_another_valid_release() {
    let selected = latest_with(&device(), |url| {
        Ok(if url == MACOS_CATALOG {
            Value::Boolean(true)
        } else {
            catalog(&"ab".repeat(20))
        })
    })
    .unwrap();
    assert_eq!(selected.build, "26A434");
}
