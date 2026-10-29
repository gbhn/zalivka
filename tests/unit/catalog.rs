use super::*;
use crate::test_support::catalog_fixture;

fn catalog(checksum: &str) -> Value {
    catalog_fixture(
        "637567235",
        "MacBookAir10,1",
        checksum,
        "https://updates.cdn-apple.com/test.ipsw",
    )
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
    for failed in [MACOS_CATALOG, BRIDGEOS_CATALOG] {
        for malformed in [Value::Boolean(true), catalog("bad-checksum")] {
            let mut called = Vec::new();
            let selected = latest_with(&device(), |url| {
                called.push(url.to_owned());
                Ok(if url == failed {
                    malformed.clone()
                } else {
                    catalog(&"ab".repeat(20))
                })
            })
            .unwrap();
            assert_eq!(selected.build, "26A434");
            assert_eq!(selected.sha1, [0xab; 20]);
            assert_eq!(called, [MACOS_CATALOG, BRIDGEOS_CATALOG]);
        }
    }
}

#[test]
fn catalog_selection_uses_advertised_hardware_without_chip_or_product_name_tables() {
    let mut device = device();
    device.chip_id = 0xabcd;
    device.board_id = 0x42;
    let key = ((u64::from(device.board_id) << 24) | u64::from(device.chip_id)).to_string();
    let matching = catalog_fixture(
        &key,
        "FutureProduct9,2",
        &"ab".repeat(20),
        "https://updates.cdn-apple.com/future.ipsw",
    );
    let other = catalog_fixture(
        "1",
        "AnotherProduct",
        &"ab".repeat(20),
        "https://updates.cdn-apple.com/other.ipsw",
    );
    let expected = resolve(&matching, &device).unwrap();
    let select = |first: &Value, second: &Value| {
        let mut catalogs = [first, second].into_iter();
        latest_with(&device, |_| Ok(catalogs.next().unwrap().clone()))
    };
    assert_eq!(select(&other, &matching).unwrap(), expected);
    assert_eq!(select(&matching, &matching).unwrap(), expected);
    assert!(select(&other, &other).is_err());
    let conflicting = catalog_fixture(
        &key,
        "FutureProduct9,2",
        &"cd".repeat(20),
        "https://updates.cdn-apple.com/different.ipsw",
    );
    assert!(select(&matching, &conflicting).is_err());
}
