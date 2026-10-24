use super::*;
use zalivka::ipsw::Behavior;

#[test]
fn https_and_fdr_targets_are_validated() {
    for good in [
        "https://updates.cdn-apple.com/file.ipsw",
        "https://gs.apple.com/TSS/controller?action=2",
    ] {
        net::validate_apple_url(good).unwrap();
    }
    for bad in [
        "http://gs.apple.com/file",
        "https://apple.com.evil.invalid/file",
        "https://127.0.0.1/file",
        "https://evil.invalid@gs.apple.com/file",
        "https://gs.apple.com:8443/file",
    ] {
        assert!(net::validate_apple_url(bad).is_err(), "{bad}");
    }
    assert!(zalivka::fdr::validate_proxy_target("gs.apple.com", 443).is_ok());
    assert!(zalivka::fdr::validate_proxy_target("localhost", 443).is_err());
    assert!(zalivka::fdr::validate_proxy_target("gs.apple.com", 22).is_err());
}

#[test]
fn apple_catalog_resolves_mac_and_t2_hardware_and_uses_current_universal_release() {
    for (chip, board, key, product, url) in [
        (
            0x8103,
            0x26,
            "637567235",
            "MacBookAir10,1",
            catalog::MACOS_CATALOG,
        ),
        (
            0x8012,
            0x0a,
            "167804946",
            "iBridge2,1",
            catalog::BRIDGEOS_CATALOG,
        ),
    ] {
        let mut device = device_info();
        device.chip_id = chip;
        device.board_id = board;
        let data = catalog_fixture(
            key,
            product,
            &"ab".repeat(20),
            "https://updates.cdn-apple.com/restore.ipsw",
        );
        assert_eq!(catalog::catalog_url(&device), url);
        for mode in [Mode::Dfu, Mode::Recovery] {
            device.mode = mode;
            let release = catalog::resolve(&data, &device).unwrap();
            assert_eq!(release.product_type, product);
            assert_eq!(release.version, "27.0.1");
            assert_eq!(release.build, "26A434");
            assert_eq!(release.sha1, [0xab; 20]);
            assert!(release.url.ends_with("/restore.ipsw"));
        }
    }
}

#[test]
fn apple_catalog_selects_the_highest_matching_schema_without_skipping_invalid_versions() {
    let product = "MacBookAir10,1";
    let mut device = device_info();
    device.board_id = 0x26;
    let schema = |url| {
        wire::get(
            &catalog_fixture("637567235", product, &"ab".repeat(20), url),
            &["MobileDeviceSoftwareVersionsByVersion", "1"],
        )
        .unwrap()
        .clone()
    };
    let newest = "https://updates.cdn-apple.com/newest.ipsw";
    let mut data = catalog_fixture("637567235", product, &"ab".repeat(20), newest);
    let versions = data.as_dictionary_mut().unwrap()["MobileDeviceSoftwareVersionsByVersion"]
        .as_dictionary_mut()
        .unwrap();
    versions.insert(
        "2".into(),
        schema("https://updates.cdn-apple.com/older.ipsw"),
    );
    versions.insert("10".into(), schema(newest));
    versions.insert(
        "010".into(),
        schema("https://updates.cdn-apple.com/tied.ipsw"),
    );
    // A newer schema that only lists other models must not hide this model.
    versions.insert("11".into(), wire::dict([] as [(&str, Value); 0]));
    assert_eq!(catalog::resolve(&data, &device).unwrap().url, newest);
    let versions = data.as_dictionary_mut().unwrap()["MobileDeviceSoftwareVersionsByVersion"]
        .as_dictionary_mut()
        .unwrap();
    versions.insert("invalid".into(), schema(newest));
    assert!(
        catalog::resolve(&data, &device)
            .unwrap_err()
            .to_string()
            .contains("schema version")
    );
    let versions = data.as_dictionary_mut().unwrap()["MobileDeviceSoftwareVersionsByVersion"]
        .as_dictionary_mut()
        .unwrap();
    versions.remove("invalid");
    // A matching but malformed newest release must fail rather than fall back.
    versions.insert(
        "11".into(),
        wire::dict([(
            "MobileDeviceSoftwareVersions",
            wire::dict([(product, wire::dict([] as [(&str, Value); 0]))]),
        )]),
    );
    assert!(catalog::resolve(&data, &device).is_err());
}

#[test]
fn apple_catalog_rejects_unknown_hardware_invalid_hashes_and_untrusted_urls() {
    let mut device = device_info();
    device.board_id = 0x26;
    let good_url = "https://updates.cdn-apple.com/restore.ipsw";
    for (product, checksum, url) in [
        ("MacBookAir10,1", "bad".to_owned(), good_url),
        ("MacBookAir10,1", "gg".repeat(20), good_url),
        (
            "MacBookAir10,1",
            "ab".repeat(20),
            "https://evil.invalid/restore.ipsw",
        ),
        (
            "MacBookAir10,1",
            "ab".repeat(20),
            "https://updates.cdn-apple.com/restore.zip",
        ),
        ("iPhone99,1", "ab".repeat(20), good_url),
    ] {
        let data = catalog_fixture("637567235", product, &checksum, url);
        assert!(catalog::resolve(&data, &device).is_err());
    }
    let data = catalog_fixture("637567235", "MacBookAir10,1", &"ab".repeat(20), good_url);
    device.board_id += 1;
    assert!(catalog::resolve(&data, &device).is_err());
    device.board_id = 0x100;
    assert!(catalog::resolve(&data, &device).is_err());
}

#[test]
fn automatic_download_reuses_a_verified_compatible_cached_ipsw() {
    let file = fixture(None, false);
    let release = fixture_release(file.path());
    let directory = tempfile::tempdir().unwrap();
    let expected = directory.path().join(format!(
        "{}-{}.ipsw",
        release.build,
        device::encode_hex(&release.sha1)
    ));
    std::fs::copy(file.path(), &expected).unwrap();
    let path = catalog::ensure_cached(
        &release,
        &device_info(),
        directory.path(),
        None,
        Behavior::Erase,
    )
    .unwrap();
    assert_eq!(path, expected);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(file.path()).unwrap()
    );
    let mut wrong_device = device_info();
    wrong_device.board_id += 1;
    assert!(
        catalog::ensure_cached(
            &release,
            &wrong_device,
            directory.path(),
            None,
            Behavior::Erase
        )
        .is_err()
    );
    let mut wrong_version = release.clone();
    wrong_version.version = "99.0".into();
    assert!(
        catalog::ensure_cached(
            &wrong_version,
            &device_info(),
            directory.path(),
            None,
            Behavior::Erase
        )
        .is_err()
    );
    let mut wrong_model = release;
    wrong_model.product_type = "Mac99,1".into();
    assert!(
        catalog::ensure_cached(
            &wrong_model,
            &device_info(),
            directory.path(),
            None,
            Behavior::Erase
        )
        .is_err()
    );
}

#[test]
fn cached_revive_selects_update_and_preserves_the_explicit_identity() {
    let mut upgrade = identity();
    upgrade
        .value
        .as_dictionary_mut()
        .unwrap()
        .insert("ApBoardID".into(), "0x0b".into());
    let info = upgrade.value.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap();
    info.insert("RestoreBehavior".into(), "Update".into());
    info.insert("Variant".into(), "Customer Upgrade Install (IPSW)".into());
    let file = fixture(Some(upgrade), false);
    let release = fixture_release(file.path());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!(
        "{}-{}.ipsw",
        release.build,
        device::encode_hex(&release.sha1)
    ));
    std::fs::copy(file.path(), &path).unwrap();
    let mut device = device_info();
    device.board_id = 0x0b;
    for index in [None, Some(1)] {
        assert_eq!(
            catalog::ensure_cached(&release, &device, directory.path(), index, Behavior::Update)
                .unwrap(),
            path
        );
    }
    assert!(
        catalog::ensure_cached(
            &release,
            &device,
            directory.path(),
            Some(0),
            Behavior::Update
        )
        .is_err()
    );
    assert!(
        catalog::ensure_cached(&release, &device, directory.path(), None, Behavior::Erase).is_err()
    );
}

#[test]
fn automatic_download_refuses_corrupt_cache_and_unsafe_build_names() {
    let file = fixture(None, false);
    let mut release = fixture_release(file.path());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!(
        "{}-{}.ipsw",
        release.build,
        device::encode_hex(&release.sha1)
    ));
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(
        catalog::ensure_cached(
            &release,
            &device_info(),
            directory.path(),
            None,
            Behavior::Erase
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
    release.build = "../escape".into();
    assert!(
        catalog::ensure_cached(
            &release,
            &device_info(),
            directory.path(),
            None,
            Behavior::Erase
        )
        .is_err()
    );
}

#[test]
fn downloaded_file_checksums_support_apple_sha1_and_explicit_sha256() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"firmware payload").unwrap();
    net::verify_file(file.path(), &sha1::Sha1::digest(b"firmware payload")).unwrap();
    net::verify_file(file.path(), &sha2::Sha256::digest(b"firmware payload")).unwrap();
    assert!(net::verify_file(file.path(), &[0; 20]).is_err());
    assert!(net::verify_file(file.path(), &[0; 32]).is_err());
    assert!(net::verify_file(file.path(), &[0; 21]).is_err());
}

fn catalog_fixture(key: &str, product: &str, checksum: &str, url: &str) -> Value {
    wire::dict([
        (
            "MobileDeviceProductTypes",
            wire::dict([
                ("DFU", wire::dict([(key, product.into())])),
                ("Recovery", wire::dict([(key, product.into())])),
            ]),
        ),
        (
            "MobileDeviceSoftwareVersionsByVersion",
            wire::dict([(
                "1",
                wire::dict([(
                    "MobileDeviceSoftwareVersions",
                    wire::dict([(
                        product,
                        wire::dict([
                            (
                                "Unknown",
                                wire::dict([(
                                    "Universal",
                                    wire::dict([(
                                        "Restore",
                                        wire::dict([
                                            ("BuildVersion", "26A434".into()),
                                            ("ProductVersion", "27.0.1".into()),
                                            ("FirmwareURL", url.into()),
                                            ("FirmwareSHA1", checksum.into()),
                                        ]),
                                    )]),
                                )]),
                            ),
                            (
                                "99Z9999",
                                wire::dict([(
                                    "Restore",
                                    wire::dict([(
                                        "FirmwareURL",
                                        "https://updates.cdn-apple.com/older.ipsw".into(),
                                    )]),
                                )]),
                            ),
                        ]),
                    )]),
                )]),
            )]),
        ),
    ])
}

fn fixture_release(file: &std::path::Path) -> catalog::Release {
    let sha1 = sha1::Sha1::digest(std::fs::read(file).unwrap()).into();
    catalog::Release {
        product_type: "MacBookAir10,1".into(),
        version: "11.0".into(),
        build: "20A2411".into(),
        url: "https://updates.cdn-apple.com/fixture.ipsw".into(),
        sha1,
    }
}
