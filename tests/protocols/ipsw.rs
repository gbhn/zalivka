use super::*;
use zalivka::ipsw::Behavior;

#[test]
fn full_ipsw_verification_checks_all_streams_and_manifest_digests() {
    for compression in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let file =
            fixture_compression(None, false, &[("extra", b"unreferenced data")], compression);
        let report = Ipsw::open(file.path()).unwrap().verify_all().unwrap();
        assert_eq!(report.entries, 8);
        assert_eq!(report.manifest_digests, 6);
        assert!(report.uncompressed_bytes > 6 * im4p(b"test").len() as u64);
    }
    let mut bad = identity();
    manifest_mut(&mut bad)
        .get_mut("OS")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Digest".into(), Value::Data(vec![1; 48]));
    let file = fixture(Some(bad), false);
    assert!(
        Ipsw::open(file.path())
            .unwrap()
            .verify_all()
            .unwrap_err()
            .to_string()
            .contains("digest mismatch")
    );
    let file = fixture_files(None, false, &[("extra", b"unreferenced unique bytes")]);
    let mut bytes = std::fs::read(file.path()).unwrap();
    let offset = bytes
        .windows(25)
        .position(|w| w == b"unreferenced unique bytes")
        .unwrap();
    bytes[offset] ^= 0xff;
    std::fs::write(file.path(), bytes).unwrap();
    assert!(Ipsw::open(file.path()).unwrap().verify_all().is_err());
}

#[test]
fn encrypted_aea_digests_are_explicitly_deferred_and_archive_hash_can_be_checked() {
    let encrypted = b"AEA1synthetic encrypted content";
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "BaseSystem".into(),
        component_entry("image.dmg.aea", b"decrypted content"),
    );
    let file = fixture_files(Some(id), false, &[("image.dmg.aea", encrypted)]);
    let report = Ipsw::open(file.path()).unwrap().verify_all().unwrap();
    assert_eq!(report.aea_content_digests_not_checked, ["image.dmg.aea"]);
    assert!(!report.archive_checksum_verified);
    let checksum = device::encode_hex(&sha2::Sha256::digest(std::fs::read(file.path()).unwrap()));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("verify")
        .arg(file.path())
        .args(["--checksum", &checksum])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["archive_checksum_verified"], true);
    assert_eq!(value["aea_content_digests_not_checked"][0], "image.dmg.aea");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("verify")
        .arg(file.path())
        .args(["--checksum", &"00".repeat(32)])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn restore_digest_hashes_the_retagged_im4p_and_preserves_the_original_file() {
    let raw = im4p(b"krnl");
    let mut restore = raw.clone();
    let offset = img4::type_offset(&raw).unwrap();
    restore[offset..offset + 4].copy_from_slice(b"rkrn");
    let mut id = identity();
    let entries = manifest_mut(&mut id);
    entries.insert(
        "RestoreKernelCache".into(),
        component_entry("Firmware/real-kernel", &restore),
    );
    entries.insert(
        "KernelCache".into(),
        component_entry("Firmware/real-kernel", &raw),
    );
    let file = fixture_files(Some(id.clone()), false, &[("Firmware/real-kernel", &raw)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(ipsw.component(&id, "RestoreKernelCache").unwrap(), raw);
    assert_eq!(ipsw.component(&id, "KernelCache").unwrap(), raw);
    ipsw.verify_all().unwrap();
    let personalized = img4::personalize("RestoreKernelCache", &raw, &ticket()).unwrap();
    assert!(personalized.windows(restore.len()).any(|w| w == restore));
    assert_eq!(img4::type_offset(&raw[..4]), None);
    let mut corrupt = raw;
    *corrupt.last_mut().unwrap() ^= 1;
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("Firmware/real-kernel", &corrupt)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.component(&id, "RestoreKernelCache").is_err());
    assert!(ipsw.verify_all().is_err());
}

#[test]
fn tcon_bundle_metadata_is_matched_without_claiming_payload_digest_verification() {
    let digest = sha2::Sha256::digest(b"vendor logical firmware digest").to_vec();
    let bundle = wire::xml(&wire::dict([(
        "1",
        wire::dict([(
            "firmware",
            wire::dict([
                ("Digest", Value::Data(digest.clone())),
                ("Payload", Value::Data(b"flash image".to_vec())),
            ]),
        )]),
    )]))
    .unwrap();
    let mut id = identity();
    manifest_mut(&mut id).insert(
        "Baobab,TCON".into(),
        wire::dict([
            ("Digest", Value::Data(digest)),
            ("Info", wire::dict([("Path", "tcon.bin".into())])),
        ]),
    );
    let file = fixture_files(Some(id.clone()), false, &[("tcon.bin", &bundle)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(ipsw.component(&id, "Baobab,TCON").unwrap(), bundle);
    let report = ipsw.verify_all().unwrap();
    assert_eq!(report.tcon_payload_digests_not_checked, ["tcon.bin"]);
    assert_eq!(report.manifest_digests, 6);
    assert!(!zalivka::firmware::tcon_metadata_matches(&bundle, &[0; 32]).unwrap());
}

#[test]
fn ftab_and_uarp_manifest_digests_validate_inner_payloads_across_stream_chunks() {
    use zalivka::firmware::{Ftab, payload_ranges};
    let payload = vec![0x35; 3 * 1024 * 1024 + 17];
    let mut header = [0; 48];
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let ftab = Ftab {
        header,
        entries: vec![(*b"rkos", payload.clone(), 0)],
    }
    .encode()
    .unwrap();
    let mut uarp = vec![0; 84];
    uarp[..4].copy_from_slice(&2u32.to_be_bytes());
    uarp[4..8].copy_from_slice(&44u32.to_be_bytes());
    uarp[36..40].copy_from_slice(&44u32.to_be_bytes());
    uarp[40..44].copy_from_slice(&40u32.to_be_bytes());
    uarp[44..48].copy_from_slice(&40u32.to_be_bytes());
    uarp[48..52].copy_from_slice(b"DL01");
    uarp[76..80].copy_from_slice(&84u32.to_be_bytes());
    uarp[80..84].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    uarp.extend_from_slice(&payload);
    let mut id = identity();
    let entries = manifest_mut(&mut id);
    entries.insert(
        "Timer,RTKitOS,1".into(),
        component_entry("Firmware/inner.ftab", &payload),
    );
    entries.insert(
        "USBPortController1,USBFirmware".into(),
        component_entry("Firmware/inner.uarp", &payload),
    );
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[
            ("Firmware/inner.ftab", &ftab),
            ("Firmware/inner.uarp", &uarp),
        ],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(ipsw.component(&id, "Timer,RTKitOS,1").unwrap(), ftab);
    assert_eq!(
        ipsw.component(&id, "USBPortController1,USBFirmware")
            .unwrap(),
        uarp
    );
    ipsw.verify_all().unwrap();
    uarp[76..80].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(payload_ranges(&uarp, uarp.len() as u64).is_err());
    let mut bad = ftab;
    bad[52..56].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(payload_ranges(&bad, bad.len() as u64).is_err());
}

#[test]
#[ignore = "streams a sparse 5 GiB ZIP64 archive; run explicitly in release mode"]
fn zip64_streams_five_gib_with_bounded_memory() {
    struct Sparse(std::fs::File);
    impl Write for Sparse {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data.iter().all(|&b| b == 0) {
                self.0.seek(SeekFrom::Current(data.len() as i64))?;
                Ok(data.len())
            } else {
                self.0.write(data)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    impl Seek for Sparse {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(from)
        }
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut zip = zip::ZipWriter::new(Sparse(file.reopen().unwrap()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);
    let manifest = wire::dict([
        ("BuildIdentities", Value::Array(vec![])),
        (
            "SupportedProductTypes",
            Value::Array(vec!["MacBookAir10,1".into()]),
        ),
    ]);
    zip.start_file("BuildManifest.plist", options).unwrap();
    zip.write_all(&wire::xml(&manifest).unwrap()).unwrap();
    zip.start_file("large.dmg", options).unwrap();
    let size = 5u64 * 1024 * 1024 * 1024 + 123;
    std::io::copy(&mut std::io::repeat(0).take(size), &mut zip).unwrap();
    zip.finish().unwrap();
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut image = ipsw.stored_image("large.dmg").unwrap().unwrap();
    assert_eq!(image.size, size);
    image
        .seek(SeekFrom::Start(4 * 1024 * 1024 * 1024 + 99))
        .unwrap();
    let mut bytes = [1; 16];
    image.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 16]);
    let report = ipsw.verify_all().unwrap();
    assert_eq!(report.entries, 2);
    assert!(report.uncompressed_bytes > size);
}

#[test]
fn ipsw_identity_selection_and_stored_image_have_bounded_seeks() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let id = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap();
    ipsw.preflight(&id).unwrap();
    assert_eq!(ipsw.component(&id, "iBSS").unwrap(), im4p(b"test"));
    let mut image = ipsw.stored_image(id.path("OS").unwrap()).unwrap().unwrap();
    let mut data = vec![];
    image.read_to_end(&mut data).unwrap();
    assert_eq!(data, im4p(b"test"));
    assert!(image.seek(SeekFrom::Start(image.size + 1)).is_err());
    image.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    image.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'd']);
    assert_eq!(image.read(&mut byte).unwrap(), 0);
}

#[test]
fn ipsw_ambiguity_mismatch_and_missing_component_are_errors() {
    let extra = identity();
    let file = fixture(Some(extra), false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    assert!(
        ipsw.select_behavior(&device_info(), None, Behavior::Erase)
            .is_err()
    );
    assert_eq!(
        ipsw.select_behavior(&device_info(), Some(1), Behavior::Erase)
            .unwrap()
            .index,
        1
    );
    let mut other = device_info();
    other.board_id += 1;
    assert!(
        ipsw.select_behavior(&other, Some(1), Behavior::Erase)
            .is_err()
    );
    let file = fixture(None, true);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.preflight(&identity()).is_err());
}

#[test]
fn identity_selection_returns_an_owned_value_and_checks_later_entries() {
    let file = fixture(None, false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    let mut selected = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap();
    assert_eq!(selected.value, ipsw.identities()[0].value);
    selected
        .value
        .as_dictionary_mut()
        .unwrap()
        .insert("ApChipID".into(), 0u64.into());
    let unchanged = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap();
    assert_eq!(
        unchanged.summary().unwrap().chip_id,
        u64::from(device_info().chip_id)
    );
    assert_ne!(selected.value, unchanged.value);

    let mut malformed = identity();
    malformed
        .value
        .as_dictionary_mut()
        .unwrap()
        .insert("ApChipID".into(), "invalid".into());
    let file = fixture(Some(malformed), false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    // Finding a match, even an explicitly selected one, must not hide a
    // malformed later identity that the original full scan would reject.
    for index in [None, Some(0)] {
        assert!(
            ipsw.select_behavior(&device_info(), index, Behavior::Erase)
                .is_err()
        );
    }
}

#[test]
fn optional_recovery_identity_distinguishes_absence_from_ambiguity() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut bridge = identity();
    bridge
        .value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("MacOSVariant");
    assert!(
        ipsw.recovery_identity(&device_info(), &bridge)
            .unwrap()
            .is_none()
    );
    assert!(ipsw.recovery_identity(&device_info(), &identity()).is_err());
    let identities = Arc::make_mut(&mut ipsw.manifest)
        .as_dictionary_mut()
        .unwrap()
        .get_mut("BuildIdentities")
        .unwrap()
        .as_array_mut()
        .unwrap();
    identities.push(recovery_identity().value);
    // Both identities say Erase; the named macOS variant is not an erase installer.
    assert_eq!(
        ipsw.select_behavior(&device_info(), None, Behavior::Erase)
            .unwrap()
            .index,
        0
    );
    assert!(
        ipsw.select_behavior(&device_info(), Some(1), Behavior::Erase)
            .is_err()
    );
    assert_eq!(
        ipsw.recovery_identity(&device_info(), &identity())
            .unwrap()
            .unwrap()
            .index,
        1
    );
    Arc::make_mut(&mut ipsw.manifest)
        .as_dictionary_mut()
        .unwrap()
        .get_mut("BuildIdentities")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(recovery_identity().value);
    assert!(ipsw.recovery_identity(&device_info(), &identity()).is_err());
}

#[test]
fn recovery_preflight_accepts_os_only_but_rejects_missing_or_invalid_paths() {
    let mut id = recovery_identity();
    let manifest = manifest_mut(&mut id);
    manifest.retain(|key, _| key == "OS");
    let file = fixture(Some(id), false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut id = ipsw
        .recovery_identity(&device_info(), &identity())
        .unwrap()
        .unwrap();
    ipsw.preflight_recovery(&id).unwrap();
    assert!(ipsw.preflight(&id).is_err());
    for bad in ["Firmware/missing", "../OS"] {
        manifest_mut(&mut id).insert(
            "Other".into(),
            wire::dict([("Info", wire::dict([("Path", bad.into())]))]),
        );
        assert!(ipsw.preflight_recovery(&id).is_err());
    }
}

#[test]
fn preflight_rejects_corrupt_boot_components_and_invalid_digest_types() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut id = identity();
    for digest in [Value::Data(vec![0; 48]), "invalid".into()] {
        manifest_mut(&mut id)
            .get_mut("iBEC")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Digest".into(), digest);
        assert!(ipsw.preflight(&id).is_err());
    }
}

#[test]
fn archive_paths_and_digest_mismatches_are_rejected() {
    for bad in [
        "../foo",
        "/absolute",
        "C:/Windows",
        "a\\b",
        "a/../b",
        "a/./b",
        "",
    ] {
        assert!(zalivka::ipsw::validate_path(bad).is_err(), "{bad}");
    }
    assert!(zalivka::ipsw::verify_digest(b"data", &[0; 48]).is_err());
    assert!(zalivka::ipsw::verify_digest(b"data", &[0; 5]).is_err());
    assert!(zalivka::ipsw::verify_digest(b"data", &Sha384::digest(b"data")).is_ok());
}
