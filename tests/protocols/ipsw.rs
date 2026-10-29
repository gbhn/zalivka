use super::*;

#[test]
fn stored_filesystem_crc_is_checked_before_restore_and_after_validation_seeks() {
    let file = fixture(None, false);
    let mut bytes = std::fs::read(file.path()).unwrap();
    let data_start = {
        let mut zip = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        zip.by_name("Firmware/OS").unwrap().data_start().unwrap() as usize
    };
    bytes[data_start + 20] ^= 1;
    std::fs::write(file.path(), bytes).unwrap();
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.prepare_filesystem(&identity()).is_err());
    assert!(ipsw.stream("Firmware/OS", &mut Vec::new()).is_err());
    let mut image = ipsw.image("Firmware/OS").unwrap();
    image.seek(SeekFrom::Start(10)).unwrap();
    image.read_exact(&mut [0; 4]).unwrap();
    image.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(
        image.read_to_end(&mut Vec::new()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn deeply_nested_manifest_is_an_error_instead_of_a_process_abort() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
    zip.start_file(
        "BuildManifest.plist",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    write!(
        zip,
        "<plist>{}<string>x</string>{}</plist>",
        "<array>".repeat(4096),
        "</array>".repeat(4096)
    )
    .unwrap();
    zip.finish().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("inspect")
        .arg(file.path())
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("nested too deeply"));
}

#[test]
fn ipsw_stream_preserves_stored_and_deflated_entries_across_block_boundaries() {
    let image: Vec<_> = (0..3 * 256 * 1024 + 123).map(|i| (i % 251) as u8).collect();
    let files = [
        ("empty", &image[..0]),
        ("small", &image[..17]),
        ("one-block", &image[..256 * 1024]),
        ("whole-blocks", &image[..2 * 256 * 1024]),
        ("partial-tail", image.as_slice()),
    ];
    for compression in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let file = fixture_compression(None, false, &files, compression);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        for (path, expected) in files {
            let mut output = Vec::new();
            assert_eq!(
                ipsw.stream(path, &mut output).unwrap(),
                expected.len() as u64
            );
            assert_eq!(output, expected, "{compression:?}: {path}");
        }
        assert_eq!(ipsw.read("Firmware/OS").unwrap(), im4p(b"test"));
    }
}

#[test]
fn reopening_an_ipsw_rejects_a_replaced_build_manifest() {
    let file = fixture(None, false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    assert_eq!(ipsw.reopen().unwrap().manifest, ipsw.manifest);
    let replacement = fixture(Some(recovery_identity()), false);
    std::fs::copy(replacement.path(), file.path()).unwrap();
    assert!(
        ipsw.reopen()
            .err()
            .unwrap()
            .to_string()
            .contains("BuildManifest changed")
    );
}

#[test]
fn empty_identity_lists_and_noncanonical_archive_paths_are_rejected() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
    zip.start_file(
        "BuildManifest.plist",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(
        &wire::xml(&wire::dict([
            ("BuildIdentities", Value::Array(vec![])),
            (
                "SupportedProductTypes",
                Value::Array(vec!["MacBookAir10,1".into()]),
            ),
        ]))
        .unwrap(),
    )
    .unwrap();
    zip.finish().unwrap();
    assert!(
        Ipsw::open(file.path())
            .err()
            .unwrap()
            .to_string()
            .contains("nonempty array")
    );
    for path in ["a//b", "a///", "//server/file"] {
        assert!(zalivka::ipsw::validate_path(path).is_err());
    }
}

#[test]
fn preflight_rejects_directory_components_and_empty_filesystems() {
    for (path, bytes) in [
        ("Firmware/directory/", b"".as_slice()),
        ("Firmware/empty", b"".as_slice()),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert("OS".into(), component_entry(path, bytes));
        let file = fixture_files(Some(id.clone()), false, &[(path, bytes)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(ipsw.validate_identity(&mut id).is_err());
    }
}

#[test]
fn recovery_variant_must_have_the_requested_restore_behavior() {
    let mut recovery = recovery_identity();
    recovery.value.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .insert("RestoreBehavior".into(), "Update".into());
    let file = fixture(Some(recovery), false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.recovery_identity(&device_info(), &identity()).is_err());
    let mut id = identity();
    id.value.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .insert("DeviceClass".into(), "".into());
    assert!(id.summary().is_err());
}

#[test]
fn metadata_variant_aliases_must_be_well_typed_and_consistent() {
    for alias in [true.into(), "DifferentCompanion".into()] {
        let mut id = identity();
        id.value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("RecoveryVariant".into(), alias);
        assert!(id.summary().is_err());
        assert!(id.is_macos().is_err());
    }
    let mut id = identity();
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("RecoveryVariant".into(), "macOS Customer".into());
    assert!(id.summary().is_ok());
    assert!(id.is_macos().unwrap());
}
use zalivka::ipsw::Behavior;

#[test]
fn im4p_headers_resolve_boot_roles_and_stage_firmware_without_changing_the_manifest() {
    let mut id = identity();
    for name in [
        "iBSS",
        "iBEC",
        "RestoreRamDisk",
        "RestoreDeviceTree",
        "RestoreKernelCache",
    ] {
        manifest_mut(&mut id).remove(name);
    }
    let mut files = Vec::new();
    for (name, tag, stage) in [
        ("OpaqueBootA", *b"ibss", None),
        ("OpaqueBootB", *b"ibec", None),
        ("OpaqueRamdisk", *b"rdsk", None),
        ("OpaqueTree", *b"rdtr", None),
        ("OpaqueKernel", *b"rkrn", None),
        ("OpaqueStageOne", *b"nx26", Some(true)),
        ("ANE", *b"anef", Some(false)),
    ] {
        let bytes = im4p(&tag);
        let path = format!("Firmware/opaque-{}", files.len());
        let mut entry = component_entry(&path, &bytes);
        let info = entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.remove("Img4PayloadType");
        if let Some(first) = stage {
            info.insert("IsLoadedByiBoot".into(), true.into());
            info.insert("IsLoadedByiBootStage1".into(), first.into());
        }
        manifest_mut(&mut id).insert(name.into(), entry);
        files.push((path, bytes));
    }
    let original = id.value.clone();
    let file_refs = files
        .iter()
        .map(|(path, data)| (path.as_str(), data.as_slice()))
        .collect::<Vec<_>>();
    let file = fixture_files(Some(id.clone()), false, &file_refs);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let stages = restore::preflight(&mut ipsw, &mut id).unwrap();
    assert_eq!(id.require_component_type(b"ibss").unwrap(), "OpaqueBootA");
    assert_eq!(id.payload_type("ANE").unwrap(), Some(*b"anef"));
    assert!(stages[0].contains(&restore::IBootStep::Component("OpaqueStageOne".into())));
    assert!(stages[1].contains(&restore::IBootStep::Component("ANE".into())));
    assert_eq!(id.value, original);
    assert_eq!(ipsw.identity(1).unwrap().value, original);
    assert_eq!(id.clone().payload_type("ANE").unwrap(), Some(*b"anef"));
    let signature = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
    for (name, tag) in [("OpaqueBootA", *b"ibss"), ("ANE", *b"anef")] {
        let bytes = ipsw.personalized(&id, name, &signature).unwrap();
        assert_eq!(bytes, img4::personalize(&im4p(&tag), &ticket()).unwrap());
    }
    let request = tss::request(&device_info(), &id).unwrap();
    assert!(wire::get(&request, &["ANE"]).is_ok());
    assert_eq!(
        request,
        tss::request(&device_info(), &Identity::new(id.index, original)).unwrap()
    );
    ipsw.verify_all().unwrap();
}

#[test]
fn header_derived_nonce_slots_still_require_explicit_slot_ids() {
    for (tag, key) in [(*b"illb", "ApNonceSlotID"), (*b"sepi", "SepNonceSlotID")] {
        let bytes = im4p(&tag);
        let mut id = identity();
        let mut entry = component_entry("Firmware/opaque-slot", &bytes);
        entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .remove("Img4PayloadType");
        manifest_mut(&mut id).insert("OpaqueSlotComponent".into(), entry);
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("RequiresNonceSlot".into(), true.into());
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/opaque-slot", &bytes)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        let error = ipsw.validate_identity(&mut id).unwrap_err();
        assert!(error.to_string().contains(key), "{error:#}");
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), 3u64.into());
        ipsw.validate_identity(&mut id).unwrap();
    }
}

#[test]
fn header_types_do_not_override_explicit_manifest_types_on_shared_files() {
    let bytes = im4p(b"krnl");
    let mut retagged = bytes.clone();
    let offset = img4::type_offset(&retagged).unwrap();
    retagged[offset..offset + 4].copy_from_slice(b"nx26");
    let mut id = identity();
    let mut normal = component_entry("Firmware/shared-kernel", &bytes);
    normal.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .remove("Img4PayloadType");
    let restore = component_entry("Firmware/shared-kernel", &retagged);
    manifest_mut(&mut id).insert("OpaqueNormal".into(), normal);
    manifest_mut(&mut id).insert("OpaqueRetagged".into(), restore);
    let original = id.value.clone();
    let file = fixture_files(
        Some(id.clone()),
        false,
        &[("Firmware/shared-kernel", &bytes)],
    );
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    ipsw.validate_identity(&mut id).unwrap();
    assert_eq!(id.payload_type("OpaqueNormal").unwrap(), Some(*b"krnl"));
    assert_eq!(id.payload_type("OpaqueRetagged").unwrap(), Some(*b"nx26"));
    let signature = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
    assert_eq!(
        ipsw.personalized(&id, "OpaqueNormal", &signature).unwrap(),
        img4::personalize(&bytes, &ticket()).unwrap()
    );
    assert_eq!(
        ipsw.personalized(&id, "OpaqueRetagged", &signature)
            .unwrap(),
        img4::personalize(&retagged, &ticket()).unwrap()
    );
    assert_eq!(id.value, original);
    ipsw.verify_all().unwrap();
}

#[test]
fn absent_or_invalid_im4p_headers_cannot_supply_missing_firmware_types() {
    let invalid_tag = im4p(&[0xff, 0, 1, 2]);
    for bytes in [
        b"opaque binary".as_slice(),
        &im4p(b"anef")[..12],
        invalid_tag.as_slice(),
    ] {
        let mut id = identity();
        let mut entry = component_entry("Firmware/opaque", bytes);
        let info = entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.remove("Img4PayloadType");
        info.insert("IsLoadedByiBoot".into(), true.into());
        info.insert("IsLoadedByiBootStage1".into(), false.into());
        manifest_mut(&mut id).insert("OpaqueFirmware".into(), entry);
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/opaque", bytes)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        let error = restore::preflight(&mut ipsw, &mut id).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot resolve iBoot firmware payload type for OpaqueFirmware"),
            "{error:#}"
        );
        let signature = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
        assert!(
            ipsw.personalized(&id, "OpaqueFirmware", &signature)
                .is_err()
        );
    }
}

#[test]
fn raw_trusted_files_do_not_require_an_img4_type_when_they_are_not_boot_objects() {
    let bytes = b"raw disk image";
    let mut id = identity();
    let mut entry = component_entry("raw.dmg", bytes);
    entry.as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .remove("Img4PayloadType");
    manifest_mut(&mut id).insert("OS".into(), entry);
    let file = fixture_files(Some(id.clone()), false, &[("raw.dmg", bytes)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    restore::preflight(&mut ipsw, &mut id).unwrap();
    assert_eq!(id.payload_type("OS").unwrap(), None);
    assert_eq!(ipsw.component(&id, "OS").unwrap(), bytes);
    ipsw.verify_all().unwrap();
}

#[test]
fn malformed_variant_metadata_is_not_treated_as_an_absent_variant() {
    for key in ["Variant", "RestoreBehavior", "MacOSVariant"] {
        for invalid in [Value::Boolean(false), "".into()] {
            let mut id = identity();
            id.value.as_dictionary_mut().unwrap()["Info"]
                .as_dictionary_mut()
                .unwrap()
                .insert(key.into(), invalid.clone());
            assert!(id.summary().is_err(), "{key}: {invalid:?}");
            if key == "MacOSVariant" {
                assert!(id.is_macos().is_err());
            }
            let file = fixture(Some(id), false);
            let ipsw = Ipsw::open(file.path()).unwrap();
            assert!(
                ipsw.select_behavior(&device_info(), Some(0), Behavior::Erase)
                    .is_err()
            );
        }
    }
}

#[test]
fn preflight_rejects_malformed_optional_flags_and_partition_sizes() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for key in [
        "RequiresUIDMode",
        "RequiresNonceSlot",
        "recoveryOSPartitionSize",
        "MinimumSystemPartition",
        "SystemPartitionPadding",
    ] {
        let mut id = identity();
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), "invalid".into());
        assert!(restore::preflight(&mut ipsw, &mut id).is_err(), "{key}");
    }
    for key in [
        "Personalize",
        "IsLoadedByiBoot",
        "IsLoadedByiBootStage1",
        "IsFirmwarePayload",
        "IsSecondaryFirmwarePayload",
        "IsFUDFirmware",
        "IsEarlyAccessFirmware",
        "IsiBootEANFirmware",
        "IsiBootNonEssentialFirmware",
    ] {
        let mut id = identity();
        manifest_mut(&mut id)["iBSS"].as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert(key.into(), "false".into());
        assert!(restore::preflight(&mut ipsw, &mut id).is_err(), "{key}");
        assert!(ipsw.validate_identity(&mut id).is_err(), "{key}");
    }
}

#[test]
fn restore_preflight_resolves_ambiguous_optional_boot_roles_before_upload() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for tag in ["rans", "rdcp", "ibdt", "rlgo", "rsep"] {
        let mut id = identity();
        for name in ["FutureA", "FutureB"] {
            manifest_mut(&mut id).insert(
                name.into(),
                component_entry("Firmware/iBSS", &im4p(b"test")),
            );
            declare_type(&mut id, name, tag);
        }
        let error = restore::preflight(&mut ipsw, &mut id).unwrap_err();
        assert!(
            error.to_string().contains("ambiguous Img4PayloadType"),
            "{tag}: {error:#}"
        );
    }
}

#[test]
fn restore_preflight_reads_each_boot_component_once_across_roles_and_stages() {
    let mut id = identity();
    let sep = im4p(b"rsep");
    manifest_mut(&mut id).insert(
        "RestoreSEP".into(),
        component_entry("Firmware/RestoreSEP", &sep),
    );
    declare_type(&mut id, "RestoreSEP", "rsep");
    for (name, stage1) in [("iBSS", true), ("iBEC", false), ("RestoreSEP", false)] {
        let info = manifest_mut(&mut id)[name].as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.insert("IsLoadedByiBoot".into(), true.into());
        info.insert("IsLoadedByiBootStage1".into(), stage1.into());
    }
    let file = fixture_files(Some(id.clone()), false, &[("Firmware/RestoreSEP", &sep)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let reads = Arc::new(Mutex::new(Vec::new()));
    let output = reads.clone();
    let stages = zalivka::progress::Context::new(move |event| {
        if let zalivka::progress::Event::Log(record) = event
            && record.source == "ipsw:read"
            && !record.message.contains(':')
        {
            output.lock().unwrap().push(record.message);
        }
    })
    .run(|| restore::preflight(&mut ipsw, &mut id))
    .unwrap();
    for (stage, name) in [(0, "iBSS"), (1, "iBEC"), (1, "RestoreSEP")] {
        assert!(stages[stage].contains(&restore::IBootStep::Component(name.into())));
    }
    let mut reads = reads.lock().unwrap();
    reads.sort();
    assert_eq!(
        *reads,
        [
            "Firmware/RestoreDeviceTree",
            "Firmware/RestoreKernelCache",
            "Firmware/RestoreRamDisk",
            "Firmware/RestoreSEP",
            "Firmware/iBEC",
            "Firmware/iBSS",
        ]
    );
}

#[test]
fn restore_preflight_verifies_additional_stage_firmware_before_upload() {
    let bytes = im4p(b"nx26");
    for first in [false, true] {
        let mut id = identity();
        let mut entry = component_entry("Firmware/future", &bytes);
        let info = entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.insert("IsLoadedByiBoot".into(), true.into());
        info.insert("IsLoadedByiBootStage1".into(), first.into());
        manifest_mut(&mut id).insert("FutureStageFirmware".into(), entry);
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/future", &bytes)]);
        restore::preflight(&mut Ipsw::open(file.path()).unwrap(), &mut id).unwrap();

        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/future", &corrupt)]);
        let error = restore::preflight(&mut Ipsw::open(file.path()).unwrap(), &mut id).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("FutureStageFirmware digest mismatch"),
            "{error:#}"
        );
    }
}

#[test]
fn boot_components_require_a_digest_even_when_not_trusted() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for trusted in [false, true] {
        for digest in [None, Some(Value::Data(vec![])), Some("invalid".into())] {
            let mut id = identity();
            let component = manifest_mut(&mut id)["iBEC"].as_dictionary_mut().unwrap();
            component.insert("Trusted".into(), trusted.into());
            component.remove("Digest");
            if let Some(digest) = digest {
                component.insert("Digest".into(), digest);
            }
            assert!(restore::preflight(&mut ipsw, &mut id).is_err());
            if trusted {
                assert!(ipsw.component(&id, "iBEC").is_err());
            }
        }
    }
}

#[test]
fn recovery_nonce_slot_metadata_is_checked_before_boot_by_declared_role() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    for (tag, slot) in [("illb", "ApNonceSlotID"), ("sepi", "SepNonceSlotID")] {
        let mut id = identity();
        manifest_mut(&mut id).insert(
            "FutureRole".into(),
            component_entry("Firmware/iBSS", &im4p(b"test")),
        );
        declare_type(&mut id, "FutureRole", tag);
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("RequiresNonceSlot".into(), true.into());
        let error = ipsw.validate_identity(&mut id).unwrap_err();
        assert!(error.to_string().contains(slot), "{error:#}");
        id.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert(slot.into(), 3u64.into());
        ipsw.validate_identity(&mut id).unwrap();
    }
}

#[test]
fn manifest_paths_are_checked_consistently_before_restore_and_full_verification() {
    for entry in [
        false.into(),
        wire::dict([("Info", false.into())]),
        wire::dict([("Info", wire::dict([("Path", false.into())]))]),
        wire::dict([("Info", wire::dict([("Path", "../OS".into())]))]),
        wire::dict([("Info", wire::dict([("Path", "Firmware/missing".into())]))]),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert("Extra".into(), entry.clone());
        let file = fixture(Some(id.clone()), false);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(restore::preflight(&mut ipsw, &mut id).is_err(), "{entry:?}");
        assert!(ipsw.validate_identity(&mut id).is_err(), "{entry:?}");
        assert!(ipsw.verify_all().is_err(), "{entry:?}");
    }
    for entry in [
        wire::dict([("Trusted", false.into())]),
        wire::dict([("Info", wire::dict([("IsFTAB", true.into())]))]),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert("SigningMetadata".into(), entry);
        let file = fixture(Some(id.clone()), false);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        restore::preflight(&mut ipsw, &mut id).unwrap();
        ipsw.validate_identity(&mut id).unwrap();
        ipsw.verify_all().unwrap();
    }
}

#[test]
fn oversized_components_are_rejected_from_zip_metadata_before_reading() {
    let file = fixture(None, false);
    let mut bytes = std::fs::read(file.path()).unwrap();
    let name = b"Firmware/iBSS";
    let offset = crate::test_support::zip_entry_offset(&bytes, std::str::from_utf8(name).unwrap());
    let size = (zalivka::ipsw::MAX_COMPONENT + 1) as u32;
    bytes[offset + 24..offset + 28].copy_from_slice(&size.to_le_bytes());
    std::fs::write(file.path(), bytes).unwrap();
    let error = Ipsw::open(file.path())
        .unwrap()
        .read("Firmware/iBSS")
        .unwrap_err();
    assert!(
        error.to_string().contains("exceeds memory limit"),
        "{error:#}"
    );
}

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

    let mut truncated_ftab = vec![0; 48];
    truncated_ftab[36..40].copy_from_slice(b"ftab");
    truncated_ftab[40..44].copy_from_slice(&1u32.to_le_bytes());
    let file = fixture_files(None, false, &[("unreferenced.ftab", &truncated_ftab)]);
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
    let checksum = hex::encode(sha2::Sha256::digest(std::fs::read(file.path()).unwrap()));
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
    let personalized = img4::personalize_with_metadata(
        "RestoreKernelCache",
        &raw,
        &wire::dict([("ApImg4Ticket", Value::Data(ticket()))]),
        &id.value,
    )
    .unwrap();
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
fn manifest_payload_types_drive_verification_and_personalization_for_new_component_names() {
    let raw = im4p(b"krnl");
    let offset = img4::type_offset(&raw).unwrap();
    for component in ["RestoreKernelCache", "Ap,FutureRestoreEngine"] {
        let mut expected = raw.clone();
        expected[offset..offset + 4].copy_from_slice(b"nx26");
        let mut entry = component_entry("Firmware/new-engine", &expected);
        entry
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Img4PayloadType".into(), "nx26".into());
        let mut id = identity();
        if component == "RestoreKernelCache" {
            let boot = manifest_mut(&mut id)["RestoreKernelCache"].clone();
            manifest_mut(&mut id).insert("DeclaredBootKernel".into(), boot);
        }
        manifest_mut(&mut id).insert(component.into(), entry);
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/new-engine", &raw)]);
        let original_archive = std::fs::read(file.path()).unwrap();
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        restore::preflight(&mut ipsw, &mut id).unwrap();
        assert_eq!(ipsw.component(&id, component).unwrap(), raw);
        ipsw.verify_all().unwrap();
        let tss = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
        let personalized = ipsw.personalized(&id, component, &tss).unwrap();
        let (image, _) = img4::parse(&personalized).unwrap();
        let (_, body) = img4::parse(image.content).unwrap();
        let (payload, _) = img4::parse(body).unwrap();
        assert_eq!(payload.encoded, expected);
        assert_eq!(std::fs::read(file.path()).unwrap(), original_archive);

        let mut corrupt = raw.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let file = fixture_files(
            Some(id.clone()),
            false,
            &[("Firmware/new-engine", &corrupt)],
        );
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(ipsw.component(&id, component).is_err());
        assert!(ipsw.verify_all().is_err());
        assert!(ipsw.personalized(&id, component, &tss).is_err());
    }
}

#[test]
fn shared_files_keep_distinct_manifest_payload_types_for_unknown_components() {
    let raw = im4p(b"orig");
    let offset = img4::type_offset(&raw).unwrap();
    let mut id = identity();
    for (name, tag) in [("FutureA", "nxa1"), ("FutureB", "nxb2")] {
        let mut bytes = raw.clone();
        bytes[offset..offset + 4].copy_from_slice(tag.as_bytes());
        let mut entry = component_entry("Firmware/shared-future", &bytes);
        entry
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Img4PayloadType".into(), tag.into());
        manifest_mut(&mut id).insert(name.into(), entry);
    }
    let file = fixture_files(Some(id.clone()), false, &[("Firmware/shared-future", &raw)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    ipsw.verify_all().unwrap();
    for name in ["FutureA", "FutureB"] {
        assert_eq!(ipsw.component(&id, name).unwrap(), raw);
    }
    // A component cannot borrow the retagged digest input of another component
    // even when both refer to the same ZIP entry.
    manifest_mut(&mut id)["FutureB"]
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Img4PayloadType".into(), "nxa1".into());
    let file = fixture_files(Some(id.clone()), false, &[("Firmware/shared-future", &raw)]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.component(&id, "FutureA").is_ok());
    assert!(ipsw.component(&id, "FutureB").is_err());
    assert!(ipsw.verify_all().is_err());
}

#[test]
fn malformed_manifest_payload_types_fail_before_restore_instead_of_using_legacy_tags() {
    for invalid in [
        Value::Boolean(true),
        "".into(),
        "abc".into(),
        "abcde".into(),
        "éxy".into(),
    ] {
        let mut id = identity();
        manifest_mut(&mut id)["RestoreKernelCache"]
            .as_dictionary_mut()
            .unwrap()
            .get_mut("Info")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("Img4PayloadType".into(), invalid);
        let file = fixture(Some(id.clone()), false);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        let tss = wire::dict([("ApImg4Ticket", Value::Data(ticket()))]);
        for error in [
            restore::preflight(&mut ipsw, &mut id).unwrap_err(),
            ipsw.validate_identity(&mut id).unwrap_err(),
            ipsw.component(&id, "RestoreKernelCache").unwrap_err(),
            ipsw.personalized(&id, "RestoreKernelCache", &tss)
                .unwrap_err(),
            ipsw.verify_all().err().unwrap(),
            img4::personalize_with_metadata("RestoreKernelCache", &im4p(b"krnl"), &tss, &id.value)
                .unwrap_err(),
        ] {
            assert!(
                format!("{error:#}").contains("RestoreKernelCache Info.Img4PayloadType"),
                "{error:#}"
            );
        }
    }
}

#[test]
fn shared_files_keep_each_components_digest_algorithm_and_restore_tag() {
    let raw = im4p(b"krnl");
    let mut restored = raw.clone();
    let offset = img4::type_offset(&raw).unwrap();
    restored[offset..offset + 4].copy_from_slice(b"rkrn");
    for kernel_digest in [
        sha2::Sha256::digest(&restored).to_vec(),
        Sha384::digest(&restored).to_vec(),
    ] {
        let mut id = identity();
        for (name, digest) in [
            ("RestoreKernelCache", kernel_digest),
            // This digest describes rkrn, although this component requires rdtr.
            ("RestoreDeviceTree", Sha384::digest(&restored).to_vec()),
        ] {
            manifest_mut(&mut id).insert(
                name.into(),
                wire::dict([
                    ("Digest", Value::Data(digest)),
                    (
                        "Info",
                        wire::dict([
                            ("Path", "Firmware/shared".into()),
                            (
                                "Img4PayloadType",
                                if name == "RestoreKernelCache" {
                                    "rkrn"
                                } else {
                                    "rdtr"
                                }
                                .into(),
                            ),
                        ]),
                    ),
                ]),
            );
        }
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/shared", &raw)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert_eq!(ipsw.component(&id, "RestoreKernelCache").unwrap(), raw);
        assert!(ipsw.component(&id, "RestoreDeviceTree").is_err());
        assert!(ipsw.verify_all().is_err());

        let mut tree = raw.clone();
        tree[offset..offset + 4].copy_from_slice(b"rdtr");
        manifest_mut(&mut id)["RestoreDeviceTree"]
            .as_dictionary_mut()
            .unwrap()
            .insert("Digest".into(), Value::Data(Sha384::digest(&tree).to_vec()));
        let file = fixture_files(Some(id.clone()), false, &[("Firmware/shared", &raw)]);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert_eq!(ipsw.component(&id, "RestoreDeviceTree").unwrap(), raw);
        ipsw.verify_all().unwrap();
    }
}

#[test]
fn shared_bundles_match_each_authenticated_digest_and_reject_metadata_only_digests() {
    let first = b"firmware payload";
    let second = b"configuration";
    let first_digest = sha1::Sha1::digest(first).to_vec();
    let second_digest = sha2::Sha256::digest(second).to_vec();
    let bundle = Value::Array(vec![
        wire::dict([
            ("Payload", Value::Data(first.to_vec())),
            ("Digest", Value::Data(first_digest.clone())),
        ]),
        wire::dict([
            ("Payload", Value::Data(second.to_vec())),
            ("Digest", Value::Data(second_digest.clone())),
        ]),
        wire::dict([("Digest", Value::Data(vec![0; 32]))]),
    ]);
    for binary in [false, true] {
        let mut bytes = Vec::new();
        if binary {
            bundle.to_writer_binary(&mut bytes).unwrap();
        } else {
            bytes = wire::xml(&bundle).unwrap();
        }
        for compression in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let mut id = identity();
            for (name, digest) in [
                ("BundleFirmware", first_digest.clone()),
                ("BundleConfiguration", second_digest.clone()),
                ("WholeBundle", Sha384::digest(&bytes).to_vec()),
            ] {
                let mut entry = component_entry("shared.plist", &bytes);
                entry
                    .as_dictionary_mut()
                    .unwrap()
                    .insert("Digest".into(), Value::Data(digest));
                manifest_mut(&mut id).insert(name.into(), entry);
            }
            let files = [("shared.plist", bytes.as_slice())];
            let file = fixture_compression(Some(id.clone()), false, &files, compression);
            let mut ipsw = Ipsw::open(file.path()).unwrap();
            for name in ["BundleFirmware", "BundleConfiguration", "WholeBundle"] {
                assert_eq!(ipsw.component(&id, name).unwrap(), bytes);
            }
            assert_eq!(ipsw.verify_all().unwrap().manifest_digests, 9);

            let mut invalid = component_entry("shared.plist", &bytes);
            invalid
                .as_dictionary_mut()
                .unwrap()
                .insert("Digest".into(), Value::Data(vec![0; 32]));
            manifest_mut(&mut id).insert("MetadataOnly".into(), invalid);
            let file = fixture_compression(Some(id.clone()), false, &files, compression);
            let mut ipsw = Ipsw::open(file.path()).unwrap();
            assert!(ipsw.component(&id, "MetadataOnly").is_err());
            assert!(ipsw.verify_all().is_err());
        }
    }
}

#[test]
fn empty_components_have_the_same_digest_in_memory_and_streaming() {
    let mut id = identity();
    manifest_mut(&mut id).insert("Empty".into(), component_entry("empty", b""));
    let file = fixture_files(Some(id.clone()), false, &[("empty", b"")]);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    assert!(ipsw.component(&id, "Empty").unwrap().is_empty());
    assert_eq!(ipsw.verify_all().unwrap().manifest_digests, 7);
}

#[test]
fn ftab_and_uarp_manifest_digests_validate_inner_payloads_across_stream_chunks() {
    use crate::test_support::Ftab;
    use zalivka::firmware::payload_ranges;
    let payload = vec![0x35; 3 * 1024 * 1024 + 17];
    let mut header = [0; 48];
    header[32..36].copy_from_slice(b"rkos");
    header[36..40].copy_from_slice(b"ftab");
    let ftab = Ftab {
        header,
        entries: vec![(*b"rkos", payload.clone(), 0)],
    }
    .encode();
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
        (
            "BuildIdentities",
            Value::Array(vec![wire::dict([(
                "Manifest",
                wire::dict([] as [(&str, Value); 0]),
            )])]),
        ),
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
    let mut image = ipsw.image("large.dmg").unwrap();
    assert_eq!(image.size(), size);
    image
        .seek(SeekFrom::Start(4 * 1024 * 1024 * 1024 + 99))
        .unwrap();
    let mut bytes = [1; 16];
    image.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 16]);
    assert_eq!(
        ipsw.stream("large.dmg", &mut std::io::sink()).unwrap(),
        size
    );
    let report = ipsw.verify_all().unwrap();
    assert_eq!(report.entries, 2);
    assert!(report.uncompressed_bytes > size);
}

#[test]
fn ipsw_identity_selection_and_stored_image_have_bounded_seeks() {
    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut id = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap();
    restore::preflight(&mut ipsw, &mut id).unwrap();
    assert_eq!(ipsw.component(&id, "iBSS").unwrap(), im4p(b"test"));
    let mut image = ipsw.image(id.path("OS").unwrap()).unwrap();
    let mut data = vec![];
    image.read_to_end(&mut data).unwrap();
    assert_eq!(data, im4p(b"test"));
    assert!(image.seek(SeekFrom::Start(image.size() + 1)).is_err());
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
    assert!(restore::preflight(&mut ipsw, &mut identity()).is_err());
}

#[test]
fn identity_selection_returns_an_owned_value_and_checks_later_entries() {
    let file = fixture(None, false);
    let ipsw = Ipsw::open(file.path()).unwrap();
    let mut selected = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap();
    assert_eq!(selected.value, ipsw.identity(0).unwrap().value);
    assert!(ipsw.identity(1).is_err());
    let summaries = ipsw
        .identity_summaries()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].chip_id, selected.summary().unwrap().chip_id);
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
fn automatic_identity_selection_follows_declared_variant_links_in_any_order() {
    let file = fixture(None, false);
    for key in ["MacOSVariant", "RecoveryVariant"] {
        let mut primary = identity();
        let info = primary.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.remove("MacOSVariant");
        info.insert("Variant".into(), "OpaquePrimary".into());
        info.insert(key.into(), "OpaqueCompanion".into());
        let mut companion = recovery_identity();
        companion.value.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap()
            .insert("Variant".into(), "OpaqueCompanion".into());
        for reversed in [false, true] {
            let mut ipsw = Ipsw::open(file.path()).unwrap();
            let values = if reversed {
                vec![companion.value.clone(), primary.value.clone()]
            } else {
                vec![primary.value.clone(), companion.value.clone()]
            };
            Arc::make_mut(&mut ipsw.manifest)
                .as_dictionary_mut()
                .unwrap()
                .insert("BuildIdentities".into(), Value::Array(values));
            let selected = ipsw
                .select_behavior(&device_info(), None, Behavior::Erase)
                .unwrap();
            assert_eq!(selected.index, usize::from(reversed), "{key}");
            assert_eq!(selected.summary().unwrap().variant, "OpaquePrimary");
            let recovery = ipsw
                .recovery_identity(&device_info(), &selected)
                .unwrap()
                .unwrap();
            assert_eq!(recovery.index, usize::from(!reversed), "{key}");
            assert_eq!(recovery.summary().unwrap().variant, "OpaqueCompanion");
        }
    }
}

#[test]
fn variant_links_do_not_hide_multiple_roots_or_choose_across_hardware() {
    let file = fixture(Some(recovery_identity()), false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let values = Arc::make_mut(&mut ipsw.manifest)
        .as_dictionary_mut()
        .unwrap()["BuildIdentities"]
        .as_array_mut()
        .unwrap();
    values.push(identity().value);
    assert!(
        ipsw.select_behavior(&device_info(), None, Behavior::Erase)
            .is_err()
    );
    assert_eq!(
        ipsw.select_behavior(&device_info(), Some(0), Behavior::Erase)
            .unwrap()
            .index,
        0
    );
    assert_eq!(
        ipsw.select_behavior(&device_info(), Some(2), Behavior::Erase)
            .unwrap()
            .index,
        2
    );

    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let values = Arc::make_mut(&mut ipsw.manifest)
        .as_dictionary_mut()
        .unwrap()["BuildIdentities"]
        .as_array_mut()
        .unwrap();
    // A reference from another board must not suppress this board's identity.
    values[0]
        .as_dictionary_mut()
        .unwrap()
        .insert("ApBoardID".into(), "0x0b".into());
    assert_eq!(
        ipsw.select_behavior(&device_info(), None, Behavior::Erase)
            .unwrap()
            .index,
        1
    );
}

#[test]
fn cyclic_variant_links_require_an_explicit_identity() {
    let file = fixture(Some(recovery_identity()), false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let values = Arc::make_mut(&mut ipsw.manifest)
        .as_dictionary_mut()
        .unwrap()["BuildIdentities"]
        .as_array_mut()
        .unwrap();
    values[1].as_dictionary_mut().unwrap()["Info"]
        .as_dictionary_mut()
        .unwrap()
        .insert(
            "RecoveryVariant".into(),
            "Customer Erase Install (IPSW)".into(),
        );
    let error = ipsw
        .select_behavior(&device_info(), None, Behavior::Erase)
        .unwrap_err();
    assert!(
        error.to_string().contains("variant reference cycle"),
        "{error:#}"
    );
    assert!(
        ipsw.select_behavior(&device_info(), Some(0), Behavior::Erase)
            .is_ok()
    );
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
    // MacOSVariant explicitly links the companion identity; it is not another
    // DFU entry point with the same restore behavior.
    assert_eq!(
        ipsw.select_behavior(&device_info(), None, Behavior::Erase)
            .unwrap()
            .index,
        0
    );
    assert_eq!(
        ipsw.select_behavior(&device_info(), Some(0), Behavior::Erase)
            .unwrap()
            .index,
        0
    );
    assert_eq!(
        ipsw.select_behavior(&device_info(), Some(1), Behavior::Erase)
            .unwrap()
            .index,
        1
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
    ipsw.validate_identity(&mut id).unwrap();
    assert!(restore::preflight(&mut ipsw, &mut id).is_err());
    for bad in ["Firmware/missing", "../OS"] {
        manifest_mut(&mut id).insert(
            "Other".into(),
            wire::dict([("Info", wire::dict([("Path", bad.into())]))]),
        );
        assert!(ipsw.validate_identity(&mut id).is_err());
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
        assert!(restore::preflight(&mut ipsw, &mut id).is_err());
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

#[test]
fn trusted_files_and_fileless_signing_metadata_use_the_same_digest_validation() {
    for (name, bad) in [
        (
            "OS",
            wire::dict([
                ("Trusted", true.into()),
                ("Info", wire::dict([("Path", "Firmware/OS".into())])),
            ]),
        ),
        ("Fileless", wire::dict([("Trusted", "true".into())])),
        ("Fileless", wire::dict([("Digest", "not data".into())])),
        (
            "Fileless",
            wire::dict([("Digest", Value::Data(vec![0; 7]))]),
        ),
    ] {
        let mut id = identity();
        manifest_mut(&mut id).insert(name.into(), bad);
        let file = fixture(Some(id.clone()), false);
        let mut ipsw = Ipsw::open(file.path()).unwrap();
        assert!(restore::preflight(&mut ipsw, &mut id).is_err(), "{name}");
        assert!(ipsw.validate_identity(&mut id).is_err(), "{name}");
        assert!(ipsw.verify_all().is_err(), "{name}");
    }
}

#[test]
fn direct_stored_images_reject_inconsistent_sizes_and_physical_truncation() {
    let file = fixture(None, false);
    let mut bytes = std::fs::read(file.path()).unwrap();
    let name = b"Firmware/OS";
    let offset = crate::test_support::zip_entry_offset(&bytes, std::str::from_utf8(name).unwrap());
    let original_size = u32::from_le_bytes(bytes[offset + 24..offset + 28].try_into().unwrap());
    bytes[offset + 24..offset + 28].copy_from_slice(&(original_size + 1).to_le_bytes());
    std::fs::write(file.path(), &bytes).unwrap();
    assert!(
        Ipsw::open(file.path())
            .unwrap()
            .image("Firmware/OS")
            .is_err()
    );

    let file = fixture(None, false);
    let mut ipsw = Ipsw::open(file.path()).unwrap();
    let mut image = ipsw.image("Firmware/OS").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(file.path())
        .unwrap()
        .set_len(0)
        .unwrap();
    assert_eq!(image.read(&mut []).unwrap(), 0);
    assert_eq!(
        image.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}
