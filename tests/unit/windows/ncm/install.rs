use super::*;

#[test]
fn ncm_backups_publish_complete_json_and_never_overwrite_original_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("backup.json");
    let mut backup = Backup {
        instance: r"USB\VID_05AC&PID_12AC&MI_00\test".into(),
        class: "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}".into(),
        inf: Some("original.inf".into()),
        section: Some("OriginalSection".into()),
        guids: Some((REG_MULTI_SZ, vec![65, 0, 0, 0, 0, 0])),
    };
    backup.save(&path).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert_eq!(original, serde_json::to_vec_pretty(&backup).unwrap());
    let restored: Backup = serde_json::from_slice(&original).unwrap();
    assert_eq!(restored.instance, backup.instance);
    assert_eq!(restored.class, backup.class);
    assert_eq!(restored.inf, backup.inf);
    assert_eq!(restored.section, backup.section);
    assert_eq!(restored.guids, backup.guids);
    backup.inf = Some("replacement.inf".into());
    assert!(backup.save(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn original_driver_properties_are_bounded_terminated_nonempty_utf16_strings() {
    let value = wide("original.inf");
    assert_eq!(
        original_property(&value, DEVPROP_TYPE_STRING, (value.len() * 2) as u32).unwrap(),
        "original.inf"
    );
    for (value, ty, size) in [
        (vec![0], DEVPROP_TYPE_STRING, 2),
        (vec![65], DEVPROP_TYPE_STRING, 2),
        (vec![65, 0], DEVPROP_TYPE_STRING, 5),
        (vec![65, 0], DEVPROP_TYPE_STRING, 3),
        (vec![65, 0], 0, 4),
        (vec![65, 0, 66, 0], DEVPROP_TYPE_STRING, 8),
        (vec![0xd800, 0], DEVPROP_TYPE_STRING, 4),
    ] {
        assert!(original_property(&value, ty, size).is_err());
    }
}

#[test]
fn adding_ncm_registration_preserves_both_registry_string_types() {
    let original = "{12345678-1234-1234-1234-123456789ABC}";
    for ty in [REG_SZ, REG_MULTI_SZ] {
        let bytes = wide(original)
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        let merged = ncm_guids(Some(&(ty, bytes)));
        let value = merged
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let names = value
            .split(|unit| *unit == 0)
            .take_while(|name| !name.is_empty())
            .map(|name| String::from_utf16(name).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, [original, GUID_TEXT]);
        assert!(value.ends_with(&[0, 0]));
    }
}

#[test]
fn saved_inf_names_cannot_name_directories_or_escape_the_windows_inf_folder() {
    for name in [
        "",
        ".",
        "..",
        ".inf",
        "../oem1.inf",
        "C:/oem1.inf",
        "oem1.inf/child",
        "name.txt",
        "ééé",
    ] {
        assert!(windows_inf(name).is_err(), "{name}");
    }
}
