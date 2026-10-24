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
