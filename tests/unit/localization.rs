use super::*;

#[test]
fn bundled_languages_are_valid_and_select_by_system_language() {
    let mut localizer = Localizer::from_directories(&[], vec!["ru-RU".into()], "system");
    assert_eq!(localizer.language(), "ru");
    {
        let _language = localizer.enter();
        assert_eq!(text("Settings"), "Настройки");
        assert_eq!(
            format("Version {}, build {}", &["15.0", "24A335"]),
            "Версия 15.0, сборка 24A335"
        );
    }
    assert_eq!(text("Settings"), "Settings");
    localizer.select("en");
    let _language = localizer.enter();
    assert_eq!(text("Settings"), "Settings");
}

#[test]
fn locale_matching_uses_region_language_and_english_fallback() {
    for (system, expected) in [
        (vec!["ru_RU.UTF-8"], "ru"),
        (vec!["en-US"], "en"),
        (vec!["unknown", "ru-RU"], "en"),
        (vec!["C"], "en"),
        (vec![], "en"),
    ] {
        let localizer = Localizer::from_directories(
            &[],
            system.into_iter().map(String::from).collect(),
            "system",
        );
        assert_eq!(localizer.language(), expected);
    }
    let mut localizer = Localizer::from_directories(&[], vec!["ru-RU".into()], "en");
    assert_eq!(localizer.language(), "en");
    localizer.select("system");
    assert_eq!(localizer.language(), "ru");
    localizer.select("missing");
    assert_eq!(localizer.language(), "en");
}

#[test]
fn third_party_language_pack_is_loaded_without_source_changes() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("french.json");
    std::fs::write(&file, r#"{"locale":"fr","name":"Français","messages":{"Settings":"Paramètres","Version {}, build {}":"Version {}, compilation {}"}}"#).unwrap();
    let localizer =
        Localizer::from_directories(&[directory.path().into()], vec!["fr-FR".into()], "system");
    assert_eq!(localizer.language(), "fr");
    assert!(
        localizer
            .languages()
            .iter()
            .any(|(id, name)| id == "fr" && name == "Français")
    );
    let _language = localizer.enter();
    assert_eq!(text("Settings"), "Paramètres");
    assert_eq!(
        format("Version {}, build {}", &["15", "24A"]),
        "Version 15, compilation 24A"
    );
    assert_eq!(text("Technical details"), "Technical details");
    assert_eq!(
        text("An unknown technical error"),
        "An unknown technical error"
    );
}

#[test]
fn malformed_packs_do_not_replace_valid_languages() {
    let english: Pack = serde_json::from_str(include_str!("../../locales/en.json")).unwrap();
    for messages in [
        BTreeMap::from([("Version {}, build {}".into(), "Version {}".into())]),
        BTreeMap::from([("Stage: {}".into(), "Stage: {missing}".into())]),
    ] {
        assert!(
            Pack::new(
                Pack {
                    locale: "fr".into(),
                    name: "Français".into(),
                    messages
                },
                &english
            )
            .is_err()
        );
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("ru.json"), "invalid JSON").unwrap();
    let localizer =
        Localizer::from_directories(&[directory.path().into()], vec!["ru".into()], "system");
    let _language = localizer.enter();
    assert_eq!(text("Settings"), "Настройки");
}

#[test]
fn formatted_ui_values_and_action_names_are_localized_at_render_time() {
    let localizer = Localizer::from_directories(&[], vec!["ru".into()], "system");
    let _language = localizer.enter();
    assert_eq!(text("Restore: error"), "Восстановление: ошибка");
    assert_eq!(
        format("Verifying {name}", &["Settings"]),
        "Проверка Settings"
    );
    assert_eq!(
        format("Transferred: {size}", &["60 Б из 100 Б"]),
        "Передано: 60 Б из 100 Б"
    );
    assert_eq!(
        format("Verifying {name}", &["Firmware/test.img4"]),
        "Проверка Firmware/test.img4"
    );
    assert_eq!(
        format("Stage: {}", &["writing filesystem"]),
        "Этап: writing filesystem"
    );
}

#[test]
fn language_choice_round_trips_without_touching_other_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("settings/language");
    write_preference(&path, "ru").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "ru");
    write_preference(&path, "system").unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap(), "system");
}

#[test]
fn russian_ui_does_not_translate_diagnostics_or_operation_names() {
    let localizer = Localizer::from_directories(&[], vec!["ru".into()], "system");
    let _language = localizer.enter();
    let records = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = records.clone();
    crate::progress::Context::new(move |event| {
        if let crate::progress::Event::Log(record) = event {
            output.lock().unwrap().push(record);
        }
    })
    .run(|| {
        let mut progress = crate::progress::Progress::new("IPSW verification", Some(1024), 0);
        progress.advance(1024);
        progress.finish();
    });
    assert_eq!(text("IPSW verification"), "Проверка IPSW");
    let records = records.lock().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.message.contains("IPSW verification"))
    );
    assert!(
        records
            .iter()
            .all(|record| !record.message.chars().any(|ch| ('А'..='я').contains(&ch)))
    );
}

#[test]
fn explicit_parameters_are_opaque_and_translations_can_reorder_them() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("fr.json"), r#"{"locale":"fr","name":"Français","messages":{"Version {}, build {}":"Compilation {1}, version {0}"}}"#).unwrap();
    let localizer = Localizer::from_directories(&[directory.path().into()], vec![], "fr");
    let _language = localizer.enter();
    assert_eq!(
        format("Version {}, build {}", &["Settings {1}", "24A"]),
        "Compilation 24A, version Settings {1}"
    );
    assert_eq!(text("Version 15, build 24A"), "Version 15, build 24A");
}

#[test]
fn retired_diagnostic_keys_do_not_disable_existing_ui_language_packs() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("fr.json"), r#"{"locale":"fr","name":"Français","messages":{"Settings":"Paramètres","TX frame={} B":"obsolete diagnostic"}}"#).unwrap();
    let localizer = Localizer::from_directories(&[directory.path().into()], vec![], "fr");
    let _language = localizer.enter();
    assert_eq!(text("Settings"), "Paramètres");
    assert_eq!(text("TX frame={} B"), "TX frame={} B");
}
