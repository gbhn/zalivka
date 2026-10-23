use super::*;

#[test]
fn theme_preference_roundtrips_and_invalid_or_missing_values_follow_the_system() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("settings").join("theme");
    assert_eq!(read_preference(&path), egui::ThemePreference::System);
    for preference in [
        egui::ThemePreference::Light,
        egui::ThemePreference::Dark,
        egui::ThemePreference::System,
    ] {
        write_preference(&path, preference).unwrap();
        assert_eq!(read_preference(&path), preference);
    }
    std::fs::write(&path, "invalid").unwrap();
    assert_eq!(read_preference(&path), egui::ThemePreference::System);
}
