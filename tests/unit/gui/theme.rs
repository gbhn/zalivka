use super::*;

#[test]
fn invalid_config_environment_falls_back_to_the_user_directory() {
    const CHILD: &str = "ZALIVKA_TEST_THEME_DIRECTORY";
    if let Some(expected) = std::env::var_os(CHILD) {
        assert_eq!(preference_file(), Some(PathBuf::from(expected)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args([
        "--exact",
        "gui::theme::tests::invalid_config_environment_falls_back_to_the_user_directory",
        "--nocapture",
    ]);
    let expected = if cfg!(windows) {
        child
            .env("LOCALAPPDATA", "relative")
            .env("USERPROFILE", directory.path());
        directory
            .path()
            .join("AppData")
            .join("Local")
            .join("zalivka")
            .join("theme")
    } else {
        child
            .env("XDG_CONFIG_HOME", "relative")
            .env("HOME", directory.path());
        directory
            .path()
            .join(".config")
            .join("zalivka")
            .join("theme")
    };
    let output = child.env(CHILD, expected).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

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
