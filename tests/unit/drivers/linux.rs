use super::*;

fn exit(code: u8) -> Command {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        &format!("printf 'setup output\\n'; printf 'setup diagnostic\\n' >&2; exit {code}"),
    ]);
    command
}

#[test]
fn desktop_elevation_runs_only_the_installer_with_literal_arguments() {
    let path = Path::new("/tmp/Zalivka folder/zalivka 'literal' $(name)");
    let command = elevation_command(path);
    assert_eq!(command.get_program(), "pkexec");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        vec![
            std::ffi::OsStr::new("--disable-internal-agent"),
            path.as_os_str(),
            std::ffi::OsStr::new("drivers"),
            std::ffi::OsStr::new("install-udev"),
        ]
    );
}

#[test]
fn installer_creates_readable_rules_before_reload_and_reuses_existing_rules() {
    use std::os::unix::fs::MetadataExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules with spaces/70-zalivka.rules");
    let marker = directory.path().join("reload count");
    let mut reload = Command::new("/bin/sh");
    reload
        .args([
            "-c",
            "test -f \"$1\" && printf reloaded >> \"$2\"",
            "udevadm-test",
        ])
        .arg(&path)
        .arg(&marker);
    install_with(&path, &mut reload).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), UDEV_RULES.as_bytes());
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
    install_with(&path, &mut reload).unwrap();
    assert_eq!(metadata.ino(), std::fs::metadata(&path).unwrap().ino());
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "reloadedreloaded");
}

#[test]
fn installer_preserves_a_different_rule_and_does_not_reload_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("70-zalivka.rules");
    std::fs::write(&path, "custom rule").unwrap();
    let marker = directory.path().join("unexpected reload");
    let mut reload = Command::new("/bin/sh");
    reload
        .args(["-c", ": > \"$1\"", "udevadm-test"])
        .arg(&marker);
    let error = install_with(&path, &mut reload).unwrap_err();
    assert!(error.to_string().contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), "custom rule");
    assert!(!marker.exists());
}

#[test]
fn installer_upgrades_the_previous_bundled_rule_and_keeps_custom_rules_protected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("70-zalivka.rules");
    std::fs::write(&path, "# Apple DFU/recovery and restore interfaces. Access for the active local seat.\nSUBSYSTEM==\"usb\", ATTR{idVendor}==\"05ac\", TAG+=\"uaccess\"\n").unwrap();
    install_with(&path, &mut exit(0)).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), UDEV_RULES);
}

#[test]
fn reload_failure_keeps_the_installed_rule_and_can_be_retried() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("70-zalivka.rules");
    let error = install_with(&path, &mut exit(1)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("rule file was saved: setup diagnostic")
    );
    assert_eq!(std::fs::read(&path).unwrap(), UDEV_RULES.as_bytes());
    install_with(&path, &mut exit(0)).unwrap();
}

#[test]
fn authorization_exit_codes_and_helper_output_reach_the_operation_journal() {
    use std::sync::{Arc, Mutex};
    for (code, expected) in [
        (0, ""),
        (1, "setup failed"),
        (126, "cancelled"),
        (127, "Polkit authentication agent"),
    ] {
        let records = Arc::new(Mutex::new(Vec::new()));
        let output = records.clone();
        let context = crate::progress::Context::new(move |event| {
            if let crate::progress::Event::Log(record) = event {
                output.lock().unwrap().push(record);
            }
        });
        let result = context.run(|| run_setup(&mut exit(code)));
        if code == 0 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains(expected));
        }
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "setup output");
        assert_eq!(records[1].message, "setup diagnostic");
        assert!(records.iter().all(|record| record.level
            == if code == 0 {
                crate::logging::Level::Info
            } else {
                crate::logging::Level::Error
            }));
    }
}

#[test]
fn missing_elevation_program_explains_the_polkit_requirement() {
    let directory = tempfile::tempdir().unwrap();
    let error = run_setup(&mut Command::new(directory.path().join("missing-pkexec"))).unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("Could not start pkexec"));
    assert!(error.contains("Install Polkit"));
    assert!(error.contains("sudo ./zalivka drivers install-udev"));
}
