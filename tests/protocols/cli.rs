use super::*;

#[test]
fn cli_inspection_and_offline_plan_run_without_usb() {
    let file = fixture(None, false);
    let inspect = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("inspect")
        .arg(file.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(output["identities"][0]["device_class"], "j313ap");
    let plan = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("plan")
        .arg(file.path())
        .args(["--identity", "0"])
        .output()
        .unwrap();
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(output["hardware_checked"], false);
    assert_eq!(output["boot_components_verified"], true);
    assert_eq!(output["runtime_operations_known"], false);
    assert_eq!(output["hardware_restore_validated"], false);
    assert_eq!(output["hardware_validation_report"], "docs/validation.md");
    assert!(
        !output["limitations"]
            .to_string()
            .contains("no physical Mac restore")
    );
    assert!(output.get("stages").is_none());
}

#[test]
fn executable_version_identifies_the_exact_build() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        format!("zalivka {}", zalivka::VERSION)
    );
    assert!(zalivka::VERSION.starts_with(concat!(env!("CARGO_PKG_VERSION"), "+")));
    let mut parts = zalivka::VERSION.rsplit('.');
    let built_at = parts.next().unwrap().parse::<u128>().unwrap();
    assert!(built_at > 0);
    assert!(!parts.next().unwrap().is_empty());
}

#[test]
fn offline_plan_uses_the_manifest_component_names_and_stage_flags() {
    let bytes = im4p(b"nx26");
    let mut id = identity();
    for (name, first) in [("FutureFirst", true), ("FutureSecond", false)] {
        let mut entry = component_entry("Firmware/future", &bytes);
        let info = entry.as_dictionary_mut().unwrap()["Info"]
            .as_dictionary_mut()
            .unwrap();
        info.remove("Img4PayloadType");
        info.insert("IsLoadedByiBoot".into(), true.into());
        info.insert("IsLoadedByiBootStage1".into(), first.into());
        manifest_mut(&mut id).insert(name.into(), entry);
    }
    let file = fixture_files(Some(id), false, &[("Firmware/future", &bytes)]);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("plan")
        .arg(file.path())
        .args(["--identity", "1"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    for (stage, expected) in [(0, "FutureFirst"), (1, "FutureSecond")] {
        let components = plan["iboot_firmware_stages"][stage]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["kind"] == "component")
            .map(|step| step["value"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(components, [expected]);
    }
    assert_eq!(plan["runtime_operations_known"], false);
    assert!(plan.get("stages").is_none());
}

#[test]
fn cli_defaults_to_trace_and_keeps_stdout_machine_readable() {
    let file = fixture(None, false);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .arg("verify")
        .arg(file.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["entries"].as_u64().unwrap() > 0);
    let diagnostics = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostics.contains("TRACE"));
    assert!(diagnostics.contains("DEBUG"));
    assert!(diagnostics.contains("ipsw:zip"));
    assert!(!diagnostics.contains("ZALIVKA_EVENT "));
}

#[test]
fn native_verification_emits_typed_progress_and_complete_diagnostics() {
    let file = fixture(None, false);
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = events.clone();
    let report = zalivka::progress::Context::new(move |event| output.lock().unwrap().push(event))
        .run(|| zalivka::operations::verify(file.path(), None))
        .unwrap();
    let events = events.lock().unwrap();
    let mut started = std::collections::HashSet::new();
    let mut completed = std::collections::HashSet::new();
    let mut bytes = 0;
    for event in events.iter() {
        if let zalivka::progress::Event::Transfer(update) = event {
            assert!(update.stage.starts_with("Verifying "));
            if update.finished {
                assert!(completed.insert(update.id));
                assert_eq!(update.total, Some(update.completed));
                bytes += update.completed;
            } else {
                started.insert(update.id);
            }
        }
    }
    assert!(!started.is_empty());
    assert_eq!(started, completed);
    assert_eq!(started.len(), report.entries);
    assert_eq!(bytes, report.uncompressed_bytes);
    assert!(events.iter().any(|event| matches!(event,
        zalivka::progress::Event::Log(record) if record.level == zalivka::logging::Level::Trace)));
}

#[test]
fn cli_restore_requires_erase_before_accessing_usb() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .args(["restore", "absent.ipsw", "--ecid", "1234"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--erase"));
    assert!(!error.contains("--experimental"));
}

#[cfg(windows)]
#[test]
fn private_uac_entry_rejects_invalid_actions_and_log_pipe_identifiers() {
    for args in [
        vec!["--driver-helper", "unknown", "invalid"],
        vec!["--driver-helper", "prepare", "../file"],
        vec!["--driver-helper", "reset", "C:/Windows/System32/file"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("drivers:uac"));
    }
}
