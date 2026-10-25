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
    assert!(output.get("stages").is_none());
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
fn gui_workers_emit_transfer_events_on_stdout_and_cli_keeps_json_clean() {
    let file = fixture(None, false);
    let checksum = device::encode_hex(&sha2::Sha256::digest(std::fs::read(file.path()).unwrap()));
    for worker in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"));
        command
            .arg("verify")
            .arg(file.path())
            .args(["--checksum", &checksum]);
        if worker {
            command.env(zalivka::progress::WORKER_EVENTS_ENV, "1");
        } else {
            command.env_remove(zalivka::progress::WORKER_EVENTS_ENV);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events = |bytes: &[u8]| {
            String::from_utf8_lossy(bytes)
                .lines()
                .filter_map(zalivka::progress::Event::parse)
                .collect::<Vec<_>>()
        };
        if worker {
            let events = events(&output.stdout);
            assert!(output.stderr.is_empty());
            assert_eq!(
                events.len(),
                String::from_utf8_lossy(&output.stdout).lines().count()
            );
            let transfers: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    zalivka::progress::Event::Transfer(update) => Some(update),
                    _ => None,
                })
                .collect();
            assert_eq!(transfers.first().unwrap().completed, 0);
            assert!(transfers.last().unwrap().finished);
            assert!(events.iter().any(|event| matches!(event,
                zalivka::progress::Event::Log(record) if record.level == zalivka::logging::Level::Debug)));
        } else {
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
            assert!(events(&output.stdout).is_empty());
            assert!(events(&output.stderr).is_empty());
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            assert!(!diagnostics.contains("DEBUG"));
            assert!(!diagnostics.contains('\u{00b7}'));
        }
    }
}

#[test]
fn verbose_diagnostics_keep_stdout_machine_readable() {
    let file = fixture(None, false);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .env_remove(zalivka::progress::WORKER_EVENTS_ENV)
        .arg("verify")
        .arg(file.path())
        .arg("--verbose")
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains("DEBUG"));
    assert!(!diagnostics.contains(zalivka::progress::EVENT_PREFIX));
}

#[test]
fn cli_restore_requires_erase_and_experimental_flags_before_accessing_usb() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zalivka"))
        .args(["restore", "absent.ipsw", "--ecid", "1234"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--erase"));
    assert!(error.contains("--experimental"));
}
