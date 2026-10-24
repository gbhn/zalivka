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
        let (event_output, text_output) = if worker {
            (&output.stdout, &output.stderr)
        } else {
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
            (&output.stderr, &output.stdout)
        };
        let events = events(event_output);
        assert!(
            matches!(events.first(), Some(zalivka::progress::Event::Transfer(update)) if update.completed == 0)
        );
        assert!(
            matches!(events.last(), Some(zalivka::progress::Event::Transfer(update)) if update.finished)
        );
        assert!(
            !String::from_utf8_lossy(text_output)
                .lines()
                .any(|line| zalivka::progress::Event::parse(line).is_some())
        );
    }
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
