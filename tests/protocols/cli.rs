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
