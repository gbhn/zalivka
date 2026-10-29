use super::*;
use std::cell::RefCell;

#[test]
fn cleanup_selects_only_whole_apple_restore_device_ids() {
    for pid in [
        "1227", "1280", "1281", "1282", "1283", "12AC", "F014", "1881",
    ] {
        assert!(is_restore_device(&format!(
            r"USB\VID_05AC&PID_{pid}\serial"
        )));
    }
    assert!(is_restore_device(
        r"usb\vid_05ac&pid_12ac&restore_mode\serial"
    ));
    for instance in [
        r"USB\VID_05AC&PID_12A8\iphone",
        r"USB\VID_05AC&PID_024F\keyboard",
        r"USB\VID_05AC&PID_030D\mouse",
        r"USB\VID_1234&PID_1227\other_vendor",
        r"USB\VID_05AC&PID_12270\long_pid",
        r"USB\VID_05AC&PID_+122\signed_pid",
        r"USB\VID_05AC&PID_12AC&MI_00\interface",
        r"USB\VID_05AC&PID_12AC&RESTORE_MODE&MI_00\interface",
        r"USB\VID_05AC&PID_12AC&OTHER\extra_field",
        r"HID\VID_05AC&PID_1227\other_bus",
        r"USB\ROOT_HUB30\hub",
        r"USB\VID_05AC&PID_1227\",
        r"USB\VID_05AC&PID_1227",
        r"USB\VID_05AC&PID_1227\serial\extra",
        "",
    ] {
        assert!(
            !is_restore_device(instance),
            "must leave {instance} untouched"
        );
    }
}

#[test]
fn rescan_runs_after_both_success_and_partial_removal_failure() {
    for failed in [false, true] {
        let calls = RefCell::new(Vec::new());
        let result = with_rescan(
            || {
                calls.borrow_mut().push("remove");
                if failed {
                    anyhow::bail!("second removal failed");
                }
                calls.borrow_mut().push("install");
                Ok(())
            },
            || {
                calls.borrow_mut().push("rescan");
                Ok(())
            },
        );
        assert_eq!(result.is_err(), failed);
        assert_eq!(
            *calls.borrow(),
            if failed {
                vec!["remove", "rescan"]
            } else {
                vec!["remove", "install", "rescan"]
            }
        );
    }
}

#[test]
fn rescan_failure_is_reported_without_losing_the_original_error() {
    let error = with_rescan(
        || anyhow::bail!("uninstall failed"),
        || anyhow::bail!("scan failed"),
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("uninstall failed"));
    assert!(message.contains("scan failed"));
    assert!(with_rescan(|| Ok(()), || anyhow::bail!("scan failed")).is_err());
}
