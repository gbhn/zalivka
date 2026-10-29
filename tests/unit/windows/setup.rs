use super::*;
use crate::drivers::UsbDiagnostic;

fn diagnostic(accessible: bool, driver: Option<&str>) -> UsbDiagnostic {
    UsbDiagnostic {
        product_id: "1227".into(),
        serial: None,
        interfaces: vec![0],
        accessible,
        transport: accessible.then(|| "apple_usb".into()),
        dfu_state: accessible.then_some(2),
        error: (!accessible).then(|| "Access is denied (os error 5)".into()),
        driver: driver.map(str::to_owned),
        instance_id: r"USB\VID_05AC&PID_1227\test".into(),
        reset_error: None,
    }
}

#[test]
fn preparation_allows_disconnected_devices_and_checks_real_usb_access() {
    assert!(verify_device_access(&[]).is_ok());
    // An unfamiliar parent driver name must not reject a working USB backend.
    assert!(verify_device_access(&[diagnostic(true, Some("usbccgp"))]).is_ok());
    for driver in [None, Some("WinUSB"), Some("AppleUsbFilter")] {
        // Neither a familiar driver name nor another accessible device can hide
        // the failing device. Preserve its instance, binding and original error.
        let error =
            verify_device_access(&[diagnostic(true, Some("WinUSB")), diagnostic(false, driver)])
                .unwrap_err()
                .to_string();
        assert!(error.contains(r"USB\VID_05AC&PID_1227\test"));
        assert!(error.contains(driver.unwrap_or("not assigned")));
        assert!(error.contains("os error 5"));
    }
}

#[test]
fn late_setup_failure_preserves_the_error_and_publishes_the_restart_requirement() {
    use std::sync::{Arc, Mutex};

    for reboot in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let received = events.clone();
        let context = crate::progress::Context::new(move |event| {
            received.lock().unwrap().push(event);
        });
        let result = context.run(|| {
            Outcome {
                result: Err(anyhow::anyhow!(
                    "device verification failed after installation"
                ))
                .context("Windows setup"),
                reboot,
            }
            .finish()
        });
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("Windows setup"));
        assert!(error.contains("device verification failed after installation"));
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| matches!(event, crate::progress::Event::RebootRequired))
                .count(),
            usize::from(reboot)
        );
    }
}

#[test]
fn uac_preserves_success_failure_and_restart_for_both_driver_actions() {
    use std::sync::{Arc, Mutex};

    for action in [Action::Prepare, Action::Reset] {
        for (succeeded, reboot, code) in [
            (true, false, 0),
            (false, false, 1),
            (true, true, 3010),
            (false, true, 3017),
        ] {
            // The same outcome travels directly in an administrator process
            // or through the helper's exit code in an ordinary process.
            let native = Outcome {
                result: if succeeded {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("post-installation check failed"))
                },
                reboot,
            };
            assert_eq!(native.exit_code(), code);
            let from_helper = Outcome::from_exit_code(action, code);
            assert_eq!(from_helper.result.is_ok(), succeeded);
            assert_eq!(from_helper.reboot, reboot);
            for outcome in [native, from_helper] {
                let events = Arc::new(Mutex::new(0));
                let received = events.clone();
                let context = crate::progress::Context::new(move |event| {
                    if matches!(event, crate::progress::Event::RebootRequired) {
                        *received.lock().unwrap() += 1;
                    }
                });
                let result = context.run(|| outcome.finish());
                assert_eq!(result.is_ok(), succeeded);
                if let Ok(required) = result {
                    assert_eq!(required, reboot);
                }
                assert_eq!(*events.lock().unwrap(), u32::from(reboot));
            }
        }
        for code in [5, 42, 3011, u32::MAX] {
            let outcome = Outcome::from_exit_code(action, code);
            let error = outcome.result.unwrap_err().to_string();
            assert!(error.contains(action.name()));
            assert!(error.contains(&code.to_string()));
            assert!(!outcome.reboot);
        }
    }
}
