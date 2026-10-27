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
        assert!(error.contains(driver.unwrap_or("не назначен")));
        assert!(error.contains("os error 5"));
    }
}
