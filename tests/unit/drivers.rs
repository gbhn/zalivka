use super::*;

#[test]
fn host_readiness_requires_stopped_service_and_a_driver() {
    for installed in [false, true] {
        for running in [false, true] {
            for apple in [false, true] {
                for winusb in [false, true] {
                    let host = HostStatus {
                        apple_service_installed: installed,
                        apple_service_running: running,
                        apple_driver_installed: apple,
                        compatible_usb_driver: winusb,
                    };
                    assert_eq!(host.needs_preparation(), running || !apple);
                    assert_eq!(
                        host.blocking_reason().is_none(),
                        !running && (apple || winusb)
                    );
                    if running {
                        assert!(
                            host.blocking_reason()
                                .unwrap()
                                .contains("Apple Mobile Device Service")
                        );
                    }
                }
            }
        }
    }
}
