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
                        usb_network_driver_available: true,
                        usb_network_interfaces: vec![],
                    };
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

#[test]
fn preparation_checks_apple_and_each_network_interface_independently() {
    for apple in [false, true] {
        for available in [false, true] {
            for control in [false, true] {
                for data in [false, true] {
                    let host = HostStatus {
                        apple_service_installed: false,
                        apple_service_running: false,
                        apple_driver_installed: apple,
                        compatible_usb_driver: false,
                        usb_network_driver_available: available,
                        usb_network_interfaces: [control, data]
                            .into_iter()
                            .enumerate()
                            .map(|(number, ready)| UsbNetworkInterfaceStatus {
                                serial: "TEST".into(),
                                interface: number as u8,
                                instance_id: format!("TEST_{number}"),
                                ready,
                                error: (!ready).then(|| "missing".into()),
                            })
                            .collect(),
                    };
                    assert_eq!(
                        host.needs_preparation(),
                        !(apple && available && control && data)
                    );
                    // Network preparation is independent of Restore readiness in DFU.
                    assert_eq!(host.blocking_reason().is_none(), apple);
                    let running = HostStatus {
                        apple_service_running: true,
                        ..host
                    };
                    assert!(running.needs_preparation());
                }
            }
        }
    }
}

#[test]
fn disconnected_mac_defers_network_binding_without_reinstalling_apple() {
    let host = HostStatus {
        apple_service_installed: false,
        apple_service_running: false,
        apple_driver_installed: true,
        compatible_usb_driver: false,
        usb_network_driver_available: true,
        usb_network_interfaces: vec![],
    };
    assert!(!host.needs_preparation());
    assert!(host.blocking_reason().is_none());
}
