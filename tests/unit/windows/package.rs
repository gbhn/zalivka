use super::*;
use std::{os::windows::process::CommandExt, process::Command};

#[test]
fn published_inf_is_resolved_by_windows_without_a_connected_device() {
    let inf = driver_store_inf(Path::new("winusb.inf"))
        .unwrap()
        .expect("Windows includes the WinUSB driver package");
    assert!(inf.is_absolute());
    assert!(inf.file_name().unwrap().eq_ignore_ascii_case("winusb.inf"));
    assert!(inf.is_file(), "{}", inf.display());
    assert!(DRIVERS.iter().all(|driver| !driver.complete(&inf)));
    assert!(
        driver_store_inf(Path::new("zalivka-nonexistent-driver.inf"))
            .unwrap()
            .is_none()
    );
    // Enumerating the class driver list must work with ordinary user rights.
    installed().unwrap();
}

#[test]
fn package_detection_requires_the_original_inf_and_every_package_file() {
    for driver in DRIVERS {
        let directory = tempfile::tempdir().unwrap();
        let inf = driver.unpack(directory.path(), "amd64").unwrap();
        assert!(driver.complete(&inf));
        assert!(!driver.complete(&directory.path().join("other.inf")));
        assert!(
            DRIVERS
                .iter()
                .filter(|other| **other != driver)
                .all(|other| !other.complete(&inf))
        );
        for name in driver.files() {
            let path = directory.path().join(name);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert!(!driver.complete(&inf), "{driver:?}: missing {name}");
            std::fs::write(path, bytes).unwrap();
        }
        assert!(driver.complete(&inf));
    }
}

#[test]
fn embedded_packages_match_windows_expansion_byte_for_byte() {
    for driver in DRIVERS {
        for arch in ["amd64", "arm64"] {
            let (bytes, _) = driver.archive(arch).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let inf = driver.unpack(directory.path(), arch).unwrap();
            let reference = tempfile::tempdir().unwrap();
            let archive = reference.path().join("apple-usb.cab");
            std::fs::write(&archive, bytes).unwrap();
            let output = Command::new(
                crate::windows::windows_directory()
                    .unwrap()
                    .join("System32/expand.exe"),
            )
            .arg("-F:*")
            .arg(archive)
            .arg(reference.path())
            .creation_flags(0x08000000)
            .output()
            .unwrap();
            assert!(output.status.success(), "{output:?}");
            for name in driver.files() {
                assert_eq!(
                    std::fs::read(directory.path().join(name)).unwrap(),
                    std::fs::read(reference.path().join(name)).unwrap(),
                    "{arch}: {name}",
                );
            }
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                driver.files().len()
            );
            let bytes = std::fs::read(inf).unwrap();
            let text = if bytes.starts_with(&[0xff, 0xfe]) {
                String::from_utf16(
                    &bytes[2..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|b| u16::from_le_bytes(*b))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            } else {
                String::from_utf8(bytes).unwrap()
            };
            let active = text
                .lines()
                .filter(|line| !line.trim_start().starts_with(';'))
                .collect::<Vec<_>>()
                .join("\n")
                .to_ascii_uppercase();
            let (version, hardware) = match driver {
                Driver::Usb => (
                    "538.0.0.0",
                    vec!["PID_1227", "PID_1281", "PID_12AC", "PID_F014"],
                ),
                Driver::Kis => ("1.1.5.0", vec![r"USB\VID_05AC&PID_1881"]),
                Driver::Rsm => ("1.1.7.0", vec![r"KIS\VID_05AC&PID_0001"]),
            };
            assert!(active.contains(version));
            for hardware in hardware {
                assert!(
                    active.contains(hardware),
                    "{driver:?}/{arch}: missing {hardware}"
                );
            }
            if driver != Driver::Usb {
                assert!(active.contains(if arch == "amd64" {
                    "NTAMD64"
                } else {
                    "NTARM64"
                }));
            }
            for name in driver
                .files()
                .iter()
                .filter(|name| name.ends_with(".sys") || name.ends_with(".dll"))
            {
                let bytes = std::fs::read(directory.path().join(name)).unwrap();
                let pe = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
                assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
                let machine = u16::from_le_bytes(bytes[pe + 4..pe + 6].try_into().unwrap());
                assert_eq!(
                    machine,
                    if arch == "amd64" { 0x8664 } else { 0xaa64 },
                    "{driver:?}/{arch}: {name}"
                );
            }
        }
    }
}

#[test]
fn package_extraction_rejects_unsupported_architectures_and_existing_files() {
    for driver in DRIVERS {
        let directory = tempfile::tempdir().unwrap();
        assert!(driver.unpack(directory.path(), "unknown").is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        let (bytes, checksum) = driver.archive("amd64").unwrap();
        let mut corrupt = bytes.to_vec();
        corrupt[0] ^= 1;
        assert!(
            unpack(directory.path(), &corrupt, checksum, driver.files())
                .unwrap_err()
                .to_string()
                .contains("corrupted")
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        let existing = directory.path().join(driver.files()[0]);
        std::fs::write(&existing, b"existing driver").unwrap();
        assert!(driver.unpack(directory.path(), "amd64").is_err());
        assert_eq!(std::fs::read(existing).unwrap(), b"existing driver");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
