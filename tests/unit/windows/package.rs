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
    assert!(!complete_apple_package(&inf));
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
    let directory = tempfile::tempdir().unwrap();
    let inf = unpack(directory.path(), "amd64").unwrap();
    assert!(complete_apple_package(&inf));
    assert!(!complete_apple_package(&directory.path().join("other.inf")));
    for name in FILES {
        let path = directory.path().join(name);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!complete_apple_package(&inf), "missing {name}");
        std::fs::write(path, bytes).unwrap();
    }
    assert!(complete_apple_package(&inf));
}

#[test]
fn embedded_packages_match_windows_expansion_byte_for_byte() {
    for (arch, bytes) in [("amd64", X64_CAB), ("arm64", ARM64_CAB)] {
        let directory = tempfile::tempdir().unwrap();
        let inf = unpack(directory.path(), arch).unwrap();
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
        for name in FILES {
            assert_eq!(
                std::fs::read(directory.path().join(name)).unwrap(),
                std::fs::read(reference.path().join(name)).unwrap(),
                "{arch}: {name}",
            );
        }
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            FILES.len()
        );
        let bytes = std::fs::read(inf).unwrap();
        let text = if bytes.starts_with(&[0xff, 0xfe]) {
            String::from_utf16(
                &bytes[2..]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        } else {
            String::from_utf8(bytes).unwrap()
        };
        assert!(text.contains("538.0.0.0"));
        for pid in ["PID_1227", "PID_1281", "PID_12AC"] {
            assert!(
                text.to_ascii_uppercase().contains(pid),
                "missing {pid} for {arch}"
            );
        }
    }
}

#[test]
fn package_extraction_rejects_unsupported_architectures_and_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    assert!(unpack(directory.path(), "unknown").is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let existing = directory.path().join("AppleUsb.inf");
    std::fs::write(&existing, b"existing driver").unwrap();
    assert!(unpack(directory.path(), "amd64").is_err());
    assert_eq!(std::fs::read(existing).unwrap(), b"existing driver");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
