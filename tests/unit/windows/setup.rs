use super::*;

#[test]
fn both_embedded_packages_are_intact_and_extract_without_installing() {
    for arch in ["amd64", "arm64"] {
        let directory = tempfile::tempdir().unwrap();
        let inf = unpack_driver(directory.path(), arch).unwrap();
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
