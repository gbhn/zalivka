//! Data builders and assertions shared by protocol and unit tests.
use crate::wire;
use anyhow::Result;
use plist::Value;

pub fn boolean(value: &Value, path: &[&str]) -> bool {
    wire::get(value, path)
        .ok()
        .and_then(Value::as_boolean)
        .unwrap_or(false)
}

pub struct Ftab {
    pub header: [u8; 48],
    pub entries: Vec<([u8; 4], Vec<u8>, u32)>,
}

impl Ftab {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = self.header.to_vec();
        output[40..44].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        output.resize(48 + self.entries.len() * 16, 0);
        for (i, (tag, data, padding)) in self.entries.iter().enumerate() {
            let offset = u32::try_from(output.len()).unwrap();
            let size = u32::try_from(data.len()).unwrap();
            let position = 48 + i * 16;
            output[position..position + 4].copy_from_slice(tag);
            output[position + 4..position + 8].copy_from_slice(&offset.to_le_bytes());
            output[position + 8..position + 12].copy_from_slice(&size.to_le_bytes());
            output[position + 12..position + 16].copy_from_slice(&padding.to_le_bytes());
            output.extend_from_slice(data);
        }
        output
    }
}

/// A normal IPSW fixture; malformed XML, ZIP64 and directory tests build their
/// own archives when they need to violate these defaults.
pub fn ipsw(
    manifest: &Value,
    files: &[(&str, &[u8])],
    compression: zip::CompressionMethod,
) -> tempfile::NamedTempFile {
    use std::io::Write;
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
    let options = zip::write::SimpleFileOptions::default().compression_method(compression);
    zip.start_file("BuildManifest.plist", options).unwrap();
    manifest.to_writer_xml(&mut zip).unwrap();
    for (name, data) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
    file
}

/// Locate the exact central-directory name for deliberate metadata corruption.
pub fn zip_entry_offset(bytes: &[u8], name: &str) -> usize {
    bytes
        .windows(4)
        .enumerate()
        .find_map(|(offset, signature)| {
            (signature == b"PK\x01\x02"
                && bytes.get(offset + 28..offset + 30) == Some(&(name.len() as u16).to_le_bytes())
                && bytes.get(offset + 46..offset + 46 + name.len()) == Some(name.as_bytes()))
            .then_some(offset)
        })
        .expect("fixture ZIP entry missing")
}

pub fn corrupt_crc(path: &std::path::Path, name: &str) {
    let mut bytes = std::fs::read(path).unwrap();
    let offset = zip_entry_offset(&bytes, name);
    bytes[offset + 16] ^= 1;
    std::fs::write(path, bytes).unwrap();
}

/// A finite packet script: an unexpected read fails instead of hanging a test.
pub struct Scripted {
    pub input: std::collections::VecDeque<Vec<u8>>,
    pub output: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl crate::mux::PacketTransport for Scripted {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.input
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected mux read"))
    }
}

pub fn scripted(
    packets: Vec<Vec<u8>>,
) -> (Scripted, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    (
        Scripted {
            input: packets.into(),
            output: output.clone(),
        },
        output,
    )
}

pub fn payloads(output: &std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>, port: u16) -> Vec<u8> {
    let mut data = Vec::new();
    for bytes in output.lock().unwrap().iter() {
        if u32::from_be_bytes(bytes[..4].try_into().unwrap()) != 6 {
            continue;
        }
        let packet = crate::mux::decode_packet(bytes, 2).unwrap();
        let header = packet.payload;
        if u16::from_be_bytes(header[2..4].try_into().unwrap()) == port {
            data.extend_from_slice(&header[usize::from(header[12] >> 4) * 4..]);
        }
    }
    data
}
