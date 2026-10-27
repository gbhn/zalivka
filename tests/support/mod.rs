//! Data builders and assertions shared by protocol and unit tests.
use crate::wire;
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
