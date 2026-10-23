//! Session-local DNS names: resolution happens when Windows opens the stream.
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
const MAX_NAMES: usize = 4096;
const MAX_MESSAGE: usize = 4096;
#[derive(Default)]
pub(super) struct Resolver {
    names: Vec<String>,
    addresses: HashMap<String, Ipv4Addr>,
}
impl Resolver {
    pub fn host(&self, ip: Ipv4Addr) -> Option<&str> {
        if !synthetic(ip) {
            return None;
        }
        let value = u32::from(ip) - u32::from(Ipv4Addr::new(198, 18, 0, 0));
        self.names
            .get(value.checked_sub(1)? as usize)
            .map(String::as_str)
    }
    pub fn reply(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 || query.len() > MAX_MESSAGE || query[2] & 0x80 != 0 {
            return None;
        }
        let mut reply = query[..12].to_vec();
        reply[2] = 0x80 | (query[2] & 1); // QR and client's RD; never claim DNSSEC validation.
        reply[3] = 0x80; // RA
        reply[4..12].fill(0);
        if query[2] & 0x78 != 0 {
            reply[3] |= 4;
            return Some(reply);
        }
        let Some((name, end)) = question(query) else {
            reply[3] |= 1;
            return Some(reply);
        };
        let kind = u16::from_be_bytes([query[end], query[end + 1]]);
        let class = u16::from_be_bytes([query[end + 2], query[end + 3]]);
        reply[5] = 1;
        for label in name.split('.') {
            reply.push(label.len() as u8);
            reply.extend(label.bytes());
        }
        reply.push(0);
        reply.extend_from_slice(&query[end..end + 4]);
        if class != 1 {
            reply[3] |= 4;
            return Some(reply);
        }
        // IPv4 gateway: no AAAA or HTTPS/SVCB hints which could bypass the name map.
        if matches!(kind, 28 | 64 | 65) {
            return Some(reply);
        }
        if kind != 1 {
            reply[3] |= 4;
            return Some(reply);
        }
        let key = name.to_ascii_lowercase();
        if key == "localhost" || key == "wpad" || key.ends_with(".local") {
            reply[3] |= 5;
            return Some(reply);
        }
        let address = if let Some(ip) = self.addresses.get(&key) {
            *ip
        } else {
            if self.names.len() == MAX_NAMES {
                reply[3] |= 2;
                return Some(reply);
            }
            let ip = Ipv4Addr::from(
                u32::from(Ipv4Addr::new(198, 18, 0, 0)) + self.names.len() as u32 + 1,
            );
            self.names.push(key.clone());
            self.addresses.insert(key, ip);
            ip
        };
        reply[7] = 1;
        reply.extend([0xc0, 0x0c, 0, 1, 0, 1]);
        // These addresses are valid only within this USB session.
        reply.extend(0u32.to_be_bytes());
        reply.extend([0, 4]);
        reply.extend(address.octets());
        Some(reply)
    }
}
pub(super) fn synthetic(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)
}
fn question(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes[4..6] != [0, 1] {
        return None;
    }
    let mut cursor = 12;
    let mut end = None;
    let mut labels = vec![];
    let mut length = 0;
    for _ in 0..128 {
        let size = *bytes.get(cursor)? as usize;
        if size == 0 {
            let end = end.unwrap_or(cursor + 1);
            bytes.get(end..end + 4)?;
            return (!labels.is_empty()).then(|| (labels.join("."), end));
        }
        if size & 0xc0 == 0xc0 {
            let next = *bytes.get(cursor + 1)? as usize;
            end.get_or_insert(cursor + 2);
            cursor = ((size & 0x3f) << 8) | next;
            continue;
        }
        if size > 63 {
            return None;
        }
        let label = bytes.get(cursor + 1..cursor + 1 + size)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        length += size + 1;
        if length > 254 {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?.to_owned());
        cursor += size + 1;
    }
    None
}

pub(super) struct Tcp {
    resolver: Arc<Mutex<Resolver>>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    closed: bool,
}
impl Tcp {
    pub fn new(resolver: Arc<Mutex<Resolver>>) -> Self {
        Self {
            resolver,
            input: vec![],
            output: VecDeque::new(),
            closed: false,
        }
    }
    pub fn shutdown_write(&mut self) {
        self.closed = true;
    }
}
impl Read for Tcp {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.output.is_empty() && !self.closed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = out.len().min(self.output.len());
        for byte in &mut out[..n] {
            *byte = self.output.pop_front().unwrap();
        }
        Ok(n)
    }
}
impl Write for Tcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let n = bytes
            .len()
            .min((MAX_MESSAGE + 2).saturating_sub(self.input.len()));
        self.input.extend_from_slice(&bytes[..n]);
        while self.input.len() >= 2 {
            let size = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
            if !(12..=MAX_MESSAGE).contains(&size) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self.input.len() < size + 2 {
                break;
            }
            if let Some(reply) = self
                .resolver
                .lock()
                .unwrap()
                .reply(&self.input[2..size + 2])
            {
                if self.output.len() + reply.len() + 2 > 65536 {
                    return Err(io::ErrorKind::OutOfMemory.into());
                }
                self.output.extend((reply.len() as u16).to_be_bytes());
                self.output.extend(reply);
            }
            self.input.drain(..size + 2);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/usb_internet/dns.rs"]
mod tests;
