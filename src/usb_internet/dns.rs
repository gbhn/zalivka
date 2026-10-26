//! Session-local DNS names: resolution happens when Windows opens the stream.
use bytes::{Buf, BytesMut};
use domain::{
    base::{
        Message, MessageBuilder, Ttl,
        iana::{Class, Opcode, Rcode, Rtype},
        name::ToLabelIter,
    },
    rdata::A,
};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read},
    net::Ipv4Addr,
};
const MAX_NAMES: usize = 4096;
const MAX_MESSAGE: usize = 4096;
const MAX_OUTPUT: usize = 65536;
const ADDRESS_BASE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
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
        let value = u32::from(ip) - u32::from(ADDRESS_BASE);
        self.names
            .get(value.checked_sub(1)? as usize)
            .map(String::as_str)
    }
    pub fn reply(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() > MAX_MESSAGE {
            return None;
        }
        let request = Message::from_slice(query).ok()?;
        if request.header().qr() {
            return None;
        }
        let mut reply = MessageBuilder::new_vec();
        reply.header_mut().set_id(request.header().id());
        reply.header_mut().set_opcode(request.header().opcode());
        reply.header_mut().set_qr(true);
        reply.header_mut().set_rd(request.header().rd());
        reply.header_mut().set_ra(true);
        if request.header().opcode() != Opcode::QUERY {
            reply.header_mut().set_rcode(Rcode::NOTIMP);
            return Some(reply.finish());
        }
        let question = request.sole_question().ok().filter(|question| {
            let name = question.qname();
            !name.is_root()
                && name.iter_labels().all(|label| {
                    label
                        .as_slice()
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
        });
        let Some(question) = question else {
            reply.header_mut().set_rcode(Rcode::FORMERR);
            return Some(reply.finish());
        };
        let mut reply = reply.question();
        reply.push(question).ok()?;
        let mut reply = reply.answer();
        let code = if question.qclass() != Class::IN {
            Rcode::NOTIMP
        } else {
            match question.qtype() {
                Rtype::A => match self.address(&question.qname().to_string()) {
                    Ok(address) => {
                        // Synthetic addresses are valid only within this USB session.
                        reply
                            .push((question.qname(), Ttl::ZERO, A::new(address)))
                            .ok()?;
                        Rcode::NOERROR
                    }
                    Err(code) => code,
                },
                // Do not advertise IPv6 or alternate connection hints outside the gateway.
                Rtype::AAAA | Rtype::SVCB | Rtype::HTTPS => Rcode::NOERROR,
                _ => Rcode::NOTIMP,
            }
        };
        reply.header_mut().set_rcode(code);
        Some(reply.finish())
    }

    fn address(&mut self, name: &str) -> Result<Ipv4Addr, Rcode> {
        let key = name.to_ascii_lowercase();
        if key == "localhost" || key == "wpad" || key.ends_with(".local") {
            return Err(Rcode::REFUSED);
        }
        if let Some(ip) = self.addresses.get(&key) {
            return Ok(*ip);
        }
        if self.names.len() == MAX_NAMES {
            return Err(Rcode::SERVFAIL);
        }
        let ip = Ipv4Addr::from(u32::from(ADDRESS_BASE) + self.names.len() as u32 + 1);
        self.names.push(key.clone());
        self.addresses.insert(key, ip);
        Ok(ip)
    }
}
pub(super) fn synthetic(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)
}

/// Per-connection DNS framing. The router owns and lends the shared name map.
#[derive(Default)]
pub(super) struct Tcp {
    input: BytesMut,
    output: VecDeque<u8>,
    closed: bool,
}
impl Tcp {
    pub fn shutdown_write(&mut self) {
        self.closed = true;
    }

    pub fn poll(&mut self, resolver: &mut Resolver) -> io::Result<()> {
        while self.input.len() >= 2 {
            let size = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
            if !(12..=MAX_MESSAGE).contains(&size) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self.input.len() < size + 2 {
                break;
            }
            // Leave complete queries buffered until their replies can be queued.
            // A slow reader must exert backpressure, not lose its DNS connection.
            if self.output.len() + MAX_MESSAGE + 2 > MAX_OUTPUT {
                return Ok(());
            }
            if let Some(reply) = resolver.reply(&self.input[2..size + 2]) {
                self.output.extend((reply.len() as u16).to_be_bytes());
                self.output.extend(reply);
            }
            self.input.advance(size + 2);
        }
        if self.closed && !self.input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS connection closed within a query",
            ));
        }
        Ok(())
    }

    pub fn write(&mut self, bytes: &[u8], resolver: &mut Resolver) -> io::Result<usize> {
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        self.poll(resolver)?;
        let n = bytes.len().min(MAX_MESSAGE + 2 - self.input.len());
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.input.extend_from_slice(&bytes[..n]);
        self.poll(resolver)?;
        Ok(n)
    }
}
impl Read for Tcp {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.output.is_empty() && (!self.closed || !self.input.is_empty()) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.output.read(out)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/usb_internet/dns.rs"]
mod tests;
