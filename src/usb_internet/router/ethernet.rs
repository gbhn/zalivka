//! Bounded Ethernet queues and IPv4 replies for the temporary USB gateway.
use super::Flow;
use smoltcp::{
    phy::{self, DeviceCapabilities, Medium},
    time::Instant,
    wire::*,
};
use std::{collections::VecDeque, net::Ipv4Addr};

pub(super) const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 1);
pub(super) const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 2);
pub(super) const MAC: EthernetAddress = EthernetAddress([2, 0x5a, 0x41, 0x4c, 0x49, 1]);
pub(super) const MAX_QUEUE: usize = 256;
const MTU: usize = 1514;
const FRAGMENT_SIZE: usize = 1480;

#[derive(Default)]
pub(super) struct Ethernet {
    pub(super) input: VecDeque<Vec<u8>>,
    pub(super) output: VecDeque<Vec<u8>>,
}
pub(super) struct Rx(Vec<u8>);
pub(super) struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let r = f(&mut bytes);
        self.0.push_back(bytes);
        r
    }
}
impl phy::Device for Ethernet {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.output.len() >= MAX_QUEUE {
            return None;
        }
        let bytes = self.input.pop_front()?;
        Some((Rx(bytes), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        (self.output.len() < MAX_QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = MTU;
        c
    }
}
impl Ethernet {
    pub(super) fn reply_udp(&mut self, key: Flow, mac: EthernetAddress, bytes: &[u8]) {
        let frames = udp_reply(key, mac, bytes);
        if frames.len() <= MAX_QUEUE - self.output.len() {
            self.output.extend(frames);
        }
    }
}

pub(super) fn dhcp_reply(bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = DhcpPacket::new_checked(bytes).ok()?;
    let mut repr = DhcpRepr::parse(&packet).ok()?;
    if repr.server_identifier.is_some_and(|a| a != GATEWAY) {
        return None;
    }
    crate::log!(Debug, "dhcp", "DHCP: {:?}", repr.message_type);
    repr.message_type = match repr.message_type {
        DhcpMessageType::Discover => DhcpMessageType::Offer,
        DhcpMessageType::Request => {
            if repr.requested_ip.is_some_and(|a| a != CLIENT) {
                return None;
            }
            DhcpMessageType::Ack
        }
        _ => return None,
    };
    repr.your_ip = CLIENT;
    repr.server_ip = GATEWAY;
    repr.router = Some(GATEWAY);
    repr.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
    repr.server_identifier = Some(GATEWAY);
    repr.lease_duration = Some(120);
    repr.renew_duration = None;
    repr.rebind_duration = None;
    repr.requested_ip = None;
    repr.client_identifier = None;
    repr.parameter_request_list = None;
    repr.max_size = None;
    repr.additional_options = &[];
    // The Mac asks this local resolver; Windows owns all upstream resolution.
    let mut dns = repr.dns_servers.take().unwrap_or_default();
    dns.clear();
    let _ = dns.push(GATEWAY);
    repr.dns_servers = Some(dns);
    let mut out = vec![0; repr.buffer_len()];
    repr.emit(&mut DhcpPacket::new_unchecked(&mut out)).ok()?;
    Some(out)
}

pub(super) fn udp_reply(key: Flow, mac: EthernetAddress, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut datagram = vec![0; 8 + payload.len()];
    let mut udp = UdpPacket::new_unchecked(&mut datagram);
    udp.set_src_port(key.destination_port);
    udp.set_dst_port(key.source_port);
    udp.set_len((8 + payload.len()) as u16);
    udp.payload_mut().copy_from_slice(payload);
    udp.fill_checksum(&key.destination.into(), &key.source.into());
    let mut result = vec![];
    let ident = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    for (index, chunk) in datagram.chunks(FRAGMENT_SIZE).enumerate() {
        let mut bytes = vec![0; 14 + 20 + chunk.len()];
        let mut ether = EthernetFrame::new_unchecked(&mut bytes);
        ether.set_dst_addr(mac);
        ether.set_src_addr(MAC);
        ether.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ether.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len((20 + chunk.len()) as u16);
        ip.set_ident(ident);
        ip.set_more_frags((index + 1) * FRAGMENT_SIZE < datagram.len());
        ip.set_frag_offset((index * FRAGMENT_SIZE) as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(key.destination);
        ip.set_dst_addr(key.source);
        ip.payload_mut().copy_from_slice(chunk);
        ip.fill_checksum();
        result.push(bytes);
    }
    result
}
