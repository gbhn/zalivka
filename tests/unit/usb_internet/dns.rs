use super::*;
pub(super) fn query(name: &str, kind: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend(l.bytes());
    }
    q.push(0);
    q.extend(kind.to_be_bytes());
    q.extend([0, 1]);
    q
}
#[test]
fn names_are_stable_distinct_bounded_and_do_not_resolve_on_the_client() {
    let mut dns = Resolver::default();
    let first = dns.reply(&query("Does-Not-Resolve.Invalid", 1)).unwrap();
    assert_eq!(
        &first[..12],
        &[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(&first[first.len() - 4..], &[198, 18, 0, 1]);
    let lower = dns.reply(&query("does-not-resolve.invalid", 1)).unwrap();
    assert_eq!(&lower[lower.len() - 4..], &first[first.len() - 4..]);
    assert!(first.windows(16).any(|bytes| bytes == b"Does-Not-Resolve"));
    assert_eq!(
        dns.host(Ipv4Addr::new(198, 18, 0, 1)),
        Some("does-not-resolve.invalid")
    );
    assert_eq!(dns.host(Ipv4Addr::new(198, 18, 0, 2)), None);
    for n in 1..MAX_NAMES {
        assert_eq!(
            dns.reply(&query(&format!("n{n}.invalid"), 1)).unwrap()[3] & 15,
            0
        );
    }
    assert_eq!(dns.reply(&query("overflow.invalid", 1)).unwrap()[3] & 15, 2);
    assert_eq!(
        dns.host(Ipv4Addr::new(198, 18, 0, 1)),
        Some("does-not-resolve.invalid")
    );
    for kind in [28, 64, 65] {
        let r = dns.reply(&query("x.invalid", kind)).unwrap();
        assert_eq!(&r[6..8], &[0, 0]);
        assert_eq!(r[3] & 15, 0);
    }
}
#[test]
fn truncated_and_cyclic_questions_are_bounded() {
    let mut dns = Resolver::default();
    let q = query("x.invalid", 1);
    for end in 0..q.len() {
        let _ = dns.reply(&q[..end]);
    }
    let mut cycle = q[..12].to_vec();
    cycle.extend([0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(dns.reply(&cycle).unwrap()[3] & 15, 1);
    for name in ["localhost", "wpad", "service.local"] {
        assert_eq!(dns.reply(&query(name, 1)).unwrap()[3] & 15, 5);
    }
}
#[test]
fn tcp_dns_handles_partial_and_pipelined_queries_and_half_close() {
    let resolver = Arc::new(Mutex::new(Resolver::default()));
    let mut tcp = Tcp::new(resolver.clone());
    let q = query("x.invalid", 1);
    let mut bytes = (q.len() as u16).to_be_bytes().to_vec();
    bytes.extend(&q);
    bytes.extend(bytes.clone());
    for chunk in bytes.chunks(3) {
        tcp.write_all(chunk).unwrap();
    }
    tcp.shutdown_write();
    let mut replies = vec![];
    tcp.read_to_end(&mut replies).unwrap();
    let n = u16::from_be_bytes([replies[0], replies[1]]) as usize;
    assert_eq!(replies.len(), 2 * (n + 2));
    assert_eq!(&replies[..n + 2], &replies[n + 2..]);
    assert_eq!(
        resolver.lock().unwrap().host(Ipv4Addr::new(198, 18, 0, 1)),
        Some("x.invalid")
    );
}
