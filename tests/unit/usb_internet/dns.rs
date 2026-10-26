use super::*;
fn query(name: &str, kind: u16) -> Vec<u8> {
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
fn unsupported_questions_echo_the_name_type_and_class_without_allocating_addresses() {
    let mut dns = Resolver::default();
    for (kind, class) in [(15, 1), (u16::MAX, 1), (1, u16::MAX)] {
        let mut q = query("Mixed-Case.invalid", kind);
        let end = q.len();
        q[end - 2..].copy_from_slice(&class.to_be_bytes());
        q[2] = 0; // RD is unset; the reply must leave it unset too.
        q[3] = 0x20; // Never echo the request's AD bit as our own validation.
        let reply = dns.reply(&q).unwrap();
        assert_eq!(
            &reply[..12],
            &[0x12, 0x34, 0x80, 0x84, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&reply[12..], &q[12..]);
    }
    assert!(dns.names.is_empty());
    assert!(dns.addresses.is_empty());
}

#[test]
fn invalid_names_and_question_counts_return_format_errors_without_allocating_addresses() {
    let mut dns = Resolver::default();
    for name in ["bad label.invalid", "dots_in_label.invalid"] {
        let mut q = query(name, 1);
        if name.starts_with("dots") {
            // A literal dot inside one label must not become a hostname separator.
            q[17] = b'.';
            q[20] = b'.';
        }
        assert_eq!(dns.reply(&q).unwrap()[3] & 15, 1);
    }
    for count in [0u16, 2, u16::MAX] {
        let mut q = query("valid.invalid", 1);
        q[4..6].copy_from_slice(&count.to_be_bytes());
        let reply = dns.reply(&q).unwrap();
        assert_eq!(reply[3] & 15, 1);
        assert_eq!(&reply[4..12], &[0; 8]);
    }
    assert!(dns.names.is_empty());
}
#[test]
fn tcp_dns_handles_partial_and_pipelined_queries_and_half_close() {
    let mut resolver = Resolver::default();
    let mut tcp = Tcp::default();
    let q = query("x.invalid", 1);
    let mut bytes = (q.len() as u16).to_be_bytes().to_vec();
    bytes.extend(&q);
    bytes.extend(bytes.clone());
    for chunk in bytes.chunks(3) {
        assert_eq!(tcp.write(chunk, &mut resolver).unwrap(), chunk.len());
    }
    tcp.shutdown_write();
    let mut replies = vec![];
    tcp.read_to_end(&mut replies).unwrap();
    let n = u16::from_be_bytes([replies[0], replies[1]]) as usize;
    assert_eq!(replies.len(), 2 * (n + 2));
    assert_eq!(&replies[..n + 2], &replies[n + 2..]);
    assert_eq!(
        resolver.host(Ipv4Addr::new(198, 18, 0, 1)),
        Some("x.invalid")
    );
}

#[test]
fn empty_tcp_reads_succeed_without_consuming_pending_dns_replies() {
    let mut tcp = Tcp::default();
    let mut resolver = Resolver::default();
    assert_eq!(tcp.read(&mut []).unwrap(), 0);
    assert_eq!(
        tcp.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let q = query("x.invalid", 1);
    assert_eq!(
        tcp.write(&(q.len() as u16).to_be_bytes(), &mut resolver)
            .unwrap(),
        2
    );
    assert_eq!(tcp.write(&q, &mut resolver).unwrap(), q.len());
    assert_eq!(tcp.read(&mut []).unwrap(), 0);
    tcp.shutdown_write();
    let mut reply = Vec::new();
    tcp.read_to_end(&mut reply).unwrap();
    assert!(!reply.is_empty());
    assert_eq!(tcp.read(&mut []).unwrap(), 0);
}

#[test]
fn tcp_dns_applies_backpressure_and_drains_pipelined_queries_after_half_close() {
    let mut resolver = Resolver::default();
    let mut tcp = Tcp::default();
    let mut input = Vec::new();
    let count = 2048u16;
    for id in 0..count {
        let mut q = query("x.invalid", 1);
        q[..2].copy_from_slice(&id.to_be_bytes());
        input.extend((q.len() as u16).to_be_bytes());
        input.extend(q);
    }

    let mut written = 0;
    loop {
        match tcp.write(&input[written..], &mut resolver) {
            Ok(n) => {
                assert!(n > 0, "writes must make progress until backpressure");
                written += n;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("DNS write failed: {error}"),
        }
        assert!(
            written < input.len(),
            "the slow reader must fill the output queue"
        );
    }
    assert!(tcp.input.len() <= MAX_MESSAGE + 2);
    assert!(tcp.output.len() <= MAX_OUTPUT);

    let mut closed = false;
    let mut replies = Vec::new();
    let mut out = [0; 137];
    for _ in 0..10000 {
        tcp.poll(&mut resolver).unwrap();
        if written < input.len() {
            match tcp.write(&input[written..], &mut resolver) {
                Ok(n) => written += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("DNS write failed: {error}"),
            }
        } else if !closed {
            tcp.shutdown_write();
            closed = true;
        }
        match tcp.read(&mut out) {
            Ok(0) => break,
            Ok(n) => replies.extend_from_slice(&out[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("DNS read failed: {error}"),
        }
        assert!(tcp.input.len() <= MAX_MESSAGE + 2);
        assert!(tcp.output.len() <= MAX_OUTPUT);
    }
    assert!(closed);
    assert_eq!(written, input.len());
    let mut replies = replies.as_slice();
    for id in 0..count {
        let size = u16::from_be_bytes(replies[..2].try_into().unwrap()) as usize;
        let reply = &replies[2..2 + size];
        assert_eq!(u16::from_be_bytes(reply[..2].try_into().unwrap()), id);
        assert_eq!(&reply[6..8], &[0, 1]);
        assert_eq!(&reply[reply.len() - 4..], &[198, 18, 0, 1]);
        replies = &replies[2 + size..];
    }
    assert!(replies.is_empty());
    assert_eq!(tcp.read(&mut out).unwrap(), 0);
}

#[test]
fn tcp_dns_rejects_invalid_lengths_and_truncated_queries_at_eof() {
    for size in [0u16, 11, MAX_MESSAGE as u16 + 1, u16::MAX] {
        let mut resolver = Resolver::default();
        let error = Tcp::default()
            .write(&size.to_be_bytes(), &mut resolver)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let q = query("x.invalid", 1);
    let mut input = (q.len() as u16).to_be_bytes().to_vec();
    input.extend(q);
    for end in 1..input.len() {
        let mut resolver = Resolver::default();
        let mut tcp = Tcp::default();
        assert_eq!(tcp.write(&input[..end], &mut resolver).unwrap(), end);
        tcp.shutdown_write();
        assert_eq!(
            tcp.poll(&mut resolver).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[test]
fn unsupported_dns_opcodes_are_echoed_in_the_error_response() {
    let mut resolver = Resolver::default();
    for opcode in [1u8, 2, 4, 5] {
        let mut request = query("x.invalid", 1);
        request[2] |= opcode << 3;
        let response = resolver.reply(&request).unwrap();
        assert_eq!((response[2] >> 3) & 15, opcode);
        assert_eq!(response[3] & 15, u8::from(Rcode::NOTIMP));
        assert!(resolver.names.is_empty());
    }
}
