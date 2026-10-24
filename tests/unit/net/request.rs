use super::*;

#[test]
fn serialized_connection_headers_never_reach_the_origin() {
    let request = serialized_asset_request(
        b"POST /key HTTP/1.1\r\nHost: gs.apple.com\r\nContent-Length: 3\r\nConnection: keep-alive, X-Private\r\nConnection: X-Other\r\nX-Private: first\r\nX-Other: second\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: secret\r\nUpgrade: h2c\r\nTE: trailers\r\nContent-Type: application/octet-stream\r\nAuthorization: Bearer fixture\r\n\r\nabc"
    ).unwrap();
    assert_eq!(request.body(), b"abc");
    assert_eq!(request.headers().len(), 2);
    assert_eq!(
        request.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(request.headers()["authorization"], "Bearer fixture");
    for value in ["", "x-private,", "invalid name"] {
        let raw = format!("GET /key HTTP/1.1\r\nHost: gs.apple.com\r\nConnection: {value}\r\n\r\n");
        assert!(serialized_asset_request(raw.as_bytes()).is_err());
    }
}

#[test]
fn asset_requests_bound_headers_and_preserve_the_plist_get_contract() {
    let direct = |method: &str, body: Vec<u8>| {
        wire::dict([
            ("RequestURL", "https://gs.apple.com/key".into()),
            ("RequestMethod", method.into()),
            ("RequestBody", Value::Data(body)),
        ])
    };
    assert!(
        asset_request(&direct("GET", vec![1]))
            .unwrap()
            .body()
            .is_empty()
    );
    assert!(asset_request(&direct("DELETE", vec![1])).is_err());
    for method in ["GET", "DELETE"] {
        let raw =
            format!("{method} /key HTTP/1.1\r\nHost: gs.apple.com\r\nContent-Length: 1\r\n\r\nx");
        assert!(serialized_asset_request(raw.as_bytes()).is_err());
    }
    let mut args = direct("POST", vec![1]);
    args.as_dictionary_mut().unwrap().insert(
        "RequestURL".into(),
        "https://gs.apple.com/key#fragment".into(),
    );
    assert!(asset_request(&args).is_err());
    args.as_dictionary_mut()
        .unwrap()
        .insert("RequestURL".into(), "https://gs.apple.com/key".into());
    args.as_dictionary_mut().unwrap().insert(
        "RequestAdditionalHeaders".into(),
        wire::dict([("X-Large", "a".repeat(65536).into())]),
    );
    assert!(asset_request(&args).is_err());
    for name in [
        "Keep-Alive",
        "Proxy-Connection",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Upgrade",
    ] {
        args.as_dictionary_mut().unwrap().insert(
            "RequestAdditionalHeaders".into(),
            wire::dict([(name, "value".into())]),
        );
        assert!(asset_request(&args).is_err(), "{name}");
    }
}

#[test]
fn serialized_assets_support_origin_form_and_absolute_urls_with_binary_bodies() {
    let request = asset_request(&wire::dict([(
        "SerializedRequest",
        Value::Data(
            b"GET /key?a=%2F HTTP/1.1\r\nHost: WKMS.SD.APPLE.COM:443\r\nRange: bytes=0-4\r\n\r\n"
                .to_vec(),
        ),
    )]))
    .unwrap();
    assert_eq!(
        request.uri().to_string(),
        "https://WKMS.SD.APPLE.COM:443/key?a=%2F"
    );
    assert_eq!(request.headers()["range"], "bytes=0-4");
    assert!(!request.headers().contains_key("host"));
    assert!(request.body().is_empty());

    let args = wire::dict([
        ("SerializedRequest", Value::Data(b"POST https://wkms.sd.apple.com/key HTTP/1.0\r\nContent-Length: 3\r\nContent-Type: application/octet-stream\r\n\r\n\0\xff\x01".to_vec())),
        ("RequestURL", "https://invalid.example/ignored".into()),
    ]);
    let request = asset_request(&args).unwrap();
    assert_eq!(request.uri().to_string(), "https://wkms.sd.apple.com/key");
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.body(), &[0, 255, 1]);
    assert_eq!(
        request.headers()["content-type"],
        "application/octet-stream"
    );
    assert!(!request.headers().contains_key("content-length"));
}

#[test]
fn serialized_assets_reject_ambiguous_framing_and_non_apple_destinations() {
    for raw in [
        "GET /key HTTP/1.1\r\n\r\n",
        "GET /key HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "GET https://wkms.sd.apple.com/key HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "GET https://wkms.sd.apple.com/key HTTP/1.1\r\nHost: user@wkms.sd.apple.com\r\n\r\n",
        "GET https://wkms.sd.apple.com/key HTTP/1.1\r\nHost: wkms.sd.apple.com:other\r\n\r\n",
        "GET /key HTTP/1.1\r\nHost: wkms.sd.apple.com\r\nHost: wkms.sd.apple.com\r\n\r\n",
        "POST https://wkms.sd.apple.com/key HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
        "POST https://wkms.sd.apple.com/key HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc",
        "GET http://wkms.sd.apple.com/key HTTP/1.1\r\n\r\n",
        "GET https://wkms.sd.apple.com:other/key HTTP/1.1\r\n\r\n",
        "GET https://wkms.sd.apple.com:999999/key HTTP/1.1\r\n\r\n",
        "GET https://wkms.sd.apple.com/key#fragment HTTP/1.1\r\n\r\n",
        "DELETE https://wkms.sd.apple.com/key HTTP/1.1\r\n\r\n",
        "GET  /key HTTP/1.1\r\nHost: wkms.sd.apple.com\r\n\r\n",
        "GET /key HTTP/1.1 extra\r\nHost: wkms.sd.apple.com\r\n\r\n",
        "GET /key HTTP/1.1 \r\nHost: wkms.sd.apple.com\r\n\r\n",
        "GET /key\r\nHost: wkms.sd.apple.com\r\n\r\n",
        "GET https://wkms.sd.apple.com/key HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
        "GET https://wkms.sd.apple.com/key HTTP/1.1\r\n invalid: folded\r\n\r\n",
    ] {
        assert!(serialized_asset_request(raw.as_bytes()).is_err(), "{raw:?}");
    }
    assert!(serialized_asset_request(&vec![b'x'; 65537]).is_err());
    let mut oversized = b"POST https://wkms.sd.apple.com/key HTTP/1.1\r\n\r\n".to_vec();
    oversized.resize(oversized.len() + 16 * 1024 * 1024 + 1, 0);
    assert!(serialized_asset_request(&oversized).is_err());
    assert!(asset_request(&wire::dict([("SerializedRequest", "not data".into())])).is_err());
}

#[test]
fn asset_requests_preserve_repeated_header_values_and_the_binary_body() {
    let direct = wire::dict([
        (
            "RequestURL",
            "https://wkms.sd.apple.com/key?value=%2F".into(),
        ),
        ("RequestMethod", "POST".into()),
        ("RequestBody", Value::Data(vec![0, 255, 1])),
        (
            "RequestAdditionalHeaders",
            wire::dict([
                ("X-Fixture", "first".into()),
                ("x-fixture", "second".into()),
            ]),
        ),
    ]);
    let serialized = wire::dict([("SerializedRequest", Value::Data(
        b"POST /key?value=%2F HTTP/1.1\r\nHost: wkms.sd.apple.com\r\nContent-Length: 3\r\nX-Fixture: first\r\nx-fixture: second\r\n\r\n\0\xff\x01".to_vec(),
    ))]);
    for args in [direct, serialized] {
        let request = asset_request(&args).unwrap();
        assert_eq!(request.uri(), "https://wkms.sd.apple.com/key?value=%2F");
        assert_eq!(request.body(), &[0, 255, 1]);
        let values: Vec<_> = request
            .headers()
            .get_all("x-fixture")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["first", "second"]);
        assert!(!request.headers().contains_key("content-length"));
        assert!(!request.headers().contains_key("host"));
    }
}

#[test]
fn chunked_serialized_requests_decode_binary_data_extensions_and_trailers() {
    let raw = b"POST /key HTTP/1.1\r\nHost: wkms.sd.apple.com\r\nTransfer-Encoding: Chunked\r\nTrailer: X-Checksum\r\n\r\n2;tag=\"a;\\\"b\";flag\r\n\0\xff\r\n3\r\nabc\r\n0;done=yes\r\nX-Checksum: fixture\r\n\r\n";
    let request = serialized_asset_request(raw).unwrap();
    assert_eq!(request.body(), b"\0\xffabc");
    for name in [
        "transfer-encoding",
        "content-length",
        "trailer",
        "x-checksum",
    ] {
        assert!(!request.headers().contains_key(name));
    }
    assert!(decode_http_chunks(b"0\r\n\r\n").unwrap().is_empty());
    assert_eq!(
        decode_http_chunks(b"A\r\n0123456789\r\n0\r\n\r\n").unwrap(),
        b"0123456789"
    );
    let mut boundary = b"1000000\r\n".to_vec();
    boundary.resize(boundary.len() + 16 * 1024 * 1024, 1);
    boundary.extend_from_slice(b"\r\n0\r\n\r\n");
    assert_eq!(
        decode_http_chunks(&boundary).unwrap().len(),
        16 * 1024 * 1024
    );
}

#[test]
fn chunked_requests_reject_truncation_overflow_and_conflicting_framing() {
    for bytes in [
        &b""[..],
        b"1\r\nx",
        b"1\r\nx\n0\r\n\r\n",
        b"0\r\n",
        b"0\r\n\r\nextra",
        b"ffffffffffffffffffffffffffffffff\r\n",
        b"1000001\r\n",
        b"+1\r\nx\r\n0\r\n\r\n",
        b"1;\r\nx\r\n0\r\n\r\n",
        b"1;foo=\r\nx\r\n0\r\n\r\n",
        b"1;foo=\"unterminated\r\nx\r\n0\r\n\r\n",
        b"1\n;foo=bar\r\nx\r\n0\r\n\r\n",
        b"0\r\nHost: other.apple.com\r\n\r\n",
        b"0\r\nAuthorization: secret\r\n\r\n",
        b"0\r\nContent-Length: 0\r\n\r\n",
        b"0\r\n malformed\r\n\r\n",
    ] {
        assert!(decode_http_chunks(bytes).is_err(), "{bytes:?}");
    }
    for headers in [
        "Transfer-Encoding: chunked\r\nContent-Length: 0",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip, chunked",
    ] {
        let raw =
            format!("POST https://wkms.sd.apple.com/key HTTP/1.1\r\n{headers}\r\n\r\n0\r\n\r\n");
        assert!(serialized_asset_request(raw.as_bytes()).is_err());
    }
    assert!(serialized_asset_request(b"POST https://wkms.sd.apple.com/key HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err());
}

#[test]
fn asset_requests_reject_invalid_headers_for_both_methods() {
    for method in ["GET", "POST"] {
        for name in [
            "Host",
            "Connection",
            "Content-Length",
            "TRANSFER-ENCODING",
            "invalid name",
        ] {
            let args = wire::dict([
                ("RequestMethod", method.into()),
                ("RequestURL", "https://gs.apple.com/key".into()),
                ("RequestBody", Value::Data(vec![1])),
                (
                    "RequestAdditionalHeaders",
                    wire::dict([(name, "value".into())]),
                ),
            ]);
            assert!(asset_request(&args).is_err(), "{method}: {name}");
        }
    }
}
