use super::*;

#[test]
fn get_and_post_forward_headers_binary_body_and_http_error_responses() {
    for (method, status, serialized) in [
        ("GET", 403, 0),
        ("POST", 500, 0),
        ("GET", 403, 1),
        ("POST", 500, 1),
        ("POST", 500, 2),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let headers = read_header(&mut stream).to_ascii_lowercase();
            assert!(
                headers.starts_with(&format!("{} /asset http/1.1", method.to_ascii_lowercase()))
            );
            assert!(headers.contains("range: bytes=0-3\r\n"));
            let length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(
                body,
                if method == "POST" {
                    &[0, 1, 2, 255][..]
                } else {
                    &[]
                }
            );
            write!(stream, "HTTP/1.1 {status} Error\r\nContent-Length: 6\r\nX-Fixture: yes\r\nConnection: close\r\n\r\ndenied").unwrap();
        });
        let mut args = wire::dict([
            ("RequestMethod", method.into()),
            ("RequestURL", "https://gs.apple.com/asset".into()),
            (
                "RequestAdditionalHeaders",
                wire::dict([("Range", "bytes=0-3".into())]),
            ),
            ("RequestBody", Value::Data(vec![0, 1, 2, 255])),
        ]);
        if serialized != 0 {
            let body = if method == "POST" {
                &[0, 1, 2, 255][..]
            } else {
                &[]
            };
            let framing = if serialized == 2 {
                "Transfer-Encoding: chunked".to_owned()
            } else {
                format!("Content-Length: {}", body.len())
            };
            let mut raw = format!("{method} https://gs.apple.com/asset HTTP/1.1\r\nHost: gs.apple.com\r\nRange: bytes=0-3\r\n{framing}\r\n\r\n").into_bytes();
            if serialized == 2 {
                raw.extend_from_slice(
                    b"2;part=first\r\n\0\x01\r\n2\r\n\x02\xff\r\n0\r\nX-Fixture: trailer\r\n\r\n",
                );
            } else {
                raw.extend_from_slice(body);
            }
            args = wire::dict([("SerializedRequest", Value::Data(raw))]);
        }
        let mut request = asset_request(&args).unwrap();
        // Only this test rewrites the validated URL to its local fixture.
        *request.uri_mut() = format!("http://{address}/asset").parse().unwrap();
        let reply = asset_reply(send_http(&agent(), &request).unwrap(), false).unwrap();
        server.join().unwrap();
        assert_eq!(
            wire::number(wire::get(&reply, &["ResponseStatus"]).unwrap()).unwrap(),
            status
        );
        assert_eq!(
            wire::get(&reply, &["ResponseBody"])
                .unwrap()
                .as_data()
                .unwrap(),
            b"denied"
        );
        assert!(wire::boolean(&reply, &["ResponseBodyDone"]));
        assert_eq!(
            wire::string(&reply, &["ResponseHeaders", "x-fixture"]).unwrap(),
            "yes"
        );
    }
}

#[test]
fn wkms_authorization_is_host_scoped_and_preserves_explicit_device_credentials() {
    let mut tokens = tempfile::NamedTempFile::new().unwrap();
    wire::dict([("WKMS.SD.APPLE.COM", "host-token".into())])
        .to_writer_binary(&mut tokens)
        .unwrap();
    let mut data = tempfile::NamedTempFile::new().unwrap();
    data.write_all(b"DAWTKN-fixture").unwrap();
    let client = AssetClient::from_files(Some(tokens.path()), Some(data.path())).unwrap();
    for (host, wrapped, expected) in [
        ("wkms.sd.apple.com", true, Some("Bearer host-token")),
        ("wkms.other.apple.com", true, Some("Bearer DAWTKN-fixture")),
        ("gs.apple.com", true, None),
        ("wkms.sd.apple.com", false, None),
    ] {
        let mut request = Request::post(format!("https://{host}/key"))
            .body(vec![1])
            .unwrap();
        client.clone().authorize(&mut request, wrapped).unwrap();
        let header = request.headers().get("authorization");
        assert_eq!(header.map(|h| h.to_str().unwrap()), expected);
        if let Some(header) = header {
            assert!(header.is_sensitive());
            assert!(!format!("{header:?}").contains("token"));
        }
    }
    let mut request = Request::post("https://wkms.sd.apple.com/key")
        .header("authorization", "Bearer device-token")
        .body(vec![])
        .unwrap();
    client.authorize(&mut request, true).unwrap();
    assert_eq!(request.headers()["authorization"], "Bearer device-token");
    redirect_request(
        &mut request,
        StatusCode::TEMPORARY_REDIRECT,
        "https://other.apple.com/key",
    )
    .unwrap();
    assert!(!request.headers().contains_key("authorization"));
    request = Request::post("https://evil.example/key")
        .body(vec![])
        .unwrap();
    assert!(client.authorize(&mut request, true).is_err());
}

#[test]
fn wkms_sends_imported_authorization_with_the_original_binary_post() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let headers = read_header(&mut stream).to_ascii_lowercase();
        assert!(headers.starts_with("post /key http/1.1\r\n"));
        assert!(headers.contains("authorization: bearer fixture-token\r\n"));
        assert!(headers.contains("content-length: 4\r\n"));
        let mut body = [0; 4];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(body, [0, 255, 1, 2]);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n\0\xff\x03",
            )
            .unwrap();
    });
    let mut tokens = tempfile::NamedTempFile::new().unwrap();
    wire::dict([("wkms.sd.apple.com", "fixture-token".into())])
        .to_writer_xml(&mut tokens)
        .unwrap();
    let client = AssetClient::from_files(Some(tokens.path()), None).unwrap();
    let mut request = asset_request(&wire::dict([
        ("RequestURL", "https://wkms.sd.apple.com/key".into()),
        ("RequestMethod", "POST".into()),
        ("RequestBody", Value::Data(vec![0, 255, 1, 2])),
    ]))
    .unwrap();
    client.authorize(&mut request, true).unwrap();
    // Only this test routes a validated Apple request to a local fixture.
    *request.uri_mut() = format!("http://{address}/key").parse().unwrap();
    let response = asset_reply(send_http(&agent(), &request).unwrap(), true).unwrap();
    server.join().unwrap();
    assert_eq!(
        wire::get(&response, &["KeyData"]).unwrap().as_data(),
        Some(&[0, 255, 3][..])
    );
    assert_eq!(wire::string(&response, &["KeySource"]).unwrap(), "Remote");
}

#[test]
fn invalid_authorization_files_fail_without_exposing_token_contents() {
    for value in [
        wire::dict([("evil.example", "secret-token".into())]),
        wire::dict([("wkms.sd.apple.com/path", "secret-token".into())]),
        wire::dict([("wkms.sd.apple.com", "secret-token\r\nInjected: yes".into())]),
        wire::dict([("wkms.sd.apple.com", false.into())]),
        wire::dict([
            ("wkms.sd.apple.com", "first-secret-token".into()),
            ("WKMS.SD.APPLE.COM", "second-secret-token".into()),
        ]),
    ] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        value.to_writer_xml(&mut file).unwrap();
        let error = AssetClient::from_files(Some(file.path()), None)
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("secret-token"));
    }
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"not-an-AppleConnect-token").unwrap();
    assert!(AssetClient::from_files(None, Some(file.path())).is_err());
    file.as_file_mut().set_len(1024 * 1024 + 1).unwrap();
    assert!(AssetClient::from_files(Some(file.path()), None).is_err());
}

#[test]
fn wkms_contract_is_selected_by_the_device_request() {
    for envelope in [
        "DataRequestMsg",
        "AsyncDataRequestMsg",
        "StreamedImageDecryptionKey",
    ] {
        let mut message = wire::dict([
            ("MsgType", envelope.into()),
            ("DataType", "StreamedImageDecryptionKey".into()),
            (
                "Arguments",
                wire::dict([
                    ("ArchiveIdentifier", "ab".repeat(48).into()),
                    ("RequestMethod", "POST".into()),
                ]),
            ),
        ]);
        let mut frame = Vec::new();
        wire::send_binary(&mut frame, &message).unwrap();
        let decoded = wire::receive(&mut std::io::Cursor::new(frame)).unwrap();
        assert!(wrapped_key_request(&decoded).unwrap());

        message.as_dictionary_mut().unwrap().remove("DataType");
        if envelope == "StreamedImageDecryptionKey" {
            assert!(wrapped_key_request(&message).unwrap());
        }
    }
    let mut message = wire::dict([
        ("DataType", "StreamedImageDecryptionKey".into()),
        ("Arguments", wire::dict([("RequestMethod", "POST".into())])),
    ]);
    assert!(!wrapped_key_request(&message).unwrap());
    for id in [Value::Data(vec![1; 48]), "".into(), false.into()] {
        message.as_dictionary_mut().unwrap().insert(
            "Arguments".into(),
            wire::dict([("ArchiveIdentifier", id), ("RequestMethod", "POST".into())]),
        );
        assert!(wrapped_key_request(&message).is_err());
    }
    message.as_dictionary_mut().unwrap().insert(
        "Arguments".into(),
        wire::dict([
            ("ArchiveIdentifier", "ab".repeat(48).into()),
            ("RequestMethod", "GET".into()),
        ]),
    );
    assert!(wrapped_key_request(&message).is_err());
    message
        .as_dictionary_mut()
        .unwrap()
        .insert("DataType".into(), "URLAsset".into());
    assert!(!wrapped_key_request(&message).unwrap());
}

#[test]
fn wkms_forwards_opaque_wrapped_key_and_rejects_http_errors_and_empty_keys() {
    for (status, body) in [
        (200, &b"\0opaque-wrapped-key\xff"[..]),
        (503, &b"denied"[..]),
        (200, &b""[..]),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            read_header(&mut stream);
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 1, 2, 255]);
            write!(
                stream,
                "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let mut request = asset_request(&wire::dict([
            ("RequestMethod", "POST".into()),
            ("RequestURL", "https://wkms.sd.apple.com/key".into()),
            ("RequestBody", Value::Data(vec![0, 1, 2, 255])),
        ]))
        .unwrap();
        *request.uri_mut() = format!("http://{address}/key").parse().unwrap();
        let reply = asset_reply(send_http(&agent(), &request).unwrap(), true);
        server.join().unwrap();
        if status != 200 || body.is_empty() {
            assert!(reply.is_err());
            continue;
        }
        let reply = reply.unwrap();
        let mut frame = Vec::new();
        wire::send_binary(&mut frame, &reply).unwrap();
        let reply = wire::receive(&mut std::io::Cursor::new(frame)).unwrap();
        assert_eq!(
            wire::get(&reply, &["KeyData"]).unwrap().as_data().unwrap(),
            body
        );
        assert_eq!(wire::string(&reply, &["KeySource"]).unwrap(), "Remote");
        assert_eq!(wire::dictionary(&reply).unwrap().len(), 2);
    }
}
