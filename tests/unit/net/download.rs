use super::*;

#[test]
fn verified_partial_is_published_without_replacing_another_file() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    let partial = directory.path().join("restore.ipsw.part");
    std::fs::write(&partial, b"firmware").unwrap();
    download_from(&destination, &Sha256::digest(b"firmware"), 0, |_| {
        panic!("verified partial needs no network")
    })
    .unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"firmware");
    assert!(!partial.exists());
    std::fs::remove_file(&destination).unwrap();
    let result = download_from(&destination, &Sha256::digest(b"firmware"), 0, |_| {
        std::fs::write(&destination, b"other file")?;
        Ok(Response::builder()
            .status(200)
            .header("Content-Length", "8")
            .body(ureq::Body::builder().data(b"firmware".to_vec()))?)
    });
    assert!(result.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"other file");
    assert_eq!(std::fs::read(&partial).unwrap(), b"firmware");
}

#[test]
fn interrupted_body_read_retries_without_an_http_retry_or_losing_bytes() {
    struct InterruptedOnce {
        interrupted: bool,
        input: std::io::Cursor<Vec<u8>>,
    }
    impl Read for InterruptedOnce {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.input.read(out)
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    let mut calls = 0;
    download_from(&destination, &Sha256::digest(b"abc"), 0, |offset| {
        calls += 1;
        assert_eq!(offset, 0);
        Ok(Response::builder()
            .status(200)
            .header("Content-Length", "3")
            .body(ureq::Body::builder().reader(InterruptedOnce {
                interrupted: false,
                input: std::io::Cursor::new(b"abc".to_vec()),
            }))?)
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(std::fs::read(destination).unwrap(), b"abc");
}

fn firmware_server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut requests = vec![];
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            requests.push(read_header(&mut stream).to_ascii_lowercase());
            stream.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (format!("http://{address}/firmware"), server)
}

fn test_download(url: &str, destination: &Path, expected: &[u8]) -> Result<()> {
    let agent = agent_with_body_timeout(None);
    // Production uses fetch(), which enforces Apple's HTTPS host allowlist.
    // These fixtures use the same downloader and request with a local server.
    download_from(destination, expected, 0, |offset| {
        send_http(&agent, &firmware_request(url, offset)?)
    })
}

#[test]
fn automatic_retry_survives_http_and_body_failures_in_one_invocation() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("retry.ipsw");
    let expected = Sha256::digest(b"firmware payload");
    let (url, server) = firmware_server(vec![
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nfirmware".into(),
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 8-15/16\r\nConnection: close\r\n\r\n payload".into(),
    ]);
    let agent = agent_with_body_timeout(None);
    download_from(&destination, &expected, 5, |offset| {
        send_http(&agent, &firmware_request(&url, offset)?)
    })
    .unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"firmware payload");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains("range: bytes=8-\r\n"));
    assert!(!retryable_download(&anyhow::anyhow!("checksum mismatch")));
    assert!(!retryable_download(&ureq::Error::StatusCode(403).into()));
}

#[test]
fn retry_budget_is_shared_by_http_errors_and_interrupted_bodies() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("retry.ipsw");
    let part = directory.path().join("retry.ipsw.part");
    std::fs::write(&part, b"firmware").unwrap();
    let (url, server) = firmware_server(vec![
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 8-15/16\r\nConnection: close\r\n\r\n pay".into(),
    ]);
    let agent = agent_with_body_timeout(None);
    let result = download_from(
        &destination,
        &Sha256::digest(b"firmware payload"),
        1,
        |offset| {
            let mut response = send_http(&agent, &firmware_request(&url, offset)?)?;
            if response.status() == StatusCode::SERVICE_UNAVAILABLE {
                // A transient status takes precedence over unusable body metadata.
                response
                    .headers_mut()
                    .insert("content-length", "invalid".parse()?);
            }
            Ok(response)
        },
    );
    assert!(result.is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(part).unwrap(), b"firmware pay");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.contains("range: bytes=8-\r\n")));
}

#[test]
fn firmware_download_resumes_after_disconnect_and_verifies_the_entire_file() {
    for expected in [
        sha1::Sha1::digest(b"firmware payload").to_vec(),
        Sha256::digest(b"firmware payload").to_vec(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        let part = directory.path().join("restore.ipsw.part");
        let (url, server) = firmware_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nfirmware".into(),
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 8\r\nContent-Range: bytes 8-15/16\r\nConnection: close\r\n\r\n payload".into(),
        ]);
        assert!(test_download(&url, &destination, &expected).is_err());
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&part).unwrap(), b"firmware");
        test_download(&url, &destination, &expected).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"firmware payload");
        assert!(!part.exists());
        let requests = server.join().unwrap();
        assert!(!requests[0].contains("range:"));
        assert!(requests[1].contains("range: bytes=8-\r\n"));
        assert!(
            requests
                .iter()
                .all(|r| r.contains("accept-encoding: identity\r\n"))
        );
        // Publication never replaces an existing user file.
        assert!(
            download_from(&destination, &expected, 0, |_| panic!("unexpected request")).is_err()
        );
    }
}

#[test]
fn firmware_resume_restarts_when_range_is_ignored_or_unsatisfiable() {
    for rejected in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        std::fs::write(directory.path().join("restore.ipsw.part"), b"stale prefix").unwrap();
        let mut responses = vec![];
        if rejected {
            responses.push("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into());
        } else {
            // Observed on an Apple distribution server: 200, original
            // Content-Length, but only the requested suffix in the body.
            responses
                .push("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nsh".into());
        }
        responses
            .push("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh".into());
        let (url, server) = firmware_server(responses);
        test_download(&url, &destination, &Sha256::digest(b"fresh")).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"fresh");
        let requests = server.join().unwrap();
        assert!(requests[0].contains("range: bytes=12-\r\n"));
        assert!(!requests[1].contains("range:"));
    }
}

#[test]
fn malformed_full_response_preserves_the_partial_download() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    let part = directory.path().join("restore.ipsw.part");
    std::fs::write(&part, b"stale prefix").unwrap();
    let (url, server) = firmware_server(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh".into(),
    ]);
    let agent = agent();
    let result = download_from(&destination, &Sha256::digest(b"fresh"), 0, |offset| {
        assert_eq!(offset, 12);
        let mut response = send_http(&agent, &firmware_request(&url, offset)?)?;
        response
            .headers_mut()
            .insert("content-length", "invalid".parse()?);
        Ok(response)
    });
    assert!(result.is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(part).unwrap(), b"stale prefix");
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn firmware_resume_handles_server_limited_ranges_without_skipping_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    std::fs::write(directory.path().join("restore.ipsw.part"), b"a").unwrap();
    let (url, server) = firmware_server(vec![
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/5\r\nConnection: close\r\n\r\nbc".into(),
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 3-4/5\r\nConnection: close\r\n\r\nde".into(),
    ]);
    test_download(&url, &destination, &Sha256::digest(b"abcde")).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"abcde");
    let requests = server.join().unwrap();
    assert!(requests[0].contains("range: bytes=1-\r\n"));
    assert!(requests[1].contains("range: bytes=3-\r\n"));
}

#[test]
fn firmware_resume_rejects_bad_ranges_and_resets_checksum_mismatches() {
    for range in [
        "bytes 0-2/3",
        "bytes 2-1/3",
        "bytes 1-3/3",
        "bytes 1-2/*",
        "items 1-2/3",
        "bytes 1-18446744073709551615/3",
        "bytes 1-1/3",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        let part = directory.path().join("restore.ipsw.part");
        std::fs::write(&part, b"a").unwrap();
        let (url, server) = firmware_server(vec![format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: {range}\r\nConnection: close\r\n\r\nbc"
        )]);
        assert!(
            test_download(&url, &destination, &Sha256::digest(b"abc")).is_err(),
            "{range}"
        );
        assert!(!destination.exists());
        assert_eq!(std::fs::read(&part).unwrap(), b"a");
        server.join().unwrap();
    }
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    let part = directory.path().join("restore.ipsw.part");
    std::fs::write(&part, b"x").unwrap();
    let (url, server) = firmware_server(vec!["HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/3\r\nConnection: close\r\n\r\nbc".into()]);
    assert!(
        test_download(&url, &destination, &Sha256::digest(b"abc"))
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch")
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::metadata(part).unwrap().len(), 0);
    server.join().unwrap();
}

#[test]
fn firmware_partial_is_locked_and_a_complete_partial_is_published_without_network() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    let part = directory.path().join("restore.ipsw.part");
    std::fs::write(&part, b"abc").unwrap();
    let lock = std::fs::File::options()
        .read(true)
        .write(true)
        .open(&part)
        .unwrap();
    lock.try_lock().unwrap();
    let hash = Sha256::digest(b"abc");
    assert!(
        download_from(&destination, &hash, 0, |_| panic!("locked file used"))
            .unwrap_err()
            .to_string()
            .contains("locked")
    );
    drop(lock);
    download_from(&destination, &hash, 0, |_| panic!("already complete")).unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"abc");
    assert!(!part.exists());
}

#[test]
fn firmware_body_streaming_is_not_limited_by_the_metadata_body_deadline() {
    for (limit, succeeds) in [(Some(Duration::from_millis(30)), false), (None, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_header(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\na")
                .unwrap();
            thread::sleep(Duration::from_millis(150));
            let _ = stream.write_all(b"b");
        });
        let request = Request::get(format!("http://{address}/firmware"))
            .body(Vec::new())
            .unwrap();
        let mut response = send_http(&agent_with_body_timeout(limit), &request).unwrap();
        let mut bytes = Vec::new();
        let result = response.body_mut().as_reader().read_to_end(&mut bytes);
        server.join().unwrap();
        assert_eq!(result.is_ok(), succeeds);
        if succeeds {
            assert_eq!(bytes, b"ab");
        }
    }
}

#[test]
fn encoded_responses_and_changing_range_totals_preserve_the_verified_prefix() {
    for encoding in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        let part = directory.path().join("restore.ipsw.part");
        std::fs::write(&part, b"a").unwrap();
        let responses = if encoding {
            vec!["HTTP/1.1 206 Partial Content\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/3\r\nConnection: close\r\n\r\nbc".into()]
        } else {
            vec![
                "HTTP/1.1 206 Partial Content\r\nContent-Length: 1\r\nContent-Range: bytes 1-1/4\r\nConnection: close\r\n\r\nb".into(),
                "HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 2-4/5\r\nConnection: close\r\n\r\ncde".into(),
            ]
        };
        let (url, server) = firmware_server(responses);
        let error = test_download(&url, &destination, &Sha256::digest(b"abcde")).unwrap_err();
        assert!(
            error.to_string().contains(if encoding {
                "Content-Encoding"
            } else {
                "total length changed"
            }),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&part).unwrap(),
            if encoding { b"a".as_slice() } else { b"ab" }
        );
        assert!(!destination.exists());
        server.join().unwrap();
    }
}
#[test]
fn repeated_resume_rejections_stop_instead_of_restarting_forever() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("restore.ipsw");
    std::fs::write(directory.path().join("restore.ipsw.part"), b"a").unwrap();
    let (url, server) = firmware_server(vec![
        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 1\r\nContent-Range: bytes 0-0/2\r\nConnection: close\r\n\r\na".into(),
        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    ]);
    let error = test_download(&url, &destination, &Sha256::digest(b"ab")).unwrap_err();
    assert!(
        error.to_string().contains("repeatedly rejected resume"),
        "{error:#}"
    );
    assert!(!destination.exists());
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn contradictory_full_response_metadata_preserves_partial_bytes() {
    for (header, value) in [("content-range", "bytes 1-2/3"), ("content-length", "+2")] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        let part = directory.path().join("restore.ipsw.part");
        std::fs::write(&part, b"a").unwrap();
        let (url, server) = firmware_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nbc".into(),
        ]);
        let result = download_from(&destination, &Sha256::digest(b"abc"), 0, |offset| {
            let mut response = send_http(&agent(), &firmware_request(&url, offset)?)?;
            response.headers_mut().insert(header, value.parse()?);
            Ok(response)
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(part).unwrap(), b"a");
        server.join().unwrap();
    }
}

#[test]
fn range_numbers_cannot_contain_signs() {
    for range in ["bytes +1-2/3", "bytes 1-+2/3", "bytes 1-2/+3"] {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("restore.ipsw");
        let part = directory.path().join("restore.ipsw.part");
        std::fs::write(&part, b"a").unwrap();
        let (url, server) = firmware_server(vec![format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: {range}\r\nConnection: close\r\n\r\nbc"
        )]);
        assert!(test_download(&url, &destination, &Sha256::digest(b"abc")).is_err());
        assert_eq!(std::fs::read(part).unwrap(), b"a");
        server.join().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn a_partial_symlink_cannot_truncate_an_unrelated_file() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    std::fs::write(&original, b"preserve me").unwrap();
    let destination = directory.path().join("restore.ipsw");
    std::os::unix::fs::symlink(&original, directory.path().join("restore.ipsw.part")).unwrap();
    assert!(
        download_from(&destination, &Sha256::digest(b"abc"), 0, |_| panic!(
            "symlink used"
        ))
        .is_err()
    );
    assert_eq!(std::fs::read(original).unwrap(), b"preserve me");
}
