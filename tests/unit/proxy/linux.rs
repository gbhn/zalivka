use super::*;
use std::{path::Path, process::Command};

fn clean_environment(command: &mut Command, directory: &Path) {
    for variable in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "PX_CONFIG_ORDER",
    ] {
        command.env_remove(variable);
    }
    command
        .env("XDG_CONFIG_HOME", directory)
        .env("GSETTINGS_BACKEND", "keyfile");
}

#[test]
fn desktop_proxy_and_pac_use_native_libproxy() {
    if let Ok(case) = std::env::var("ZALIVKA_PROXY_CASE") {
        let routes = for_url(&"https://gs.apple.com/TSS/controller".parse().unwrap()).unwrap();
        if case.ends_with("pac") {
            assert_eq!(routes.len(), 3);
            assert_eq!(routes[0].as_ref().unwrap().host(), "one.example");
            assert_eq!(routes[0].as_ref().unwrap().port(), 3128);
            assert_eq!(routes[1].as_ref().unwrap().host(), "two.example");
            assert_eq!(routes[1].as_ref().unwrap().port(), 8080);
            assert_eq!(routes[2].as_ref().unwrap().host(), "socks.example");
            assert_eq!(routes[2].as_ref().unwrap().port(), 1080);
            assert_eq!(
                routes[2].as_ref().unwrap().protocol(),
                ureq::ProxyProtocol::Socks5h
            );
            let direct = for_url(&"https://direct.example/".parse().unwrap()).unwrap();
            assert!(matches!(direct.as_slice(), [None]));
        } else {
            assert_eq!(routes.len(), 1);
            assert_eq!(routes[0].as_ref().unwrap().host(), "proxy.example");
            assert_eq!(routes[0].as_ref().unwrap().port(), 3128);
        }
        let bypass = for_url(&"https://host.internal/".parse().unwrap()).unwrap();
        assert!(bypass.iter().all(Option::is_none));
        return;
    }
    for case in ["kde-manual", "kde-pac", "gnome-manual", "gnome-pac"] {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("proxy.pac");
        // Ubuntu 24.04's libproxy 0.5.4 drops DIRECT from mixed PAC lists.
        // Check proxy ordering and DIRECT-only decisions separately.
        std::fs::write(
            &script,
            r"function FindProxyForURL(url, host) {
                if (host === 'direct.example' || dnsDomainIs(host, '.internal')) return 'DIRECT';
                return 'PROXY one.example:3128; PROXY two.example:8080; SOCKS5 socks.example:1080';
            }",
        )
        .unwrap();
        let pac = format!("file://{}", script.display());
        if case.starts_with("kde") {
            std::fs::write(directory.path().join("kioslaverc"), format!("[Proxy Settings]\nProxyType={}\nhttpsProxy=http://proxy.example:3128\nNoProxyFor=*.internal\nProxy Config Script={pac}\n", if case.ends_with("pac") {2} else {1})).unwrap();
        } else {
            for (schema, key, value) in [
                (
                    "org.gnome.system.proxy",
                    "mode",
                    if case.ends_with("pac") {
                        "'auto'"
                    } else {
                        "'manual'"
                    },
                ),
                (
                    "org.gnome.system.proxy",
                    "autoconfig-url",
                    &format!("'{pac}'"),
                ),
                ("org.gnome.system.proxy", "ignore-hosts", "['*.internal']"),
                ("org.gnome.system.proxy.https", "host", "'proxy.example'"),
                ("org.gnome.system.proxy.https", "port", "3128"),
            ] {
                let mut command = Command::new("gsettings");
                clean_environment(&mut command, directory.path());
                let output = command.args(["set", schema, key, value]).output().unwrap();
                assert!(
                    output.status.success(),
                    "{case}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        clean_environment(&mut command, directory.path());
        command
            .env("ZALIVKA_PROXY_CASE", case)
            .env(
                "XDG_CURRENT_DESKTOP",
                if case.starts_with("kde") {
                    "KDE"
                } else {
                    "GNOME"
                },
            )
            .env(
                "PX_FORCE_CONFIG",
                if case.starts_with("kde") {
                    "config-kde"
                } else {
                    "config-gnome"
                },
            );
        let output = command
            .args([
                "proxy::linux::tests::desktop_proxy_and_pac_use_native_libproxy",
                "--exact",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "isolated DNS WPAD fixture; needs libnss_wrapper and a free local TCP port 80"]
fn wpad_discovers_and_downloads_the_pac_without_changing_system_dns() {
    if std::env::var_os("ZALIVKA_WPAD_CHILD").is_some() {
        let routes = crate::proxy::for_url(&"https://gs.apple.com/".parse().unwrap()).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].as_ref().unwrap().host(), "discovered.example");
        assert_eq!(routes[0].as_ref().unwrap().port(), 3128);
        assert!(routes[1].is_none());
        return;
    }
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };
    let wrapper =
        std::env::var("ZALIVKA_NSS_WRAPPER").expect("set ZALIVKA_NSS_WRAPPER to libnss_wrapper.so");
    let listener =
        TcpListener::bind("127.0.0.1:80").expect("WPAD fixture needs free local TCP port 80");
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "WPAD resolver did not fetch its script"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("WPAD accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 65536);
        }
        assert!(header.starts_with(b"GET /wpad.dat "));
        let script = "function FindProxyForURL(url, host) { return 'PROXY discovered.example:3128; DIRECT'; }";
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}", script.len()).unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let hosts = directory.path().join("hosts");
    std::fs::write(&hosts, "127.0.0.1 wpad\n").unwrap();
    for (key, value) in [("mode", "'auto'"), ("autoconfig-url", "''")] {
        let mut command = Command::new("gsettings");
        clean_environment(&mut command, directory.path());
        assert!(
            command
                .args(["set", "org.gnome.system.proxy", key, value])
                .status()
                .unwrap()
                .success()
        );
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    clean_environment(&mut command, directory.path());
    let output = command
        .env("ZALIVKA_WPAD_CHILD", "1")
        .env("XDG_CURRENT_DESKTOP", "GNOME")
        .env("PX_FORCE_CONFIG", "config-gnome")
        .env("LD_PRELOAD", wrapper)
        .env("NSS_WRAPPER_HOSTS", hosts)
        .args([
            "proxy::linux::tests::wpad_discovers_and_downloads_the_pac_without_changing_system_dns",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
}
