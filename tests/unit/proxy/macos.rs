use super::*;
use core_foundation::{boolean::CFBoolean, number::CFNumber};

fn settings(items: &[(&str, CFType)]) -> Dictionary {
    Dictionary::from_CFType_pairs(
        &items
            .iter()
            .map(|(key, value)| (CFString::new(key), value.clone()))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn system_manual_proxy_uses_connect_and_honors_exception_lists() {
    let settings = settings(&[
        ("HTTPSEnable", CFNumber::from(1).as_CFType()),
        ("HTTPSProxy", CFString::new("proxy.example").as_CFType()),
        ("HTTPSPort", CFNumber::from(3128).as_CFType()),
        (
            "ExceptionsList",
            CFArray::from_CFTypes(&[CFString::new("*.internal")]).as_CFType(),
        ),
        (
            "ExcludeSimpleHostnames",
            CFBoolean::true_value().as_CFType(),
        ),
    ]);
    let routes = proxies_for_settings(&url("https://gs.apple.com/").unwrap(), &settings).unwrap();
    assert_eq!(routes.len(), 1);
    let proxy = routes[0].as_ref().unwrap();
    assert_eq!(proxy.host(), "proxy.example");
    assert_eq!(proxy.port(), 3128);
    assert_eq!(proxy.protocol(), ProxyProtocol::Http);
    for host in ["host.internal", "intranet"] {
        assert!(bypassed(&settings, &url(&format!("https://{host}/")).unwrap()).unwrap());
        let routes =
            proxies_for_settings(&url(&format!("https://{host}/")).unwrap(), &settings).unwrap();
        assert!(routes.iter().all(Option::is_none));
    }
    assert!(!bypassed(&settings, &url("https://gs.apple.com/").unwrap()).unwrap());
}

#[test]
fn configured_pac_url_is_fetched_and_evaluated_by_cfnetwork() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 65536);
        }
        assert!(request.starts_with(b"GET /proxy.pac "));
        let script =
            "function FindProxyForURL(url, host) { return 'PROXY pac.example:8080; DIRECT'; }";
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}", script.len()).unwrap();
    });
    let settings = settings(&[
        ("ProxyAutoConfigEnable", CFNumber::from(1).as_CFType()),
        (
            "ProxyAutoConfigURLString",
            CFString::new(&format!("http://{address}/proxy.pac")).as_CFType(),
        ),
    ]);
    let routes = proxies_for_settings(&url("https://gs.apple.com/").unwrap(), &settings).unwrap();
    assert_eq!(routes[0].as_ref().unwrap().host(), "pac.example");
    assert!(routes[1].is_none());
    server.join().unwrap();
}

#[test]
fn native_pac_returns_ordered_proxies_and_explicit_direct_without_a_browser() {
    let script = CFString::new(
        "function FindProxyForURL(url, host) { return 'PROXY one.example:3128; PROXY two.example:8080; DIRECT'; }",
    );
    let target = url("https://gs.apple.com/").unwrap();
    let result = execute_pac(|callback, context| unsafe {
        CFNetworkExecuteProxyAutoConfigurationScript(
            script.as_concrete_TypeRef(),
            target.as_concrete_TypeRef(),
            callback,
            context,
        )
    })
    .unwrap();
    let routes = resolve(&result, &target, 0).unwrap();
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].as_ref().unwrap().host(), "one.example");
    assert_eq!(routes[1].as_ref().unwrap().host(), "two.example");
    assert!(routes[2].is_none());
}

#[test]
fn invalid_native_pac_is_an_error_and_does_not_become_direct() {
    let script = CFString::new("this is invalid javascript {{{");
    let target = url("https://gs.apple.com/").unwrap();
    let result = execute_pac(|callback, context| unsafe {
        CFNetworkExecuteProxyAutoConfigurationScript(
            script.as_concrete_TypeRef(),
            target.as_concrete_TypeRef(),
            callback,
            context,
        )
    });
    assert!(result.is_err());
}
