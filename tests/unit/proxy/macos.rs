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

/// CFNetwork's proxy machinery shares process-wide state between run loop
/// sources, so proxy resolutions must not overlap. Cargo runs tests in
/// parallel, which would otherwise let them race.
fn pac_lock() -> std::sync::MutexGuard<'static, ()> {
    static PAC: std::sync::Mutex<()> = std::sync::Mutex::new(());
    PAC.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn system_manual_proxy_uses_connect_and_honors_exception_lists() {
    let _pac = pac_lock();
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
fn configured_pac_url_is_reported_as_an_autoconfiguration_route() {
    let _pac = pac_lock();
    // macOS 12 and later may upgrade a cleartext HTTP PAC URL to HTTPS while
    // loading it, so a loopback HTTP fixture cannot portably download the
    // script. The adjacent test evaluates a PAC script end to end; this covers
    // the other half the resolver owns: settings carrying a PAC URL must
    // surface as a PAC route for `resolve` to expand.
    let pac = "http://pac.example/proxy.pac";
    let settings = settings(&[
        ("ProxyAutoConfigEnable", CFNumber::from(1).as_CFType()),
        ("ProxyAutoConfigURLString", CFString::new(pac).as_CFType()),
    ]);
    let proxies = system_proxies(&url("https://gs.apple.com/").unwrap(), &settings).unwrap();
    let proxy = proxies
        .iter()
        .find(|proxy| {
            value(proxy, unsafe { kCFProxyTypeKey })
                .and_then(|value| value.downcast::<CFString>())
                .is_some_and(|kind| kind_is(&kind, unsafe { kCFProxyTypeAutoConfigurationURL }))
        })
        .expect("autoconfiguration route");
    let advertised = value(&proxy, unsafe { kCFProxyAutoConfigurationURLKey }).expect("PAC URL");
    let advertised = advertised
        .downcast::<CFURL>()
        .map(|url| url.get_string().to_string())
        .or_else(|| advertised.downcast::<CFString>().map(|url| url.to_string()))
        .expect("PAC URL");
    assert!(advertised.starts_with("http://pac.example"), "{advertised}");
    assert!(advertised.ends_with("/proxy.pac"), "{advertised}");
}

#[test]
fn native_pac_returns_ordered_proxies_and_explicit_direct_without_a_browser() {
    let _pac = pac_lock();
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
    let _pac = pac_lock();
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
