//! System proxy exceptions, PAC and automatic discovery through CFNetwork.
use anyhow::{Context, Result, bail, ensure};
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{CFIndex, CFType, TCFType},
    boolean::CFBoolean,
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFDictionaryRef},
    error::{CFError, CFErrorRef},
    number::CFNumber,
    runloop::{
        CFRunLoop, CFRunLoopSource, CFRunLoopSourceInvalidate, CFRunLoopSourceRef,
        kCFRunLoopDefaultMode,
    },
    string::{CFString, CFStringRef},
    url::{CFURL, CFURLCreateWithString, CFURLRef},
};
use std::{
    ffi::c_void,
    ptr,
    time::{Duration, Instant},
};
use ureq::{Proxy, ProxyProtocol, http::Uri};

type Dictionary = CFDictionary<CFString, CFType>;
type Proxies = CFArray<Dictionary>;
type Callback = extern "C" fn(*mut c_void, CFArrayRef, CFErrorRef);

#[repr(C)]
struct ClientContext {
    version: CFIndex,
    info: *mut c_void,
    retain: Option<extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<extern "C" fn(*const c_void)>,
    description: Option<extern "C" fn(*const c_void) -> CFStringRef>,
}

#[link(name = "CFNetwork", kind = "framework")]
unsafe extern "C" {
    static kCFProxyTypeKey: CFStringRef;
    static kCFProxyHostNameKey: CFStringRef;
    static kCFProxyPortNumberKey: CFStringRef;
    static kCFProxyUsernameKey: CFStringRef;
    static kCFProxyPasswordKey: CFStringRef;
    static kCFProxyAutoConfigurationURLKey: CFStringRef;
    static kCFProxyAutoConfigurationJavaScriptKey: CFStringRef;
    static kCFProxyTypeNone: CFStringRef;
    static kCFProxyTypeHTTP: CFStringRef;
    static kCFProxyTypeHTTPS: CFStringRef;
    static kCFProxyTypeSOCKS: CFStringRef;
    static kCFProxyTypeAutoConfigurationURL: CFStringRef;
    static kCFProxyTypeAutoConfigurationJavaScript: CFStringRef;
    fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
    fn CFNetworkCopyProxiesForURL(url: CFURLRef, settings: CFDictionaryRef) -> CFArrayRef;
    fn CFNetworkExecuteProxyAutoConfigurationURL(
        pac: CFURLRef,
        target: CFURLRef,
        callback: Callback,
        context: *mut ClientContext,
    ) -> CFRunLoopSourceRef;
    fn CFNetworkExecuteProxyAutoConfigurationScript(
        script: CFStringRef,
        target: CFURLRef,
        callback: Callback,
        context: *mut ClientContext,
    ) -> CFRunLoopSourceRef;
}

fn url(text: &str) -> Result<CFURL> {
    let text = CFString::new(text);
    // CFURLCreateWithString follows the create rule; the wrapper owns its retain.
    let value =
        unsafe { CFURLCreateWithString(ptr::null(), text.as_concrete_TypeRef(), ptr::null()) };
    ensure!(!value.is_null(), "invalid macOS proxy URL");
    Ok(unsafe { CFURL::wrap_under_create_rule(value) })
}

fn value(dictionary: &Dictionary, key: CFStringRef) -> Option<CFType> {
    // Keys are the immortal constants exported by CFNetwork. The dictionary
    // retains its values; cloning a CFType adds our independent retain.
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    dictionary.find(&key).map(|value| (*value).clone())
}
fn string(dictionary: &Dictionary, key: CFStringRef) -> Result<String> {
    value(dictionary, key)
        .and_then(|v| v.downcast::<CFString>())
        .map(|v| v.to_string())
        .context("missing or invalid CFNetwork proxy string")
}
fn kind_is(kind: &CFString, expected: CFStringRef) -> bool {
    *kind == unsafe { CFString::wrap_under_get_rule(expected) }
}

pub(super) fn for_url(uri: &Uri) -> Result<Vec<Option<Proxy>>> {
    let target = url(&uri.to_string())?;
    let settings = unsafe { CFNetworkCopySystemProxySettings() };
    ensure!(!settings.is_null(), "reading macOS system proxy settings");
    let settings = unsafe { Dictionary::wrap_under_create_rule(settings) };
    let proxies = system_proxies(&target, &settings)?;
    let has_pac = proxies.iter().any(|proxy| {
        value(&proxy, unsafe { kCFProxyTypeKey })
            .and_then(|value| value.downcast::<CFString>())
            .is_some_and(|kind| {
                kind_is(&kind, unsafe { kCFProxyTypeAutoConfigurationURL })
                    || kind_is(&kind, unsafe { kCFProxyTypeAutoConfigurationJavaScript })
            })
    });
    // Prefer a referral already discovered by the OS. If none was supplied,
    // try the active DHCP lease before DNS, preserving native bypass semantics.
    if !has_pac
        && setting_enabled(&settings, "ProxyAutoDiscoveryEnable")
        && !setting_enabled(&settings, "ProxyAutoConfigEnable")
        && !bypassed(&settings, &target)?
    {
        if let Some(pac) = dhcp_pac()? {
            return pac_routes(&url(&pac)?, &target);
        }
        match pac_routes(&url("http://wpad/wpad.dat")?, &target) {
            Ok(discovered) => return Ok(discovered),
            Err(error) => {
                crate::progress::check_cancelled()?;
                crate::log!(
                    Debug,
                    "proxy:wpad",
                    "No DNS WPAD route: {error:#}; using the system's concrete route"
                );
            }
        }
    }
    resolve(&proxies, &target, 0)
}

fn setting(dictionary: &Dictionary, key: &str) -> Option<CFType> {
    dictionary
        .find(CFString::new(key))
        .map(|value| (*value).clone())
}
fn setting_enabled(dictionary: &Dictionary, key: &str) -> bool {
    setting(dictionary, key).is_some_and(|value| {
        value
            .downcast::<CFNumber>()
            .and_then(|number| number.to_i64())
            .is_some_and(|number| number != 0)
            || value.downcast::<CFBoolean>().is_some_and(bool::from)
    })
}
fn bypassed(settings: &Dictionary, target: &CFURL) -> Result<bool> {
    // Ask CFNetwork to apply its own exceptions (including CIDR and simple
    // hostnames) to an otherwise unconditional dummy proxy.
    let mut items = Vec::new();
    for key in ["ExceptionsList", "ExcludeSimpleHostnames"] {
        if let Some(value) = setting(settings, key) {
            items.push((CFString::new(key), value));
        }
    }
    for (enable, host, port) in [
        ("HTTPEnable", "HTTPProxy", "HTTPPort"),
        ("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
    ] {
        items.push((CFString::new(enable), CFNumber::from(1).as_CFType()));
        items.push((
            CFString::new(host),
            CFString::new("proxy.invalid").as_CFType(),
        ));
        items.push((CFString::new(port), CFNumber::from(80).as_CFType()));
    }
    let routes = proxies_for_settings(target, &Dictionary::from_CFType_pairs(&items))?;
    Ok(routes.iter().all(Option::is_none))
}

fn pac_routes(pac: &CFURL, target: &CFURL) -> Result<Vec<Option<Proxy>>> {
    resolve(
        &execute_pac(|callback, context| unsafe {
            CFNetworkExecuteProxyAutoConfigurationURL(
                pac.as_concrete_TypeRef(),
                target.as_concrete_TypeRef(),
                callback,
                context,
            )
        })?,
        target,
        1,
    )
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCreate(
        allocator: *const c_void,
        name: CFStringRef,
        callback: Option<extern "C" fn(*const c_void, CFArrayRef, *mut c_void)>,
        context: *mut c_void,
    ) -> *const c_void;
    fn SCDynamicStoreCopyValue(store: *const c_void, key: CFStringRef) -> *const c_void;
    fn SCDynamicStoreCopyDHCPInfo(store: *const c_void, service: CFStringRef) -> CFDictionaryRef;
    fn DHCPInfoGetOptionData(info: CFDictionaryRef, option: u8) -> CFDataRef;
}

/// Read the active interface's already acquired DHCP option 252. No new DHCP
/// requests, elevated privileges or changes to network configuration are needed.
fn dhcp_pac() -> Result<Option<String>> {
    let name = CFString::new("Zalivka proxy discovery");
    let store = unsafe {
        SCDynamicStoreCreate(
            ptr::null(),
            name.as_concrete_TypeRef(),
            None,
            ptr::null_mut(),
        )
    };
    ensure!(
        !store.is_null(),
        "opening macOS network configuration for WPAD"
    );
    let store = unsafe { CFType::wrap_under_create_rule(store) };
    let key = CFString::new("State:/Network/Global/IPv4");
    let global =
        unsafe { SCDynamicStoreCopyValue(store.as_CFTypeRef(), key.as_concrete_TypeRef()) };
    if global.is_null() {
        return Ok(None);
    }
    let global = unsafe { CFType::wrap_under_create_rule(global) }
        .downcast::<CFDictionary>()
        .context("invalid macOS IPv4 configuration")?;
    let global: Dictionary =
        unsafe { Dictionary::wrap_under_get_rule(global.as_concrete_TypeRef()) };
    let Some(service) =
        setting(&global, "PrimaryService").and_then(|value| value.downcast::<CFString>())
    else {
        return Ok(None);
    };
    let dhcp =
        unsafe { SCDynamicStoreCopyDHCPInfo(store.as_CFTypeRef(), service.as_concrete_TypeRef()) };
    if dhcp.is_null() {
        return Ok(None);
    }
    let dhcp = unsafe { Dictionary::wrap_under_create_rule(dhcp) };
    let data = unsafe { DHCPInfoGetOptionData(dhcp.as_concrete_TypeRef(), 252) };
    if data.is_null() {
        return Ok(None);
    }
    let data = unsafe { CFData::wrap_under_get_rule(data) };
    let pac = std::str::from_utf8(data.bytes())
        .context("DHCP WPAD URL is not UTF-8")?
        .trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if pac.is_empty() {
        return Ok(None);
    }
    let uri: Uri = pac.parse().context("invalid DHCP WPAD URL")?;
    ensure!(
        matches!(uri.scheme_str(), Some("http" | "https"))
            && uri.host().is_some()
            && !uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@')),
        "DHCP WPAD requires an HTTP(S) PAC URL without embedded credentials"
    );
    Ok(Some(pac.to_owned()))
}

fn system_proxies(target: &CFURL, settings: &Dictionary) -> Result<Proxies> {
    // CFNetwork applies scoped settings and returns explicit PAC referrals.
    let proxies = unsafe {
        CFNetworkCopyProxiesForURL(target.as_concrete_TypeRef(), settings.as_concrete_TypeRef())
    };
    ensure!(!proxies.is_null(), "resolving macOS system proxy");
    Ok(unsafe { Proxies::wrap_under_create_rule(proxies) })
}

fn proxies_for_settings(target: &CFURL, settings: &Dictionary) -> Result<Vec<Option<Proxy>>> {
    resolve(&system_proxies(target, settings)?, target, 0)
}

fn resolve(proxies: &Proxies, target: &CFURL, depth: usize) -> Result<Vec<Option<Proxy>>> {
    ensure!(
        depth < 3 && !proxies.is_empty() && proxies.len() <= 32,
        "invalid CFNetwork proxy route list"
    );
    let mut routes = Vec::new();
    for proxy in proxies.iter() {
        let kind = value(&proxy, unsafe { kCFProxyTypeKey })
            .and_then(|v| v.downcast::<CFString>())
            .context("invalid CFNetwork proxy type")?;
        if kind_is(&kind, unsafe { kCFProxyTypeNone }) {
            routes.push(None);
        } else if kind_is(&kind, unsafe { kCFProxyTypeAutoConfigurationURL }) {
            let value = value(&proxy, unsafe { kCFProxyAutoConfigurationURLKey })
                .context("missing PAC URL")?;
            let pac = if let Some(url) = value.downcast::<CFURL>() {
                url
            } else {
                url(&value
                    .downcast::<CFString>()
                    .context("invalid PAC URL")?
                    .to_string())?
            };
            routes.extend(resolve(
                &execute_pac(|callback, context| unsafe {
                    CFNetworkExecuteProxyAutoConfigurationURL(
                        pac.as_concrete_TypeRef(),
                        target.as_concrete_TypeRef(),
                        callback,
                        context,
                    )
                })?,
                target,
                depth + 1,
            )?);
        } else if kind_is(&kind, unsafe { kCFProxyTypeAutoConfigurationJavaScript }) {
            let script = value(&proxy, unsafe { kCFProxyAutoConfigurationJavaScriptKey })
                .and_then(|v| v.downcast::<CFString>())
                .context("missing PAC script")?;
            routes.extend(resolve(
                &execute_pac(|callback, context| unsafe {
                    CFNetworkExecuteProxyAutoConfigurationScript(
                        script.as_concrete_TypeRef(),
                        target.as_concrete_TypeRef(),
                        callback,
                        context,
                    )
                })?,
                target,
                depth + 1,
            )?);
        } else {
            let protocols: &[ProxyProtocol] = if kind_is(&kind, unsafe { kCFProxyTypeSOCKS }) {
                &[ProxyProtocol::Socks5h, ProxyProtocol::Socks4A]
            } else if kind_is(&kind, unsafe { kCFProxyTypeHTTP })
                || kind_is(&kind, unsafe { kCFProxyTypeHTTPS })
            {
                // macOS's Secure Web Proxy is an HTTP CONNECT proxy for HTTPS
                // destinations. It does not imply TLS to the proxy itself.
                &[ProxyProtocol::Http]
            } else {
                bail!("unsupported CFNetwork proxy type {kind}");
            };
            let host = string(&proxy, unsafe { kCFProxyHostNameKey })?;
            let port = value(&proxy, unsafe { kCFProxyPortNumberKey })
                .and_then(|v| v.downcast::<CFNumber>())
                .and_then(|v| v.to_i64())
                .context("invalid CFNetwork proxy port")?;
            let port = u16::try_from(port).context("CFNetwork proxy port out of range")?;
            ensure!(
                !host.is_empty() && port != 0,
                "invalid CFNetwork proxy address"
            );
            for protocol in protocols {
                let mut builder = Proxy::builder(*protocol).host(&host).port(port);
                if let Ok(user) = string(&proxy, unsafe { kCFProxyUsernameKey }) {
                    builder = builder.username(&user);
                }
                if let Ok(password) = string(&proxy, unsafe { kCFProxyPasswordKey }) {
                    builder = builder.password(&password);
                }
                routes.push(Some(builder.build()?));
            }
        }
    }
    ensure!(
        !routes.is_empty(),
        "macOS proxy resolver returned no routes"
    );
    Ok(routes)
}

extern "C" fn pac_finished(info: *mut c_void, proxies: CFArrayRef, error: CFErrorRef) {
    // CFNetwork delivers this callback on the run loop where we scheduled the
    // source. The stack-owned slot lives until source invalidation/removal.
    let result = if !error.is_null() {
        let error = unsafe { CFError::wrap_under_get_rule(error) };
        Err(anyhow::anyhow!("macOS PAC/WPAD failed: {error}"))
    } else if proxies.is_null() {
        Err(anyhow::anyhow!("macOS PAC returned no proxy list"))
    } else {
        Ok(unsafe { Proxies::wrap_under_get_rule(proxies) })
    };
    unsafe {
        *info.cast::<Option<Result<Proxies>>>() = Some(result);
    }
}

fn execute_pac(
    start: impl FnOnce(Callback, *mut ClientContext) -> CFRunLoopSourceRef,
) -> Result<Proxies> {
    let mut result: Option<Result<Proxies>> = None;
    let mut context = ClientContext {
        version: 0,
        info: (&mut result as *mut Option<Result<Proxies>>).cast(),
        retain: None,
        release: None,
        description: None,
    };
    let source = start(pac_finished, &mut context);
    ensure!(!source.is_null(), "starting macOS PAC/WPAD resolution");
    let source = unsafe { CFRunLoopSource::wrap_under_create_rule(source) };
    let run_loop = CFRunLoop::get_current();
    let mode = unsafe { kCFRunLoopDefaultMode };
    run_loop.add_source(&source, mode);
    let deadline = Instant::now() + Duration::from_secs(30);
    let waited = (|| {
        while result.is_none() {
            crate::progress::check_cancelled()?;
            ensure!(
                Instant::now() < deadline,
                "macOS PAC/WPAD resolution timed out"
            );
            CFRunLoop::run_in_mode(mode, Duration::from_millis(50), true);
        }
        Ok(())
    })();
    // No callback can retain the stack pointer after invalidation/removal.
    unsafe {
        CFRunLoopSourceInvalidate(source.as_concrete_TypeRef());
    }
    run_loop.remove_source(&source, mode);
    waited?;
    result.context("macOS PAC did not complete")?
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/macos.rs"]
mod tests;
