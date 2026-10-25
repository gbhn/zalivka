//! Resolve the current user's Windows proxy settings, including PAC and WPAD.
//! https://learn.microsoft.com/windows/win32/winhttp/setting-wininet-proxy-configurations-in-winhttp
use super::wide;
use anyhow::{Context, Result, ensure};
use std::{cell::RefCell, ffi::c_void, ptr::null};
use ureq::{Proxy, http::Uri};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, GlobalFree},
    Networking::WinHttp::*,
};

struct UserConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG);

impl Drop for UserConfig {
    fn drop(&mut self) {
        // These strings are allocated by WinHTTP even though we own the struct.
        unsafe {
            GlobalFree(self.0.lpszAutoConfigUrl.cast());
            GlobalFree(self.0.lpszProxy.cast());
            GlobalFree(self.0.lpszProxyBypass.cast());
        }
    }
}

struct ProxyInfo(WINHTTP_PROXY_INFO);

impl Drop for ProxyInfo {
    fn drop(&mut self) {
        unsafe {
            GlobalFree(self.0.lpszProxy.cast());
            GlobalFree(self.0.lpszProxyBypass.cast());
        }
    }
}

impl ProxyInfo {
    fn proxy(&self, uri: &Uri) -> Result<Option<Proxy>> {
        match self.0.dwAccessType {
            WINHTTP_ACCESS_TYPE_NO_PROXY => Ok(None),
            WINHTTP_ACCESS_TYPE_NAMED_PROXY => crate::proxy::from_windows_list(
                uri,
                &string(self.0.lpszProxy),
                &string(self.0.lpszProxyBypass),
            ),
            _ => anyhow::bail!("Windows returned an unsupported proxy access type"),
        }
    }
}

struct Session(*mut c_void);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

thread_local! {
    // WinHTTP caches PAC downloads and WPAD discovery within this session.
    // Keep the handle on its owning thread; no unsafe Send/Sync implementations.
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

fn string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // All callers pass NUL-terminated strings owned by a live WinHTTP result.
    unsafe {
        let mut len = 0;
        while *pointer.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, len))
    }
}

impl Session {
    fn open() -> Result<Self> {
        let handle = unsafe {
            WinHttpOpen(
                wide("zalivka").as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                null(),
                null(),
                0,
            )
        };
        ensure!(
            !handle.is_null(),
            "opening Windows proxy resolver: {}",
            std::io::Error::last_os_error()
        );
        let session = Self(handle);
        ensure!(
            unsafe { WinHttpSetTimeouts(session.0, 30_000, 30_000, 30_000, 30_000) } != 0,
            "setting Windows proxy resolver timeouts: {}",
            std::io::Error::last_os_error()
        );
        Ok(session)
    }

    fn proxy(&self, uri: &Uri, detect: bool, pac: &str) -> Result<Option<Proxy>> {
        let pac_url = wide(pac);
        let url = wide(uri.to_string());
        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: if detect {
                WINHTTP_AUTOPROXY_AUTO_DETECT
            } else {
                0
            } | if pac.is_empty() {
                0
            } else {
                WINHTTP_AUTOPROXY_CONFIG_URL
            },
            dwAutoDetectFlags: if detect {
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
            } else {
                0
            },
            lpszAutoConfigUrl: if pac.is_empty() {
                null()
            } else {
                pac_url.as_ptr()
            },
            ..Default::default()
        };
        // Try without credentials first so WinHTTP can cache the script.
        // Each attempt owns its result, including any allocations on failure.
        loop {
            let mut info = ProxyInfo(WINHTTP_PROXY_INFO::default());
            if unsafe { WinHttpGetProxyForUrl(self.0, url.as_ptr(), &mut options, &mut info.0) }
                != 0
            {
                return info.proxy(uri);
            }
            let error = std::io::Error::last_os_error();
            if options.fAutoLogonIfChallenged == 0
                && error.raw_os_error() == Some(ERROR_WINHTTP_LOGIN_FAILURE as i32)
            {
                options.fAutoLogonIfChallenged = 1;
            } else {
                return Err(error).context("resolving Windows PAC/WPAD proxy");
            }
        }
    }
}

fn auto_proxy(uri: &Uri, detect: bool, pac: &str) -> Result<Option<Proxy>> {
    SESSION.with(|cell| {
        let mut cached = cell.borrow_mut();
        let session = match &mut *cached {
            Some(session) => session,
            slot @ None => slot.insert(Session::open()?),
        };
        session.proxy(uri, detect, pac)
    })
}

/// Outer None means no Windows proxy policy, so environment settings may apply.
/// Some(None) means Windows explicitly selected a direct connection.
pub(crate) fn for_url(uri: &Uri) -> Result<Option<Option<Proxy>>> {
    let mut config = UserConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default());
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config.0) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) {
            return Err(error).context("reading Windows user proxy settings");
        }
    } else {
        let pac = string(config.0.lpszAutoConfigUrl);
        let manual = string(config.0.lpszProxy);
        if config.0.fAutoDetect != 0 || !pac.is_empty() {
            match auto_proxy(uri, config.0.fAutoDetect != 0, &pac) {
                Ok(proxy) => return Ok(Some(proxy)),
                Err(error) if !manual.is_empty() => {
                    crate::log!(
                        Warning,
                        "proxy",
                        "Windows PAC/WPAD unavailable ({error:#}); using configured manual proxy"
                    );
                }
                // "Automatically detect" is commonly enabled without a WPAD
                // server. Only absence of discovery permits normal fallback.
                Err(error)
                    if pac.is_empty()
                        && error
                            .downcast_ref::<std::io::Error>()
                            .and_then(|e| e.raw_os_error())
                            == Some(ERROR_WINHTTP_AUTODETECTION_FAILED as i32) => {}
                Err(error) => return Err(error),
            }
        }
        if !manual.is_empty() {
            return crate::proxy::from_windows_list(
                uri,
                &manual,
                &string(config.0.lpszProxyBypass),
            )
            .map(Some);
        }
    }
    let mut info = ProxyInfo(WINHTTP_PROXY_INFO::default());
    ensure!(
        unsafe { WinHttpGetDefaultProxyConfiguration(&mut info.0) } != 0,
        "reading Windows WinHTTP proxy settings: {}",
        std::io::Error::last_os_error()
    );
    if info.0.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
        return info.proxy(uri).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
#[path = "../../tests/unit/windows/proxy.rs"]
mod tests;
