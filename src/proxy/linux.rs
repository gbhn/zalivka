//! GNOME, KDE, sysconfig, PAC and WPAD through the system libproxy resolver.
use anyhow::{Context, Result};
use std::cell::RefCell;
use ureq::{Proxy, http::Uri};

thread_local! {
    // libproxy owns configuration/PAC caching and invalidation. Keep its factory
    // on its original thread rather than assuming the C object is Send/Sync.
    static FACTORY: RefCell<Option<libproxy::ProxyFactory>> = const { RefCell::new(None) };
}

pub(super) fn for_url(uri: &Uri) -> Result<Vec<Option<Proxy>>> {
    FACTORY.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(libproxy::ProxyFactory::new().context("initializing libproxy")?);
        }
        let values = slot
            .as_ref()
            .unwrap()
            .get_proxies(&uri.to_string())
            .map_err(|error| anyhow::anyhow!("resolving Linux system proxy/PAC/WPAD: {error:?}"))?;
        super::routes_from_strings(values)
    })
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/linux.rs"]
mod tests;
