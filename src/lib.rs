pub mod aea;
pub mod asr;
pub mod catalog;
mod checksum;
pub mod device;
pub mod dfu;
pub mod drivers;
pub mod fdr;
pub mod firmware;
pub mod img4;
pub mod ipsw;
pub mod logging;
pub mod mux;
pub mod net;
pub mod progress;
mod proxy;
pub mod restore;
pub mod storage;
pub mod tss;
pub mod usb;
pub mod usb_internet;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
pub mod wire;

/// Package version, source revision and fingerprint of this exact build.
pub const VERSION: &str = env!("ZALIVKA_VERSION");

#[cfg(test)]
#[path = "../tests/support/mux.rs"]
mod test_mux;
