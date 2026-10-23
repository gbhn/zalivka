//! SHA implementations shared by archive, component and download verification.
use sha2::{Digest, Sha256, Sha384, digest::DynDigest};

pub(crate) fn hasher(length: usize) -> Option<Box<dyn DynDigest>> {
    Some(match length {
        20 => Box::new(sha1::Sha1::new()),
        32 => Box::new(Sha256::new()),
        48 => Box::new(Sha384::new()),
        _ => return None,
    })
}
