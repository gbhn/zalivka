//! Public FCS key unwrapping for AEA profile 1. No AppleConnect credentials.
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use hpke::{Deserializable, Kem, OpModeR, aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256};
use p256::{SecretKey, elliptic_curve::sec1::ToSec1Point, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};

const MAX_AUTH: usize = 1024 * 1024;
pub const MAX_PREFIX: usize = 12 + MAX_AUTH + 144;

pub enum Prefix {
    Incomplete,
    Unsupported,
    Public(Box<PublicFcs>),
}

// An instance belongs to one file transfer. Never match an unverified key to
// an arbitrary ArchiveIdentifier or reuse a previous image's archive key.
pub struct PublicFcs {
    pub url: String,
    fingerprint: String,
    sender: Vec<u8>,
    wrapped: Vec<u8>,
    auth: Vec<u8>,
    salt: [u8; 32],
    root: [u8; 112],
}

impl PublicFcs {
    pub fn from_prefix(bytes: &[u8]) -> Result<Prefix> {
        if bytes.len() < 12 {
            return Ok(Prefix::Incomplete);
        }
        if &bytes[..4] != b"AEA1" || u32::from_le_bytes(bytes[4..8].try_into()?) != 1 {
            return Ok(Prefix::Unsupported);
        }
        let length = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(
            length <= MAX_AUTH,
            "AEA authentication metadata exceeds 1 MiB"
        );
        let end = 12 + length;
        if bytes.len() < end + 144 {
            return Ok(Prefix::Incomplete);
        }
        let mut fields = std::collections::HashMap::new();
        let mut remaining = &bytes[12..end];
        while !remaining.is_empty() {
            let size = remaining.get(..4).context("truncated AEA metadata field")?;
            let size = u32::from_le_bytes(size.try_into()?) as usize;
            ensure!(
                size >= 5 && size <= remaining.len(),
                "invalid AEA metadata field size"
            );
            let field = &remaining[4..size];
            let separator = field
                .iter()
                .position(|b| *b == 0)
                .context("AEA metadata field has no name separator")?;
            let name = std::str::from_utf8(&field[..separator])
                .context("invalid AEA metadata field name")?;
            ensure!(
                !name.is_empty() && fields.insert(name, &field[separator + 1..]).is_none(),
                "empty or duplicate AEA metadata field"
            );
            remaining = &remaining[size..];
        }
        let (Some(url), Some(response)) = (
            fields.get("com.apple.wkms.fcs-key-url"),
            fields.get("com.apple.wkms.fcs-response"),
        ) else {
            return Ok(Prefix::Unsupported);
        };
        let url = std::str::from_utf8(url)
            .context("invalid FCS URL")?
            .to_owned();
        let uri = crate::net::apple_url(&url)?;
        ensure!(
            uri.host() == Some("wkms-public.apple.com") && uri.query().is_none(),
            "FCS key must use Apple's public key service"
        );
        let fingerprint = uri
            .path()
            .strip_prefix("/fcs-keys/")
            .context("invalid public FCS path")?
            .to_owned();
        ensure!(
            URL_SAFE.decode(&fingerprint)?.len() == 32,
            "invalid FCS key fingerprint"
        );
        #[derive(serde::Deserialize)]
        struct Response {
            #[serde(rename = "enc-request")]
            enc: String,
            #[serde(rename = "wrapped-key")]
            wrapped: String,
        }
        let response: Response =
            serde_json::from_slice(response).context("invalid FCS response metadata")?;
        let sender = STANDARD
            .decode(response.enc)
            .context("invalid FCS encapsulated key")?;
        let wrapped = STANDARD
            .decode(response.wrapped)
            .context("invalid FCS wrapped key")?;
        ensure!(
            sender.len() == 65 && sender[0] == 4 && wrapped.len() == 48,
            "unsupported FCS key lengths"
        );
        Ok(Prefix::Public(Box::new(Self {
            url,
            fingerprint,
            sender,
            wrapped,
            auth: bytes[12..end].to_vec(),
            salt: bytes[end..end + 32].try_into()?,
            root: bytes[end + 32..end + 144].try_into()?,
        })))
    }

    pub fn fetch_key(&self) -> Result<[u8; 32]> {
        let pem = crate::storage::read_limited(
            crate::net::get(&self.url)?.body_mut().as_reader(),
            65536,
            "public FCS key response exceeds 64 KiB",
        )?;
        self.unwrap_key(&pem)
    }

    pub fn unwrap_key(&self, pem: &[u8]) -> Result<[u8; 32]> {
        ensure!(pem.len() <= 65536, "public FCS key response exceeds 64 KiB");
        let pem = std::str::from_utf8(pem).context("FCS key is not UTF-8 PEM")?;
        let secret = SecretKey::from_pkcs8_pem(pem).context("FCS key is not PKCS#8 P-256")?;
        let recipient = secret.public_key().to_sec1_point(false);
        ensure!(
            URL_SAFE.encode(Sha256::digest(recipient.as_bytes())) == self.fingerprint,
            "public FCS key fingerprint mismatch"
        );
        let key = hpke_open(&secret, &self.sender, &self.wrapped, &[], &[])?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("FCS archive key must contain 32 bytes"))?;
        // Authenticate this image's encrypted root header before returning
        // LocalUnwrapped. A successful HPKE open alone does not bind the key
        // to the remainder of this file's AEA metadata and root header.
        let mut main = [0; 32];
        Hkdf::<Sha256>::new(Some(&self.salt), &key)
            .expand(b"AEA_AMK\x01\0\0\0", &mut main)
            .map_err(|_| anyhow::anyhow!("AEA key derivation failed"))?;
        let mut mac_key = [0; 32];
        Hkdf::<Sha256>::new(None, &main)
            .expand(b"AEA_RHEK", &mut mac_key)
            .map_err(|_| anyhow::anyhow!("AEA header key derivation failed"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key)?;
        mac.update(&self.root[80..112]);
        mac.update(&self.auth);
        mac.update(&self.root[32..80]);
        mac.update(&(32 + self.auth.len() as u64).to_le_bytes());
        mac.verify_slice(&self.root[..32])
            .map_err(|_| anyhow::anyhow!("AEA root header authentication failed"))?;
        Ok(key)
    }
}

// RFC 9180 base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM. FCS uses empty info/AAD and sequence number zero.
fn hpke_open(
    secret: &SecretKey,
    enc: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let secret = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&secret.to_bytes())
        .context("invalid FCS recipient key")?;
    let enc = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(enc)
        .context("invalid FCS P-256 point")?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &secret,
        &enc,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| anyhow::anyhow!("FCS wrapped key authentication failed"))
}

#[cfg(test)]
#[path = "../tests/unit/aea.rs"]
mod tests;
