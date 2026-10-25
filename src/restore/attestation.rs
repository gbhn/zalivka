//! BAA certificate authentication and restore-ticket binding, matching
//! MobileDevice 1860.2.5's AMRestoreAttestationAuthenticate.
use crate::{
    device::DeviceInfo,
    img4,
    ipsw::{Behavior, Identity},
    tss, wire,
};
use anyhow::{Context, Result, bail, ensure};
use asn1_rs::{Any, Class, FromDer, ToDer};
use plist::Value;
use rustls::pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use x509_parser::{oid_registry::Oid, prelude::X509Certificate};

const SYSTEM_ROOT: &[u8] = include_bytes!("../../certs/baa-system-root.cer");
const USER_ROOT: &[u8] = include_bytes!("../../certs/baa-user-root.cer");
const DEVICE_IDENTIFIERS: &str = "1.2.840.113635.100.8.3";

#[derive(Debug, PartialEq)]
enum Phase {
    Waiting,
    Requested,
    Verified,
}

pub(super) struct Attestation {
    level: u64,
    phase: Phase,
    device: DeviceInfo,
    ticket_digest: Vec<u8>,
}

impl Attestation {
    pub(super) fn new(id: &Identity, device: &DeviceInfo, ticket: &Value) -> Result<Self> {
        let mode = wire::dictionary(wire::get(&id.value, &["Info"])?)?
            .get("RestoreAttestationMode")
            .map(wire::number)
            .transpose()?
            .unwrap_or(0);
        ensure!(mode <= 8, "unsupported RestoreAttestationMode {mode}");
        let enabled = mode != 0 && id.behavior()? == Behavior::Erase;
        // Apple's legacy levels 1..4 correspond to levels 5..8 during
        // authentication. Levels 6+ also require an ibss measurement tag;
        // level 8 requires the LocalBoot bit to be both measured and clear.
        let level = if !enabled {
            0
        } else if mode < 5 {
            mode + 4
        } else {
            mode
        };
        Ok(Self {
            level,
            phase: Phase::Waiting,
            device: device.clone(),
            ticket_digest: Sha384::digest(tss::ticket(ticket)?).to_vec(),
        })
    }

    pub(super) fn handle(&mut self, message: &Value) -> Result<Option<Value>> {
        match wire::string(message, &["RestoreAttestationState"])? {
            "RestoreShouldAttest" => {
                ensure!(
                    self.phase != Phase::Verified,
                    "attestation question after certificate verification"
                );
                let enabled = self.level != 0;
                if enabled {
                    self.phase = Phase::Requested;
                    crate::log!(
                        Info,
                        "restore",
                        "Запрошена аттестация восстановления: уровень {}",
                        self.level
                    );
                } else {
                    crate::log!(
                        Debug,
                        "restore",
                        "Аттестация не предусмотрена выбранным режимом восстановления"
                    );
                }
                Ok(Some(wire::dict([("RestoreShouldAttest", enabled.into())])))
            }
            "AttestationIssued" => {
                ensure!(
                    self.phase == Phase::Requested,
                    "unsolicited or repeated attestation certificate"
                );
                let certificates = wire::get(message, &["Certificates"])?
                    .as_array()
                    .context("invalid restore attestation Certificates")?;
                ensure!(
                    certificates.len() == 2,
                    "restore attestation requires a leaf and one intermediate certificate"
                );
                let cert = |index: usize| -> Result<&[u8]> {
                    certificates[index]
                        .as_data()
                        .filter(|v| !v.is_empty() && v.len() <= 16384)
                        .context("invalid or oversized attestation certificate")
                };
                let use_scrt = wire::dictionary(message)?
                    .get("AttestationUseSCRT")
                    .map(|v| v.as_boolean().context("invalid AttestationUseSCRT"))
                    .transpose()?
                    .unwrap_or(false);
                let leaf = cert(0)?;
                verify_chain(
                    leaf,
                    cert(1)?,
                    if use_scrt { SYSTEM_ROOT } else { USER_ROOT },
                    UnixTime::now(),
                )?;
                self.verify_properties(leaf)?;
                self.phase = Phase::Verified;
                crate::log!(
                    Info,
                    "restore",
                    "Аттестация проверена: цепочка Apple BAA, ECID {:016x}, restore-ticket, уровень {}",
                    self.device.ecid,
                    self.level
                );
                // AttestationIssued is a notification; restored expects no ACK.
                Ok(None)
            }
            "AttestationError" => bail!(
                "Mac failed to issue restore attestation: {}",
                wire::string(message, &["Error"]).unwrap_or("no error description")
            ),
            state => bail!("unexpected restore attestation state {state}"),
        }
    }

    pub(super) fn finish(&self) -> Result<()> {
        ensure!(
            self.level == 0 || self.phase == Phase::Verified,
            "restore finished without a verified attestation certificate"
        );
        Ok(())
    }

    fn verify_properties(&self, leaf: &[u8]) -> Result<()> {
        let properties = device_identifiers(leaf)?;
        self.verify_identifiers(&properties)
    }

    fn verify_identifiers(&self, properties: &HashMap<u32, &[u8]>) -> Result<()> {
        let required = |tag| {
            properties
                .get(&tag)
                .copied()
                .with_context(|| format!("attestation is missing device identifier {tag}"))
        };
        // The signed BAA device identity is chip-id/ECID/security attributes,
        // encoded as dash-separated hexadecimal fields (CoreTrust CTCopyDeviceIdentifiers).
        let identity = std::str::from_utf8(required(2)?).context("invalid BAA device identity")?;
        let mut fields = identity.split('-');
        let mut number = || -> Result<u64> {
            let field = fields.next().context("incomplete BAA device identity")?;
            ensure!(
                !field.is_empty() && field.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid BAA identity field"
            );
            Ok(u64::from_str_radix(field, 16)?)
        };
        ensure!(
            number()? == u64::from(self.device.chip_id),
            "attestation chip ID mismatch"
        );
        ensure!(number()? == self.device.ecid, "attestation ECID mismatch");
        let security = number()?;
        ensure!(
            security <= 255 && security & 3 == u64::from(self.device.security_domain),
            "attestation security domain mismatch"
        );
        // Restore TSS requests require ApProductionMode and ApSecurityMode.
        ensure!(
            security & 12 == 12,
            "attestation is not in production security mode"
        );
        ensure!(
            required(1002)? == self.ticket_digest,
            "attestation restore-ticket digest mismatch"
        );
        if self.level >= 6 {
            ensure!(
                required(1007)? == b"ibss",
                "attestation digest tag is not ibss (DFU)"
            );
        }
        if self.level >= 8 {
            let flags = required(1010)?;
            let mask = required(1011)?;
            ensure!(
                flags.len() == 4 && mask.len() == 4,
                "invalid attestation flags/mask length"
            );
            let flags = u32::from_be_bytes(flags.try_into()?);
            let mask = u32::from_be_bytes(mask.try_into()?);
            ensure!(mask & 8 != 0, "attestation LocalBoot flag is not measured");
            ensure!(flags & 8 == 0, "attestation LocalBoot flag is set");
        }
        Ok(())
    }
}

// BAA uses Apple's Basic X.509 policy, not a TLS server/client EKU. Its purpose
// is fixed by the pinned BAA root. Still reject malformed EKU encodings.
struct BaaUsage;
impl webpki::ExtendedKeyUsageValidator for BaaUsage {
    fn validate(&self, mut iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        iter.try_for_each(|oid| oid.map(|_| ()))
    }
}

fn verify_chain(leaf: &[u8], intermediate: &[u8], root: &[u8], now: UnixTime) -> Result<()> {
    let leaf_der = CertificateDer::from(leaf);
    let root_der = CertificateDer::from(root);
    let anchors = [webpki::anchor_from_trusted_cert(&root_der).context("invalid pinned BAA root")?];
    let intermediates = [CertificateDer::from(intermediate)];
    let certificate =
        webpki::EndEntityCert::try_from(&leaf_der).context("invalid BAA leaf certificate")?;
    let provider = oxitls_rustcrypto_provider::provider();
    let path = certificate
        .verify_for_usage(
            provider.signature_verification_algorithms.all,
            &anchors,
            &intermediates,
            now,
            BaaUsage,
            None,
            None,
        )
        .context("BAA certificate chain verification failed")?;
    ensure!(
        path.intermediate_certificates().count() == 1,
        "BAA chain must contain exactly three certificates"
    );
    // webpki verifies signatures, issuer links, validity, CA/path constraints
    // and critical extensions. Enforce signing key usage as well.
    for (bytes, ca) in [(leaf, false), (intermediate, true)] {
        let parsed = certificate_from_der(bytes)?;
        if let Some(usage) = parsed.key_usage().context("invalid BAA key usage")? {
            ensure!(
                if ca {
                    usage.value.key_cert_sign()
                } else {
                    usage.value.digital_signature()
                },
                "invalid BAA signing key usage"
            );
        }
    }
    Ok(())
}

fn certificate_from_der(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, certificate) = X509Certificate::from_der(bytes)
        .map_err(|e| anyhow::anyhow!("invalid X.509 certificate: {e}"))?;
    ensure!(rest.is_empty(), "trailing data after X.509 certificate");
    certificate
        .extensions_map()
        .context("duplicate X.509 extensions")?;
    Ok(certificate)
}

fn device_identifiers(leaf: &[u8]) -> Result<HashMap<u32, &[u8]>> {
    let certificate = certificate_from_der(leaf)?;
    let oid = Oid::from(&[1, 2, 840, 113635, 100, 8, 3]).expect("fixed BAA OID");
    let extension = certificate
        .get_extension_unique(&oid)?
        .with_context(|| format!("missing BAA device identifiers ({DEVICE_IDENTIFIERS})"))?;
    parse_identifiers(extension.value)
}

fn parse_identifiers(bytes: &[u8]) -> Result<HashMap<u32, &[u8]>> {
    let (sequence, rest) = img4::parse(bytes)?;
    ensure!(
        sequence.tag == 0x30 && rest.is_empty(),
        "invalid BAA device identifier sequence"
    );
    let mut fields = sequence.content;
    let mut properties = HashMap::new();
    while !fields.is_empty() {
        let (rest, field) =
            Any::from_der(fields).map_err(|e| anyhow::anyhow!("invalid BAA field: {e}"))?;
        ensure!(
            field.class() == Class::ContextSpecific && field.header.constructed(),
            "invalid BAA property tag"
        );
        let mut header = Vec::new();
        field.header.write_der_header(&mut header)?;
        ensure!(
            fields.starts_with(&header),
            "noncanonical BAA property header"
        );
        let (value, trailing) = img4::parse(field.data)?;
        ensure!(trailing.is_empty(), "trailing BAA property data");
        // Known restore properties are byte strings. Other signed BAA fields
        // (integers, booleans, etc.) are unrelated to restore authentication.
        if matches!(value.tag, 0x04 | 0x0c | 0x16) {
            ensure!(
                properties.insert(field.tag().0, value.content).is_none(),
                "duplicate BAA property"
            );
        } else {
            ensure!(
                ![2, 1002, 1007, 1010, 1011].contains(&field.tag().0),
                "invalid restore attestation property type"
            );
        }
        fields = rest;
    }
    Ok(properties)
}

#[cfg(test)]
#[path = "../../tests/unit/restore/attestation.rs"]
mod tests;
