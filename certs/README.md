# Apple trust anchors

`AppleIncRootCertificate.cer` is the public DER certificate published by Apple:

- PKI index: <https://www.apple.com/certificateauthority/>
- Download: <https://www.apple.com/appleca/AppleIncRootCertificate.cer>
- Retrieved: 2026-10-20 over verified HTTPS.
- Subject/issuer: `C=US, O=Apple Inc., OU=Apple Certification Authority, CN=Apple Root CA`
- Validity: 2006-04-25 21:40:36 UTC through 2035-02-09 21:40:36 UTC.
- Size: 1215 bytes.
- SHA-256: `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`

The TSS endpoint `https://gs.apple.com/TSS/controller?action=2` presents a chain
through Apple Server Authentication CA to this root, which is absent from the
public Mozilla root set. The certificate is embedded only in the TSS agent,
alongside system trust. CDN, catalog, asset and HTTPS proxy connections use the
system certificate store on Windows, Linux and macOS, or Mozilla roots on other
platforms.

Certificate-chain validation, hostname checking, validity checking and TLS
handshake signature verification remain enabled. No system certificate store
is changed. No certificates are learned from a failed/untrusted connection.
The root observed in the server chain was compared byte-for-byte with this
independently downloaded official certificate; OpenSSL then validated the chain
and `gs.apple.com` hostname with this trust anchor.

## Restore attestation (BAA)

The following DER certificates are pinned exclusively for restore attestation;
they are not added to HTTPS trust stores:

| File | Subject | SHA-256 |
| --- | --- | --- |
| `baa-system-root.cer` | Basic Attestation System Root CA | `10d3c867f0aefb2431a0a97a8818bd64f7f90ffe1194484fca97f0f29eca0047` |
| `baa-user-root.cer` | Basic Attestation User Root CA | `03751c80fcbe5819d170d267ce1ad6d094407c91d873d7a6562de3666d3594c6` |

Sources, retrieved over verified HTTPS on 2026-10-25:

- [Apple Security: system root](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/shared_regressions/si-20-sectrust-policies-data/baa_system_root.cer)
- [Apple Security: user root](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/shared_regressions/si-20-sectrust-policies-data/baa_user_root.cer)

Both certificates were also compared byte-for-byte against
`aks_baa_scrt_root_cert` / `aks_baa_ucrt_root_cert` in AppleKeyStore from the
26A434 restore ramdisk. These are the anchors selected by MobileDevice
1860.2.5's `AMRestoreAttestationAuthenticate`.

[Apple's BAA policy](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/trust/headers/SecPolicyPriv.h)
requires a valid X.509 chain of exactly three certificates anchored to the
matching system/user BAA root. Restore authentication additionally binds the
leaf's device identifiers to the bootstrap ticket and DFU measurements; a
trusted generic BAA certificate alone does not prove a restore.
