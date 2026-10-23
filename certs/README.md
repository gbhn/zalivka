# Apple TSS trust anchor

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
Mozilla roots used by the normal HTTP agent. The certificate is embedded only
in the TSS agent. CDN, catalog and asset requests retain the Mozilla root set.

Certificate-chain validation, hostname checking, validity checking and TLS
handshake signature verification remain enabled. No system certificate store
is changed. No certificates are learned from a failed/untrusted connection.
The root observed in the server chain was compared byte-for-byte with this
independently downloaded official certificate; OpenSSL then validated the chain
and `gs.apple.com` hostname with this trust anchor.
