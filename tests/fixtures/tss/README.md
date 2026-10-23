# TSS certificate regression fixtures

Public certificates captured from a TLS handshake with `gs.apple.com:443`
using SNI `gs.apple.com` on 2026-10-20. These files contain no private keys.

| File | Description | SHA-256 |
| --- | --- | --- |
| `gs-2026-04-28.der` | Leaf for `gs.apple.com`, valid 2026-04-28 18:26:07 UTC through 2026-11-12 18:30:14 UTC | `71dc1a659fd55d3b9d8072a01633d78645f711d507ccd63087bd80a2a69cbe0d` |
| `apple-server-auth-ca.der` | Apple Server Authentication CA, issued by Apple Root CA, valid 2014-03-08 through 2029-03-08 | `efd0c3352e8f5cc6c7678a5cb48370c341db58d39fc0569d5e106f02c4fcaceb` |

The trust anchor comes separately from Apple's official PKI publication; see
`certs/README.md`. Neither a server-provided root nor a leaf certificate is
automatically trusted by the client.

The offline regression test verifies the recorded chain at a fixed capture
time of 2026-10-20 00:00:00 UTC. It rejects a different hostname, missing
intermediate, modified signature and a verification date after expiry.
Normal connections always use the actual current time.

The separate ignored live HTTPS test can be run explicitly:

```sh
cargo test --locked --lib live_tss_https_uses_verified_apple_private_pki -- --ignored --nocapture
```

It performs a GET without a device identifier or a signing payload. It does
not open USB, send firmware or request a personalized ticket. A valid TLS
handshake is checked independently of the HTTP status returned for GET.
