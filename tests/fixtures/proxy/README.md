# Local HTTPS proxy fixtures

`localhost.der` is a self-signed P-256 certificate for `localhost` and
`127.0.0.1`, generated with OpenSSL on 2026-10-23 with a 100-year lifetime.
`localhost-key.der` is its deliberately public PKCS#8 test key.
Neither file is used by production code or installed into any trust store.

TLS unit tests do not load `localhost.der`: macOS rejects certificates whose
validity period exceeds its TLS limits ("not standards compliant"), and a
checked-in certificate short enough for it would expire. `tests/support/net.rs`
instead mints a loopback CA and leaf, valid for one year from the test run, and
serves that leaf. `localhost.der` is kept because `localhost-key.der` is the
deliberately public test key shared with the FDR laboratory below.

`fdr-lab.pem` and `fdr-lab.der` are the same self-signed P-256 server certificate,
valid for `tbsc.apple.com`, `localhost`, and `127.0.0.1`. They use the existing public
`localhost-key.der` test key and are valid for ten years from 2026-10-27.
The FDR laboratory uses them only on loopback: rustls and the independent Windows
curl client verify the certificate with a per-test trust configuration. The Apple
hostname is sent to the local HTTP CONNECT proxy; no request goes to Apple.
The certificate is never installed into the Windows certificate store.
