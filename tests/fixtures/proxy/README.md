# Local HTTPS proxy fixture

`localhost.der` is a self-signed P-256 certificate for `localhost` and
`127.0.0.1`, generated with OpenSSL on 2026-10-23 with a 100-year lifetime.
`localhost-key.der` is its deliberately public PKCS#8 test key.
Neither file is used by production code or installed into any trust store.

The HTTPS proxy regression uses this certificate only in the proxy's test
trust configuration. It verifies that CONNECT works while the destination
retains Apple's separate TSS trust anchor.
