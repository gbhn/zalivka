# Restore attestation fixtures

`baa-scrt-leaf.cer`, `baa-system-subca.cer`, `baa-ucrt-leaf.cer`, and
`baa-user-subca.cer` are Apple's public BAA regression certificates from
[Security, commit db15acbe6a7f257a859ad9a3bb86097bfe0679d9](https://github.com/apple-oss-distributions/Security/tree/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/shared_regressions/si-20-sectrust-policies-data).
Original names are `baa_scrt_leaf.cer`, `baa_system_subca1.cer`,
`baa_ucrt_leaf.cer`, and `baa_user_subca1.cer`. Roots are in `certs/`.
Tests validate these historical certificates within their validity periods
and reject them at the current time, under the wrong root, or after tampering.
They are generic BAA certificates and intentionally lack the restore proof.

`synthetic-*.cer` are test-only public certificates generated with Python
cryptography 46.0.5. No private keys are retained. The P-384 root and P-256
intermediate/leaf cover 2020-01-01 through 2030-01-01. The leaf's signed
`1.2.840.113635.100.8.3` extension contains:

- `[2]`: `8103-123456789abcd-d-a0000000` (synthetic device identity).
- `[1002]`: SHA-384 of `synthetic iBSS restore ticket`.
- `[1007]`: `ibss`.
- `[1010]`: big-endian flags `0`.
- `[1011]`: big-endian flags mask `8` (LocalBoot measured).

The production protocol rejects this synthetic chain because its root is not
one of the pinned Apple roots. Tests separately exercise X.509 verification
and all restore bindings, including identity/ticket substitution and LocalBoot.
