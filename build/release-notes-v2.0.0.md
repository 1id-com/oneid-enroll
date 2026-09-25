# oneid-enroll v2.0.0 -- enrollment that never needs elevation

**Breaking release** (pairs with the `oneid` 3.0.0 Python SDK and the `1id`
3.0.0 Node SDK).

## What changed

- **No TPM operation needs elevation any more (Windows 10 and 11).** Sovereign
  enrollment proves that the attestation key lives in the TPM holding the
  certified Endorsement Key with an import-and-certify ceremony
  (TPM2_Import + TPM2_Load under the EK, then TPM2_Certify by the AK over the
  Registrar's nonce). Windows blocks TPM2_ActivateCredential for non-elevated
  processes; import-and-certify runs as the ordinary user. New command:
  `import-certify`.
- **Nothing on the machine is changed.** The retired `setup-tbs` command wrote
  TBS registry values that have been obsolete since Windows 8. `activate`,
  `setup-tbs` and the elevated `session` are retired; `extract` never elevates.
- **Sovereign Profile v1 anchor.** The helper reads the RSA-2048 EK certificate
  (NV 0x01C00002) and the manufacturer intermediate chain stored on the TPM
  (NV 0x01C00100..0x01C001FF, e.g. Intel PTT), and reports the anchor
  fingerprint as SHA-256 of the EK SubjectPublicKeyInfo.
- Keys are derived deterministically each time (transient CreatePrimary): no
  persistent TPM handles, no NV writes.

## Downloads

| Platform | File | Signature |
|---|---|---|
| Windows x64 | `oneid-enroll-windows-amd64.exe` | Authenticode (Certum) + GPG |
| Linux x64 | `oneid-enroll-linux-amd64` | GPG |
| Linux ARM64 | `oneid-enroll-linux-arm64` | GPG |
| macOS Intel | `oneid-enroll-darwin-amd64` (+ notarized `.zip`) | Apple Developer ID + notarization, GPG |
| macOS Apple silicon | `oneid-enroll-darwin-arm64` (+ notarized `.zip`) | Apple Developer ID + notarization, GPG |
| macOS Secure Enclave helper | `oneid-se-helper`, `oneid-se-helper-arm64` | unchanged from v1.1.0 |

Each file has a `.sha256` checksum with a detached GPG signature
(`.sha256.asc`); `SHA256SUMS` + `SHA256SUMS.asc` cover everything. The
signing key (`releases@1id.com`) is in `signing/release-signing-key.pub.asc`.
