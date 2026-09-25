# oneid-enroll v2.1.0 -- security fix for the TPM enrollment proof

**Required update.** The 1id.com Registrar no longer accepts the enrollment
proof produced by v2.0.0. If an SDK has cached v2.0.0, delete the cached helper
(`%APPDATA%\oneid\bin\` on Windows, `~/.oneid/bin/` elsewhere) so the SDK
downloads this release.

## What changed

- **The TPM co-residency proof is corrected.** In v2.0.0 the Attestation Key
  certified an object the Registrar had wrapped for the Endorsement Key. That
  did not prove anything about the Attestation Key: its attributes were the
  enrollee's own claim and every attested field was public, so software could
  forge the attestation (found by an external review on 2026-09-25; no
  third-party enrollment used the flaw). Now the Registrar wraps a restricted
  ECDSA P-256 *signing key* for the Endorsement Key; the helper imports it
  under the EK and uses it to `TPM2_Certify` the Attestation Key over the
  Registrar's nonce. Only the TPM holding the EK private key can load that key,
  and a restricted key signs only TPM-generated attestations, so the
  Registrar's check (with the key it generated) proves that the Attestation Key
  lives in the certified TPM.
- **Still no elevation.** The ceremony uses only TPM2_Import, TPM2_Load and
  TPM2_Certify, which Windows allows to ordinary users (verified on Windows 10
  and Windows 11 with Intel PTT, non-elevated). Keys stay transient: no
  persistent handles, no NV writes.
- `import-certify` keeps its arguments and output fields; `certify_signature`
  is now an ECDSA P-256 `r||s` signature by the imported Registrar key.

## Downloads

| Platform | File | Signature |
|---|---|---|
| Windows x64 | `oneid-enroll-windows-amd64.exe` | Authenticode (Certum) + GPG |
| Linux x64 | `oneid-enroll-linux-amd64` | GPG |
| Linux arm64 | `oneid-enroll-linux-arm64` | GPG |
| macOS Intel | `oneid-enroll-darwin-amd64` (+ `.zip`) | Developer ID + notarized + GPG |
| macOS Apple Silicon | `oneid-enroll-darwin-arm64` (+ `.zip`) | Developer ID + notarized + GPG |
| macOS Secure Enclave helper | `oneid-se-helper`, `oneid-se-helper-arm64` | GPG |

Every file has a `.sha256` and a GPG `.sha256.asc` (key `releases@1id.com`,
fingerprint `F8516F1FA6E36EAD2263C0F79B5C12DDE66D4B6B`); `SHA256SUMS` and
`SHA256SUMS.asc` cover them all.
