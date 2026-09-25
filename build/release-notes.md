# oneid-enroll v2.2.0 -- hardware-bound requests; every binary signed

**Required update** for `oneid` / `1id` SDK 3.1.0, which the SDKs fetch
automatically (they require helper 2.2.0 or later).

## What changed

- **`sign` accepts up to 64 KiB.** 1ID access tokens are now sender-constrained:
  every request that presents one carries an RFC 9421 HTTP Message Signature by
  the enrolled key (registry-04 "HTTP Message Signatures"). The signature base
  includes the whole `Authorization` header, which is larger than the 1024
  bytes `TPM2_Hash` accepts. For longer input the helper now hashes inside the
  TPM with `TPM2_HashSequenceStart` / `TPM2_SequenceUpdate` /
  `TPM2_SequenceComplete`, which yields the same ticket the restricted
  Attestation Key requires, so the key still never signs TPM-generated data.
  Verified on Intel PTT (Windows 10), non-elevated. PIV signing (hashed in
  software) accepts the same 64 KiB.
- **Every macOS binary is Developer ID signed and notarized**, including the
  Secure Enclave helpers `oneid-se-helper` (Intel) and `oneid-se-helper-arm64`
  (Apple silicon), which earlier releases shipped only ad-hoc signed. The
  release build now refuses to finish unless Gatekeeper accepts every macOS
  binary as "Notarized Developer ID".
- No change to enrollment (the v2.1.0 co-residency proof stands), no
  elevation, no persistent TPM handles, no NV writes.

## Downloads

| Platform | File | Signature |
|---|---|---|
| Windows x64 | `oneid-enroll-windows-amd64.exe` | Authenticode (Certum) + GPG |
| Linux x64 | `oneid-enroll-linux-amd64` | GPG |
| Linux arm64 | `oneid-enroll-linux-arm64` | GPG |
| macOS Intel | `oneid-enroll-darwin-amd64` (+ `.zip`) | Developer ID + notarized + GPG |
| macOS Apple Silicon | `oneid-enroll-darwin-arm64` (+ `.zip`) | Developer ID + notarized + GPG |
| macOS Secure Enclave helper | `oneid-se-helper` (Intel), `oneid-se-helper-arm64` | Developer ID + notarized + GPG |

Every file has a `.sha256` and a GPG `.sha256.asc` (key `releases@1id.com`,
fingerprint `F8516F1FA6E36EAD2263C0F79B5C12DDE66D4B6B`); `SHA256SUMS` and
`SHA256SUMS.asc` cover them all.
