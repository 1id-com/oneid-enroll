# oneid-enroll v2.2.1 -- YubiKey slot 9a is never overwritten

Recommended update. Works with `oneid` / `1id` SDK 3.1.0 and later (the SDKs
fetch the latest helper automatically; SDK 3.1.2 verifies its publisher
signature before use).

## What changed

- **Portable (YubiKey) enrollment never replaces an existing key.** The helper
  generates a key in PIV slot 9a only when the card reports the slot as empty.
  Any other attestation failure -- for example a key that was imported rather
  than generated on the card (which cannot be attested), or a card that could
  not be read -- now stops enrollment with an error instead of generating a new
  key over the one already there. Before this release such a failure could
  silently replace a key the owner was still using.
  Verified on a YubiKey 4 (firmware 4.3.7) with an occupied slot: `extract`
  reports `key_was_newly_generated: false` and the slot's public key is
  unchanged.
- No change to TPM or Secure Enclave behaviour, no elevation, no persistent TPM
  handles, no NV writes.

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
