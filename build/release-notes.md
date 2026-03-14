## What's new

### New subcommands for TPM/PIV co-location binding

- **`sign --output-clock`** — Extends the existing `sign` subcommand to also perform a TPM Quote capturing clock/reset/restart counters (C1 in the binding protocol).
- **`piv-sign --data <b64>`** — Signs arbitrary base64-encoded data with the PIV key in slot 9a (ECDSA-SHA256). Used in Phase 2 of co-location binding to produce S2.
- **`tpm-bind-quote`** — Extends PCR 16 with provided data and performs a TPM Quote with qualifying data. Used in Phase 3 of co-location binding.

### TBS setup improvement

- `setup-tbs` now also sets `HKLM\SOFTWARE\Policies\Microsoft\TPM\IgnoreDefaultList = 1`, which bypasses the Windows TBS default blocked command list. This allows `PCR_Extend` (used by `tpm-bind-quote`) to work without elevation.

### Build

- All 5 platform binaries built with full CGo/PIV support (no stubs)
- Windows: signed with Certum code-signing certificate
- macOS (amd64 + arm64): signed and notarized with Apple Developer ID
- Linux: SHA-256 checksums provided

## Checksums (SHA-256)

```
d03d84d050f9ef829284d23d61279c8072bd38c8f7ce72e5855968745ea71844  oneid-enroll-darwin-amd64
1a867e9d480a7a0de5849a2087f2ad63a480810a44cde758b92904523f9d4e4e  oneid-enroll-darwin-arm64
c85feea38e4aecef2a42dd8c8c21dc0d811ce7f785361547b13353fc078814be  oneid-enroll-linux-amd64
d7f4ad85db33761c9c18652464da709f4200b4991686fbbca02bbdbfd7a4c4da  oneid-enroll-linux-arm64
013805096cd2bf99889cdb17d5a3ca5d9255e35d497ddde3e11b29e523802410  oneid-enroll-windows-amd64.exe
```
