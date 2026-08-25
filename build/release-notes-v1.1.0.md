## Changes

- **Windows only:** Simplified TBS access configuration logic
- **Windows only:** Auto-retry `ActivateCredential` with UAC elevation when TBS returns `COMMAND_BLOCKED` (0x80280400)
- Version bump: 1.0.0 -> 1.1.0

## Platform notes

- Windows amd64: freshly built and Authenticode-signed (Aura Friday, Certum CA, timestamped)
- Linux amd64: freshly built from v1.1.0 source
- Linux arm64 / macOS: carried forward from v1.0.2 (all v1.1.0 changes are `runtime.GOOS == "windows"` gated, functionally identical on non-Windows)
- SE helpers: unchanged from v1.0.2

## Verification

All binaries have SHA256 checksums in `SHA256SUMS`, GPG-signed with `releases@1id.com` (key `F8516F1FA6E36EAD2263C0F79B5C12DDE66D4B6B`).
Windows binary has Authenticode signature (verify with `signtool verify /pa`).
