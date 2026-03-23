## What's new in v0.7.0

### Apple Secure Enclave Support
- New enclave trust tier: private keys are generated inside the Apple Secure Enclave and can never be extracted. The `dataRepresentation` blob is persisted in `credentials.json` so the key survives across sessions while remaining hardware-bound.
- macOS helper binary (`oneid-se-helper`) delegates CryptoKit.SecureEnclave operations via a Swift subprocess on Apple Silicon Macs.

### Transient AK Architecture
- TPM Attestation Keys are created on-demand and never persisted via `EvictControl`, eliminating NV storage exhaustion. AKs are recreated for each signing operation using deterministic parameters.

### Hardware-Based Identity Recovery
- When `credentials.json` is lost, the bound hardware (TPM or YubiKey) can prove the agent's identity through challenge-response authentication.

### Certificate Chain Support
- `--cert-chain-file` flag on `sign` subcommand outputs the agent's full X.509 certificate chain for offline peer identity verification.

### Hardware Presence Enforcement
- `sign` subcommand integrated with the server-side hardware challenge-response flow that rejects bare `client_credentials` for hardware-tier identities.

### Build
- All 5 platform binaries built with full CGo/PIV support
- Windows amd64: signed with Certum code-signing certificate (SHA-256 + timestamp)
- macOS amd64 + arm64: signed with Apple Developer ID + notarized by Apple
- Linux amd64 + arm64: native and cross-compiled with PCSC support
- All binaries: SHA-256 checksums with GPG detached signatures (key: `releases@1id.com`)

## Checksums (SHA-256)

```
71a4b89d66bc712bc77e09f018290e16adfb75bb3fa26c13583735f49d713eea  oneid-enroll-darwin-amd64
45788f3eb0296e4b075a983d5efd9d5d6c420965274a924c16fcf29f56f972ab  oneid-enroll-darwin-arm64
476e149fb27d1024996aab4621b99157e6aebc186c623014f989e78e9d8a3b08  oneid-enroll-linux-amd64
26a3831e719cc47362a190ecc2f4dc3706b8457dfe12908e0f5caa70843baa9d  oneid-enroll-linux-arm64
1057a33a2f47aeeb4061cd7bfd629439a928e408e03e5374654dd50794088c43  oneid-enroll-windows-amd64.exe
```

