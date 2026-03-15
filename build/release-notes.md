## What's new in v0.5.0

### Transient AK Architecture
- TPM Attestation Keys are now created on-demand and never persisted via `EvictControl`. This eliminates the need for `setup-tbs` in most cases and avoids NV storage exhaustion. AKs are recreated for each signing operation using deterministic parameters.

### Hardware-Based Identity Recovery
- When `credentials.json` is lost, the bound hardware (TPM or YubiKey) can prove the agent's identity through challenge-response authentication. The hardware IS the identity.

### Certificate Chain Support (Milestone 9)
- New `--cert-chain-file` flag on `sign` subcommand outputs the agent's full X.509 certificate chain (agent cert → 1ID intermediate → 1ID root) for offline peer identity verification.

### Milestone 10: Hardware Presence Enforcement
- `sign` subcommand integrated with the server-side hardware challenge-response flow that rejects bare `client_credentials` for hardware-tier identities.

### Build
- All 5 platform binaries built with full CGo/PIV support
- Windows: signed with Certum code-signing certificate (SHA-256 + timestamp)
- macOS (amd64 + arm64): signed with Apple Developer ID + notarized
- All binaries: SHA-256 checksums with GPG detached signatures

## Checksums (SHA-256)

```
e405d62fa71499e7d66065190d153cada26fde8a34f23d56493c5f348f899762  oneid-enroll-darwin-amd64
fe226bfdaa63b7cc3064665ed6421d2e4a80a00bebb3caf594aaa17ab403d9db  oneid-enroll-darwin-arm64
dc79e77759e7a94a8559af43d491ccf6671ca041a8aa206267371bcdc5cd46a6  oneid-enroll-linux-amd64
25d8ec83708193eab0e324d934bae233493549776685b10be158f1e00f46db80  oneid-enroll-linux-arm64
1057a33a2f47aeeb4061cd7bfd629439a928e408e03e5374654dd50794088c43  oneid-enroll-windows-amd64.exe
```
