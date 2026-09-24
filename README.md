# oneid-enroll

Cross-platform Go binary for TPM/HSM enrollment operations, used by the
[1id.com](https://1id.com) identity SDK.

This is the hardware security helper for AI agents -- it talks to TPMs, YubiKeys,
and other security hardware that the Python/Node SDKs cannot access directly.

## What it does

- **Detects** TPMs and security keys on the local machine
- **Extracts** Endorsement Key (EK) certificates from TPMs
- **Generates** Attestation Identity Keys (AKs) in the TPM
- **Activates** credential challenges during enrollment
- All operations output JSON for easy SDK integration

## Usage

```bash
# Detect available security hardware
oneid-enroll detect --json

# Get TPM Endorsement Key certificate
oneid-enroll ek --json

# Version info
oneid-enroll version --json
```

The binary is normally invoked automatically by the
[oneid-sdk](https://github.com/1id-com/oneid-sdk) Python package.
You don't need to call it directly unless building a custom integration.

## Pre-built binaries

Pre-built, signed binaries are available in the `build/` folder:

| Platform | Binary |
|----------|--------|
| Windows x64 | `oneid-enroll-windows-amd64.exe` |
| Linux x64 | `oneid-enroll-linux-amd64` |
| Linux ARM64 | `oneid-enroll-linux-arm64` |
| macOS x64 | `oneid-enroll-darwin-amd64` |
| macOS ARM64 | `oneid-enroll-darwin-arm64` |

Each binary has a `.sha256` checksum and `.sha256.asc` GPG signature.
The signing public key is in `signing/release-signing-key.pub.asc`.

## Building from source

Requires Go 1.24+.

```bash
make build          # build for current platform
make build-all      # cross-compile all 5 targets
make sign           # GPG-sign all binaries
make verify         # verify all signatures
```

## Security

- No TPM operation needs elevation (2.0.0+): extraction, enrollment (`import-certify`: TPM2_Import/Load/Certify) and signing all run as the ordinary user on Windows 10/11 (verified 2026-09-24). The retired `activate` used TPM2_ActivateCredential, which Windows blocks for non-elevated processes; `setup-tbs` wrote TBS registry values that have been obsolete since Windows 8, and nothing on the user's machine is changed any more.
- Keys are derived deterministically each time (transient CreatePrimary): no persistent TPM handles, no NV writes
- The `--output-file` flag strictly validates paths to prevent writes outside the system temp directory
- All hardware access code is read-only by design (detect, extract, generate)
- No network access -- the binary never phones home

## License

MIT
