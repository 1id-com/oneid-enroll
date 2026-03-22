//go:build !darwin

// Package enclave handles Apple Secure Enclave detection, key generation,
// and signing on macOS. On non-macOS platforms, all functions return
// graceful "not available" responses.
//
// The Secure Enclave is available on:
//   - Apple Silicon Macs (M1, M2, M3, M4)
//   - Intel Macs with T2 security chip (MacBook Pro 2018+, Mac mini 2018, iMac Pro)
//
// Key characteristics:
//   - Only supports P-256 (secp256r1) ECDSA keys
//   - Private key never leaves the Secure Enclave hardware
//   - Keys are bound to the specific device (non-portable)
//   - Factory reset destroys keys (NOT Sybil-resistant)
package enclave

// DetectSecureEnclave checks if Apple Secure Enclave is available.
// On non-macOS platforms, always returns nil (no Enclave possible).
func DetectSecureEnclave() []DetectedSecureEnclave {
  return nil
}

