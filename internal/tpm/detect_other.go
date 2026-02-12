//go:build !windows && !linux

package tpm

// detectTPMsPlatform returns nil on platforms without TPM support (macOS, etc.).
func detectTPMsPlatform() []DetectedTPM {
	return nil
}
