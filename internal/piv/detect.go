// Package piv handles YubiKey/Nitrokey/PIV device detection.
//
// PIV (Personal Identity Verification) devices include:
// - YubiKey 5 series (via PCSC/PIV applet)
// - Nitrokey Pro 2 / Start
// - Feitian ePass FIDO
// - SoloKeys
//
// This is a stub implementation for Phase 1. Full PIV support will
// be added after TPM enrollment is working end-to-end.
package piv

// DetectedPIVDevice holds information about a detected PIV device.
type DetectedPIVDevice struct {
	Type             string `json:"type"`              // "yubikey", "nitrokey", "feitian", "solokeys"
	Manufacturer     string `json:"manufacturer"`      // e.g., "Yubico"
	Model            string `json:"model"`             // e.g., "YubiKey 5 NFC"
	SerialNumber     string `json:"serial_number"`     // Device serial number
	FirmwareVersion  string `json:"firmware_version"`  // Device firmware version
	Status           string `json:"status"`            // "ready", "locked", "error"
	HasPIVApplet     bool   `json:"has_piv_applet"`    // Whether the PIV applet is available
}

// DetectPIVDevices scans for connected PIV-capable security keys.
//
// This does NOT require elevation. It uses PCSC (PC/SC smart card
// interface) to enumerate connected devices and check for PIV applets.
//
// Returns a slice of detected devices (may be empty).
//
// TODO: Implement actual PCSC enumeration using go-piv or similar.
// For Phase 1, this always returns an empty slice.
func DetectPIVDevices() []DetectedPIVDevice {
	// Phase 1 stub: no PIV detection implemented yet.
	// This ensures requests for sovereign-portable tier get a clean
	// NoHSMError ("no compatible HSM found") rather than a crash.
	return nil
}
