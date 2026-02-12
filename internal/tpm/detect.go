// Package tpm handles TPM 2.0 detection, EK certificate extraction,
// AK generation, and credential activation across Windows and Linux.
//
// Windows: Uses TBS (TPM Base Services) via the go-tpm library.
// Linux:   Uses /dev/tpmrm0 (kernel resource manager) or /dev/tpm0 (raw).
// macOS:   No TPM exists; detection returns empty results gracefully.
package tpm

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DetectedTPM holds information about a detected TPM device.
type DetectedTPM struct {
	Type             string `json:"type"`              // Always "tpm"
	Manufacturer     string `json:"manufacturer"`      // e.g., "INTC", "AMD", "IFX", "VMW"
	ManufacturerName string `json:"manufacturer_name"` // e.g., "Intel", "AMD", "Infineon"
	FirmwareVersion  string `json:"firmware_version"`  // e.g., "600.18.0.0"
	Status           string `json:"status"`            // "ready", "error"
	Interface        string `json:"interface"`         // "tbs" (Windows), "devtpmrm0" (Linux)
	ErrorDetail      string `json:"error_detail,omitempty"`
}

// knownManufacturerCodes maps TPM manufacturer 4-byte ASCII codes to
// human-readable names.
var knownManufacturerCodes = map[string]string{
	"INTC": "Intel",
	"AMD ": "AMD",
	"AMDJ": "AMD",
	"IFX ": "Infineon",
	"STM ": "STMicroelectronics",
	"NTC ": "Nuvoton",
	"ROCC": "Futurex",
	"SMSC": "SMSC",
	"VMW ": "VMware",
	"MSFT": "Microsoft",
	"QCOM": "Qualcomm",
}

// DetectTPMs scans for available TPM devices on this platform.
//
// This does NOT require elevation. It only checks whether a TPM
// device exists and reads basic properties (manufacturer, firmware).
//
// Returns a slice of detected TPMs (usually 0 or 1).
// On unsupported platforms, returns nil.
//
// The actual implementation is in detect_windows.go and detect_linux.go,
// selected at compile time via build tags.
func DetectTPMs() []DetectedTPM {
	return detectTPMsPlatform()
}

// manufacturerCodeToName converts a TPM manufacturer code to a human name.
func manufacturerCodeToName(code string) string {
	if name, found := knownManufacturerCodes[code]; found {
		return name
	}
	return fmt.Sprintf("Unknown (%s)", code)
}

// queryTPMProperties reads manufacturer and firmware info from an open TPM.
// This is shared by all platform-specific detect functions.
func queryTPMProperties(tpmTransport transport.TPMCloser, interfaceName string) []DetectedTPM {
	manufacturer, err := getTPMProperty(tpmTransport, tpm2.TPMPTManufacturer)
	if err != nil {
		return []DetectedTPM{{
			Type:        "tpm",
			Status:      "error",
			Interface:   interfaceName,
			ErrorDetail: fmt.Sprintf("could not read manufacturer: %v", err),
		}}
	}

	manufacturerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(manufacturerBytes, manufacturer)
	manufacturerCode := string(manufacturerBytes)

	fwMajor, _ := getTPMProperty(tpmTransport, tpm2.TPMPTFirmwareVersion1)
	fwMinor, _ := getTPMProperty(tpmTransport, tpm2.TPMPTFirmwareVersion2)

	firmwareVersion := fmt.Sprintf("%d.%d.%d.%d",
		(fwMajor>>16)&0xFFFF, fwMajor&0xFFFF,
		(fwMinor>>16)&0xFFFF, fwMinor&0xFFFF,
	)

	return []DetectedTPM{{
		Type:             "tpm",
		Manufacturer:     manufacturerCode,
		ManufacturerName: manufacturerCodeToName(manufacturerCode),
		FirmwareVersion:  firmwareVersion,
		Status:           "ready",
		Interface:        interfaceName,
	}}
}

// getTPMProperty reads a single fixed TPM property.
func getTPMProperty(tpmTransport transport.TPMCloser, property tpm2.TPMPT) (uint32, error) {
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(property),
		PropertyCount: 1,
	}

	getCapResp, err := getCapCmd.Execute(tpmTransport)
	if err != nil {
		return 0, fmt.Errorf("TPM2_GetCapability failed for property %d: %w", property, err)
	}

	tpmProperties, err := getCapResp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, fmt.Errorf("could not parse TPM properties: %w", err)
	}

	if len(tpmProperties.TPMProperty) == 0 {
		return 0, fmt.Errorf("no property returned for %d", property)
	}

	return tpmProperties.TPMProperty[0].Value, nil
}
