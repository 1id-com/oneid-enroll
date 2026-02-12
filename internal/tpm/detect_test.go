package tpm

import (
	"runtime"
	"testing"
)

func TestManufacturerCodeToName_KnownCodes(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"INTC", "Intel"},
		{"AMD ", "AMD"},
		{"IFX ", "Infineon"},
		{"STM ", "STMicroelectronics"},
		{"NTC ", "Nuvoton"},
		{"VMW ", "VMware"},
		{"MSFT", "Microsoft"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			result := manufacturerCodeToName(tt.code)
			if result != tt.expected {
				t.Errorf("manufacturerCodeToName(%q) = %q, want %q", tt.code, result, tt.expected)
			}
		})
	}
}

func TestManufacturerCodeToName_UnknownCode(t *testing.T) {
	result := manufacturerCodeToName("ZZZZ")
	if result == "" {
		t.Error("unknown code should return a non-empty string")
	}
	// Should contain the unknown code in the result
	if len(result) < 4 {
		t.Errorf("expected result containing code, got %q", result)
	}
}

func TestDetectTPMs_ReturnsSlice(t *testing.T) {
	// DetectTPMs should return a slice (possibly empty, never error)
	result := DetectTPMs()

	// On Windows with Intel PTT, we expect at least one TPM
	if runtime.GOOS == "windows" {
		// This test may find a TPM on the dev machine
		t.Logf("Detected %d TPM(s)", len(result))
		for i, tpm := range result {
			t.Logf("  TPM[%d]: manufacturer=%s (%s), firmware=%s, status=%s, interface=%s",
				i, tpm.Manufacturer, tpm.ManufacturerName,
				tpm.FirmwareVersion, tpm.Status, tpm.Interface)
		}
	}

	// On any platform, verify structure if TPMs were found
	for _, tpm := range result {
		if tpm.Type != "tpm" {
			t.Errorf("expected Type='tpm', got %q", tpm.Type)
		}
		if tpm.Status != "ready" && tpm.Status != "error" {
			t.Errorf("expected Status='ready' or 'error', got %q", tpm.Status)
		}
	}
}
