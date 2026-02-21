// Package piv handles YubiKey/PIV device detection, key generation,
// attestation extraction, and challenge signing via PCSC.
//
// Uses github.com/go-piv/piv-go which communicates with PIV applets
// through the platform's PC/SC smart card interface (winscard.dll on
// Windows, pcsclite on Linux/macOS).
//
// No elevation/admin privileges required for any PIV operation when
// keys are generated with pin-policy=NEVER and touch-policy=NEVER.
package piv

import (
  "fmt"
)

// DetectedPIVDevice holds information about a detected PIV device.
type DetectedPIVDevice struct {
  Type            string `json:"type"`
  Manufacturer    string `json:"manufacturer"`
  Model           string `json:"model"`
  SerialNumber    string `json:"serial_number"`
  FirmwareVersion string `json:"firmware_version"`
  Status          string `json:"status"`
  HasPIVApplet    bool   `json:"has_piv_applet"`
  ReaderName      string `json:"reader_name"`
}

// DetectPIVDevices scans for connected PIV-capable security keys via PCSC.
//
// Uses the shared OpenFirstAvailablePIVDevice() helper which retries with
// backoff if the PCSC lock is temporarily held by a previous session.
//
// Does NOT require elevation. Uses PCSC (winscard.dll on Windows).
// Through VMware virtual smart card passthrough, the reader name will
// be "VMware Virtual USB CCID" rather than the native Yubico reader name.
func DetectPIVDevices() []DetectedPIVDevice {
  yubikey_connection, reader_name, err := OpenFirstAvailablePIVDevice()
  if err != nil {
    return nil
  }
  defer yubikey_connection.Close()

  device_serial_number, serial_read_err := yubikey_connection.Serial()
  device_firmware_version := yubikey_connection.Version()

  device_status := "ready"
  serial_number_string := ""
  if serial_read_err != nil {
    device_status = "error"
  } else {
    serial_number_string = fmt.Sprintf("%d", device_serial_number)
  }

  return []DetectedPIVDevice{{
    Type:         "yubikey",
    Manufacturer: "Yubico",
    Model: fmt.Sprintf("YubiKey %d.%d.%d",
      device_firmware_version.Major,
      device_firmware_version.Minor,
      device_firmware_version.Patch),
    SerialNumber: serial_number_string,
    FirmwareVersion: fmt.Sprintf("%d.%d.%d",
      device_firmware_version.Major,
      device_firmware_version.Minor,
      device_firmware_version.Patch),
    Status:       device_status,
    HasPIVApplet: true,
    ReaderName:   reader_name,
  }}
}

