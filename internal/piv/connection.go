// Centralized PCSC connection management for PIV devices.
//
// go-piv's Open() takes an exclusive PCSC lock on the smart card reader.
// If a previous process exited without calling Close(), or if the OS PCSC
// daemon hasn't released the lock yet, Open() will fail immediately.
//
// This is especially common with VMware virtual smart card passthrough,
// where the PCSC lock release can lag behind process termination.
//
// This module provides a retry-with-backoff wrapper that handles transient
// lock contention without requiring a physical unplug/replug cycle.

package piv

import (
  "fmt"
  "strings"
  "time"

  gopiv "github.com/go-piv/piv-go/piv"
)

const (
  pcsc_open_max_retry_attempts        = 3
  pcsc_open_initial_retry_delay       = 500 * time.Millisecond
  pcsc_open_retry_delay_backoff_factor = 2
)

// CROSS_IMPL_SYNC: piv_sign, piv_multi_key
// Implementations: py:oneid/helper.py go:internal/piv/connection.go node:src/helper.ts
//
// OpenFirstAvailablePIVDevice enumerates PCSC readers, finds the first one
// that responds as a YubiKey PIV device, and returns an open connection.
//
// Retries with exponential backoff if the initial Open() fails due to
// PCSC lock contention (common after rapid sequential commands or through
// VMware virtual smart card passthrough).
//
// IMPORTANT: The caller MUST call Close() on the returned YubiKey when done.
// Use defer immediately after a successful return:
//
//	yubikey, readerName, err := OpenFirstAvailablePIVDevice()
//	if err != nil { return err }
//	defer yubikey.Close()
func OpenFirstAvailablePIVDevice() (*gopiv.YubiKey, string, error) {
  var last_open_error error

  for attempt_number := 0; attempt_number < pcsc_open_max_retry_attempts; attempt_number++ {
    if attempt_number > 0 {
      retry_delay := pcsc_open_initial_retry_delay
      for backoff_step := 1; backoff_step < attempt_number; backoff_step++ {
        retry_delay *= time.Duration(pcsc_open_retry_delay_backoff_factor)
      }
      time.Sleep(retry_delay)
    }

    card_reader_names, err := gopiv.Cards()
    if err != nil {
      last_open_error = fmt.Errorf("could not list smart card readers: %w", err)
      continue
    }
    if len(card_reader_names) == 0 {
      last_open_error = fmt.Errorf("no smart card readers found (attempt %d/%d)",
        attempt_number+1, pcsc_open_max_retry_attempts)
      continue
    }

    for _, reader_name := range card_reader_names {
      yubikey_connection, open_err := gopiv.Open(reader_name)
      if open_err != nil {
        last_open_error = fmt.Errorf("could not open reader %q: %w", reader_name, open_err)
        continue
      }
      return yubikey_connection, reader_name, nil
    }
  }

  return nil, "", fmt.Errorf("could not open any PIV device after %d attempts (last error: %w)",
    pcsc_open_max_retry_attempts, last_open_error)
}

// OpenPIVDeviceByReaderNameSubstring opens a specific PIV device whose PC/SC
// reader name contains the given substring. This supports both --reader (partial
// reader name match, e.g. "Yubikey" or "Yubico YubiKey OTP+FIDO+CCID 01") and
// --serial targeting (caller converts serial to a reader-name substring first).
//
// Uses the same retry-with-backoff strategy as OpenFirstAvailablePIVDevice.
//
// IMPORTANT: The caller MUST call Close() on the returned YubiKey when done.
func OpenPIVDeviceByReaderNameSubstring(reader_name_substring string) (*gopiv.YubiKey, string, error) {
  var last_open_error error

  for attempt_number := 0; attempt_number < pcsc_open_max_retry_attempts; attempt_number++ {
    if attempt_number > 0 {
      retry_delay := pcsc_open_initial_retry_delay
      for backoff_step := 1; backoff_step < attempt_number; backoff_step++ {
        retry_delay *= time.Duration(pcsc_open_retry_delay_backoff_factor)
      }
      time.Sleep(retry_delay)
    }

    card_reader_names, err := gopiv.Cards()
    if err != nil {
      last_open_error = fmt.Errorf("could not list smart card readers: %w", err)
      continue
    }

    for _, reader_name := range card_reader_names {
      if !strings.Contains(strings.ToLower(reader_name), strings.ToLower(reader_name_substring)) {
        continue
      }
      yubikey_connection, open_err := gopiv.Open(reader_name)
      if open_err != nil {
        last_open_error = fmt.Errorf("could not open reader %q: %w", reader_name, open_err)
        continue
      }
      return yubikey_connection, reader_name, nil
    }
    last_open_error = fmt.Errorf("no reader matching %q found among %d readers",
      reader_name_substring, len(card_reader_names))
  }

  return nil, "", fmt.Errorf("could not open PIV device matching %q after %d attempts (last error: %w)",
    reader_name_substring, pcsc_open_max_retry_attempts, last_open_error)
}

// OpenPIVDeviceBySerialNumber opens a specific PIV device by its YubiKey serial
// number. Enumerates all readers, opens each that looks like a YubiKey, checks
// the serial, and returns the connection whose serial matches.
//
// This is the primary mechanism for multi-YubiKey selection: the caller passes
// the serial number of the enrolled device (from credentials.json), and this
// function ensures the correct key is opened even when multiple keys are connected.
//
// IMPORTANT: The caller MUST call Close() on the returned YubiKey when done.
func OpenPIVDeviceBySerialNumber(target_serial_number uint32) (*gopiv.YubiKey, string, error) {
  var last_open_error error

  for attempt_number := 0; attempt_number < pcsc_open_max_retry_attempts; attempt_number++ {
    if attempt_number > 0 {
      retry_delay := pcsc_open_initial_retry_delay
      for backoff_step := 1; backoff_step < attempt_number; backoff_step++ {
        retry_delay *= time.Duration(pcsc_open_retry_delay_backoff_factor)
      }
      time.Sleep(retry_delay)
    }

    card_reader_names, err := gopiv.Cards()
    if err != nil {
      last_open_error = fmt.Errorf("could not list smart card readers: %w", err)
      continue
    }

    for _, reader_name := range card_reader_names {
      yubikey_connection, open_err := gopiv.Open(reader_name)
      if open_err != nil {
        last_open_error = fmt.Errorf("could not open reader %q: %w", reader_name, open_err)
        continue
      }
      device_serial, serial_err := yubikey_connection.Serial()
      if serial_err != nil {
        yubikey_connection.Close()
        last_open_error = fmt.Errorf("could not read serial from %q: %w", reader_name, serial_err)
        continue
      }
      if device_serial == target_serial_number {
        return yubikey_connection, reader_name, nil
      }
      yubikey_connection.Close()
    }
    last_open_error = fmt.Errorf("no YubiKey with serial %d found among readers", target_serial_number)
  }

  return nil, "", fmt.Errorf("could not find PIV device with serial %d after %d attempts (last error: %w)",
    target_serial_number, pcsc_open_max_retry_attempts, last_open_error)
}

