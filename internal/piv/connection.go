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
  "time"

  gopiv "github.com/go-piv/piv-go/piv"
)

const (
  pcsc_open_max_retry_attempts        = 3
  pcsc_open_initial_retry_delay       = 500 * time.Millisecond
  pcsc_open_retry_delay_backoff_factor = 2
)

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

