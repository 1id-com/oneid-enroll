//go:build windows

// Package tbs manages the Windows registry setting that controls
// whether non-admin users can open TBS contexts at all:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI
//	  Deny_TBS_Access_From_Non_Admin (DWORD) = 0
//
// This one-time admin registry write enables most TPM operations
// without elevation: EK read, AK creation, credential activation,
// signing, and quoting.
//
// IMPORTANT: PCR_Extend is on the TBS default blocked command list
// for standard users. Starting with Windows 10 1809, this list is
// FIXED IN THE TPM DRIVER and cannot be overridden via registry
// settings (IgnoreDefaultList has no effect on TPM 2.0 commands).
// See: https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking
//
// Therefore, tpm-bind-quote (which uses PCR_Extend) always requires
// elevation on Windows. The binary is code-signed so the UAC dialog
// shows a verified publisher.
package tbs

import (
  "fmt"

  "golang.org/x/sys/windows/registry"
)

const (
  tbs_wmi_registry_key_path           = `SYSTEM\CurrentControlSet\Services\TPM\WMI`
  tbs_deny_nonadmin_access_value_name = "Deny_TBS_Access_From_Non_Admin"
)

// CheckTBSAccessIsGrantedToNonAdminUsers reads the Windows registry
// to determine if the TBS access restriction has been lifted.
//
// Returns true if the registry value is set to 0 (access granted).
// Returns false if the key/value doesn't exist or is set to non-zero.
// Any user can call this (reading HKLM requires no special privileges).
//
// Note: this only checks TBS context access. PCR_Extend remains blocked
// for standard users on Windows 10 1809+ regardless of registry settings.
func CheckTBSAccessIsGrantedToNonAdminUsers() (bool, error) {
  key, err := registry.OpenKey(registry.LOCAL_MACHINE, tbs_wmi_registry_key_path, registry.QUERY_VALUE)
  if err != nil {
    return false, nil
  }
  defer key.Close()

  val, _, err := key.GetIntegerValue(tbs_deny_nonadmin_access_value_name)
  if err != nil {
    return false, nil
  }

  return val == 0, nil
}

// GrantTBSAccessToNonAdminUsersViaRegistryKey writes the registry DWORD
// value to 0, allowing non-admin users to open TBS contexts for most
// TPM operations (EK read, AK create, sign, quote).
//
// Does NOT enable PCR_Extend for standard users -- that command is on
// the TBS default blocked list which is hardcoded in the TPM driver on
// Windows 10 1809+. Use --elevated for tpm-bind-quote instead.
//
// REQUIRES ADMINISTRATOR PRIVILEGES.
func GrantTBSAccessToNonAdminUsersViaRegistryKey() error {
  wmi_key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tbs_wmi_registry_key_path, registry.SET_VALUE)
  if err != nil {
    return fmt.Errorf("could not open/create registry key %s: %w", tbs_wmi_registry_key_path, err)
  }
  defer wmi_key.Close()

  if err := wmi_key.SetDWordValue(tbs_deny_nonadmin_access_value_name, 0); err != nil {
    return fmt.Errorf("could not set %s to 0: %w", tbs_deny_nonadmin_access_value_name, err)
  }

  return nil
}
