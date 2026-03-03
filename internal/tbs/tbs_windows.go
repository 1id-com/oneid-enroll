//go:build windows

// Package tbs manages the Windows TPM Base Services (TBS) registry key
// that controls whether non-admin users can access TPM operations.
//
// After setup-tbs has been run once (with admin), all subsequent TPM
// operations (EK read, AK creation, credential activation, signing)
// work without elevation.
//
// Registry key:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI
//	Value: Deny_TBS_Access_From_Non_Admin (DWORD)
//	  0 = non-admin users CAN access TBS
//	  1 = non-admin users CANNOT access TBS (Windows default)
package tbs

import (
  "fmt"

  "golang.org/x/sys/windows/registry"
)

const (
  tbs_registry_key_path  = `SYSTEM\CurrentControlSet\Services\TPM\WMI`
  tbs_registry_value_name = "Deny_TBS_Access_From_Non_Admin"
)

// CheckTBSAccessIsGrantedToNonAdminUsers reads the Windows registry
// to determine if the TBS access restriction has been lifted.
//
// Returns true if the registry value is set to 0 (access granted).
// Returns false if the key/value doesn't exist or is set to non-zero.
// Any user can call this (reading HKLM requires no special privileges).
func CheckTBSAccessIsGrantedToNonAdminUsers() (bool, error) {
  key, err := registry.OpenKey(registry.LOCAL_MACHINE, tbs_registry_key_path, registry.QUERY_VALUE)
  if err != nil {
    return false, nil
  }
  defer key.Close()

  val, _, err := key.GetIntegerValue(tbs_registry_value_name)
  if err != nil {
    return false, nil
  }

  return val == 0, nil
}

// GrantTBSAccessToNonAdminUsersViaRegistryKey writes the registry DWORD
// value to 0, allowing non-admin users to access TPM Base Services.
//
// REQUIRES ADMINISTRATOR PRIVILEGES. The caller must be running elevated
// (e.g., via UAC) or this will fail with an access denied error.
func GrantTBSAccessToNonAdminUsersViaRegistryKey() error {
  key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tbs_registry_key_path, registry.SET_VALUE)
  if err != nil {
    return fmt.Errorf("could not open/create registry key %s: %w", tbs_registry_key_path, err)
  }
  defer key.Close()

  if err := key.SetDWordValue(tbs_registry_value_name, 0); err != nil {
    return fmt.Errorf("could not set registry value %s to 0: %w", tbs_registry_value_name, err)
  }

  return nil
}
