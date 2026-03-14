//go:build windows

// Package tbs manages two Windows registry settings required for
// non-admin TPM access:
//
// 1. TBS context access (allows opening TBS at all):
//
//	HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI
//	  Deny_TBS_Access_From_Non_Admin (DWORD) = 0
//
// 2. TBS command filtering (allows PCR_Extend and other commands
//    that are on the Windows default blocked list):
//
//	HKLM\SOFTWARE\Policies\Microsoft\TPM
//	  IgnoreDefaultList (DWORD) = 1
//
// Both are one-time admin-required registry writes. After setup-tbs
// runs once with admin, ALL TPM operations work without elevation:
// EK read, AK creation, credential activation, signing, PCR extend,
// and quoting.
package tbs

import (
  "fmt"

  "golang.org/x/sys/windows/registry"
)

const (
  tbs_wmi_registry_key_path                  = `SYSTEM\CurrentControlSet\Services\TPM\WMI`
  tbs_deny_nonadmin_access_value_name        = "Deny_TBS_Access_From_Non_Admin"

  tbs_tpm_policy_registry_key_path           = `SOFTWARE\Policies\Microsoft\TPM`
  tbs_ignore_default_blocked_list_value_name = "IgnoreDefaultList"
)

// CheckTBSAccessIsGrantedToNonAdminUsers checks both registry settings:
// (1) non-admin TBS context access, and (2) default blocked list bypass.
//
// Returns true only if BOTH are correctly configured.
func CheckTBSAccessIsGrantedToNonAdminUsers() (bool, error) {
  tbs_context_access_is_configured, err := checkDenyNonAdminAccessIsDisabled()
  if err != nil {
    return false, err
  }

  default_blocked_list_is_bypassed, err := checkDefaultBlockedListIsIgnored()
  if err != nil {
    return false, err
  }

  return tbs_context_access_is_configured && default_blocked_list_is_bypassed, nil
}

func checkDenyNonAdminAccessIsDisabled() (bool, error) {
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

func checkDefaultBlockedListIsIgnored() (bool, error) {
  key, err := registry.OpenKey(registry.LOCAL_MACHINE, tbs_tpm_policy_registry_key_path, registry.QUERY_VALUE)
  if err != nil {
    return false, nil
  }
  defer key.Close()

  val, _, err := key.GetIntegerValue(tbs_ignore_default_blocked_list_value_name)
  if err != nil {
    return false, nil
  }

  return val == 1, nil
}

// GrantTBSAccessToNonAdminUsersViaRegistryKey sets both registry keys:
// (1) disables non-admin TBS denial, (2) bypasses the default blocked
// command list (which includes PCR_Extend, PCR_Reset, NV_Write, etc.).
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

  tpm_policy_key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tbs_tpm_policy_registry_key_path, registry.SET_VALUE)
  if err != nil {
    return fmt.Errorf("could not open/create registry key %s: %w", tbs_tpm_policy_registry_key_path, err)
  }
  defer tpm_policy_key.Close()

  if err := tpm_policy_key.SetDWordValue(tbs_ignore_default_blocked_list_value_name, 1); err != nil {
    return fmt.Errorf("could not set %s to 1: %w", tbs_ignore_default_blocked_list_value_name, err)
  }

  return nil
}
