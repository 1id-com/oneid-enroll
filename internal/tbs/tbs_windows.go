//go:build windows

// Package tbs manages the Windows registry settings that control
// non-admin access to TPM Base Services (TBS).
//
// The primary mechanism is the TBS SecurityDescriptor:
//
//	HKLM\Software\Microsoft\TPM\Access
//	  SecurityDescriptor (REG_SZ) = SDDL granting AU (Authenticated Users)
//
// When this key exists and includes an AU ACE, all authenticated users
// can submit TPM commands through TBS without elevation: EK read,
// AK creation, ActivateCredential, signing, and quoting.
//
// As a belt-and-suspenders measure, setup-tbs also sets the older:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI
//	  Deny_TBS_Access_From_Non_Admin (DWORD) = 0
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
  "strings"

  "golang.org/x/sys/windows/registry"
)

const (
  tbs_security_descriptor_registry_key_path = `Software\Microsoft\TPM\Access`
  tbs_security_descriptor_value_name        = "SecurityDescriptor"

  // BA = Builtin Administrators, NS = Network Service, LS = Local Service,
  // AU = Authenticated Users. 0x00000001 = TBS access right.
  tbs_security_descriptor_sddl_with_authenticated_users = `O:BAG:BAD:(A;;0x00000001;;;BA)(A;;0x00000001;;;NS)(A;;0x00000001;;;LS)(A;;0x00000001;;;AU)`

  tbs_wmi_registry_key_path           = `SYSTEM\CurrentControlSet\Services\TPM\WMI`
  tbs_deny_nonadmin_access_value_name = "Deny_TBS_Access_From_Non_Admin"
)

// CheckTBSAccessIsGrantedToNonAdminUsers reads the Windows registry
// to determine if the TBS SecurityDescriptor grants access to
// Authenticated Users (AU).
//
// Returns true if HKLM\Software\Microsoft\TPM\Access\SecurityDescriptor
// exists and contains "AU" (meaning all authenticated users can submit
// TPM commands). Returns false if the key is absent or does not include
// the AU ACE.
//
// Any user can call this (reading HKLM requires no special privileges).
//
// Note: PCR_Extend remains blocked for standard users on Windows 10
// 1809+ regardless of registry settings.
func CheckTBSAccessIsGrantedToNonAdminUsers() (bool, error) {
  key, err := registry.OpenKey(registry.LOCAL_MACHINE, tbs_security_descriptor_registry_key_path, registry.QUERY_VALUE)
  if err != nil {
    return false, nil
  }
  defer key.Close()

  sddl_value, _, err := key.GetStringValue(tbs_security_descriptor_value_name)
  if err != nil {
    return false, nil
  }

  return strings.Contains(sddl_value, "AU"), nil
}

// GrantTBSAccessToNonAdminUsersViaRegistryKey sets the TBS
// SecurityDescriptor to grant Authenticated Users (AU) access to all
// non-blocked TPM commands. This is the one-time admin operation that
// enables agents to use TPMs without elevation.
//
// Sets two registry values:
//  1. HKLM\Software\Microsoft\TPM\Access\SecurityDescriptor (primary)
//  2. HKLM\SYSTEM\...\TPM\WMI\Deny_TBS_Access_From_Non_Admin = 0 (compat)
//
// Does NOT enable PCR_Extend for standard users -- that command is on
// the TBS default blocked list which is hardcoded in the TPM driver on
// Windows 10 1809+. Use --elevated for tpm-bind-quote instead.
//
// REQUIRES ADMINISTRATOR PRIVILEGES.
func GrantTBSAccessToNonAdminUsersViaRegistryKey() error {
  tpm_access_key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tbs_security_descriptor_registry_key_path, registry.SET_VALUE)
  if err != nil {
    return fmt.Errorf("could not open/create registry key HKLM\\%s: %w", tbs_security_descriptor_registry_key_path, err)
  }
  defer tpm_access_key.Close()

  if err := tpm_access_key.SetStringValue(tbs_security_descriptor_value_name, tbs_security_descriptor_sddl_with_authenticated_users); err != nil {
    return fmt.Errorf("could not set SecurityDescriptor: %w", err)
  }

  wmi_key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tbs_wmi_registry_key_path, registry.SET_VALUE)
  if err != nil {
    return fmt.Errorf("could not open/create registry key HKLM\\%s: %w", tbs_wmi_registry_key_path, err)
  }
  defer wmi_key.Close()

  if err := wmi_key.SetDWordValue(tbs_deny_nonadmin_access_value_name, 0); err != nil {
    return fmt.Errorf("could not set %s to 0: %w", tbs_deny_nonadmin_access_value_name, err)
  }

  return nil
}
