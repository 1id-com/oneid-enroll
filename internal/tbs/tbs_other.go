//go:build !windows

// Package tbs manages the Windows TPM Base Services (TBS) registry key.
// On non-Windows platforms, all functions are no-ops that report success.
package tbs

// CheckTBSAccessIsGrantedToNonAdminUsers is a no-op on non-Windows.
// TBS is a Windows-only service; other platforms don't restrict TPM access
// based on a registry key.
func CheckTBSAccessIsGrantedToNonAdminUsers() (bool, error) {
  return true, nil
}

// GrantTBSAccessToNonAdminUsersViaRegistryKey is a no-op on non-Windows.
func GrantTBSAccessToNonAdminUsersViaRegistryKey() error {
  return nil
}
