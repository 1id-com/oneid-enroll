//go:build !windows

package elevate

// isRunningElevatedWindows is a no-op stub on non-Windows platforms.
// The switch in IsRunningElevated() never calls this on non-Windows,
// but the compiler needs the symbol to exist.
func isRunningElevatedWindows() bool {
	return false
}

// relaunchElevatedWindows is a no-op stub on non-Windows platforms.
func relaunchElevatedWindows(executablePath string, args []string) error {
	return nil
}
