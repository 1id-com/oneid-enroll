//go:build !windows

package elevate

import "fmt"

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

// RunSubcommandElevated is a no-op stub on non-Windows platforms.
// TBS does not exist outside Windows, so this is never called.
func RunSubcommandElevated(subcommand_args []string) (uint32, []byte, error) {
	return 1, nil, fmt.Errorf("RunSubcommandElevated is only supported on Windows")
}
