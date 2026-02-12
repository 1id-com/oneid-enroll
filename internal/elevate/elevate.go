// Package elevate handles privilege elevation across platforms.
//
// HSM operations (reading EK certs, generating AKs, credential activation)
// require admin/root privileges:
// - Windows: UAC (User Account Control) prompt
// - Linux:   pkexec (polkit) or sudo
// - macOS:   osascript (AppleScript privilege prompt)
//
// When the SDK calls the Go binary with --elevated, this package
// re-launches the binary with elevated privileges if not already running
// as admin/root.
//
// RECURSION GUARD: When re-launching, --elevated is replaced with
// --_already-elevated so the child process NEVER attempts to elevate
// again, regardless of what IsRunningElevated() returns. This prevents
// the fork-bomb scenario where the token check fails on some Windows
// configurations.
package elevate

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// AlreadyElevatedFlag is the internal flag that marks a process as
// having been launched by the elevation mechanism. The child process
// should check for this flag and skip any further elevation attempts.
const AlreadyElevatedFlag = "--_already-elevated"

// WasLaunchedElevated checks if this process was launched by our
// elevation mechanism (i.e., it has the --_already-elevated flag).
// This is the SAFE way to check, because it doesn't depend on
// unreliable Windows token inspection.
func WasLaunchedElevated() bool {
	for _, arg := range os.Args {
		if arg == AlreadyElevatedFlag {
			return true
		}
	}
	return false
}

// IsRunningElevated checks whether the current process has admin/root privileges.
func IsRunningElevated() bool {
	// If we were launched by our own elevation mechanism, trust that
	if WasLaunchedElevated() {
		return true
	}
	switch runtime.GOOS {
	case "windows":
		return isRunningElevatedWindows()
	default:
		// Unix: check if we're root (uid 0)
		return os.Getuid() == 0
	}
}

// RelaunchElevated re-executes the current binary with elevated privileges.
// It replaces the current process -- this function does not return on success.
//
// CRITICAL: This function replaces --elevated with --_already-elevated
// in the child args to prevent infinite recursion.
//
// Returns an error only if elevation fails (e.g., user denied UAC,
// pkexec not available, etc.).
func RelaunchElevated() error {
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}

	// Build child args: replace --elevated with --_already-elevated
	// to prevent the child from ever trying to elevate again.
	var childArgs []string
	for _, arg := range os.Args[1:] {
		if arg == "--elevated" {
			childArgs = append(childArgs, AlreadyElevatedFlag)
		} else {
			childArgs = append(childArgs, arg)
		}
	}

	switch runtime.GOOS {
	case "windows":
		return relaunchElevatedWindows(executablePath, childArgs)
	case "linux":
		return relaunchElevatedLinux(executablePath, childArgs)
	case "darwin":
		return relaunchElevatedDarwin(executablePath, childArgs)
	default:
		return fmt.Errorf("elevation not supported on %s", runtime.GOOS)
	}
}

// relaunchElevatedLinux uses pkexec (polkit) or falls back to sudo.
func relaunchElevatedLinux(executablePath string, args []string) error {
	// Try pkexec first (GUI prompt, no terminal needed)
	pkexecPath, err := exec.LookPath("pkexec")
	if err == nil {
		cmdArgs := append([]string{executablePath}, args...)
		cmd := exec.Command(pkexecPath, cmdArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("pkexec elevation failed (user may have denied): %w", err)
		}
		os.Exit(cmd.ProcessState.ExitCode())
	}

	// Fall back to sudo
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("neither pkexec nor sudo found -- cannot elevate")
	}

	cmdArgs := append([]string{executablePath}, args...)
	cmd := exec.Command(sudoPath, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("sudo elevation failed: %w", err)
	}
	os.Exit(cmd.ProcessState.ExitCode())
	return nil // unreachable
}

// relaunchElevatedDarwin uses osascript to show an authorization dialog.
func relaunchElevatedDarwin(executablePath string, args []string) error {
	shellCmd := executablePath
	for _, arg := range args {
		// Quote args containing spaces
		if strings.Contains(arg, " ") {
			shellCmd += ` \"` + arg + `\"`
		} else {
			shellCmd += " " + arg
		}
	}

	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, shellCmd)
	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("macOS elevation failed (user may have denied): %w", err)
	}
	os.Exit(cmd.ProcessState.ExitCode())
	return nil // unreachable
}
