//go:build windows

package elevate

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isRunningElevatedWindows checks if the process has admin privileges.
func isRunningElevatedWindows() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.GetCurrentProcessToken()
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// relaunchElevatedWindows uses ShellExecuteExW with "runas" verb for UAC.
//
// Since ShellExecuteEx creates a NEW console for the elevated process,
// stdout/stderr don't flow back to the parent. To capture the output,
// we tell the child to write its output to a temp file using --output-file,
// then the parent reads and prints that file.
func relaunchElevatedWindows(executablePath string, args []string) error {
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteExW := shell32.NewProc("ShellExecuteExW")

	// Create a temp file for the elevated process to write its JSON output
	tempFile, err := os.CreateTemp("", "oneid-elevated-*.json")
	if err != nil {
		return fmt.Errorf("could not create temp file for elevated output: %v", err)
	}
	outputFilePath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(outputFilePath)

	// Add --output-file to the args so the child writes JSON there
	elevatedArgs := append(args, "--output-file", outputFilePath)
	argsStr := strings.Join(elevatedArgs, " ")

	type SHELLEXECUTEINFO struct {
		cbSize       uint32
		fMask        uint32
		hwnd         uintptr
		lpVerb       *uint16
		lpFile       *uint16
		lpParameters *uint16
		lpDirectory  *uint16
		nShow        int32
		hInstApp     uintptr
		lpIDList     uintptr
		lpClass      *uint16
		hkeyClass    uintptr
		dwHotKey     uint32
		hIcon        uintptr
		hProcess     uintptr
	}

	const SEE_MASK_NOCLOSEPROCESS = 0x00000040
	const SW_HIDE = 0 // Hide the elevated console window

	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(executablePath)
	params, _ := windows.UTF16PtrFromString(argsStr)
	dir, _ := windows.UTF16PtrFromString("")

	sei := SHELLEXECUTEINFO{
		fMask:        SEE_MASK_NOCLOSEPROCESS,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        SW_HIDE,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	ret, _, callErr := shellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		return fmt.Errorf("UAC elevation denied or ShellExecuteEx failed: %v", callErr)
	}

	// Wait for the elevated process to finish
	exitCode := uint32(0)
	if sei.hProcess != 0 {
		handle := windows.Handle(sei.hProcess)
		windows.WaitForSingleObject(handle, windows.INFINITE)
		windows.GetExitCodeProcess(handle, &exitCode)
		windows.CloseHandle(handle)
	}

	// Read the output file and print it to our stdout
	outputData, readErr := os.ReadFile(outputFilePath)
	if readErr == nil && len(outputData) > 0 {
		os.Stdout.Write(outputData)
	}

	os.Exit(int(exitCode))
	return nil // unreachable
}
