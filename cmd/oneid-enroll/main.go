// oneid-enroll is the HSM helper binary for the 1id.com identity SDK.
//
// It handles all platform-specific hardware security module operations:
// - TPM detection, EK extraction, AK generation, credential activation
// - YubiKey/PIV detection (future)
// - Privilege elevation (UAC, sudo, pkexec, osascript)
//
// The Python and Node.js SDKs spawn this binary and communicate via
// JSON on stdout. Human-readable messages go to stderr.
//
// Usage:
//
//	oneid-enroll detect [--json]
//	oneid-enroll extract [--json] [--elevated] [--type tpm]
//	oneid-enroll activate [--json] [--elevated] --challenge <base64>
//	oneid-enroll version [--json]
//
// The --json flag makes output machine-parseable (default for SDK use).
// The --elevated flag triggers UAC/sudo if not already running as admin.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AuraFriday/oneid-enroll/internal/elevate"
	"github.com/AuraFriday/oneid-enroll/internal/piv"
	"github.com/AuraFriday/oneid-enroll/internal/protocol"
	"github.com/AuraFriday/oneid-enroll/internal/tpm"
	"github.com/google/go-tpm/tpm2/transport"
)

// validateOutputFilePath ensures the --output-file path is safe.
//
// SECURITY: This binary runs as admin/root. A malicious caller could
// pass --output-file C:\Windows\System32\evil.dll to overwrite system
// files. We enforce ALL of the following:
//
//  1. Path resolves to an absolute path with no ".." components
//  2. Path must be inside the system temp directory (os.TempDir())
//  3. Path must be a direct child of temp (no subdirectories)
//  4. Filename must match exactly: oneid-elevated-<digits>.json
//
// The only entity that should ever set --output-file is our own
// elevation code in elevate_windows.go, which creates a temp file
// using os.CreateTemp("", "oneid-elevated-*.json").
func validateOutputFilePath(outputFilePath string) error {
	// Resolve to absolute path
	absPath, err := filepath.Abs(outputFilePath)
	if err != nil {
		return fmt.Errorf("could not resolve output file path: %w", err)
	}

	// Check for path traversal anywhere in the resolved path
	if strings.Contains(absPath, "..") {
		return fmt.Errorf("output file path must not contain '..'")
	}

	// Must be in the system temp directory
	tempDir := os.TempDir()
	absTempDir, _ := filepath.Abs(tempDir)

	// Ensure temp dir ends with separator for strict prefix matching
	// (prevents %TEMP%evil/ matching %TEMP%)
	if !strings.HasSuffix(strings.ToLower(absTempDir), string(filepath.Separator)) {
		absTempDir += string(filepath.Separator)
	}

	if !strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absTempDir)) {
		return fmt.Errorf("output file must be in temp directory (%s), got: %s", absTempDir, absPath)
	}

	// Must be a DIRECT child of temp dir (no subdirectories allowed)
	relativePath, err := filepath.Rel(os.TempDir(), absPath)
	if err != nil || strings.Contains(relativePath, string(filepath.Separator)) {
		return fmt.Errorf("output file must be directly inside temp directory, not in a subdirectory")
	}

	// Filename must match: oneid-elevated-<digits>.json
	// os.CreateTemp inserts a random numeric string where the * is.
	baseName := filepath.Base(absPath)
	const prefix = "oneid-elevated-"
	const suffix = ".json"
	if !strings.HasPrefix(baseName, prefix) || !strings.HasSuffix(baseName, suffix) {
		return fmt.Errorf("output file must match pattern 'oneid-elevated-<digits>.json', got: %s", baseName)
	}
	middle := baseName[len(prefix) : len(baseName)-len(suffix)]
	if len(middle) == 0 {
		return fmt.Errorf("output file must match pattern 'oneid-elevated-<digits>.json', got: %s", baseName)
	}
	for _, c := range middle {
		if c < '0' || c > '9' {
			return fmt.Errorf("output file must match pattern 'oneid-elevated-<digits>.json', got: %s", baseName)
		}
	}

	return nil
}

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	subArgs := os.Args[2:]

	switch subcommand {
	case "detect":
		runDetect(subArgs)
	case "extract":
		runExtract(subArgs)
	case "activate":
		runActivate(subArgs)
	case "version":
		runVersion(subArgs)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `oneid-enroll -- HSM helper for 1id.com identity SDK

Usage:
  oneid-enroll detect    [--json]                      Detect available HSMs
  oneid-enroll extract   [--json] [--elevated]         Extract EK cert + generate AK
  oneid-enroll activate  [--json] [--elevated] --challenge <b64>  Decrypt credential challenge
  oneid-enroll version   [--json]                      Print version
  oneid-enroll help                                    Print this help

Flags:
  --json       Output JSON to stdout (for SDK consumption)
  --elevated   Trigger UAC/sudo if not already running as admin`)
}

// runDetect scans for available HSMs (no elevation required).
func runDetect(args []string) {
	flags := flag.NewFlagSet("detect", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	flags.Parse(args)

	// Detect TPMs
	detectedTPMs := tpm.DetectTPMs()

	// Detect PIV devices (stub -- returns empty in Phase 1)
	detectedPIV := piv.DetectPIVDevices()

	// Build unified HSM list
	type hsmEntry struct {
		Type             string `json:"type"`
		Manufacturer     string `json:"manufacturer,omitempty"`
		ManufacturerName string `json:"manufacturer_name,omitempty"`
		FirmwareVersion  string `json:"firmware_version,omitempty"`
		Status           string `json:"status"`
		Interface        string `json:"interface,omitempty"`
		ErrorDetail      string `json:"error_detail,omitempty"`
	}

	var hsms []hsmEntry

	for _, t := range detectedTPMs {
		hsms = append(hsms, hsmEntry{
			Type:             t.Type,
			Manufacturer:     t.Manufacturer,
			ManufacturerName: t.ManufacturerName,
			FirmwareVersion:  t.FirmwareVersion,
			Status:           t.Status,
			Interface:        t.Interface,
			ErrorDetail:      t.ErrorDetail,
		})
	}

	for _, p := range detectedPIV {
		hsms = append(hsms, hsmEntry{
			Type:             p.Type,
			Manufacturer:     p.Manufacturer,
			FirmwareVersion:  p.FirmwareVersion,
			Status:           p.Status,
		})
	}

	if *jsonOutput {
		protocol.SuccessResponse(map[string]interface{}{
			"hsms":  hsms,
			"count": len(hsms),
		})
	} else {
		if len(hsms) == 0 {
			protocol.HumanMessage("No hardware security modules detected.")
		} else {
			for _, h := range hsms {
				protocol.HumanMessage("Found %s: %s %s (firmware %s, status: %s)",
					h.Type, h.ManufacturerName, h.Manufacturer, h.FirmwareVersion, h.Status)
			}
		}
	}
}

// runExtract reads EK cert and generates AK (requires elevation).
func runExtract(args []string) {
	flags := flag.NewFlagSet("extract", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo")
	hsmType := flags.String("type", "tpm", "HSM type to extract from")
	outputFile := flags.String("output-file", "", "write output to file instead of stdout (used by elevation)")
	// Internal flag: set by the elevation mechanism to prevent recursion.
	// The child process sees this instead of --elevated.
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

	// If --output-file is set, redirect stdout to that file.
	// SECURITY: validate the path to prevent arbitrary file writes as admin.
	if *outputFile != "" {
		if err := validateOutputFilePath(*outputFile); err != nil {
			protocol.HumanMessage("SECURITY: rejected output file path: %v", err)
			os.Exit(1)
		}
		f, err := os.Create(*outputFile)
		if err != nil {
			protocol.HumanMessage("Error: could not create output file %s: %v", *outputFile, err)
			os.Exit(1)
		}
		defer f.Close()
		os.Stdout = f
	}

	// If already elevated (child of UAC), treat as elevated
	if *alreadyElevated {
		*wantElevation = false // Don't try to elevate again -- we already are
	}

	// Handle elevation: only if --elevated was passed AND we're not already elevated
	if *wantElevation && !elevate.IsRunningElevated() {
		protocol.HumanMessage("Requesting administrator privileges...")
		if err := elevate.RelaunchElevated(); err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("UAC_DENIED", err.Error())
			} else {
				protocol.HumanMessage("Elevation failed: %v", err)
				os.Exit(1)
			}
		}
		return // unreachable -- RelaunchElevated calls os.Exit
	}

	switch *hsmType {
	case "tpm":
		runExtractTPM(*jsonOutput)
	default:
		if *jsonOutput {
			protocol.ErrorResponse("UNSUPPORTED_HSM", fmt.Sprintf("HSM type '%s' is not yet supported for extraction", *hsmType))
		} else {
			protocol.HumanMessage("HSM type '%s' is not yet supported", *hsmType)
			os.Exit(1)
		}
	}
}

// runExtractTPM reads EK cert and (optionally) generates AK from a TPM.
func runExtractTPM(jsonOutput bool) {
	// Open TPM
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("NO_HSM_FOUND", fmt.Sprintf("Could not open TPM: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not open TPM: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpmDevice.Close()

	// Extract EK certificate from NV storage
	ekData, err := tpm.ExtractEKCertificate(tpmDevice)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not read EK certificate: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not read EK certificate: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		protocol.SuccessResponse(ekData)
	} else {
		protocol.HumanMessage("EK Certificate extracted successfully")
		protocol.HumanMessage("  Subject:     %s", ekData.SubjectCN)
		protocol.HumanMessage("  Issuer:      %s", ekData.IssuerCN)
		protocol.HumanMessage("  Valid:       %s to %s", ekData.NotBefore, ekData.NotAfter)
		protocol.HumanMessage("  Fingerprint: %s", ekData.Fingerprint)
	}
}

// runActivate decrypts a credential activation challenge.
func runActivate(args []string) {
	flags := flag.NewFlagSet("activate", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo")
	challenge := flags.String("challenge", "", "base64-encoded credential blob")
	outputFile := flags.String("output-file", "", "write output to file instead of stdout (used by elevation)")
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

	// SECURITY: validate output file path to prevent arbitrary file writes as admin.
	if *outputFile != "" {
		if err := validateOutputFilePath(*outputFile); err != nil {
			protocol.HumanMessage("SECURITY: rejected output file path: %v", err)
			os.Exit(1)
		}
		f, err := os.Create(*outputFile)
		if err != nil {
			protocol.HumanMessage("Error: could not create output file %s: %v", *outputFile, err)
			os.Exit(1)
		}
		defer f.Close()
		os.Stdout = f
	}

	if *alreadyElevated {
		*wantElevation = false
	}

	if *challenge == "" {
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", "--challenge is required")
		} else {
			protocol.HumanMessage("Error: --challenge is required")
			os.Exit(1)
		}
		return
	}

	// Handle elevation
	if *wantElevation && !elevate.IsRunningElevated() {
		protocol.HumanMessage("Requesting administrator privileges...")
		if err := elevate.RelaunchElevated(); err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("UAC_DENIED", err.Error())
			} else {
				protocol.HumanMessage("Elevation failed: %v", err)
				os.Exit(1)
			}
		}
		return
	}

	// Credential activation is under development
	if *jsonOutput {
		protocol.ErrorResponse("NOT_IMPLEMENTED", "Credential activation is under development")
	} else {
		protocol.HumanMessage("Credential activation is under development.")
		os.Exit(1)
	}
}

// runVersion prints version info.
func runVersion(args []string) {
	flags := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	flags.Parse(args)

	if *jsonOutput {
		protocol.SuccessResponse(map[string]string{
			"binary":  "oneid-enroll",
			"version": version,
		})
	} else {
		fmt.Printf("oneid-enroll version %s\n", version)
	}
}
