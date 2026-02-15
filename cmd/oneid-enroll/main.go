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
//	oneid-enroll activate [--json] [--elevated] --credential-blob <b64> --encrypted-secret <b64> --ak-handle <hex>
//	oneid-enroll version [--json]
//
// The --json flag makes output machine-parseable (default for SDK use).
// The --elevated flag triggers UAC/sudo if not already running as admin.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/1id-com/oneid-enroll/internal/elevate"
	"github.com/1id-com/oneid-enroll/internal/piv"
	"github.com/1id-com/oneid-enroll/internal/protocol"
	"github.com/1id-com/oneid-enroll/internal/session"
	"github.com/1id-com/oneid-enroll/internal/tpm"
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
	case "sign":
		runSign(subArgs)
	case "session":
		runSession(subArgs)
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
  oneid-enroll detect    [--json]                          Detect available HSMs
  oneid-enroll extract   [--json] [--elevated]             Extract EK cert + generate AK
  oneid-enroll activate  [--json] [--elevated]             Decrypt credential challenge
                         --credential-blob <b64>
                         --encrypted-secret <b64>
                         --ak-handle <hex>
  oneid-enroll sign      [--json]                          Sign a challenge nonce (NO elevation)
                         --nonce <b64>
                         --ak-handle <hex>
  oneid-enroll session   [--elevated] [--pipe <name>]      Interactive session (one UAC)
  oneid-enroll version   [--json]                          Print version
  oneid-enroll help                                        Print this help

Flags:
  --json       Output JSON to stdout (for SDK consumption)
  --elevated   Trigger UAC/sudo if not already running as admin
  --pipe       Named pipe for session I/O (Windows; Linux/macOS uses stdin/stdout)`)
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

// ExtractAndGenerateAKResult combines EK data and AK data for the SDK.
// This is the full attestation data the server needs for enrollment.
type ExtractAndGenerateAKResult struct {
	// EK fields (from tpm.EKData)
	EKCertificatePEM   string   `json:"ek_cert_pem"`
	EKPublicKeyPEM     string   `json:"ek_public_pem"`
	EKCertificateChain []string `json:"chain_pem"`
	EKFingerprint      string   `json:"ek_fingerprint"`
	EKSubjectCN        string   `json:"subject_cn"`
	EKIssuerCN         string   `json:"issuer_cn"`
	EKNotBefore        string   `json:"not_before"`
	EKNotAfter         string   `json:"not_after"`
	// AK fields (from tpm.AKData)
	AKPublicKeyPEM     string `json:"ak_public_pem"`
	AKHandle           string `json:"ak_handle"`
	AKAlgorithm        string `json:"ak_algorithm"`
	AKTPMTPublicBase64 string `json:"ak_tpmt_public_b64"` // Base64-encoded marshaled TPMT_PUBLIC
	AKTPMName          string `json:"ak_tpm_name"`         // Hex-encoded TPM Name
}

// runExtractTPM reads EK cert and generates an AK from a TPM.
// Both pieces of data are needed for the enrollment flow:
//   - EK cert: sent to server for chain validation and MakeCredential
//   - AK public + TPM Name: server uses TPM Name in MakeCredential
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

	// Step 1: Extract EK certificate from NV storage
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

	// Step 2: Get or generate an AK (Attestation Identity Key).
	// If a persistent AK already exists in our handle range, reuse it.
	// Otherwise, create a new one and persist it.
	// The AK is bound to the EK via credential activation -- this binding
	// proves the AK lives inside the same TPM as the EK.
	akData, err := tpm.GetOrCreateAK(tpmDevice)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not generate AK: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not generate AK: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		// Combine EK and AK data into a single response for the SDK.
		// The SDK sends all of this to the server's /enroll/begin endpoint.
		import_b64 := base64.StdEncoding.EncodeToString(akData.TPMTPublicBytes)
		result := ExtractAndGenerateAKResult{
			EKCertificatePEM:   ekData.CertificatePEM,
			EKPublicKeyPEM:     ekData.PublicKeyPEM,
			EKCertificateChain: ekData.CertificateChain,
			EKFingerprint:      ekData.Fingerprint,
			EKSubjectCN:        ekData.SubjectCN,
			EKIssuerCN:         ekData.IssuerCN,
			EKNotBefore:        ekData.NotBefore,
			EKNotAfter:         ekData.NotAfter,
			AKPublicKeyPEM:     akData.PublicKeyPEM,
			AKHandle:           akData.Handle,
			AKAlgorithm:        akData.KeyAlgorithm,
			AKTPMTPublicBase64: import_b64,
			AKTPMName:          akData.TPMName,
		}
		protocol.SuccessResponse(result)
	} else {
		protocol.HumanMessage("EK Certificate extracted successfully")
		protocol.HumanMessage("  Subject:     %s", ekData.SubjectCN)
		protocol.HumanMessage("  Issuer:      %s", ekData.IssuerCN)
		protocol.HumanMessage("  Valid:       %s to %s", ekData.NotBefore, ekData.NotAfter)
		protocol.HumanMessage("  Fingerprint: %s", ekData.Fingerprint)
		protocol.HumanMessage("")
		protocol.HumanMessage("AK generated and persisted")
		protocol.HumanMessage("  Handle:      %s", akData.Handle)
		protocol.HumanMessage("  Algorithm:   %s", akData.KeyAlgorithm)
		protocol.HumanMessage("  TPM Name:    %s", akData.TPMName)
	}
}

// runActivate decrypts a credential activation challenge using the TPM.
//
// This is Phase 2 of enrollment: the server has created a MakeCredential
// challenge (credential_blob + encrypted_secret), and we need the TPM
// to call ActivateCredential to decrypt it, proving this AK is in this TPM.
//
// REQUIRES ELEVATION: uses the EK via endorsement hierarchy.
func runActivate(args []string) {
	flags := flag.NewFlagSet("activate", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo")
	credentialBlobB64 := flags.String("credential-blob", "", "base64-encoded credential blob from server")
	encryptedSecretB64 := flags.String("encrypted-secret", "", "base64-encoded encrypted secret from server")
	akHandleStr := flags.String("ak-handle", "", "AK persistent handle (hex, e.g. 0x81000100)")
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

	// Validate required arguments
	if *credentialBlobB64 == "" || *encryptedSecretB64 == "" || *akHandleStr == "" {
		missingArgs := ""
		if *credentialBlobB64 == "" { missingArgs += " --credential-blob" }
		if *encryptedSecretB64 == "" { missingArgs += " --encrypted-secret" }
		if *akHandleStr == "" { missingArgs += " --ak-handle" }
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", fmt.Sprintf("Required arguments:%s", missingArgs))
		} else {
			protocol.HumanMessage("Error: required arguments:%s", missingArgs)
			os.Exit(1)
		}
		return
	}

	// Parse AK handle (hex string like "0x81000100")
	akHandleClean := strings.TrimPrefix(strings.TrimPrefix(*akHandleStr, "0x"), "0X")
	akHandleVal, err := strconv.ParseUint(akHandleClean, 16, 32)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("Invalid AK handle '%s': %v", *akHandleStr, err))
		} else {
			protocol.HumanMessage("Error: invalid AK handle '%s': %v", *akHandleStr, err)
			os.Exit(1)
		}
		return
	}

	// SECURITY: Validate AK handle is within our expected range (0x81000100-0x810001FF)
	// to prevent using arbitrary persistent handles.
	if akHandleVal < 0x81000100 || akHandleVal > 0x810001FF {
		if *jsonOutput {
			protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf(
				"AK handle 0x%08X is outside the allowed range 0x81000100-0x810001FF", akHandleVal))
		} else {
			protocol.HumanMessage("Error: AK handle 0x%08X is outside the allowed range", akHandleVal)
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

	// Open the TPM
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("NO_HSM_FOUND", fmt.Sprintf("Could not open TPM: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not open TPM: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpmDevice.Close()

	// Call TPM2_ActivateCredential to decrypt the server's challenge.
	// This proves our AK is inside the TPM that owns the EK.
	result, err := tpm.ActivateCredential(
		tpmDevice,
		uint32(akHandleVal),
		*credentialBlobB64,
		*encryptedSecretB64,
	)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("ACTIVATE_CREDENTIAL_FAILED", fmt.Sprintf("TPM2_ActivateCredential failed: %v", err))
		} else {
			protocol.HumanMessage("Error: TPM2_ActivateCredential failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(result)
	} else {
		protocol.HumanMessage("Credential activation successful!")
		protocol.HumanMessage("  Decrypted credential: %s", result.DecryptedCredential)
	}
}

// runSign signs a challenge nonce using the persistent AK.
//
// NO ELEVATION REQUIRED. The AK has UserWithAuth=true, so TPM2_Sign
// works at normal user privilege. This is the core of ongoing TPM-backed
// authentication -- agents sign server-provided nonces to prove they
// still control the same hardware.
func runSign(args []string) {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	nonceB64 := flags.String("nonce", "", "base64-encoded nonce from server")
	akHandleStr := flags.String("ak-handle", "", "AK persistent handle (hex, e.g. 0x81000100)")
	flags.Parse(args)

	// Validate required arguments
	if *nonceB64 == "" || *akHandleStr == "" {
		missingArgs := ""
		if *nonceB64 == "" { missingArgs += " --nonce" }
		if *akHandleStr == "" { missingArgs += " --ak-handle" }
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", fmt.Sprintf("Required arguments:%s", missingArgs))
		} else {
			protocol.HumanMessage("Error: required arguments:%s", missingArgs)
			os.Exit(1)
		}
		return
	}

	// Parse AK handle
	akHandleClean := strings.TrimPrefix(strings.TrimPrefix(*akHandleStr, "0x"), "0X")
	akHandleVal, err := strconv.ParseUint(akHandleClean, 16, 32)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("Invalid AK handle '%s': %v", *akHandleStr, err))
		} else {
			protocol.HumanMessage("Error: invalid AK handle '%s': %v", *akHandleStr, err)
			os.Exit(1)
		}
		return
	}

	// SECURITY: Validate AK handle is within our expected range
	if akHandleVal < 0x81000100 || akHandleVal > 0x810001FF {
		if *jsonOutput {
			protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf(
				"AK handle 0x%08X is outside the allowed range 0x81000100-0x810001FF", akHandleVal))
		} else {
			protocol.HumanMessage("Error: AK handle 0x%08X is outside the allowed range", akHandleVal)
			os.Exit(1)
		}
		return
	}

	// Open TPM -- NO elevation needed for TPM2_Sign with UserWithAuth key
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("NO_HSM_FOUND", fmt.Sprintf("Could not open TPM: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not open TPM: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpmDevice.Close()

	result, err := tpm.SignChallengeWithAK(tpmDevice, uint32(akHandleVal), *nonceB64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("SIGN_FAILED", fmt.Sprintf("TPM signing failed: %v", err))
		} else {
			protocol.HumanMessage("Error: TPM signing failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(result)
	} else {
		protocol.HumanMessage("Challenge signed successfully")
		protocol.HumanMessage("  Algorithm:  %s", result.Algorithm)
		protocol.HumanMessage("  AK Handle:  %s", result.AKHandle)
		protocol.HumanMessage("  Signature:  %s... (%d chars)", result.SignatureBase64[:40], len(result.SignatureBase64))
	}
}

// runSession starts an interactive session.
//
// Session mode keeps the TPM open and accepts multiple commands over a pipe
// or stdin/stdout, requiring only ONE elevation (UAC/sudo) for the entire
// enrollment flow instead of separate elevations for extract and activate.
//
// On Windows: uses a named pipe (passed via --pipe) because ShellExecuteEx
// doesn't pass stdin/stdout to elevated processes.
// On Linux/macOS: uses stdin/stdout (preserved by pkexec/sudo).
func runSession(args []string) {
	flags := flag.NewFlagSet("session", flag.ExitOnError)
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo")
	pipeName := flags.String("pipe", "", "TCP address for session I/O (Windows)")
	sessionToken := flags.String("session-token", "", "authentication token for session (required with --pipe)")
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

	if *alreadyElevated {
		*wantElevation = false
	}

	// Handle elevation
	if *wantElevation && !elevate.IsRunningElevated() {
		protocol.HumanMessage("Requesting administrator privileges...")
		if err := elevate.RelaunchElevated(); err != nil {
			protocol.ErrorResponse("UAC_DENIED", err.Error())
		}
		return
	}

	// SECURITY: Require session token when using TCP socket mode.
	// The token prevents rogue local processes from connecting to the
	// session socket and issuing TPM commands as admin.
	if *pipeName != "" && *sessionToken == "" {
		protocol.ErrorResponse("SESSION_ERROR", "--session-token is required when using --pipe")
		return
	}

	// Determine I/O: TCP socket (Windows) or stdin/stdout (Linux/macOS)
	var reader io.Reader
	var writer io.Writer
	var sessionCloser io.Closer

	if *pipeName != "" {
		// TCP loopback socket mode (Windows elevated processes can't use stdin/stdout).
		// The parent process is listening on this address; we connect to it.
		conn, err := net.Dial("tcp", *pipeName)
		if err != nil {
			protocol.ErrorResponse("SESSION_ERROR", fmt.Sprintf("Could not connect to session socket %s: %v", *pipeName, err))
			return
		}
		sessionCloser = conn
		defer conn.Close()
		reader = conn
		writer = conn
	} else {
		// stdin/stdout mode (Linux/macOS, or direct testing)
		reader = os.Stdin
		writer = os.Stdout
	}
	_ = sessionCloser // used only for cleanup

	if err := session.RunSession(reader, writer, *sessionToken); err != nil {
		protocol.HumanMessage("Session ended with error: %v", err)
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
