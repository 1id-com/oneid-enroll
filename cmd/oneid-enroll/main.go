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
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"runtime"

	"github.com/1id-com/oneid-enroll/internal/elevate"
	"github.com/1id-com/oneid-enroll/internal/enclave"
	"github.com/1id-com/oneid-enroll/internal/piv"
	"github.com/1id-com/oneid-enroll/internal/protocol"
	"github.com/1id-com/oneid-enroll/internal/session"
	"github.com/1id-com/oneid-enroll/internal/tbs"
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

var version = "0.7.0"

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
	case "piv-sign":
		runPIVSignArbitraryData(subArgs)
	case "tpm-bind-quote":
		runTPMBindQuote(subArgs)
	case "piv-bind-ceremony":
		runPIVBindCeremony(subArgs)
	case "setup-tbs":
		runSetupTBS(subArgs)
	case "session":
		runSession(subArgs)
	case "version":
		runVersion(subArgs)
	case "test-enclave":
		runTestEnclave(subArgs)
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
  oneid-enroll detect    [--json]                          Detect available HSMs (TPM + PIV)
  oneid-enroll setup-tbs [--json] [--elevated]             One-time: grant non-admin TBS access (Windows)
  oneid-enroll extract   [--json] [--elevated]             Extract attestation data
                         [--type tpm|yubikey|enclave]        tpm: EK cert + AK
                                                             yubikey: PIV attestation (no elevation)
                                                             enclave: Secure Enclave P-256 key (macOS)
  oneid-enroll activate  [--json] [--elevated]             Decrypt credential challenge (TPM only)
                         --credential-blob <b64>
                         --encrypted-secret <b64>
                         --ak-handle <hex>
  oneid-enroll sign      [--json]                          Sign a challenge nonce (NO elevation)
                         --nonce <b64>
                         [--type tpm|yubikey]                tpm: requires --ak-handle
                         [--ak-handle <hex>]                 yubikey: uses slot 9a automatically
                         [--output-clock]                    (tpm only) also TPM Quote for clock capture
  oneid-enroll piv-sign  [--json]                          Sign arbitrary data with PIV slot 9a
                         --data <b64>
  oneid-enroll tpm-bind-quote [--json] [--elevated]         Extend PCR + Quote for co-location binding
                         --extend-pcr <num>                  (Windows: --elevated required; PCR_Extend
                         --extend-data <b64>                  is blocked by TBS for standard users)
                         --qualifying-data <b64>
                         --ak-handle <hex>
  oneid-enroll session   [--elevated] [--pipe <name>]      Interactive session (one UAC, TPM only)
  oneid-enroll version   [--json]                          Print version
  oneid-enroll help                                        Print this help

Flags:
  --json       Output JSON to stdout (for SDK consumption)
  --elevated   Trigger UAC/sudo if not already running as admin
  --type       HSM type: tpm (default), yubikey, or enclave
  --pipe       Named pipe for session I/O (Windows; Linux/macOS uses stdin/stdout)`)
}

// runSetupTBS configures the Windows registry to allow non-admin users
// to access TPM Base Services (TBS). This is a one-time operation that
// requires administrator privileges. After this, all TPM operations
// (extract, activate, sign) work without elevation.
//
// On non-Windows platforms, this is a no-op that reports success.
func runSetupTBS(args []string) {
	flags := flag.NewFlagSet("setup-tbs", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo")
	outputFile := flags.String("output-file", "", "write output to file instead of stdout (used by elevation)")
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

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

	if runtime.GOOS != "windows" {
		if *jsonOutput {
			protocol.SuccessResponse(map[string]interface{}{
				"ok":          true,
				"already_set": true,
				"platform":    "not_windows",
				"message":     "TBS configuration is Windows-only; no action needed on " + runtime.GOOS,
			})
		} else {
			protocol.HumanMessage("TBS configuration is Windows-only. No action needed on %s.", runtime.GOOS)
		}
		return
	}

	tbs_access_is_already_configured, err := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("TBS_CHECK_FAILED", fmt.Sprintf("Could not check TBS registry state: %v", err))
		} else {
			protocol.HumanMessage("Error: could not check TBS registry state: %v", err)
			os.Exit(1)
		}
		return
	}

	if tbs_access_is_already_configured {
		if *jsonOutput {
			protocol.SuccessResponse(map[string]interface{}{
				"ok":          true,
				"already_set": true,
			})
		} else {
			protocol.HumanMessage("TBS access is already configured for non-admin users. No changes needed.")
		}
		return
	}

	if *wantElevation && !elevate.IsRunningElevated() {
		protocol.HumanMessage("Requesting administrator privileges to set TBS registry key...")
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

	if !elevate.IsRunningElevated() {
		if *jsonOutput {
			protocol.ErrorResponse("TBS_ACCESS_NOT_CONFIGURED",
				"TBS access is not configured for non-admin users. Run with --elevated to set the registry key.")
		} else {
			protocol.HumanMessage("Error: TBS access is not configured. Run with --elevated to set the registry key.")
			os.Exit(1)
		}
		return
	}

	if err := tbs.GrantTBSAccessToNonAdminUsersViaRegistryKey(); err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("TBS_SET_FAILED", fmt.Sprintf("Could not set TBS registry key: %v", err))
		} else {
			protocol.HumanMessage("Error: could not set TBS registry key: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(map[string]interface{}{
			"ok":          true,
			"already_set": false,
		})
	} else {
		protocol.HumanMessage("TBS access configured successfully. Non-admin users can now access the TPM.")
		protocol.HumanMessage("All future TPM operations (extract, activate, sign) will work without elevation.")
	}
}

// runDetect scans for available HSMs (no elevation required).
func runDetect(args []string) {
	flags := flag.NewFlagSet("detect", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	flags.Parse(args)

	// Detect TPMs
	detectedTPMs := tpm.DetectTPMs()

	detectedPIV := piv.DetectPIVDevices()

	detectedEnclaves := enclave.DetectSecureEnclave()

	type hsmEntry struct {
		Type             string `json:"type"`
		Manufacturer     string `json:"manufacturer,omitempty"`
		ManufacturerName string `json:"manufacturer_name,omitempty"`
		FirmwareVersion  string `json:"firmware_version,omitempty"`
		Status           string `json:"status"`
		Interface        string `json:"interface,omitempty"`
		Platform         string `json:"platform,omitempty"`
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

	for _, e := range detectedEnclaves {
		if e.HasSecureEnclave {
			hsms = append(hsms, hsmEntry{
				Type:         e.Type,
				Manufacturer: "Apple",
				Status:       e.Status,
				Platform:     e.Platform,
			})
		}
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

	// On Windows for TPM: try accessing the TPM at current privilege level first.
	// With transient-only AK architecture, CreatePrimary does NOT need elevation
	// (after one-time TBS setup). So if OpenTPM works, skip UAC entirely.
	//
	// Result:
	//   - 0 UAC prompts when TBS was previously configured
	//   - 1 UAC prompt on first-ever use (to set the TBS registry key)
	//   - Never 2+ prompts
	if *wantElevation && !elevate.IsRunningElevated() && runtime.GOOS == "windows" && (*hsmType == "tpm" || *hsmType == "") {
		tpm_probe, tpm_probe_err := transport.OpenTPM()
		if tpm_probe_err == nil {
			tpm_probe.Close()
			protocol.HumanMessage("TPM accessible without elevation -- skipping UAC")
			*wantElevation = false
		} else {
			tbs_is_configured, _ := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
			if !tbs_is_configured {
				protocol.HumanMessage("TPM not accessible -- configuring TBS for non-admin access (one-time setup)...")
				exit_code, _, setup_err := elevate.RunSubcommandElevated([]string{"setup-tbs", "--json"})
				if setup_err == nil && exit_code == 0 {
					tpm_retry, retry_err := transport.OpenTPM()
					if retry_err == nil {
						tpm_retry.Close()
						protocol.HumanMessage("TBS configured -- TPM now accessible without elevation")
						*wantElevation = false
					}
				}
			}
		}
	}

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
	case "yubikey", "piv":
		runExtractPIV(*jsonOutput)
	case "enclave", "secure_enclave":
		runExtractEnclave(*jsonOutput)
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
		tbs_access_is_configured, _ := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
		if !tbs_access_is_configured && !elevate.IsRunningElevated() {
			if jsonOutput {
				protocol.ErrorResponse("TBS_ACCESS_DENIED",
					"TPM detected but TBS access is not configured for non-admin users. "+
						"Run 'oneid-enroll setup-tbs --elevated --json' first (one-time setup).")
			} else {
				protocol.HumanMessage("Error: TPM access denied. TBS is not configured for non-admin users.")
				protocol.HumanMessage("Run: oneid-enroll setup-tbs --elevated")
				os.Exit(1)
			}
			return
		}
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

	// Step 2: Create a transient AK (Attestation Identity Key).
	// The AK is deterministic: same template + same hierarchy seed = same key
	// every time on the same TPM. No NV persistence needed (no EvictControl).
	// The AK is bound to the EK via credential activation -- this binding
	// proves the AK lives inside the same TPM as the EK.
	akData, err := tpm.CreateTransientAK(tpmDevice)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not generate AK: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not generate AK: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpm.FlushTransientAK(tpmDevice, akData)

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
		protocol.HumanMessage("AK generated (transient, deterministic)")
		protocol.HumanMessage("  Handle:      %s", akData.Handle)
		protocol.HumanMessage("  Algorithm:   %s", akData.KeyAlgorithm)
		protocol.HumanMessage("  TPM Name:    %s", akData.TPMName)
	}
}

// runExtractPIV generates (or reuses) a PIV key and extracts attestation data.
//
// This is the YubiKey equivalent of runExtractTPM. Instead of EK+AK, it uses
// PIV attestation certificates to prove the key lives on genuine Yubico hardware.
//
// NO ELEVATION REQUIRED: PIV operations go through PCSC, not privileged
// hardware interfaces. With pin-policy=NEVER, no human interaction needed.
func runExtractPIV(jsonOutput bool) {
	piv_extract_result, err := piv.ExtractPIVAttestationAndEnsureKeyExists(piv.DefaultManagementKey)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("PIV extraction failed: %v", err))
		} else {
			protocol.HumanMessage("Error: PIV extraction failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		protocol.SuccessResponse(piv_extract_result)
	} else {
		generated_or_reused_label := "Existing key reused"
		if piv_extract_result.KeyWasNewlyGenerated {
			generated_or_reused_label = "New key generated"
		}
		protocol.HumanMessage("PIV attestation extracted successfully")
		protocol.HumanMessage("  Serial:       %s", piv_extract_result.SerialNumber)
		protocol.HumanMessage("  Firmware:     %s", piv_extract_result.FirmwareVersion)
		protocol.HumanMessage("  Slot:         %s", piv_extract_result.SlotName)
		protocol.HumanMessage("  Algorithm:    %s", piv_extract_result.Algorithm)
		protocol.HumanMessage("  PIN policy:   %s", piv_extract_result.PINPolicy)
		protocol.HumanMessage("  Touch policy: %s", piv_extract_result.TouchPolicy)
		protocol.HumanMessage("  Key status:   %s", generated_or_reused_label)
	}
}

// runExtractEnclave generates (or reuses) a P-256 key in the Apple Secure Enclave.
//
// NO ELEVATION REQUIRED: Secure Enclave keys are accessed through the Keychain,
// which is available to the current user without admin privileges.
//
// The key is tagged with "com.1id.enclave.default" in the Keychain.
// Future: the tag should include the agent_id for multi-identity support.
func runExtractEnclave(jsonOutput bool) {
	const enclave_keychain_application_tag = "com.1id.enclave.default"

	result, err := enclave.GenerateOrRetrieveEnclaveKey(enclave_keychain_application_tag)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Secure Enclave extraction failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Secure Enclave extraction failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		protocol.SuccessResponse(result)
	} else {
		generated_or_reused_label := "Existing key reused"
		if result.KeyWasNewlyGenerated {
			generated_or_reused_label = "New key generated in Secure Enclave"
		}
		protocol.HumanMessage("Secure Enclave key extracted successfully")
		protocol.HumanMessage("  Algorithm:  %s", result.Algorithm)
		protocol.HumanMessage("  Key tag:    %s", result.KeyTag)
		protocol.HumanMessage("  Key status: %s", generated_or_reused_label)
	}
}

// runSignEnclave signs a nonce with the Secure Enclave key.
//
// NO ELEVATION REQUIRED.
func runSignEnclave(jsonOutput bool, nonceB64 string, identity_certificate_chain_pem string) {
	const enclave_keychain_application_tag = "com.1id.enclave.default"

	result, err := enclave.SignChallengeWithEnclaveKey(nonceB64, enclave_keychain_application_tag)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("SIGN_FAILED", fmt.Sprintf("Secure Enclave signing failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Secure Enclave signing failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		if identity_certificate_chain_pem != "" {
			protocol.SuccessResponse(map[string]interface{}{
				"signature_b64":                  result.SignatureBase64,
				"algorithm":                      result.Algorithm,
				"key_tag":                         result.KeyTag,
				"identity_certificate_chain_pem": identity_certificate_chain_pem,
			})
		} else {
			protocol.SuccessResponse(result)
		}
	} else {
		protocol.HumanMessage("Challenge signed successfully (Secure Enclave)")
		protocol.HumanMessage("  Algorithm:  %s", result.Algorithm)
		protocol.HumanMessage("  Key tag:    %s", result.KeyTag)
		signature_preview_length := 40
		if len(result.SignatureBase64) < signature_preview_length {
			signature_preview_length = len(result.SignatureBase64)
		}
		protocol.HumanMessage("  Signature:  %s... (%d chars)", result.SignatureBase64[:signature_preview_length], len(result.SignatureBase64))
		if identity_certificate_chain_pem != "" {
			protocol.HumanMessage("  Cert chain: included (%d bytes)", len(identity_certificate_chain_pem))
		}
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
	if *credentialBlobB64 == "" || *encryptedSecretB64 == "" {
		missingArgs := ""
		if *credentialBlobB64 == "" { missingArgs += " --credential-blob" }
		if *encryptedSecretB64 == "" { missingArgs += " --encrypted-secret" }
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", fmt.Sprintf("Required arguments:%s", missingArgs))
		} else {
			protocol.HumanMessage("Error: required arguments:%s", missingArgs)
			os.Exit(1)
		}
		return
	}

	// Parse AK handle if provided (backward compat with persistent AKs).
	// If empty or "transient", we recreate the AK on-demand (preferred path).
	use_transient_ak := *akHandleStr == "" || *akHandleStr == "transient"
	var akHandleVal uint64
	if !use_transient_ak {
		akHandleClean := strings.TrimPrefix(strings.TrimPrefix(*akHandleStr, "0x"), "0X")
		var parse_err error
		akHandleVal, parse_err = strconv.ParseUint(akHandleClean, 16, 32)
		if parse_err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("Invalid AK handle '%s': %v", *akHandleStr, parse_err))
			} else {
				protocol.HumanMessage("Error: invalid AK handle '%s': %v", *akHandleStr, parse_err)
				os.Exit(1)
			}
			return
		}
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
	}

	// On Windows: try the TPM at current privilege level first.
	// With transient-only architecture, no elevation is needed for ActivateCredential
	// (after one-time TBS setup).
	if *wantElevation && !elevate.IsRunningElevated() && runtime.GOOS == "windows" {
		tpm_probe, tpm_probe_err := transport.OpenTPM()
		if tpm_probe_err == nil {
			tpm_probe.Close()
			protocol.HumanMessage("TPM accessible without elevation -- skipping UAC")
			*wantElevation = false
		} else {
			tbs_is_configured, _ := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
			if !tbs_is_configured {
				protocol.HumanMessage("TPM not accessible -- configuring TBS for non-admin access (one-time setup)...")
				exit_code, _, setup_err := elevate.RunSubcommandElevated([]string{"setup-tbs", "--json"})
				if setup_err == nil && exit_code == 0 {
					tpm_retry, retry_err := transport.OpenTPM()
					if retry_err == nil {
						tpm_retry.Close()
						protocol.HumanMessage("TBS configured -- TPM now accessible without elevation")
						*wantElevation = false
					}
				}
			}
		}
	}

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
		tbs_access_is_configured, _ := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
		if !tbs_access_is_configured && !elevate.IsRunningElevated() {
			if *jsonOutput {
				protocol.ErrorResponse("TBS_ACCESS_DENIED",
					"TPM detected but TBS access is not configured for non-admin users. "+
						"Run 'oneid-enroll setup-tbs --elevated --json' first (one-time setup).")
			} else {
				protocol.HumanMessage("Error: TPM access denied. TBS is not configured for non-admin users.")
				protocol.HumanMessage("Run: oneid-enroll setup-tbs --elevated")
				os.Exit(1)
			}
			return
		}
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
	// Preferred: recreate transient AK (deterministic, no persistent handle needed).
	// Fallback: use provided persistent handle for backward compat.
	var result *tpm.ActivateCredentialResult
	if use_transient_ak {
		result, err = tpm.ActivateCredentialWithTransientAK(
			tpmDevice,
			*credentialBlobB64,
			*encryptedSecretB64,
		)
	} else {
		result, err = tpm.ActivateCredential(
			tpmDevice,
			uint32(akHandleVal),
			*credentialBlobB64,
			*encryptedSecretB64,
		)
	}
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

// runSign signs a challenge nonce using a hardware-backed key.
//
// For TPM: uses the persistent AK. NO ELEVATION REQUIRED (UserWithAuth=true).
// For PIV/YubiKey: uses the slot 9a key. NO ELEVATION REQUIRED (pin-policy=NEVER).
//
// This is the core of ongoing hardware-backed authentication -- agents sign
// server-provided nonces to prove they still control the same hardware.
func runSign(args []string) {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	nonceB64 := flags.String("nonce", "", "base64-encoded nonce from server")
	akHandleStr := flags.String("ak-handle", "", "AK persistent handle (hex, e.g. 0x81000100) [TPM only]")
	hsmType := flags.String("type", "tpm", "HSM type: tpm or yubikey")
	outputClock := flags.Bool("output-clock", false, "also perform TPM Quote for clock capture [TPM only]")
	certChainFile := flags.String("cert-chain-file", "", "path to PEM certificate chain file (included in proof bundle output)")
	flags.Parse(args)

	if *nonceB64 == "" {
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", "Required argument: --nonce")
		} else {
			protocol.HumanMessage("Error: required argument: --nonce")
			os.Exit(1)
		}
		return
	}

	// Load certificate chain for proof bundle assembly (optional)
	var identity_certificate_chain_pem string
	if *certChainFile != "" {
		chain_bytes, read_err := os.ReadFile(*certChainFile)
		if read_err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("CERT_CHAIN_READ_ERROR", fmt.Sprintf("Could not read cert chain file: %v", read_err))
			} else {
				protocol.HumanMessage("Error: could not read cert chain file: %v", read_err)
				os.Exit(1)
			}
			return
		}
		identity_certificate_chain_pem = string(chain_bytes)
	}

	switch *hsmType {
	case "yubikey", "piv":
		if *outputClock {
			if *jsonOutput {
				protocol.ErrorResponse("UNSUPPORTED_OPTION", "--output-clock is only supported for TPM signing")
			} else {
				protocol.HumanMessage("Error: --output-clock is only supported for TPM signing")
				os.Exit(1)
			}
			return
		}
		runSignPIV(*jsonOutput, *nonceB64, identity_certificate_chain_pem)
	case "tpm":
		runSignTPM(*jsonOutput, *nonceB64, *akHandleStr, *outputClock, identity_certificate_chain_pem)
	case "enclave", "secure_enclave":
		if *outputClock {
			if *jsonOutput {
				protocol.ErrorResponse("UNSUPPORTED_OPTION", "--output-clock is only supported for TPM signing")
			} else {
				protocol.HumanMessage("Error: --output-clock is only supported for TPM signing")
				os.Exit(1)
			}
			return
		}
		runSignEnclave(*jsonOutput, *nonceB64, identity_certificate_chain_pem)
	default:
		if *jsonOutput {
			protocol.ErrorResponse("UNSUPPORTED_HSM", fmt.Sprintf("HSM type '%s' is not supported for signing", *hsmType))
		} else {
			protocol.HumanMessage("HSM type '%s' is not supported for signing", *hsmType)
			os.Exit(1)
		}
	}
}

// runSignTPM signs a nonce with the TPM AK.
// Preferred: recreates transient AK (deterministic). Fallback: persistent handle.
// When outputClock is true, also performs a TPM Quote for clock capture.
func runSignTPM(jsonOutput bool, nonceB64 string, akHandleStr string, outputClock bool, identity_certificate_chain_pem string) {
	use_transient_ak := akHandleStr == "" || akHandleStr == "transient"
	var akHandleVal uint64
	if !use_transient_ak {
		akHandleClean := strings.TrimPrefix(strings.TrimPrefix(akHandleStr, "0x"), "0X")
		var parse_err error
		akHandleVal, parse_err = strconv.ParseUint(akHandleClean, 16, 32)
		if parse_err != nil {
			if jsonOutput {
				protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("Invalid AK handle '%s': %v", akHandleStr, parse_err))
			} else {
				protocol.HumanMessage("Error: invalid AK handle '%s': %v", akHandleStr, parse_err)
				os.Exit(1)
			}
			return
		}
		if akHandleVal < 0x81000100 || akHandleVal > 0x810001FF {
			if jsonOutput {
				protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf(
					"AK handle 0x%08X is outside the allowed range 0x81000100-0x810001FF", akHandleVal))
			} else {
				protocol.HumanMessage("Error: AK handle 0x%08X is outside the allowed range", akHandleVal)
				os.Exit(1)
			}
			return
		}
	}

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

	var result *tpm.SignChallengeResult
	if use_transient_ak {
		result, err = tpm.SignChallengeWithTransientAK(tpmDevice, nonceB64)
	} else {
		result, err = tpm.SignChallengeWithAK(tpmDevice, uint32(akHandleVal), nonceB64)
	}
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("SIGN_FAILED", fmt.Sprintf("TPM signing failed: %v", err))
		} else {
			protocol.HumanMessage("Error: TPM signing failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if !outputClock {
		if jsonOutput {
			if identity_certificate_chain_pem != "" {
				protocol.SuccessResponse(map[string]interface{}{
					"signature_b64":                result.SignatureBase64,
					"ak_handle":                    result.AKHandle,
					"algorithm":                    result.Algorithm,
					"identity_certificate_chain_pem": identity_certificate_chain_pem,
				})
			} else {
				protocol.SuccessResponse(result)
			}
		} else {
			protocol.HumanMessage("Challenge signed successfully")
			protocol.HumanMessage("  Algorithm:  %s", result.Algorithm)
			protocol.HumanMessage("  AK Handle:  %s", result.AKHandle)
			protocol.HumanMessage("  Signature:  %s... (%d chars)", result.SignatureBase64[:40], len(result.SignatureBase64))
			if identity_certificate_chain_pem != "" {
				protocol.HumanMessage("  Cert chain: included (%d bytes)", len(identity_certificate_chain_pem))
			}
		}
		return
	}

	// For the quote, we need a valid AK handle. In transient mode, recreate it
	// (CreatePrimary is deterministic, so the second call produces the same key).
	var quote_ak_handle_val uint32
	if use_transient_ak {
		quote_ak_data, quote_ak_err := tpm.CreateTransientAK(tpmDevice)
		if quote_ak_err != nil {
			if jsonOutput {
				protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not recreate AK for quote: %v", quote_ak_err))
			} else {
				protocol.HumanMessage("Error: Could not recreate AK for quote: %v", quote_ak_err)
				os.Exit(1)
			}
			return
		}
		defer tpm.FlushTransientAK(tpmDevice, quote_ak_data)
		quote_ak_handle_val = uint32(quote_ak_data.TransientHandle)
	} else {
		quote_ak_handle_val = uint32(akHandleVal)
	}
	quoteResult, quoteErr := tpm.PerformQuoteForClockCapture(tpmDevice, quote_ak_handle_val, nonceB64)
	if quoteErr != nil {
		if jsonOutput {
			protocol.ErrorResponse("QUOTE_FAILED", fmt.Sprintf("TPM Quote for clock capture failed: %v", quoteErr))
		} else {
			protocol.HumanMessage("Error: TPM Quote for clock capture failed: %v", quoteErr)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		protocol.SuccessResponse(map[string]interface{}{
			"s1_signature_b64": result.SignatureBase64,
			"ak_handle":        result.AKHandle,
			"algorithm":        result.Algorithm,
			"c1_quote":         quoteResult,
		})
	} else {
		protocol.HumanMessage("Challenge signed with clock capture")
		protocol.HumanMessage("  Algorithm:      %s", result.Algorithm)
		protocol.HumanMessage("  AK Handle:      %s", result.AKHandle)
		sigPreviewLen := 40
		if len(result.SignatureBase64) < sigPreviewLen { sigPreviewLen = len(result.SignatureBase64) }
		protocol.HumanMessage("  Signature:      %s... (%d chars)", result.SignatureBase64[:sigPreviewLen], len(result.SignatureBase64))
		protocol.HumanMessage("  Clock (ms):     %d", quoteResult.ClockMilliseconds)
		protocol.HumanMessage("  Reset count:    %d", quoteResult.ResetCount)
		protocol.HumanMessage("  Restart count:  %d", quoteResult.RestartCount)
		protocol.HumanMessage("  Clock safe:     %v", quoteResult.ClockSafe)
	}
}

// runSignPIV signs a nonce with the PIV key in slot 9a.
func runSignPIV(jsonOutput bool, nonceB64 string, identity_certificate_chain_pem string) {
	result, err := piv.SignChallengeWithPIVKey(nonceB64)
	if err != nil {
		if jsonOutput {
			protocol.ErrorResponse("SIGN_FAILED", fmt.Sprintf("PIV signing failed: %v", err))
		} else {
			protocol.HumanMessage("Error: PIV signing failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if jsonOutput {
		if identity_certificate_chain_pem != "" {
			protocol.SuccessResponse(map[string]interface{}{
				"signature_b64":                result.SignatureBase64,
				"algorithm":                    result.Algorithm,
				"serial_number":                result.SerialNumber,
				"identity_certificate_chain_pem": identity_certificate_chain_pem,
			})
		} else {
			protocol.SuccessResponse(result)
		}
	} else {
		protocol.HumanMessage("Challenge signed successfully (PIV)")
		protocol.HumanMessage("  Algorithm:    %s", result.Algorithm)
		protocol.HumanMessage("  Serial:       %s", result.SerialNumber)
		signature_preview_length := 40
		if len(result.SignatureBase64) < signature_preview_length {
			signature_preview_length = len(result.SignatureBase64)
		}
		protocol.HumanMessage("  Signature:    %s... (%d chars)", result.SignatureBase64[:signature_preview_length], len(result.SignatureBase64))
		if identity_certificate_chain_pem != "" {
			protocol.HumanMessage("  Cert chain:   included (%d bytes)", len(identity_certificate_chain_pem))
		}
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

	// On Windows: try TPM at current privilege first, setup TBS if needed.
	if *wantElevation && !elevate.IsRunningElevated() && runtime.GOOS == "windows" {
		tpm_probe, tpm_probe_err := transport.OpenTPM()
		if tpm_probe_err == nil {
			tpm_probe.Close()
			protocol.HumanMessage("TPM accessible without elevation -- skipping UAC")
			*wantElevation = false
		} else {
			tbs_is_configured, _ := tbs.CheckTBSAccessIsGrantedToNonAdminUsers()
			if !tbs_is_configured {
				protocol.HumanMessage("TPM not accessible -- configuring TBS for non-admin access (one-time setup)...")
				exit_code, _, setup_err := elevate.RunSubcommandElevated([]string{"setup-tbs", "--json"})
				if setup_err == nil && exit_code == 0 {
					tpm_retry, retry_err := transport.OpenTPM()
					if retry_err == nil {
						tpm_retry.Close()
						protocol.HumanMessage("TBS configured -- TPM now accessible without elevation")
						*wantElevation = false
					}
				}
			}
		}
	}

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

// runPIVSignArbitraryData signs arbitrary base64-encoded data with the PIV
// key in slot 9a. Used in co-location binding Phase 2: signing (N1 || S1)
// to produce S2, proving the PIV device was present.
//
// No elevation required.
func runPIVSignArbitraryData(args []string) {
	flags := flag.NewFlagSet("piv-sign", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	dataB64 := flags.String("data", "", "base64-encoded data to sign")
	flags.Parse(args)

	if *dataB64 == "" {
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", "Required argument: --data")
		} else {
			protocol.HumanMessage("Error: required argument: --data")
			os.Exit(1)
		}
		return
	}

	result, err := piv.SignArbitraryDataWithPIVKey(*dataB64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("SIGN_FAILED", fmt.Sprintf("PIV signing failed: %v", err))
		} else {
			protocol.HumanMessage("Error: PIV signing failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(result)
	} else {
		protocol.HumanMessage("PIV data signed successfully")
		protocol.HumanMessage("  Algorithm:    %s", result.Algorithm)
		protocol.HumanMessage("  Serial:       %s", result.PIVDeviceSerial)
		sigPreviewLen := 40
		if len(result.S2SignatureBase64) < sigPreviewLen { sigPreviewLen = len(result.S2SignatureBase64) }
		protocol.HumanMessage("  Signature:    %s... (%d chars)", result.S2SignatureBase64[:sigPreviewLen], len(result.S2SignatureBase64))
	}
}

// runTPMBindQuote extends a PCR with provided data and then performs a
// TPM Quote. This is Phase 3 of co-location binding: extend PCR 16
// with SHA256(S2), then quote with qualifying data = (N1 || S1 || S2).
//
// Windows elevation: PCR_Extend is on the TBS default blocked command
// list for standard users. Starting with Windows 10 1809, this list is
// fixed in the TPM driver and CANNOT be unblocked via registry settings
// (IgnoreDefaultList has no effect on TPM 2.0 commands). Elevation is
// required on Windows. The binary is code-signed, so the UAC dialog
// shows a verified publisher.
//
// Linux/macOS: PCR_Extend works without elevation (no TBS filtering).
func runTPMBindQuote(args []string) {
	flags := flag.NewFlagSet("tpm-bind-quote", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo for PCR_Extend (required on Windows)")
	extendPCR := flags.Int("extend-pcr", 16, "PCR index to extend")
	extendDataB64 := flags.String("extend-data", "", "base64-encoded SHA-256 hash to extend into the PCR")
	qualifyingDataB64 := flags.String("qualifying-data", "", "base64-encoded qualifying data for the Quote")
	akHandleStr := flags.String("ak-handle", "", "AK persistent handle (hex, e.g. 0x81000100)")
	outputFile := flags.String("output-file", "", "write output to file instead of stdout (used by elevation)")
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

	if *wantElevation && !*alreadyElevated && !elevate.IsRunningElevated() {
		if err := elevate.RelaunchElevated(); err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("ELEVATION_FAILED", fmt.Sprintf("Could not elevate: %v", err))
			} else {
				protocol.HumanMessage("Error: could not elevate: %v", err)
				os.Exit(1)
			}
			return
		}
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err == nil {
			os.Stdout = f
			defer f.Close()
		}
	}

	if *extendDataB64 == "" || *qualifyingDataB64 == "" {
		missingArgs := ""
		if *extendDataB64 == "" { missingArgs += " --extend-data" }
		if *qualifyingDataB64 == "" { missingArgs += " --qualifying-data" }
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", fmt.Sprintf("Required arguments:%s", missingArgs))
		} else {
			protocol.HumanMessage("Error: required arguments:%s", missingArgs)
			os.Exit(1)
		}
		return
	}

	use_transient_ak_for_bind_quote := *akHandleStr == "" || *akHandleStr == "transient"
	var akHandleVal uint64
	if !use_transient_ak_for_bind_quote {
		akHandleClean := strings.TrimPrefix(strings.TrimPrefix(*akHandleStr, "0x"), "0X")
		var parse_err error
		akHandleVal, parse_err = strconv.ParseUint(akHandleClean, 16, 32)
		if parse_err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("Invalid AK handle '%s': %v", *akHandleStr, parse_err))
			} else {
				protocol.HumanMessage("Error: invalid AK handle '%s': %v", *akHandleStr, parse_err)
				os.Exit(1)
			}
			return
		}
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
	}

	if *extendPCR < 0 || *extendPCR > 23 {
		if *jsonOutput {
			protocol.ErrorResponse("INVALID_ARGUMENT", fmt.Sprintf("PCR index must be 0-23, got %d", *extendPCR))
		} else {
			protocol.HumanMessage("Error: PCR index must be 0-23, got %d", *extendPCR)
			os.Exit(1)
		}
		return
	}

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

	var bind_quote_ak_handle uint32
	if use_transient_ak_for_bind_quote {
		bind_ak, bind_ak_err := tpm.CreateTransientAK(tpmDevice)
		if bind_ak_err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not recreate AK for bind-quote: %v", bind_ak_err))
			} else {
				protocol.HumanMessage("Error: Could not recreate AK for bind-quote: %v", bind_ak_err)
				os.Exit(1)
			}
			return
		}
		defer tpm.FlushTransientAK(tpmDevice, bind_ak)
		bind_quote_ak_handle = uint32(bind_ak.TransientHandle)
	} else {
		bind_quote_ak_handle = uint32(akHandleVal)
	}
	result, err := tpm.ExtendPCRAndQuote(tpmDevice, bind_quote_ak_handle, *extendPCR, *extendDataB64, *qualifyingDataB64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("BIND_QUOTE_FAILED", fmt.Sprintf("TPM bind-quote failed: %v", err))
		} else {
			protocol.HumanMessage("Error: TPM bind-quote failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(map[string]interface{}{
			"c2_quote": result,
		})
	} else {
		protocol.HumanMessage("TPM bind-quote completed")
		protocol.HumanMessage("  Clock (ms):     %d", result.ClockMilliseconds)
		protocol.HumanMessage("  Reset count:    %d", result.ResetCount)
		protocol.HumanMessage("  Restart count:  %d", result.RestartCount)
		protocol.HumanMessage("  Clock safe:     %v", result.ClockSafe)
		protocol.HumanMessage("  PCR%d value:    %s", *extendPCR, result.PCR16ValueBase64)
	}
}

// runPIVBindCeremony orchestrates all 3 phases of co-location binding in
// a single process invocation. This eliminates TPM2_CreatePrimary overhead
// from separate process launches, keeping the clock delta within the 365ms
// threshold required by the server.
//
// Phase 1: TPM2_Quote with server nonce (captures C1 clock + S1 signature)
// Phase 2: PIV sign SHA256(N1 || S1) (produces S2 + attestation cert)
// Phase 3: TPM2_PCR_Extend(16, SHA256(S2)) then TPM2_Quote (captures C2 clock)
//
// Windows: PCR_Extend requires elevation (UAC). The binary is code-signed.
func runPIVBindCeremony(args []string) {
	flags := flag.NewFlagSet("piv-bind-ceremony", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	nonceB64 := flags.String("nonce", "", "base64-encoded server nonce (N1)")
	sessionID := flags.String("session-id", "", "binding session ID from server")
	wantElevation := flags.Bool("elevated", false, "trigger UAC/sudo for PCR_Extend (required on Windows)")
	outputFile := flags.String("output-file", "", "write output to file (used by elevation)")
	alreadyElevated := flags.Bool("_already-elevated", false, "internal: marks process as already elevated")
	flags.Parse(args)

	if *wantElevation && !*alreadyElevated && !elevate.IsRunningElevated() {
		if err := elevate.RelaunchElevated(); err != nil {
			if *jsonOutput {
				protocol.ErrorResponse("ELEVATION_FAILED", fmt.Sprintf("Could not elevate: %v", err))
			} else {
				protocol.HumanMessage("Error: could not elevate: %v", err)
				os.Exit(1)
			}
			return
		}
	}

	if *outputFile != "" {
		if err := validateOutputFilePath(*outputFile); err != nil {
			protocol.ErrorResponse("INVALID_OUTPUT_PATH", fmt.Sprintf("Rejected output file path: %v", err))
			return
		}
		f, err := os.Create(*outputFile)
		if err == nil {
			os.Stdout = f
			defer f.Close()
		}
	}

	if *nonceB64 == "" {
		if *jsonOutput {
			protocol.ErrorResponse("MISSING_ARGUMENT", "Required argument: --nonce")
		} else {
			protocol.HumanMessage("Error: required argument: --nonce")
			os.Exit(1)
		}
		return
	}

	// ── Open TPM (once) ──
	tpm_device, err := transport.OpenTPM()
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("NO_HSM_FOUND", fmt.Sprintf("Could not open TPM: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not open TPM: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpm_device.Close()

	// ── Create transient AK (once) ──
	ak_data, err := tpm.CreateTransientAK(tpm_device)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("HSM_ACCESS_ERROR", fmt.Sprintf("Could not create AK: %v", err))
		} else {
			protocol.HumanMessage("Error: Could not create AK: %v", err)
			os.Exit(1)
		}
		return
	}
	defer tpm.FlushTransientAK(tpm_device, ak_data)
	ceremony_ak_handle := uint32(ak_data.TransientHandle)

	// ── Phase 1: TPM Quote with server nonce (clock capture C1) ──
	c1_quote, err := tpm.PerformQuoteForClockCapture(tpm_device, ceremony_ak_handle, *nonceB64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("PHASE1_QUOTE_FAILED", fmt.Sprintf("Phase 1 TPM Quote failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Phase 1 TPM Quote failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// S1 = quote signature from Phase 1
	s1_signature_b64 := c1_quote.SignatureBase64

	// ── Phase 2: PIV sign SHA256(N1 || S1) ──
	// SignArbitraryDataWithPIVKey manages its own PCSC connection internally
	// (PCSC only allows one exclusive lock at a time per reader).
	// Decode nonce for concatenation
	nonce_bytes, _ := base64.StdEncoding.DecodeString(*nonceB64)
	s1_signature_bytes, _ := base64.StdEncoding.DecodeString(s1_signature_b64)
	phase2_input := append(nonce_bytes, s1_signature_bytes...)
	phase2_input_b64 := base64.StdEncoding.EncodeToString(phase2_input)

	piv_sign_result, err := piv.SignArbitraryDataWithPIVKey(phase2_input_b64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("PHASE2_PIV_SIGN_FAILED", fmt.Sprintf("Phase 2 PIV sign failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Phase 2 PIV sign failed: %v", err)
			os.Exit(1)
		}
		return
	}

	s2_signature_b64 := piv_sign_result.S2SignatureBase64
	s2_signature_bytes, _ := base64.StdEncoding.DecodeString(s2_signature_b64)

	// ── Phase 3: PCR_Extend(16, SHA256(S2)) then TPM Quote ──
	// Compute SHA256(S2) for PCR extend
	s2_hash_for_pcr_extend := compute_sha256_digest(s2_signature_bytes)
	extend_data_b64 := base64.StdEncoding.EncodeToString(s2_hash_for_pcr_extend)

	// Qualifying data for Phase 3 quote = SHA256(N1 || S1 || S2)
	phase3_qualifying_input := append(nonce_bytes, s1_signature_bytes...)
	phase3_qualifying_input = append(phase3_qualifying_input, s2_signature_bytes...)
	phase3_qualifying_hash := compute_sha256_digest(phase3_qualifying_input)
	phase3_qualifying_b64 := base64.StdEncoding.EncodeToString(phase3_qualifying_hash)

	c2_quote, err := tpm.ExtendPCRAndQuote(tpm_device, ceremony_ak_handle, 16, extend_data_b64, phase3_qualifying_b64)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("PHASE3_BIND_QUOTE_FAILED", fmt.Sprintf("Phase 3 TPM bind-quote failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Phase 3 TPM bind-quote failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// ── Output complete proof bundle ──
	proof_bundle := map[string]interface{}{
		"session_id":              *sessionID,
		"ak_public_pem":          ak_data.PublicKeyPEM,
		"s1_signature_b64":       s1_signature_b64,
		"c1_quote":               c1_quote,
		"s2_signature_b64":       s2_signature_b64,
		"piv_attestation_cert_pem": piv_sign_result.PIVAttestationCertPEM,
		"piv_device_serial":      piv_sign_result.PIVDeviceSerial,
		"c2_quote":               c2_quote,
	}

	if *jsonOutput {
		protocol.SuccessResponse(proof_bundle)
	} else {
		protocol.HumanMessage("Co-location binding ceremony completed")
		protocol.HumanMessage("  C1 clock (ms): %d", c1_quote.ClockMilliseconds)
		protocol.HumanMessage("  C2 clock (ms): %d", c2_quote.ClockMilliseconds)
		elapsed_ms := c2_quote.ClockMilliseconds - c1_quote.ClockMilliseconds
		protocol.HumanMessage("  Elapsed (ms):  %d", elapsed_ms)
		protocol.HumanMessage("  PIV serial:    %s", piv_sign_result.PIVDeviceSerial)
		protocol.HumanMessage("  Session:       %s", *sessionID)
	}
}

func compute_sha256_digest(data []byte) []byte {
	hash_result := sha256.Sum256(data)
	return hash_result[:]
}

// runTestEnclave creates a transient (non-persistent) Secure Enclave key,
// signs test data, and reports the results. No Keychain entitlements needed
// because the key is not stored persistently. This validates that the Secure
// Enclave hardware is accessible and functional.
func runTestEnclave(args []string) {
	flags := flag.NewFlagSet("test-enclave", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "output JSON")
	flags.Parse(args)

	test_data_for_signing := []byte("1id.com Secure Enclave hardware verification test")
	result, err := enclave.TestTransientEnclaveKeygenAndSign(test_data_for_signing)
	if err != nil {
		if *jsonOutput {
			protocol.ErrorResponse("ENCLAVE_TEST_FAILED", fmt.Sprintf("Secure Enclave test failed: %v", err))
		} else {
			protocol.HumanMessage("Error: Secure Enclave test failed: %v", err)
			os.Exit(1)
		}
		return
	}

	if *jsonOutput {
		protocol.SuccessResponse(result)
	} else {
		protocol.HumanMessage("Secure Enclave transient key test PASSED")
		protocol.HumanMessage("  Algorithm:  %s", result.Algorithm)
		protocol.HumanMessage("  Public key: %s...", result.PublicKeyPEM[:60])
		protocol.HumanMessage("  Signature:  %s...", result.SignatureBase64[:40])
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
