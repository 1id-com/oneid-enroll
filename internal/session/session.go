// Package session implements an interactive command session for the oneid-enroll binary.
//
// Instead of spawning the binary separately for each TPM operation (extract, activate),
// session mode keeps a single elevated process alive. This means only ONE UAC/sudo
// prompt per enrollment, not two.
//
// Protocol:
//   - The parent process spawns "oneid-enroll session --elevated"
//   - On Windows, communication is via a named pipe (pipe name passed as argument)
//   - On Linux/macOS, communication is via stdin/stdout (preserved by pkexec/sudo)
//   - Each command is a single-line JSON object, terminated by newline
//   - Each response is a single-line JSON object, terminated by newline
//   - The session ends when the parent sends {"command":"quit"} or closes the pipe
//
// Command format:
//
//	{"command": "extract", "args": {"type": "tpm"}}
//	{"command": "activate", "args": {"credential_blob": "...", "encrypted_secret": "...", "ak_handle": "0x81000100"}}
//	{"command": "quit"}
//
// Response format:
//
//	{"ok": true, "data": {...}}
//	{"ok": false, "error_code": "...", "error": "..."}
package session

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1id-com/oneid-enroll/internal/tpm"
	"github.com/google/go-tpm/tpm2/transport"
)

// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY LIMITS                                                     │
// │                                                                     │
// │ The session is an elevated process accepting commands over a TCP     │
// │ socket. These limits contain the blast radius if something goes      │
// │ wrong:                                                               │
// │                                                                     │
// │ - Max 10 commands per session (extract + activate = 2, plenty of    │
// │   margin for retries)                                                │
// │ - 120 second total session lifetime (enrollment takes ~15s)          │
// │ - Authentication token required as first message                     │
// └─────────────────────────────────────────────────────────────────────┘
const (
	maxCommandsPerSession         = 10
	maxSessionLifetimeSeconds     = 120
)

// SessionCommand is the JSON structure sent by the parent process.
type SessionCommand struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args,omitempty"`
}

// SessionResponse is the JSON structure sent back to the parent.
type SessionResponse struct {
	OK        bool        `json:"ok"`
	Data      interface{} `json:"data,omitempty"`
	ErrorCode string      `json:"error_code,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// RunSession starts the interactive session loop.
//
// SECURITY: The expectedSessionToken MUST be verified before any TPM commands
// are executed. The very first line read from the connection must be a JSON
// object {"command":"auth","args":{"token":"<hex>"}}. If the token doesn't
// match, the session terminates immediately.
//
// The session is time-limited (maxSessionLifetimeSeconds) and command-limited
// (maxCommandsPerSession).
func RunSession(reader io.Reader, writer io.Writer, expectedSessionToken string) error {
	sessionDeadline := time.Now().Add(maxSessionLifetimeSeconds * time.Second)

	scanner := bufio.NewScanner(reader)
	// Allow large commands (credential blobs can be long)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// ── Step 1: Authenticate the connection ──
	// The parent must send an auth command with the shared token as its
	// very first message. This prevents a rogue local process that
	// connects to our TCP port from issuing TPM commands.
	if expectedSessionToken != "" {
		if !authenticateConnection(scanner, writer, expectedSessionToken) {
			return fmt.Errorf("session authentication failed")
		}
	}

	// ── Step 2: Open the TPM (only after successful auth) ──
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "NO_HSM_FOUND",
			Error:     fmt.Sprintf("Could not open TPM: %v", err),
		})
		return err
	}
	defer tpmDevice.Close()

	// Signal that the session is ready
	writeResponse(writer, SessionResponse{
		OK:   true,
		Data: map[string]string{"status": "ready", "message": "session started, TPM open"},
	})

	// ── Step 3: Command loop with limits ──
	commandCount := 0

	for scanner.Scan() {
		// Check session lifetime
		if time.Now().After(sessionDeadline) {
			writeResponse(writer, SessionResponse{
				OK:        false,
				ErrorCode: "SESSION_EXPIRED",
				Error:     fmt.Sprintf("Session expired after %d seconds", maxSessionLifetimeSeconds),
			})
			return nil
		}

		// Check command count
		commandCount++
		if commandCount > maxCommandsPerSession {
			writeResponse(writer, SessionResponse{
				OK:        false,
				ErrorCode: "SESSION_COMMAND_LIMIT",
				Error:     fmt.Sprintf("Maximum of %d commands per session exceeded", maxCommandsPerSession),
			})
			return nil
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			commandCount-- // empty lines don't count
			continue
		}

		var cmd SessionCommand
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			writeResponse(writer, SessionResponse{
				OK:        false,
				ErrorCode: "INVALID_COMMAND",
				Error:     fmt.Sprintf("Could not parse command JSON: %v", err),
			})
			continue
		}

		if cmd.Command == "quit" {
			writeResponse(writer, SessionResponse{
				OK:   true,
				Data: map[string]string{"status": "quit"},
			})
			return nil
		}

		response := handleSessionCommand(tpmDevice, cmd)
		writeResponse(writer, response)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("session reader error: %w", err)
	}

	return nil
}

// authenticateConnection reads the first command and verifies it's an auth
// command with the correct token. Returns true if auth succeeds.
//
// SECURITY: Uses constant-time comparison to prevent timing attacks on the
// token value (unlikely over localhost TCP, but defense-in-depth).
func authenticateConnection(scanner *bufio.Scanner, writer io.Writer, expectedToken string) bool {
	if !scanner.Scan() {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "AUTH_FAILED",
			Error:     "Connection closed before authentication",
		})
		return false
	}

	line := strings.TrimSpace(scanner.Text())
	var cmd SessionCommand
	if err := json.Unmarshal([]byte(line), &cmd); err != nil {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "AUTH_FAILED",
			Error:     "First message must be a valid JSON auth command",
		})
		return false
	}

	if cmd.Command != "auth" {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "AUTH_FAILED",
			Error:     fmt.Sprintf("First command must be 'auth', got '%s'", cmd.Command),
		})
		return false
	}

	providedToken, _ := cmd.Args["token"].(string)
	if providedToken == "" {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "AUTH_FAILED",
			Error:     "Auth command missing 'token' argument",
		})
		return false
	}

	// Constant-time comparison
	if !hmac.Equal([]byte(expectedToken), []byte(providedToken)) {
		writeResponse(writer, SessionResponse{
			OK:        false,
			ErrorCode: "AUTH_FAILED",
			Error:     "Invalid session token",
		})
		return false
	}

	writeResponse(writer, SessionResponse{
		OK:   true,
		Data: map[string]string{"status": "authenticated"},
	})
	return true
}

// handleSessionCommand dispatches a single command and returns the response.
func handleSessionCommand(tpmDevice transport.TPMCloser, cmd SessionCommand) SessionResponse {
	switch cmd.Command {
	case "extract":
		return handleExtract(tpmDevice, cmd.Args)
	case "activate":
		return handleActivate(tpmDevice, cmd.Args)
	case "sign":
		return handleSign(tpmDevice, cmd.Args)
	case "detect":
		return handleDetect()
	default:
		return SessionResponse{
			OK:        false,
			ErrorCode: "UNKNOWN_COMMAND",
			Error:     fmt.Sprintf("Unknown session command: %s", cmd.Command),
		}
	}
}

// handleExtract runs EK extraction + AK generation within the session.
func handleExtract(tpmDevice transport.TPMCloser, args map[string]interface{}) SessionResponse {
	// Extract EK certificate
	ekData, err := tpm.ExtractEKCertificate(tpmDevice)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "HSM_ACCESS_ERROR",
			Error:     fmt.Sprintf("Could not read EK certificate: %v", err),
		}
	}

	// Get or create AK
	akData, err := tpm.GetOrCreateAK(tpmDevice)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "HSM_ACCESS_ERROR",
			Error:     fmt.Sprintf("Could not generate AK: %v", err),
		}
	}

	tpmtPublicB64 := base64.StdEncoding.EncodeToString(akData.TPMTPublicBytes)

	result := map[string]interface{}{
		"ek_cert_pem":          ekData.CertificatePEM,
		"ek_public_pem":        ekData.PublicKeyPEM,
		"chain_pem":            ekData.CertificateChain,
		"ek_fingerprint":       ekData.Fingerprint,
		"subject_cn":           ekData.SubjectCN,
		"issuer_cn":            ekData.IssuerCN,
		"not_before":           ekData.NotBefore,
		"not_after":            ekData.NotAfter,
		"ak_public_pem":        akData.PublicKeyPEM,
		"ak_handle":            akData.Handle,
		"ak_algorithm":         akData.KeyAlgorithm,
		"ak_tpmt_public_b64":   tpmtPublicB64,
		"ak_tpm_name":          akData.TPMName,
	}

	return SessionResponse{OK: true, Data: result}
}

// handleActivate runs credential activation within the session.
func handleActivate(tpmDevice transport.TPMCloser, args map[string]interface{}) SessionResponse {
	// Extract required arguments
	credentialBlobB64, ok := args["credential_blob"].(string)
	if !ok || credentialBlobB64 == "" {
		return SessionResponse{
			OK:        false,
			ErrorCode: "MISSING_ARGUMENT",
			Error:     "Missing required argument: credential_blob",
		}
	}

	encryptedSecretB64, ok := args["encrypted_secret"].(string)
	if !ok || encryptedSecretB64 == "" {
		return SessionResponse{
			OK:        false,
			ErrorCode: "MISSING_ARGUMENT",
			Error:     "Missing required argument: encrypted_secret",
		}
	}

	akHandleStr, ok := args["ak_handle"].(string)
	if !ok || akHandleStr == "" {
		return SessionResponse{
			OK:        false,
			ErrorCode: "MISSING_ARGUMENT",
			Error:     "Missing required argument: ak_handle",
		}
	}

	// Parse AK handle
	akHandleClean := strings.TrimPrefix(strings.TrimPrefix(akHandleStr, "0x"), "0X")
	akHandleVal, err := strconv.ParseUint(akHandleClean, 16, 32)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "INVALID_ARGUMENT",
			Error:     fmt.Sprintf("Invalid AK handle '%s': %v", akHandleStr, err),
		}
	}

	// Validate handle range
	if akHandleVal < 0x81000100 || akHandleVal > 0x810001FF {
		return SessionResponse{
			OK:        false,
			ErrorCode: "INVALID_ARGUMENT",
			Error:     fmt.Sprintf("AK handle 0x%08X is outside allowed range 0x81000100-0x810001FF", akHandleVal),
		}
	}

	result, err := tpm.ActivateCredential(
		tpmDevice,
		uint32(akHandleVal),
		credentialBlobB64,
		encryptedSecretB64,
	)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "ACTIVATE_CREDENTIAL_FAILED",
			Error:     fmt.Sprintf("TPM2_ActivateCredential failed: %v", err),
		}
	}

	return SessionResponse{OK: true, Data: result}
}

// handleSign signs a challenge nonce with the AK within the session.
//
// NO ELEVATION actually needed for this operation (the AK has UserWithAuth),
// but it can still be used via the session for convenience when the session
// is already open.
func handleSign(tpmDevice transport.TPMCloser, args map[string]interface{}) SessionResponse {
	nonceB64, ok := args["nonce"].(string)
	if !ok || nonceB64 == "" {
		return SessionResponse{
			OK:        false,
			ErrorCode: "MISSING_ARGUMENT",
			Error:     "Missing required argument: nonce",
		}
	}

	akHandleStr, ok := args["ak_handle"].(string)
	if !ok || akHandleStr == "" {
		return SessionResponse{
			OK:        false,
			ErrorCode: "MISSING_ARGUMENT",
			Error:     "Missing required argument: ak_handle",
		}
	}

	// Parse AK handle
	akHandleClean := strings.TrimPrefix(strings.TrimPrefix(akHandleStr, "0x"), "0X")
	akHandleVal, err := strconv.ParseUint(akHandleClean, 16, 32)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "INVALID_ARGUMENT",
			Error:     fmt.Sprintf("Invalid AK handle '%s': %v", akHandleStr, err),
		}
	}

	if akHandleVal < 0x81000100 || akHandleVal > 0x810001FF {
		return SessionResponse{
			OK:        false,
			ErrorCode: "INVALID_ARGUMENT",
			Error:     fmt.Sprintf("AK handle 0x%08X is outside allowed range 0x81000100-0x810001FF", akHandleVal),
		}
	}

	result, err := tpm.SignChallengeWithAK(tpmDevice, uint32(akHandleVal), nonceB64)
	if err != nil {
		return SessionResponse{
			OK:        false,
			ErrorCode: "SIGN_FAILED",
			Error:     fmt.Sprintf("TPM signing failed: %v", err),
		}
	}

	return SessionResponse{OK: true, Data: result}
}

// handleDetect runs HSM detection within the session.
func handleDetect() SessionResponse {
	detectedTPMs := tpm.DetectTPMs()
	return SessionResponse{
		OK: true,
		Data: map[string]interface{}{
			"hsms":  detectedTPMs,
			"count": len(detectedTPMs),
		},
	}
}

// writeResponse writes a single JSON response as a newline-terminated line.
func writeResponse(writer io.Writer, response SessionResponse) {
	data, err := json.Marshal(response)
	if err != nil {
		// Last resort: write a raw error
		fmt.Fprintf(os.Stderr, "FATAL: could not marshal session response: %v\n", err)
		return
	}
	writer.Write(data)
	writer.Write([]byte("\n"))
}
