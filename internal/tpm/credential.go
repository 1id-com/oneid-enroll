// Credential activation for TPM-based enrollment.
//
// Credential activation is the cryptographic proof that an AK lives inside
// the same TPM that owns a specific EK. The server encrypts a challenge
// using the EK public key, and only the real TPM can decrypt it.
//
// Flow:
// 1. Server calls TPM2_MakeCredential(EK_pub, AK_name, secret) -> credential blob
// 2. Client receives credential blob
// 3. Client calls TPM2_ActivateCredential(EK, AK, blob) -> decrypted secret
// 4. Client sends decrypted secret back to server
// 5. Server verifies it matches -> AK is proven to be in this TPM
//
// This is the anti-Sybil mechanism. Software cannot fake this.
//
// REQUIRES ELEVATION: ActivateCredential uses the EK, which requires
// admin/root access on most platforms.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY WARNING                                                    │
// │                                                                     │
// │ This file contains TPM operations that run as admin/root:           │
// │   - TPM2_CreatePrimary      (creates a transient EK, then flushed) │
// │   - TPM2_PolicySecret       (authorizes EK usage)                   │
// │   - TPM2_ActivateCredential (decrypts a server-provided blob)       │
// │                                                                     │
// │ ActivateCredential accepts a caller-provided credential blob and    │
// │ encrypted secret (base64 strings). These flow directly into TPM     │
// │ commands. The TPM itself validates them cryptographically, so       │
// │ malformed input causes a TPM error, not a security breach. However: │
// │                                                                     │
// │   1. The akHandle parameter selects which persistent key to use.    │
// │      Validate it is within our expected range (0x81000100-1FF).     │
// │   2. The credential blob comes from the SERVER, not the local user. │
// │      Ensure the SDK validates server identity (TLS + pinned cert)   │
// │      before passing blobs to this function.                         │
// │   3. Consider whether a malicious local process could abuse this    │
// │      to perform unwanted credential activations.                    │
// │                                                                     │
// │ As of Phase 1, ActivateCredential() is NOT called from main.go.    │
// │ The activate command returns NOT_IMPLEMENTED.                       │
// └─────────────────────────────────────────────────────────────────────┘
package tpm

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ActivateCredentialResult holds the output of credential activation.
type ActivateCredentialResult struct {
	DecryptedCredential string `json:"decrypted_credential"` // Base64-encoded decrypted secret
}

// ActivateCredential decrypts a credential challenge from the server.
//
// This proves to the server that our AK is inside the TPM that owns
// the EK whose public key they used to encrypt the challenge.
//
// REQUIRES ELEVATION.
//
// Parameters:
//   - tpmTransport: open TPM connection
//   - akHandle: persistent handle of the AK (e.g., 0x81000100)
//   - credentialBlobB64: base64-encoded credential blob from the server
//   - encryptedSecretB64: base64-encoded encrypted secret from the server
//
// Returns the decrypted credential as base64.
func ActivateCredential(
	tpmTransport transport.TPMCloser,
	akHandle uint32,
	credentialBlobB64 string,
	encryptedSecretB64 string,
) (*ActivateCredentialResult, error) {
	// Decode the base64 inputs
	credentialBlob, err := base64.StdEncoding.DecodeString(credentialBlobB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in credential_blob: %w", err)
	}

	encryptedSecret, err := base64.StdEncoding.DecodeString(encryptedSecretB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in encrypted_secret: %w", err)
	}

	// Create EK primary in the endorsement hierarchy.
	// The EK template matches the TCG EK Credential Profile for RSA-2048.
	ekTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			AdminWithPolicy:     true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		),
	}

	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement},
		InPublic:      tpm2.New2B(ekTemplate),
	}

	ekResp, err := createEKCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not load EK for credential activation: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: ekResp.ObjectHandle}
		_, _ = flushCmd.Execute(tpmTransport)
	}()

	// Start a policy session for EK usage
	// The default EK requires PolicySecret(TPM_RH_ENDORSEMENT)
	sess, sessClose, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("could not start policy session: %w", err)
	}
	defer sessClose()

	// Execute PolicySecret with endorsement hierarchy auth
	policySecretCmd := tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement},
		PolicySession: sess.Handle(),
	}
	_, err = policySecretCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("PolicySecret(endorsement) failed: %w", err)
	}

	// Call TPM2_ActivateCredential
	activateCmd := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(akHandle)},
		KeyHandle: tpm2.AuthHandle{
			Handle: ekResp.ObjectHandle,
			Auth:   sess,
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}

	activateResp, err := activateCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ActivateCredential failed: %w", err)
	}

	decryptedSecret := base64.StdEncoding.EncodeToString(activateResp.CertInfo.Buffer)

	return &ActivateCredentialResult{
		DecryptedCredential: decryptedSecret,
	}, nil
}
