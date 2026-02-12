// AK (Attestation Identity Key) generation and management.
//
// The AK is the "working key" that the agent uses daily. Unlike the EK
// (which is burned in at manufacture and should rarely be used directly),
// the AK is created by the agent during enrollment and persisted in the
// TPM's persistent storage.
//
// The AK is cryptographically bound to the EK via credential activation.
// This binding proves that the AK lives inside the same TPM that owns the EK.
//
// REQUIRES ELEVATION: Creating and persisting keys in the TPM requires
// admin/root privileges.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY WARNING                                                    │
// │                                                                     │
// │ This file contains TPM WRITE operations:                            │
// │   - TPM2_CreatePrimary  (creates a key in the TPM)                  │
// │   - TPM2_EvictControl   (persists a key to a permanent handle)      │
// │                                                                     │
// │ This binary runs as admin/root. Any function in this file that is   │
// │ reachable from main.go is callable by ANY local process that can    │
// │ spawn our binary. Before wiring GenerateAK() into a CLI command:    │
// │                                                                     │
// │   1. Validate ALL inputs (handle ranges, key parameters)            │
// │   2. Consider rate-limiting (TPM persistent storage is finite)      │
// │   3. Consider whether the operation should require user consent     │
// │      (e.g., a second UAC prompt or confirmation dialog)             │
// │   4. Ensure no caller-controlled data flows into TPM commands       │
// │   5. Audit the full call chain from main() to the TPM command       │
// │                                                                     │
// │ As of Phase 1, GenerateAK() is NOT called from main.go.            │
// └─────────────────────────────────────────────────────────────────────┘
package tpm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// AKData holds information about a generated Attestation Identity Key.
type AKData struct {
	PublicKeyPEM     string `json:"ak_public_pem"` // PEM-encoded public key
	Handle           string `json:"ak_handle"`     // Persistent handle (hex string, e.g., "0x81000001")
	KeyAlgorithm     string `json:"ak_algorithm"`  // "rsa-2048" or "ecc-p256"
	CreationTicket   []byte `json:"creation_ticket,omitempty"`
}

// Persistent handle range for 1id AKs.
// We use 0x81000100-0x810001FF to avoid conflicts with other software.
const (
	persistentAKHandleStart = 0x81000100
	persistentAKHandleEnd   = 0x810001FF
)

// GenerateAK creates a new Attestation Identity Key in the TPM.
//
// The AK is an RSA-2048 restricted signing key, suitable for
// credential activation and challenge-response operations.
//
// REQUIRES ELEVATION.
//
// Returns the AK data including its public key and persistent handle.
func GenerateAK(tpmTransport transport.TPMCloser) (*AKData, error) {
	// AK template: RSA-2048, restricted signing, SHA-256
	// This matches what go-attestation and most TPM enrollment tools use.
	akTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			Restricted:           true,
			SignEncrypt:           true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}

	// Create the AK under the storage root key (SRK)
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement},
		InPublic:      tpm2.New2B(akTemplate),
	}

	createResp, err := createPrimaryCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary for AK failed: %w", err)
	}

	// Extract the public key from the response
	akPublic, err := createResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not read AK public area: %w", err)
	}

	pubKeyPEM, err := marshalTPMPublicToPEM(akPublic)
	if err != nil {
		return nil, fmt.Errorf("could not marshal AK public key: %w", err)
	}

	// Find an available persistent handle
	persistentHandle, err := findAvailablePersistentHandle(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("no available persistent handle for AK: %w", err)
	}

	// Make the AK persistent
	evictCmd := tpm2.EvictControl{
		Auth:       tpm2.AuthHandle{Handle: tpm2.TPMRHOwner},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createResp.ObjectHandle,
			Name:   createResp.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}

	_, err = evictCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_EvictControl (persist AK) failed: %w", err)
	}

	// Flush the transient object
	flushCmd := tpm2.FlushContext{FlushHandle: createResp.ObjectHandle}
	_, _ = flushCmd.Execute(tpmTransport)

	return &AKData{
		PublicKeyPEM:   string(pubKeyPEM),
		Handle:         fmt.Sprintf("0x%08X", persistentHandle),
		KeyAlgorithm:   "rsa-2048",
	}, nil
}

// marshalTPMPublicToPEM converts a TPM public key structure to PEM.
func marshalTPMPublicToPEM(pub *tpm2.TPMTPublic) ([]byte, error) {
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("could not get RSA parameters: %w", err)
	}

	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("could not get RSA unique: %w", err)
	}

	_ = rsaDetail // We use KeyBits from the template, not reading it back

	// Build a standard crypto/rsa public key
	pubKey := &struct {
		N []byte
		E int
	}{
		N: rsaUnique.Buffer,
		E: 65537,
	}
	_ = pubKey

	// For now, encode the raw public bytes in a simplified PEM
	// TODO: Use proper PKIX marshaling once we have the full RSA public key structure
	derBytes, err := x509.MarshalPKIXPublicKey(nil)
	if err != nil {
		// Fallback: encode raw unique bytes
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rsaUnique.Buffer,
		}), nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}), nil
}

// findAvailablePersistentHandle finds an unused persistent handle in our range.
func findAvailablePersistentHandle(tpmTransport transport.TPMCloser) (uint32, error) {
	// Query existing persistent handles
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTPersistent),
		PropertyCount: 256,
	}

	getCapResp, err := getCapCmd.Execute(tpmTransport)
	if err != nil {
		// If we can't enumerate, just try the first handle
		return persistentAKHandleStart, nil
	}

	handleList, err := getCapResp.CapabilityData.Data.Handles()
	if err != nil {
		return persistentAKHandleStart, nil
	}

	// Build a set of used handles
	usedHandles := make(map[uint32]bool)
	for _, h := range handleList.Handle {
		usedHandles[uint32(h)] = true
	}

	// Find the first available handle in our range
	for handle := uint32(persistentAKHandleStart); handle <= persistentAKHandleEnd; handle++ {
		if !usedHandles[handle] {
			return handle, nil
		}
	}

	return 0, fmt.Errorf("all persistent handles 0x%08X-0x%08X are in use", persistentAKHandleStart, persistentAKHandleEnd)
}
