// EK (Endorsement Key) certificate extraction from TPM.
//
// The EK certificate is burned into the TPM at manufacture time.
// It is the root of trust -- it proves the TPM is a real,
// manufacturer-issued device, not a software emulation.
//
// Reading the EK certificate requires admin/root privileges because
// it can be used to uniquely identify the device (privacy concern).
//
// This is the anti-Sybil mechanism: each EK is globally unique.
// One EK = one identity. No duplicates allowed.
package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EKData holds the extracted Endorsement Key certificate and metadata.
type EKData struct {
	CertificatePEM   string   `json:"ek_cert_pem"`    // PEM-encoded X.509 certificate
	PublicKeyPEM     string   `json:"ek_public_pem"`  // PEM-encoded public key (from cert)
	CertificateChain []string `json:"chain_pem"`      // Intermediate CA certs (if found)
	Fingerprint      string   `json:"ek_fingerprint"` // SHA-256 of DER-encoded certificate
	SubjectCN        string   `json:"subject_cn"`     // Certificate subject common name
	IssuerCN         string   `json:"issuer_cn"`      // Certificate issuer common name
	NotBefore        string   `json:"not_before"`     // Validity start (ISO 8601)
	NotAfter         string   `json:"not_after"`      // Validity end (ISO 8601)
}

// Well-known TPM NV indices for EK certificates (TCG PC Client spec)
const (
	nvIndexEKCertRSA2048 = 0x01C00002
	nvIndexEKCertECCP256 = 0x01C0000A
)

// AMD EK certificate server and HTTP client (both overridable for testing)
var (
	amdEKCertServerURL = "https://ftpm.amd.com/pki/aia"
	amdHTTPClient      = &http.Client{Timeout: 15 * time.Second}
)

// maxAMDEKCertBytes caps the response body read from AMD's server (EK certs are ~1 KB).
const maxAMDEKCertBytes = 64 * 1024

// ExtractEKCertificate reads the EK certificate from the TPM.
//
// For Intel/Infineon TPMs: reads from NV storage (requires elevation).
// For AMD fTPMs: creates an EK and fetches certificate from AMD server.
func ExtractEKCertificate(tpmTransport transport.TPMCloser) (*EKData, error) {
	// Try NV storage first (Intel/Infineon discrete TPMs)
	certDER, err := readNVCertificate(tpmTransport, nvIndexEKCertRSA2048)
	if err == nil {
		return parseEKData(certDER, nil)
	}

	// Try ECC EK cert from NV
	certDER, err = readNVCertificate(tpmTransport, nvIndexEKCertECCP256)
	if err == nil {
		return parseEKData(certDER, nil)
	}

	// Only fall through to AMD server fetch for AMD fTPMs. Attempting this on
	// non-AMD hardware would leak the device's EK public key to AMD's servers
	// and return a confusing "404" error rather than a meaningful one.
	manufacturer, propErr := getTPMProperty(tpmTransport, tpm2.TPMPTManufacturer)
	if propErr != nil {
		return nil, fmt.Errorf("no EK certificate in NV storage and could not query TPM manufacturer: %w", propErr)
	}
	mfgBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(mfgBytes, manufacturer)
	mfgCode := string(mfgBytes)
	if mfgCode != "AMD " && mfgCode != "AMDJ" {
		return nil, fmt.Errorf("no EK certificate found in NV storage (TPM manufacturer: %s)", mfgCode)
	}

	return FetchAMDEKCertificate(tpmTransport)
}

// FetchAMDEKCertificate creates an EK in the TPM and fetches the certificate from AMD.
//
// AMD fTPM doesn't store EK certificates in NV. Instead, the certificate is
// retrieved from AMD's server based on the EK public key hash.
// This does NOT require elevation.
func FetchAMDEKCertificate(tpmTransport transport.TPMCloser) (*EKData, error) {
	// Create an ECC EK in the TPM
	ekResult, err := CreateEKPublic(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not create EK in TPM: %w", err)
	}
	defer FlushEK(tpmTransport, ekResult.Handle)

	// Compute AMD EK certificate hash: sha256(0x0000_4444 || public_key)[0:16]
	hash := computeAMDEKHash(ekResult.PublicKey)

	// Fetch DER-encoded certificate from AMD server
	certDER, err := fetchFromAMDServer(hash)
	if err != nil {
		return nil, fmt.Errorf("could not fetch AMD EK certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD EK certificate: %w", err)
	}

	// Verify the fetched certificate's public key matches the EK we just created.
	// This is essential: the EK certificate is the binding between this TPM's
	// hardware identity and a public key. A compromised server or MITM returning
	// a cert for a different key would break the attestation chain.
	if err := validateAMDCertMatchesEK(cert, ekResult.PublicKey); err != nil {
		return nil, err
	}

	return parseEKData(certDER, nil)
}

// validateAMDCertMatchesEK checks that the public key in cert matches ekPublicKey.
// ekPublicKey is the raw X||Y bytes (each 32 bytes for P-256) from the TPM.
func validateAMDCertMatchesEK(cert *x509.Certificate, ekPublicKey []byte) error {
	ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("AMD EK certificate does not contain an ECC public key")
	}
	if len(ekPublicKey) != 64 {
		return fmt.Errorf("unexpected EK public key length %d (expected 64 bytes for P-256 X||Y)", len(ekPublicKey))
	}
	xBytes := ecKey.X.FillBytes(make([]byte, 32))
	yBytes := ecKey.Y.FillBytes(make([]byte, 32))
	if !bytes.Equal(xBytes, ekPublicKey[:32]) || !bytes.Equal(yBytes, ekPublicKey[32:]) {
		return fmt.Errorf("AMD EK certificate public key does not match TPM EK public key")
	}
	return nil
}

// computeAMDEKHash computes the AMD EK certificate hash.
// Format: sha256(0x0000_4444 || public_key)[0:16] as hex string
func computeAMDEKHash(ekPublic []byte) string {
	// AMD uses 0x00004444 prefix for ECC EK certificates
	prefix := []byte{0x00, 0x00, 0x44, 0x44}
	data := append(prefix, ekPublic...)
	hash := sha256.Sum256(data)
	// Return first 16 bytes as hex
	return hex.EncodeToString(hash[:16])
}

// fetchFromAMDServer fetches the DER-encoded EK certificate from AMD's server.
func fetchFromAMDServer(hash string) ([]byte, error) {
	url := amdEKCertServerURL + "/" + hash

	resp, err := amdHTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AMD server returned status %d", resp.StatusCode)
	}

	// Read up to limit+1 bytes so we can detect an oversized response.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAMDEKCertBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if len(data) > maxAMDEKCertBytes {
		return nil, fmt.Errorf("AMD server response too large (>%d bytes)", maxAMDEKCertBytes)
	}
	return data, nil
}

// CreateEKPublicResult holds the result of creating an ECC EK.
type CreateEKPublicResult struct {
	PublicKey []byte
	Handle    tpm2.TPMHandle
}

// CreateEKPublic creates a transient ECC EK in the TPM and returns its public key bytes.
//
// This is used for AMD fTPM which requires fetching the EK certificate from AMD's server.
// The ECC EK is created using the standard TCG template (TPMAlgNull scheme, AES-128-CFB).
func CreateEKPublic(tpmTransport transport.TPMCloser) (*CreateEKPublicResult, error) {
	ekTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
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
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				// TCG default ECC EK template uses NULL scheme (restricted decrypt key,
				// not a signing key — ECDSA would be wrong here).
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: []byte{}},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}

	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(ekTemplate),
	}

	ekResp, err := createEKCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not create ECC EK: %w", err)
	}

	ekPublic, err := ekResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not read EK public area: %w", err)
	}

	unique, err := ekPublic.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("could not get ECC unique: %w", err)
	}

	pubBytes := append(unique.X.Buffer, unique.Y.Buffer...)
	return &CreateEKPublicResult{
		PublicKey: pubBytes,
		Handle:    ekResp.ObjectHandle,
	}, nil
}

// FlushEK flushes a transient EK from TPM memory.
// Safe to call even if the handle is invalid (errors are silently ignored).
func FlushEK(tpmTransport transport.TPMCloser, handle tpm2.TPMHandle) {
	if handle == 0 {
		return
	}
	flushCmd := tpm2.FlushContext{FlushHandle: handle}
	_, _ = flushCmd.Execute(tpmTransport)
}

// parseEKData parses EK certificate bytes into EKData struct.
func parseEKData(certDER []byte, chain []string) (*EKData, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("could not parse EK certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal EK public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	fingerprint := sha256.Sum256(certDER)

	return &EKData{
		CertificatePEM:   string(certPEM),
		PublicKeyPEM:     string(pubKeyPEM),
		CertificateChain: chain,
		Fingerprint:      hex.EncodeToString(fingerprint[:]),
		SubjectCN:        cert.Subject.CommonName,
		IssuerCN:         cert.Issuer.CommonName,
		NotBefore:        cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:         cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// readNVCertificate reads a certificate from a TPM NV index.
//
// EK certificate NV indices (0x01C00002 etc.) are defined by the TCG
// PC Client spec. They are typically:
//   - TPMA_NV_PPREAD set (readable by platform hierarchy)
//   - TPMA_NV_OWNERREAD set (readable by owner hierarchy)
//   - TPMA_NV_AUTHREAD sometimes set (readable by the NV index itself)
//
// We try multiple auth strategies:
// 1. NV index as its own auth (works when AUTHREAD is set)
// 2. TPM_RH_OWNER with empty password (works when elevated on Windows)
func readNVCertificate(tpmTransport transport.TPMCloser, nvIndex uint32) ([]byte, error) {
	nvHandle := tpm2.TPMHandle(nvIndex)

	// Read NV public area to get data size (no auth needed for this)
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.AuthHandle{Handle: nvHandle},
	}

	readPubResp, err := readPubCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("NV index 0x%08X not found: %w", nvIndex, err)
	}

	nvPublic, err := readPubResp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not parse NV public area for 0x%08X: %w", nvIndex, err)
	}
	dataSize := nvPublic.DataSize

	// Try reading with different auth strategies.
	// The go-tpm library requires Auth to be non-nil on AuthHandle.
	//
	// Strategy 1: Use TPM_RH_OWNER with empty password (PasswordAuth(nil))
	// This is the standard way to read EK cert NV indices when running as admin.
	certData, err := readNVDataWithOwnerAuth(tpmTransport, nvHandle, readPubResp.NVName, dataSize)
	if err == nil {
		return certData, nil
	}

	// Strategy 2: Use the NV index itself as auth (AUTHREAD flag)
	certData, err = readNVDataWithIndexAuth(tpmTransport, nvHandle, readPubResp.NVName, dataSize)
	if err == nil {
		return certData, nil
	}

	return nil, fmt.Errorf("could not read NV index 0x%08X (tried owner and index auth): %w", nvIndex, err)
}

// readNVDataWithOwnerAuth reads NV data using TPM_RH_OWNER with empty password.
// This is the standard approach when running as admin on Windows (TBS grants
// owner auth automatically) or on Linux as root.
func readNVDataWithOwnerAuth(
	tpmTransport transport.TPMCloser,
	nvHandle tpm2.TPMHandle,
	nvName tpm2.TPM2BName,
	dataSize uint16,
) ([]byte, error) {
	const maxChunkSize = 512
	var certData []byte

	for offset := uint16(0); offset < dataSize; {
		chunkSize := uint16(maxChunkSize)
		remaining := dataSize - offset
		if remaining < chunkSize {
			chunkSize = remaining
		}

		readCmd := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil), // Empty password -- owner auth
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvHandle,
				Name:   nvName,
			},
			Size:   chunkSize,
			Offset: offset,
		}

		readResp, err := readCmd.Execute(tpmTransport)
		if err != nil {
			return nil, fmt.Errorf("NV read (owner auth) at offset %d failed: %w", offset, err)
		}

		certData = append(certData, readResp.Data.Buffer...)
		offset += uint16(len(readResp.Data.Buffer))
	}

	return certData, nil
}

// readNVDataWithIndexAuth reads NV data using the NV index itself as auth.
// This works when the NV index has TPMA_NV_AUTHREAD set.
func readNVDataWithIndexAuth(
	tpmTransport transport.TPMCloser,
	nvHandle tpm2.TPMHandle,
	nvName tpm2.TPM2BName,
	dataSize uint16,
) ([]byte, error) {
	const maxChunkSize = 512
	var certData []byte

	for offset := uint16(0); offset < dataSize; {
		chunkSize := uint16(maxChunkSize)
		remaining := dataSize - offset
		if remaining < chunkSize {
			chunkSize = remaining
		}

		readCmd := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvHandle,
				Auth:   tpm2.PasswordAuth(nil), // Empty password for index auth
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvHandle,
				Name:   nvName,
			},
			Size:   chunkSize,
			Offset: offset,
		}

		readResp, err := readCmd.Execute(tpmTransport)
		if err != nil {
			return nil, fmt.Errorf("NV read (index auth) at offset %d failed: %w", offset, err)
		}

		certData = append(certData, readResp.Data.Buffer...)
		offset += uint16(len(readResp.Data.Buffer))
	}

	return certData, nil
}
