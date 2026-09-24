// EK (Endorsement Key) certificate extraction from TPM.
//
// The EK certificate is burned into the TPM at manufacture time.
// It is the root of trust -- it proves the TPM is a real,
// manufacturer-issued device, not a software emulation.
//
// Reading the EK certificate works as an ordinary user on Windows (owner
// hierarchy empty password; verified 2026-09-24) and via the tss group on Linux.
//
// This is the anti-Sybil mechanism: each EK is globally unique.
// One EK = one identity. No duplicates allowed.
package tpm

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EKData holds the extracted Endorsement Key certificate and metadata.
type EKData struct {
	CertificatePEM   string   `json:"ek_cert_pem"`    // PEM-encoded X.509 certificate
	PublicKeyPEM     string   `json:"ek_public_pem"`  // PEM-encoded public key (from cert)
	CertificateChain []string `json:"chain_pem"`      // Intermediate CA certs (if found)
	Fingerprint      string   `json:"ek_fingerprint"` // SHA-256 of the EK SubjectPublicKeyInfo (anchor fingerprint)
	SubjectCN        string   `json:"subject_cn"`     // Certificate subject common name
	IssuerCN         string   `json:"issuer_cn"`      // Certificate issuer common name
	NotBefore        string   `json:"not_before"`     // Validity start (ISO 8601)
	NotAfter         string   `json:"not_after"`      // Validity end (ISO 8601)
}

// Well-known TPM NV indices (TCG EK Credential Profile).
//
// The AIRS sovereign anchor profile (registry draft "Sovereign Tier") is the
// TPM's RSA-2048 Endorsement Key with its manufacturer credential. ECC EK
// credentials are deliberately NOT used as a fallback: an ECC anchor would be
// a second, disjoint anchor for the same physical TPM.
//
// The manufacturer's intermediate CA certificates are commonly stored on the
// TPM itself in the EK-chain NV range (Intel PTT: three concatenated DER
// certificates at 0x01C00100). The Registrar needs them to reach its trust
// store, which normally holds only the manufacturers' issuing roots.
const (
	nvIndexEKCertRSA2048        = 0x01C00002
	nvIndexEKCertificateChainLo = 0x01C00100
	nvIndexEKCertificateChainHi = 0x01C001FF
)

// ExtractEKCertificate reads the RSA-2048 EK certificate and the on-TPM EK
// certificate chain from NV storage.
//
// Works as an ordinary (non-elevated) user: NV_ReadPublic + NV_Read with the
// owner hierarchy's empty password are allowed by Windows command blocking
// (verified on Windows 10 1809 and Windows 11 26200, 2026-09-24).
func ExtractEKCertificate(tpmTransport transport.TPMCloser) (*EKData, error) {
	certDER, err := readNVCertificate(tpmTransport, nvIndexEKCertRSA2048)
	if err != nil {
		return nil, fmt.Errorf("no RSA EK certificate found in TPM NV storage (index 0x%08X): %w", nvIndexEKCertRSA2048, err)
	}

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

	// Anchor fingerprint = SHA-256 over the EK SubjectPublicKeyInfo (registry
	// draft "Anchor Fingerprint"), never over the certificate bytes.
	fingerprint := sha256.Sum256(pubKeyDER)

	return &EKData{
		CertificatePEM:   string(certPEM),
		PublicKeyPEM:     string(pubKeyPEM),
		CertificateChain: readEKCertificateChainFromNV(tpmTransport),
		Fingerprint:      hex.EncodeToString(fingerprint[:]),
		SubjectCN:        cert.Subject.CommonName,
		IssuerCN:         cert.Issuer.CommonName,
		NotBefore:        cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:         cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// readEKCertificateChainFromNV returns every certificate stored in the TPM's
// EK-chain NV range, as PEM, in the order found. Missing or unreadable
// indices are skipped: the chain is best-effort evidence the Registrar
// verifies itself.
func readEKCertificateChainFromNV(tpmTransport transport.TPMCloser) []string {
	capability, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      nvIndexEKCertificateChainLo,
		PropertyCount: 256,
	}.Execute(tpmTransport)
	if err != nil {
		return nil
	}
	handles, err := capability.CapabilityData.Data.Handles()
	if err != nil {
		return nil
	}
	var chainPEMs []string
	for _, handle := range handles.Handle {
		nvIndex := uint32(handle)
		if nvIndex < nvIndexEKCertificateChainLo || nvIndex > nvIndexEKCertificateChainHi {
			continue
		}
		data, err := readNVCertificate(tpmTransport, nvIndex)
		if err != nil {
			continue
		}
		for _, certificateDER := range splitConcatenatedDERCertificates(data) {
			chainPEMs = append(chainPEMs, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})))
		}
	}
	return chainPEMs
}

// splitConcatenatedDERCertificates splits back-to-back DER SEQUENCEs.
func splitConcatenatedDERCertificates(data []byte) [][]byte {
	var certificates [][]byte
	for offset := 0; offset+2 <= len(data) && data[offset] == 0x30; {
		length := int(data[offset+1])
		headerLength := 2
		if length&0x80 != 0 {
			lengthOctets := length & 0x7F
			if lengthOctets == 0 || lengthOctets > 4 || offset+2+lengthOctets > len(data) {
				break
			}
			length = 0
			for _, octet := range data[offset+2 : offset+2+lengthOctets] {
				length = length<<8 | int(octet)
			}
			headerLength += lengthOctets
		}
		end := offset + headerLength + length
		if end > len(data) {
			break
		}
		certificates = append(certificates, data[offset:end])
		offset = end
	}
	return certificates
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
