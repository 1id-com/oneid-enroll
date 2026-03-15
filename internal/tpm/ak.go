// AK (Attestation Identity Key) generation -- transient-only architecture.
//
// The AK is the "working key" that the agent uses daily. Unlike the EK
// (which is burned in at manufacture and should rarely be used directly),
// the AK is created by the agent during enrollment and recreated on demand.
//
// CRITICAL INSIGHT: TPM2_CreatePrimary with the same template under the same
// hierarchy with the same seed ALWAYS produces the SAME key. The hierarchy
// seed is deterministic per TPM and survives reboots. This means:
//
//   - AKs do NOT need to be persisted in NV storage (EvictControl)
//   - Keys are recreated on demand -- same public key every time
//   - No NV slots consumed (some TPMs have as few as 7)
//   - No elevation needed (CreatePrimary works without admin after TBS setup)
//   - The credentials file is a CACHE, not a requirement -- the TPM IS the credential
//
// The AK is cryptographically bound to the EK via credential activation.
// This binding proves that the AK lives inside the same TPM that owns the EK.
//
// DOES NOT REQUIRE ELEVATION after one-time TBS setup (Windows) or tss group (Linux).
//
// WARNING: The AKTemplate MUST remain identical across all binary versions.
// Any change to the template or hierarchy produces a different key, breaking
// existing enrollments.
package tpm

import (
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/binary"
  "encoding/hex"
  "encoding/pem"
  "fmt"
  "math/big"

  "github.com/google/go-tpm/tpm2"
  "github.com/google/go-tpm/tpm2/transport"
)

// AKData holds information about a generated Attestation Identity Key.
type AKData struct {
  PublicKeyPEM       string `json:"ak_public_pem"`
  Handle             string `json:"ak_handle"`
  HandleNumeric      uint32 `json:"-"`
  KeyAlgorithm       string `json:"ak_algorithm"`
  TPMTPublicBytes    []byte `json:"tpmt_public_bytes"`
  TPMName            string `json:"ak_tpm_name"`
  CreationTicket     []byte `json:"creation_ticket,omitempty"`
  TransientHandle    tpm2.TPMHandle `json:"-"`
}

// AKTemplate is the canonical AK template used by all 1id enrollments.
// RSA-2048, restricted signing, SHA-256, under the Endorsement hierarchy.
//
// WARNING: Changing ANY field here produces a different key and breaks
// every existing enrollment. This template is frozen.
var AKTemplate = tpm2.TPMTPublic{
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

// CreateTransientAK creates a transient AK in the TPM's endorsement hierarchy.
//
// The returned key is deterministic: calling this function on the same TPM
// with the same template always produces the same public key. The caller
// MUST flush the transient handle (via FlushContext or closing the TPM
// connection) when done.
//
// DOES NOT REQUIRE ELEVATION (after one-time TBS setup on Windows).
func CreateTransientAK(tpmTransport transport.TPMCloser) (*AKData, error) {
  createPrimaryCmd := tpm2.CreatePrimary{
    PrimaryHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMRHEndorsement,
      Auth:   tpm2.PasswordAuth(nil),
    },
    InPublic: tpm2.New2B(AKTemplate),
  }

  createResp, err := createPrimaryCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_CreatePrimary for AK failed: %w", err)
  }

  akPublic, err := createResp.OutPublic.Contents()
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area: %w", err)
  }

  pubKeyPEM, err := marshalTPMPublicToPEM(akPublic)
  if err != nil {
    return nil, fmt.Errorf("could not marshal AK public key: %w", err)
  }

  tpmtPublicBytes := createResp.OutPublic.Bytes()
  akTPMNameBytes := createResp.Name.Buffer

  return &AKData{
    PublicKeyPEM:    string(pubKeyPEM),
    Handle:          "transient",
    HandleNumeric:   uint32(createResp.ObjectHandle),
    KeyAlgorithm:    "rsa-2048",
    TPMTPublicBytes: tpmtPublicBytes,
    TPMName:         hex.EncodeToString(akTPMNameBytes),
    TransientHandle: createResp.ObjectHandle,
  }, nil
}

// FlushTransientAK flushes a transient AK from TPM memory.
// Safe to call even if the handle is invalid (errors are silently ignored).
func FlushTransientAK(tpmTransport transport.TPMCloser, ak *AKData) {
  if ak == nil || ak.TransientHandle == 0 { return; }
  flushCmd := tpm2.FlushContext{FlushHandle: ak.TransientHandle}
  _, _ = flushCmd.Execute(tpmTransport)
}

// marshalTPMPublicToPEM converts a TPM RSA public key structure to standard PKIX PEM.
//
// The TPM stores RSA public keys as just the modulus (N) bytes. The exponent
// is always 65537 (0x10001) per the TCG EK Credential Profile. We reconstruct
// a standard crypto/rsa.PublicKey and marshal it via x509.MarshalPKIXPublicKey.
func marshalTPMPublicToPEM(pub *tpm2.TPMTPublic) ([]byte, error) {
  rsaUnique, err := pub.Unique.RSA()
  if err != nil {
    return nil, fmt.Errorf("could not get RSA unique (modulus): %w", err)
  }

  n := new(big.Int).SetBytes(rsaUnique.Buffer)
  rsaPubKey := &rsa.PublicKey{
    N: n,
    E: 65537,
  }

  derBytes, err := x509.MarshalPKIXPublicKey(rsaPubKey)
  if err != nil {
    return nil, fmt.Errorf("could not marshal RSA public key to PKIX DER: %w", err)
  }

  return pem.EncodeToMemory(&pem.Block{
    Type:  "PUBLIC KEY",
    Bytes: derBytes,
  }), nil
}

// ComputeTPMNameFromPublicBytes computes the TPM Name from marshaled TPMT_PUBLIC bytes.
// TPM Name = nameAlg (2 bytes big-endian) || hash(TPMT_PUBLIC).
// For SHA-256 nameAlg: 0x000B || SHA256(bytes).
func ComputeTPMNameFromPublicBytes(tpmtPublicBytes []byte) []byte {
  digest := sha256.Sum256(tpmtPublicBytes)
  name := make([]byte, 2+sha256.Size)
  binary.BigEndian.PutUint16(name[0:2], uint16(tpm2.TPMAlgSHA256))
  copy(name[2:], digest[:])
  return name
}
