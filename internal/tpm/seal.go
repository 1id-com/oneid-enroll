// TPM2 data sealing and unsealing for hardware-bound encryption.
//
// Sealed data is encrypted under the Storage Root Key (SRK) in the
// owner hierarchy. The SRK is deterministic per TPM (same hierarchy
// seed = same key), so sealed blobs survive reboots and can only be
// unsealed on the same physical TPM.
//
// Use case: encrypt SQLite database keys (DEK) so they cannot be
// extracted from a disk image without the TPM present.
//
// TPM2_Create produces a private/public blob pair. The private blob
// contains the sealed data encrypted under the SRK. TPM2_Load +
// TPM2_Unseal recovers the plaintext.
//
// DOES NOT REQUIRE ELEVATION (after one-time TBS setup on Windows).
package tpm

import (
  "encoding/base64"
  "fmt"

  "github.com/google/go-tpm/tpm2"
  "github.com/google/go-tpm/tpm2/transport"
)

// SealResult holds the output of a TPM seal operation. Both fields
// are needed to unseal; losing either one makes the data unrecoverable.
type SealResult struct {
  SealedPrivateB64 string `json:"sealed_private_b64"`
  SealedPublicB64  string `json:"sealed_public_b64"`
}

// UnsealResult holds the recovered plaintext from an unseal operation.
type UnsealResult struct {
  PlaintextB64 string `json:"plaintext_b64"`
}

// SealData encrypts up to 128 bytes of arbitrary data under the TPM
// Storage Root Key. The sealed blob can only be recovered on this
// same physical TPM via UnsealData.
//
// plaintextB64: base64-encoded data to seal (max 128 bytes decoded).
//
// Returns sealed private/public blobs (both base64-encoded). Store
// these blobs alongside the encrypted database; they are useless
// without the TPM.
func SealData(
  tpmTransport transport.TPMCloser,
  plaintextB64 string,
) (*SealResult, error) {
  plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in plaintext: %w", err)
  }
  if len(plaintext) > 128 {
    return nil, fmt.Errorf("plaintext too large: %d bytes (max 128)", len(plaintext))
  }
  if len(plaintext) == 0 {
    return nil, fmt.Errorf("plaintext is empty")
  }

  srkResp, err := createTransientSRK(tpmTransport)
  if err != nil {
    return nil, err
  }
  defer func() {
    flushCmd := tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}
    _, _ = flushCmd.Execute(tpmTransport)
  }()

  sealTemplate := tpm2.TPMTPublic{
    Type:    tpm2.TPMAlgKeyedHash,
    NameAlg: tpm2.TPMAlgSHA256,
    ObjectAttributes: tpm2.TPMAObject{
      FixedTPM:     true,
      FixedParent:  true,
      UserWithAuth: true,
      NoDA:         true,
    },
  }

  createCmd := tpm2.Create{
    ParentHandle: tpm2.AuthHandle{
      Handle: srkResp.ObjectHandle,
      Name:   srkResp.Name,
      Auth:   tpm2.PasswordAuth(nil),
    },
    InPublic: tpm2.New2B(sealTemplate),
    InSensitive: tpm2.TPM2BSensitiveCreate{
      Sensitive: &tpm2.TPMSSensitiveCreate{
        Data: tpm2.NewTPMUSensitiveCreate(
          &tpm2.TPM2BSensitiveData{Buffer: plaintext},
        ),
      },
    },
  }

  createResp, err := createCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Create (seal) failed: %w", err)
  }

  return &SealResult{
    SealedPrivateB64: base64.StdEncoding.EncodeToString(createResp.OutPrivate.Buffer),
    SealedPublicB64:  base64.StdEncoding.EncodeToString(createResp.OutPublic.Bytes()),
  }, nil
}

// UnsealData recovers plaintext from a previously sealed blob.
// Both the private and public blobs from SealData are required.
//
// Returns the original plaintext (base64-encoded).
func UnsealData(
  tpmTransport transport.TPMCloser,
  sealedPrivateB64 string,
  sealedPublicB64 string,
) (*UnsealResult, error) {
  sealedPrivate, err := base64.StdEncoding.DecodeString(sealedPrivateB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in sealed_private: %w", err)
  }

  sealedPublic, err := base64.StdEncoding.DecodeString(sealedPublicB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in sealed_public: %w", err)
  }

  srkResp, err := createTransientSRK(tpmTransport)
  if err != nil {
    return nil, err
  }
  defer func() {
    flushCmd := tpm2.FlushContext{FlushHandle: srkResp.ObjectHandle}
    _, _ = flushCmd.Execute(tpmTransport)
  }()

  loadCmd := tpm2.Load{
    ParentHandle: tpm2.AuthHandle{
      Handle: srkResp.ObjectHandle,
      Name:   srkResp.Name,
      Auth:   tpm2.PasswordAuth(nil),
    },
    InPrivate: tpm2.TPM2BPrivate{Buffer: sealedPrivate},
    InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](sealedPublic),
  }

  loadResp, err := loadCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Load (unseal) failed: %w", err)
  }
  defer func() {
    flushCmd := tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}
    _, _ = flushCmd.Execute(tpmTransport)
  }()

  unsealCmd := tpm2.Unseal{
    ItemHandle: tpm2.AuthHandle{
      Handle: loadResp.ObjectHandle,
      Name:   loadResp.Name,
      Auth:   tpm2.PasswordAuth(nil),
    },
  }

  unsealResp, err := unsealCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Unseal failed: %w", err)
  }

  return &UnsealResult{
    PlaintextB64: base64.StdEncoding.EncodeToString(unsealResp.OutData.Buffer),
  }, nil
}

// createTransientSRK creates a transient Storage Root Key under the
// owner hierarchy. Deterministic: same key every time on the same TPM.
// Uses the TCG-recommended RSA-2048 SRK template.
func createTransientSRK(tpmTransport transport.TPMCloser) (*tpm2.CreatePrimaryResponse, error) {
  srkTemplate := tpm2.TPMTPublic{
    Type:    tpm2.TPMAlgRSA,
    NameAlg: tpm2.TPMAlgSHA256,
    ObjectAttributes: tpm2.TPMAObject{
      FixedTPM:            true,
      FixedParent:         true,
      SensitiveDataOrigin: true,
      UserWithAuth:        true,
      NoDA:                true,
      Restricted:          true,
      Decrypt:             true,
    },
    Parameters: tpm2.NewTPMUPublicParms(
      tpm2.TPMAlgRSA,
      &tpm2.TPMSRSAParms{
        Symmetric: tpm2.TPMTSymDefObject{
          Algorithm: tpm2.TPMAlgAES,
          KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
          Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
        },
        Scheme: tpm2.TPMTRSAScheme{
          Scheme: tpm2.TPMAlgNull,
        },
        KeyBits: 2048,
      },
    ),
    Unique: tpm2.NewTPMUPublicID(
      tpm2.TPMAlgRSA,
      &tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
    ),
  }

  createCmd := tpm2.CreatePrimary{
    PrimaryHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMRHOwner,
      Auth:   tpm2.PasswordAuth(nil),
    },
    InPublic: tpm2.New2B(srkTemplate),
  }

  resp, err := createCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_CreatePrimary (SRK) failed: %w", err)
  }

  return resp, nil
}
