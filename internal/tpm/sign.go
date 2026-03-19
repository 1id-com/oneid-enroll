// TPM signing operations for challenge-response authentication.
//
// After enrollment, agents authenticate to 1id.com by signing a server-provided
// nonce with their AK (Attestation Identity Key). The AK private key never
// leaves the TPM chip, so this proves the agent is running on the same hardware
// that was enrolled.
//
// DOES NOT REQUIRE ELEVATION: The AK was created with UserWithAuth=true and
// empty auth, so TPM2_Sign works at normal user privilege. This is critical
// for ongoing authentication -- agents should not need UAC/sudo every time
// they sign in.
//
// TRANSIENT-ONLY: The AK is recreated on demand via CreatePrimary. Same
// template + same hierarchy seed = same key every time. No persistent handles.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY NOTE                                                       │
// │                                                                     │
// │ The AK is a RESTRICTED signing key. The TPM enforces that it can    │
// │ only sign data that was NOT produced by the TPM itself (i.e., it    │
// │ will refuse to sign a TPM quote or audit digest). For signing       │
// │ arbitrary nonces, we must use a "ticket" from TPM2_Hash to prove    │
// │ the data originated outside the TPM, OR we use an unrestricted key. │
// │                                                                     │
// │ Since our AK IS restricted, we use TPM2_Hash to hash the nonce     │
// │ externally, then pass the hash + ticket to TPM2_Sign.               │
// └─────────────────────────────────────────────────────────────────────┘

package tpm

import (
  "encoding/base64"
  "fmt"

  "github.com/google/go-tpm/tpm2"
  "github.com/google/go-tpm/tpm2/transport"
)

// SignChallengeResult holds the output of signing a challenge nonce.
type SignChallengeResult struct {
  SignatureBase64 string `json:"signature_b64"`
  AKHandle        string `json:"ak_handle"`
  Algorithm       string `json:"algorithm"`
}

// SignChallengeWithTransientAK signs a nonce by recreating the transient AK.
//
// This is the preferred method: the AK is deterministic (same key every time),
// so no persistent handle is needed. CreatePrimary + Sign + Flush.
//
// DOES NOT REQUIRE ELEVATION (after one-time TBS setup on Windows).
func SignChallengeWithTransientAK(
  tpmTransport transport.TPMCloser,
  nonceBase64 string,
) (*SignChallengeResult, error) {
  akData, err := CreateTransientAK(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not recreate transient AK for signing: %w", err)
  }
  defer FlushTransientAK(tpmTransport, akData)

  return signWithAKHandle(tpmTransport, akData.TransientHandle, nonceBase64)
}

// SignChallengeWithAK signs a nonce using a persistent AK handle.
// DEPRECATED: Use SignChallengeWithTransientAK instead. This function
// exists for backward compatibility with machines that have persistent AKs
// from older binary versions.
func SignChallengeWithAK(
  tpmTransport transport.TPMCloser,
  akHandle uint32,
  nonceBase64 string,
) (*SignChallengeResult, error) {
  return signWithAKHandle(tpmTransport, tpm2.TPMHandle(akHandle), nonceBase64)
}

// signWithAKHandle is the shared implementation for signing with any AK handle
// (transient or persistent).
func signWithAKHandle(
  tpmTransport transport.TPMCloser,
  akHandle tpm2.TPMHandle,
  nonceBase64 string,
) (*SignChallengeResult, error) {
  nonceBytes, err := base64.StdEncoding.DecodeString(nonceBase64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 nonce: %w", err)
  }

  if len(nonceBytes) == 0 || len(nonceBytes) > 1024 {
    return nil, fmt.Errorf("nonce must be 1-1024 bytes, got %d", len(nonceBytes))
  }

  hashCmd := tpm2.Hash{
    Data:      tpm2.TPM2BMaxBuffer{Buffer: nonceBytes},
    HashAlg:   tpm2.TPMAlgSHA256,
    Hierarchy: tpm2.TPMRHEndorsement,
  }

  hashResp, err := hashCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Hash failed: %w", err)
  }

  readPubResp, err := tpm2.ReadPublic{
    ObjectHandle: akHandle,
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area (handle 0x%08X): %w", uint32(akHandle), err)
  }

  signCmd := tpm2.Sign{
    KeyHandle: tpm2.NamedHandle{
      Handle: akHandle,
      Name:   readPubResp.Name,
    },
    Digest: hashResp.OutHash,
    InScheme: tpm2.TPMTSigScheme{
      Scheme: tpm2.TPMAlgRSASSA,
      Details: tpm2.NewTPMUSigScheme(
        tpm2.TPMAlgRSASSA,
        &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
      ),
    },
    Validation: hashResp.Validation,
  }

  signResp, err := signCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("TPM2_Sign failed: %w", err)
  }

  rsaSig, err := signResp.Signature.Signature.RSASSA()
  if err != nil {
    return nil, fmt.Errorf("could not extract RSASSA signature: %w", err)
  }

  signatureB64 := base64.StdEncoding.EncodeToString(rsaSig.Sig.Buffer)

  return &SignChallengeResult{
    SignatureBase64: signatureB64,
    AKHandle:        fmt.Sprintf("0x%08X", uint32(akHandle)),
    Algorithm:       "RSASSA-SHA256",
  }, nil
}
