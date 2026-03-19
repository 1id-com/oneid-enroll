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
// DOES NOT REQUIRE ELEVATION after one-time TBS setup on Windows.
// Both EK and AK are recreated as transient objects (deterministic from
// the same templates + hierarchy seeds).
package tpm

import (
  "encoding/base64"
  "fmt"

  "github.com/google/go-tpm/tpm2"
  "github.com/google/go-tpm/tpm2/transport"
)

// ActivateCredentialResult holds the output of credential activation.
type ActivateCredentialResult struct {
  DecryptedCredential string `json:"decrypted_credential"`
}

// ActivateCredentialWithTransientAK decrypts a credential challenge by
// recreating both the EK and AK as transient objects.
//
// This is the preferred method: it does not depend on any persistent handles.
// Both keys are deterministic (same template + same hierarchy seed = same key
// every time on the same TPM), so recreating them produces the exact same
// key material and TPM Names as the original enrollment.
//
// DOES NOT REQUIRE ELEVATION (after one-time TBS setup on Windows).
func ActivateCredentialWithTransientAK(
  tpmTransport transport.TPMCloser,
  credentialBlobB64 string,
  encryptedSecretB64 string,
) (*ActivateCredentialResult, error) {
  credentialBlob, err := base64.StdEncoding.DecodeString(credentialBlobB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in credential_blob: %w", err)
  }

  encryptedSecret, err := base64.StdEncoding.DecodeString(encryptedSecretB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in encrypted_secret: %w", err)
  }

  // Step 1: Recreate the transient EK using the standard TCG template.
  ekResp, err := createTransientEK(tpmTransport)
  if err != nil {
    return nil, err
  }
  defer func() {
    flushCmd := tpm2.FlushContext{FlushHandle: ekResp.ObjectHandle}
    _, _ = flushCmd.Execute(tpmTransport)
  }()

  // Step 2: Recreate the transient AK (deterministic -- same key as enrollment).
  akData, err := CreateTransientAK(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not recreate transient AK for activation: %w", err)
  }
  defer FlushTransientAK(tpmTransport, akData)

  // Step 3: Start a policy session for EK usage.
  // The default EK requires PolicySecret(TPM_RH_ENDORSEMENT).
  sess, sessClose, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
  if err != nil {
    return nil, fmt.Errorf("could not start policy session: %w", err)
  }
  defer sessClose()

  policySecretCmd := tpm2.PolicySecret{
    AuthHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMRHEndorsement,
      Auth:   tpm2.PasswordAuth(nil),
    },
    PolicySession: sess.Handle(),
  }
  _, err = policySecretCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("PolicySecret(endorsement) failed: %w", err)
  }

  // Step 4: Read the EK's public area to get its Name.
  readEKPubResp, err := tpm2.ReadPublic{
    ObjectHandle: ekResp.ObjectHandle,
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read EK public area: %w", err)
  }

  // Step 5: Read the AK's public area to get its Name.
  readAKPubResp, err := tpm2.ReadPublic{
    ObjectHandle: akData.TransientHandle,
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area: %w", err)
  }

  // Step 6: TPM2_ActivateCredential.
  // ActivateHandle (AK) uses UserWithAuth, so PasswordAuth(nil) suffices.
  // KeyHandle (EK) uses the policy session (PolicySecret on endorsement).
  activateCmd := tpm2.ActivateCredential{
    ActivateHandle: tpm2.AuthHandle{
      Handle: akData.TransientHandle,
      Name:   readAKPubResp.Name,
      Auth:   tpm2.PasswordAuth(nil),
    },
    KeyHandle: tpm2.AuthHandle{
      Handle: ekResp.ObjectHandle,
      Name:   readEKPubResp.Name,
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

// ActivateCredential decrypts a credential challenge using a persistent AK handle.
// DEPRECATED: Use ActivateCredentialWithTransientAK instead. This function
// exists for backward compatibility with machines that have persistent AKs
// from older binary versions.
func ActivateCredential(
  tpmTransport transport.TPMCloser,
  akHandle uint32,
  credentialBlobB64 string,
  encryptedSecretB64 string,
) (*ActivateCredentialResult, error) {
  credentialBlob, err := base64.StdEncoding.DecodeString(credentialBlobB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in credential_blob: %w", err)
  }

  encryptedSecret, err := base64.StdEncoding.DecodeString(encryptedSecretB64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 in encrypted_secret: %w", err)
  }

  ekResp, err := createTransientEK(tpmTransport)
  if err != nil {
    return nil, err
  }
  defer func() {
    flushCmd := tpm2.FlushContext{FlushHandle: ekResp.ObjectHandle}
    _, _ = flushCmd.Execute(tpmTransport)
  }()

  sess, sessClose, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
  if err != nil {
    return nil, fmt.Errorf("could not start policy session: %w", err)
  }
  defer sessClose()

  policySecretCmd := tpm2.PolicySecret{
    AuthHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMRHEndorsement,
      Auth:   tpm2.PasswordAuth(nil),
    },
    PolicySession: sess.Handle(),
  }
  _, err = policySecretCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("PolicySecret(endorsement) failed: %w", err)
  }

  readAKPubResp, err := tpm2.ReadPublic{
    ObjectHandle: tpm2.TPMHandle(akHandle),
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read AK public area at handle 0x%08X: %w", akHandle, err)
  }

  readEKPubResp, err := tpm2.ReadPublic{
    ObjectHandle: ekResp.ObjectHandle,
  }.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not read EK public area: %w", err)
  }

  activateCmd := tpm2.ActivateCredential{
    ActivateHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMHandle(akHandle),
      Name:   readAKPubResp.Name,
      Auth:   tpm2.PasswordAuth(nil),
    },
    KeyHandle: tpm2.AuthHandle{
      Handle: ekResp.ObjectHandle,
      Name:   readEKPubResp.Name,
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

// createTransientEK creates a transient EK using the standard TCG RSA-2048 template.
// The template MUST exactly match what the TPM manufacturer used to create
// the EK certificate. Deterministic: same key every time on the same TPM.
func createTransientEK(tpmTransport transport.TPMCloser) (*tpm2.CreatePrimaryResponse, error) {
  tcgEKPolicyDigest := []byte{
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
  }

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
    AuthPolicy: tpm2.TPM2BDigest{Buffer: tcgEKPolicyDigest},
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

  createEKCmd := tpm2.CreatePrimary{
    PrimaryHandle: tpm2.AuthHandle{
      Handle: tpm2.TPMRHEndorsement,
      Auth:   tpm2.PasswordAuth(nil),
    },
    InPublic: tpm2.New2B(ekTemplate),
  }

  ekResp, err := createEKCmd.Execute(tpmTransport)
  if err != nil {
    return nil, fmt.Errorf("could not create transient EK for credential activation: %w", err)
  }

  return ekResp, nil
}
