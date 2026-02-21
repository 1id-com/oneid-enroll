// PIV challenge-response signing for ongoing authentication.
//
// After enrollment, agents authenticate to 1id.com by signing a
// server-provided nonce with the PIV key in slot 9a. The private key
// never leaves the YubiKey hardware.
//
// With pin-policy=NEVER, no PIN prompt or human interaction is needed.
// This is the PIV equivalent of TPM AK signing (tpm/sign.go).
//
// No elevation required.

package piv

import (
  "crypto"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "errors"
  "fmt"

  gopiv "github.com/go-piv/piv-go/piv"
)

// PIVSignChallengeResult holds the output of signing a challenge nonce with PIV.
type PIVSignChallengeResult struct {
  SignatureBase64 string `json:"signature_b64"`
  Algorithm       string `json:"algorithm"`
  SerialNumber    string `json:"serial_number"`
}

// SignChallengeWithPIVKey opens the first PIV device, retrieves the slot 9a
// private key, and signs the given nonce using ECDSA-SHA256.
//
// The nonce_base64 parameter is a base64-encoded server-provided challenge.
//
// Returns the signature as base64-encoded ASN.1 DER (standard ECDSA format),
// which the server can verify against the public key stored during enrollment.
func SignChallengeWithPIVKey(nonce_base64 string) (*PIVSignChallengeResult, error) {
  nonce_bytes, err := base64.StdEncoding.DecodeString(nonce_base64)
  if err != nil {
    return nil, fmt.Errorf("invalid base64 nonce: %w", err)
  }
  if len(nonce_bytes) == 0 || len(nonce_bytes) > 1024 {
    return nil, fmt.Errorf("nonce must be 1-1024 bytes, got %d", len(nonce_bytes))
  }

  yubikey_connection, _, err := OpenFirstAvailablePIVDevice()
  if err != nil {
    return nil, err
  }
  defer yubikey_connection.Close()

  device_serial_number, err := yubikey_connection.Serial()
  if err != nil {
    return nil, fmt.Errorf("could not read device serial number: %w", err)
  }

  // Get the public key from the stored certificate or via attestation.
  // Certificate(slot) returns the cert stored by SetCertificate() during extract.
  slot_9a := gopiv.SlotAuthentication
  var signing_public_key *ecdsa.PublicKey

  stored_cert, cert_err := yubikey_connection.Certificate(slot_9a)
  if cert_err == nil {
    ecdsa_key, ok := stored_cert.PublicKey.(*ecdsa.PublicKey)
    if ok {
      signing_public_key = ecdsa_key
    }
  }

  // Fallback: use Attest() to get the public key if no stored cert
  if signing_public_key == nil {
    attest_cert, attest_err := yubikey_connection.Attest(slot_9a)
    if attest_err != nil {
      return nil, fmt.Errorf("no key found in slot 9a (no stored cert and attestation failed): %w", attest_err)
    }
    ecdsa_key, ok := attest_cert.PublicKey.(*ecdsa.PublicKey)
    if !ok {
      return nil, fmt.Errorf("slot 9a key is not ECDSA (got %T)", attest_cert.PublicKey)
    }
    signing_public_key = ecdsa_key
  }

  if signing_public_key.Curve != elliptic.P256() {
    return nil, fmt.Errorf("expected P-256 key in slot 9a, got %s", signing_public_key.Curve.Params().Name)
  }

  // Get a crypto.Signer backed by the YubiKey hardware.
  // KeyAuth{} with no PIN because pin-policy=NEVER.
  private_key_interface, err := yubikey_connection.PrivateKey(
    slot_9a,
    signing_public_key,
    gopiv.KeyAuth{},
  )
  if err != nil {
    return nil, fmt.Errorf("could not get private key handle for slot 9a: %w", err)
  }

  hardware_signer, ok := private_key_interface.(crypto.Signer)
  if !ok {
    return nil, fmt.Errorf("private key does not implement crypto.Signer")
  }

  // Hash the nonce and sign with ECDSA-SHA256
  nonce_sha256_hash := sha256.Sum256(nonce_bytes)
  der_signature_bytes, err := hardware_signer.Sign(rand.Reader, nonce_sha256_hash[:], crypto.SHA256)
  if err != nil {
    return nil, fmt.Errorf("PIV signing failed: %w", err)
  }

  // Verify the signature locally before returning it (defense-in-depth)
  if !ecdsa.VerifyASN1(signing_public_key, nonce_sha256_hash[:], der_signature_bytes) {
    return nil, errors.New("CRITICAL: locally generated signature failed self-verification")
  }

  signature_base64 := base64.StdEncoding.EncodeToString(der_signature_bytes)

  return &PIVSignChallengeResult{
    SignatureBase64: signature_base64,
    Algorithm:       "ECDSA-SHA256",
    SerialNumber:    fmt.Sprintf("%d", device_serial_number),
  }, nil
}

