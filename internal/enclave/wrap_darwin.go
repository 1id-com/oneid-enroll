//go:build darwin

package enclave

import (
  "crypto/elliptic"
  "crypto/rand"
  "encoding/base64"
  "fmt"

  "github.com/1id-com/oneid-enroll/internal/piv"
)

const enclave_keywrap_application_tag = "com.1id.keywrap"

func GetEnclaveKeywrapPublicKey() (*swift_helper_json_response, error) {
  return run_se_helper("keywrap-pubkey", "--tag", enclave_keywrap_application_tag)
}

func PerformEnclaveECDH(peer_public_key_x963_base64 string) (*swift_helper_json_response, error) {
  return run_se_helper("ecdh", "--tag", enclave_keywrap_application_tag, "--peer-pub", peer_public_key_x963_base64)
}

// WrapKeyWithEnclave encrypts a key using Secure Enclave ECDH-P256 + Concat
// KDF + AES-256 Key Wrap. The caller provides the plaintext key as base64.
//
// Flow:
//  1. Get the Enclave's persistent P-256 KeyAgreement public key
//  2. Generate an ephemeral P-256 key pair in software
//  3. Ask the Enclave to perform ECDH(enclave_privkey, ephemeral_pubkey)
//  4. Derive AES-256 KEK from the shared secret via NIST Concat KDF
//  5. Wrap the plaintext key with AES Key Wrap (RFC 3394)
//
// To unwrap, the caller needs the ephemeral public key and the wrapped
// ciphertext. The Enclave private key provides the other half of the ECDH.
func WrapKeyWithEnclave(plaintext_key_base64 string) (*EnclaveKeyWrapResult, error) {
  plaintext_key_bytes, err := base64.StdEncoding.DecodeString(plaintext_key_base64)
  if err != nil {
    return nil, fmt.Errorf("could not decode plaintext key from base64: %w", err)
  }

  if len(plaintext_key_bytes) < 16 {
    return nil, fmt.Errorf("plaintext key must be at least 16 bytes (got %d)", len(plaintext_key_bytes))
  }
  if len(plaintext_key_bytes) > 128 {
    return nil, fmt.Errorf("plaintext key must be at most 128 bytes (got %d)", len(plaintext_key_bytes))
  }
  if len(plaintext_key_bytes)%8 != 0 {
    return nil, fmt.Errorf("plaintext key must be a multiple of 8 bytes for AES Key Wrap (got %d)", len(plaintext_key_bytes))
  }

  enclave_pubkey_response, err := GetEnclaveKeywrapPublicKey()
  if err != nil {
    return nil, fmt.Errorf("could not get Enclave keywrap public key: %w", err)
  }

  _, ephemeral_x_coordinate, ephemeral_y_coordinate, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return nil, fmt.Errorf("could not generate ephemeral P-256 key: %w", err)
  }

  ephemeral_public_key_x963 := elliptic.Marshal(elliptic.P256(), ephemeral_x_coordinate, ephemeral_y_coordinate)
  ephemeral_public_key_x963_b64 := base64.StdEncoding.EncodeToString(ephemeral_public_key_x963)

  ecdh_response, err := PerformEnclaveECDH(ephemeral_public_key_x963_b64)
  if err != nil {
    return nil, fmt.Errorf("Secure Enclave ECDH failed: %w", err)
  }

  shared_secret_bytes, err := base64.StdEncoding.DecodeString(ecdh_response.SharedSecretB64)
  if err != nil {
    return nil, fmt.Errorf("could not decode shared secret from SE helper: %w", err)
  }

  padded_shared_secret := piv.PadECDHSharedSecretTo32Bytes(shared_secret_bytes)
  kek := piv.DeriveAES256KEKViaConcatKDF(padded_shared_secret)

  wrapped_key, err := piv.AESKeyWrap(kek, plaintext_key_bytes)
  if err != nil {
    return nil, fmt.Errorf("AES Key Wrap failed: %w", err)
  }

  return &EnclaveKeyWrapResult{
    EphemeralPublicKeyBase64: ephemeral_public_key_x963_b64,
    WrappedKeyBase64:         base64.StdEncoding.EncodeToString(wrapped_key),
    EnclavePublicKeyBase64:   enclave_pubkey_response.PublicKeyX963B64,
    EnclavePublicKeyPEM:      enclave_pubkey_response.PublicKeyPEM,
    Algorithm:                "ecdh-p256+concat-kdf+aes256-keywrap",
    PlaintextKeySizeBytes:    len(plaintext_key_bytes),
  }, nil
}

// UnwrapKeyWithEnclave decrypts a wrapped key using Secure Enclave ECDH and
// AES Key Unwrap. The caller provides the ephemeral public key (from the
// original wrap) and the wrapped ciphertext.
func UnwrapKeyWithEnclave(ephemeral_public_key_x963_base64 string, wrapped_key_base64 string) (*EnclaveKeyUnwrapResult, error) {
  wrapped_key_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_base64)
  if err != nil {
    return nil, fmt.Errorf("could not decode wrapped key from base64: %w", err)
  }

  ecdh_response, err := PerformEnclaveECDH(ephemeral_public_key_x963_base64)
  if err != nil {
    return nil, fmt.Errorf("Secure Enclave ECDH (unwrap) failed: %w", err)
  }

  shared_secret_bytes, err := base64.StdEncoding.DecodeString(ecdh_response.SharedSecretB64)
  if err != nil {
    return nil, fmt.Errorf("could not decode shared secret from SE helper: %w", err)
  }

  padded_shared_secret := piv.PadECDHSharedSecretTo32Bytes(shared_secret_bytes)
  kek := piv.DeriveAES256KEKViaConcatKDF(padded_shared_secret)

  plaintext_key_bytes, err := piv.AESKeyUnwrap(kek, wrapped_key_bytes)
  if err != nil {
    return nil, fmt.Errorf("AES Key Unwrap failed (wrong enclave key or corrupted data?): %w", err)
  }

  return &EnclaveKeyUnwrapResult{
    PlaintextKeyBase64:    base64.StdEncoding.EncodeToString(plaintext_key_bytes),
    PlaintextKeySizeBytes: len(plaintext_key_bytes),
    Algorithm:             "ecdh-p256+concat-kdf+aes256-keywrap",
  }, nil
}
