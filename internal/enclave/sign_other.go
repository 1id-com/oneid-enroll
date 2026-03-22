//go:build !darwin

package enclave

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/x509"
  "encoding/base64"
  "encoding/pem"
  "fmt"
)

func GenerateOrRetrieveEnclaveKey(application_tag_for_keychain string) (*GenerateEnclaveKeyResult, error) {
  return nil, fmt.Errorf("Apple Secure Enclave is only available on macOS (this platform: non-darwin)")
}

func SignChallengeWithEnclaveKey(nonce_base64 string, application_tag_for_keychain string) (*SignChallengeResult, error) {
  return nil, fmt.Errorf("Apple Secure Enclave is only available on macOS (this platform: non-darwin)")
}

func VerifyEnclaveSignature(public_key_pem string, signature_base64 string, original_data []byte) error {
  block, _ := pem.Decode([]byte(public_key_pem))
  if block == nil {
    return fmt.Errorf("could not decode PEM public key")
  }

  pub_key_interface, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    return fmt.Errorf("could not parse SPKI public key: %w", err)
  }

  ecdsa_pub, ok := pub_key_interface.(*ecdsa.PublicKey)
  if !ok {
    return fmt.Errorf("public key is not ECDSA")
  }

  if ecdsa_pub.Curve != elliptic.P256() {
    return fmt.Errorf("public key is not P-256")
  }

  signature_der, err := base64.StdEncoding.DecodeString(signature_base64)
  if err != nil {
    return fmt.Errorf("could not decode signature from base64: %w", err)
  }

  if !ecdsa.VerifyASN1(ecdsa_pub, original_data, signature_der) {
    return fmt.Errorf("ECDSA signature verification failed")
  }

  return nil
}

