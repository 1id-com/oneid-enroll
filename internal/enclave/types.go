package enclave

// DetectedSecureEnclave holds information about a detected Secure Enclave.
type DetectedSecureEnclave struct {
  Type             string `json:"type"`
  Status           string `json:"status"`
  Platform         string `json:"platform"`
  HasSecureEnclave bool   `json:"has_secure_enclave"`
  ErrorDetail      string `json:"error_detail,omitempty"`
}

// GenerateEnclaveKeyResult holds the output of a key generation operation.
type GenerateEnclaveKeyResult struct {
  PublicKeyPEM         string `json:"public_key_pem"`
  KeyTag               string `json:"key_tag"`
  Algorithm            string `json:"algorithm"`
  KeyWasNewlyGenerated bool   `json:"key_was_newly_generated"`
}

// SignChallengeResult holds the output of a signing operation.
type SignChallengeResult struct {
  SignatureBase64 string `json:"signature_b64"`
  Algorithm       string `json:"algorithm"`
  KeyTag          string `json:"key_tag"`
}

// TransientEnclaveTestResult holds the output of a transient key test.
// Transient keys don't require Keychain entitlements (no persistent storage).
type TransientEnclaveTestResult struct {
  PublicKeyPEM    string `json:"public_key_pem"`
  SignatureBase64 string `json:"signature_b64"`
  Algorithm       string `json:"algorithm"`
  TestDataBase64  string `json:"test_data_b64"`
}

// EnclaveKeyWrapResult holds the output of a Secure Enclave ECDH + AES Key
// Wrap operation. The ephemeral public key and wrapped ciphertext are both
// needed to unwrap later (the Enclave private key is the other half).
type EnclaveKeyWrapResult struct {
  EphemeralPublicKeyBase64     string `json:"ephemeral_public_key_b64"`
  WrappedKeyBase64             string `json:"wrapped_key_b64"`
  EnclavePublicKeyBase64       string `json:"enclave_public_key_b64"`
  EnclavePublicKeyPEM          string `json:"enclave_public_key_pem"`
  Algorithm                    string `json:"algorithm"`
  PlaintextKeySizeBytes        int    `json:"plaintext_key_size_bytes"`
}

// EnclaveKeyUnwrapResult holds the recovered plaintext key after a Secure
// Enclave ECDH + AES Key Unwrap operation.
type EnclaveKeyUnwrapResult struct {
  PlaintextKeyBase64     string `json:"plaintext_key_b64"`
  PlaintextKeySizeBytes  int    `json:"plaintext_key_size_bytes"`
  Algorithm              string `json:"algorithm"`
}

