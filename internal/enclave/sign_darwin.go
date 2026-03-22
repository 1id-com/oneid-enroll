//go:build darwin

package enclave

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "os"
  "os/exec"
  "path/filepath"
)

func find_se_helper_binary_path() (string, error) {
  current_executable_path, err := os.Executable()
  if err == nil {
    sibling_helper_path := filepath.Join(filepath.Dir(current_executable_path), "oneid-se-helper")
    if _, stat_err := os.Stat(sibling_helper_path); stat_err == nil {
      return sibling_helper_path, nil
    }
  }

  path_helper_path, err := exec.LookPath("oneid-se-helper")
  if err == nil {
    return path_helper_path, nil
  }

  return "", fmt.Errorf("oneid-se-helper not found (looked next to binary and in PATH). " +
    "The Swift Secure Enclave helper is required for key generation and signing on macOS. " +
    "Build it with: swiftc -O -o oneid-se-helper cmd/oneid-se-helper/main.swift")
}

type swift_helper_json_response struct {
  Status              string `json:"status"`
  Error               string `json:"error"`
  ErrorCode           string `json:"error_code"`
  PublicKeyPEM        string `json:"public_key_pem"`
  KeyTag              string `json:"key_tag"`
  Algorithm           string `json:"algorithm"`
  KeyWasNewlyGenerated bool  `json:"key_was_newly_generated"`
  SignatureBase64     string `json:"signature_b64"`
  TestDataBase64      string `json:"test_data_b64"`
  HasSecureEnclave    bool   `json:"has_secure_enclave"`
  Platform            string `json:"platform"`
}

func run_se_helper(args ...string) (*swift_helper_json_response, error) {
  helper_path, err := find_se_helper_binary_path()
  if err != nil {
    return nil, err
  }

  cmd := exec.Command(helper_path, args...)
  output, err := cmd.Output()
  if err != nil {
    if exit_err, ok := err.(*exec.ExitError); ok {
      return nil, fmt.Errorf("oneid-se-helper failed (exit %d): %s", exit_err.ExitCode(), string(exit_err.Stderr))
    }
    return nil, fmt.Errorf("oneid-se-helper execution failed: %w", err)
  }

  var response swift_helper_json_response
  if json_err := json.Unmarshal(output, &response); json_err != nil {
    return nil, fmt.Errorf("could not parse oneid-se-helper JSON output: %w (raw: %s)", json_err, string(output))
  }

  if response.Error != "" {
    return nil, fmt.Errorf("%s: %s", response.ErrorCode, response.Error)
  }

  return &response, nil
}

func GenerateOrRetrieveEnclaveKey(application_tag_for_keychain string) (*GenerateEnclaveKeyResult, error) {
  response, err := run_se_helper("generate", "--tag", application_tag_for_keychain)
  if err != nil {
    return nil, fmt.Errorf("Secure Enclave key generation failed: %w", err)
  }

  return &GenerateEnclaveKeyResult{
    PublicKeyPEM:         response.PublicKeyPEM,
    KeyTag:              response.KeyTag,
    Algorithm:           response.Algorithm,
    KeyWasNewlyGenerated: response.KeyWasNewlyGenerated,
  }, nil
}

func SignChallengeWithEnclaveKey(nonce_base64 string, application_tag_for_keychain string) (*SignChallengeResult, error) {
  response, err := run_se_helper("sign", "--tag", application_tag_for_keychain, "--nonce", nonce_base64)
  if err != nil {
    return nil, fmt.Errorf("Secure Enclave signing failed: %w", err)
  }

  return &SignChallengeResult{
    SignatureBase64: response.SignatureBase64,
    Algorithm:      response.Algorithm,
    KeyTag:         response.KeyTag,
  }, nil
}

func TestTransientEnclaveKeygenAndSign(test_data_for_signing []byte) (*TransientEnclaveTestResult, error) {
  response, err := run_se_helper("test")
  if err != nil {
    return nil, fmt.Errorf("Secure Enclave transient test failed: %w", err)
  }

  _ = test_data_for_signing

  return &TransientEnclaveTestResult{
    PublicKeyPEM:    response.PublicKeyPEM,
    SignatureBase64: response.SignatureBase64,
    Algorithm:      response.Algorithm,
    TestDataBase64:  response.TestDataBase64,
  }, nil
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

