//go:build !darwin

package enclave

import "fmt"

func WrapKeyWithEnclave(plaintext_key_base64 string) (*EnclaveKeyWrapResult, error) {
  return nil, fmt.Errorf("Secure Enclave key wrapping is only available on macOS (this platform: non-darwin)")
}

func UnwrapKeyWithEnclave(ephemeral_public_key_x963_base64 string, wrapped_key_base64 string) (*EnclaveKeyUnwrapResult, error) {
  return nil, fmt.Errorf("Secure Enclave key unwrapping is only available on macOS (this platform: non-darwin)")
}
