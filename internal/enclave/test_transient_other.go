//go:build !darwin

package enclave

import "fmt"

func TestTransientEnclaveKeygenAndSign(test_data_for_signing []byte) (*TransientEnclaveTestResult, error) {
  return nil, fmt.Errorf("Secure Enclave transient test is only available on macOS")
}

