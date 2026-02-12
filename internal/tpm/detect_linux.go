//go:build linux

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
)

// detectTPMsPlatform opens the TPM via go-tpm's cross-platform OpenTPM().
// On Linux, this tries /dev/tpmrm0 first, then /dev/tpm0.
func detectTPMsPlatform() []DetectedTPM {
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		return nil
	}
	defer tpmDevice.Close()

	return queryTPMProperties(tpmDevice, "/dev/tpmrm0")
}
