//go:build windows

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
)

// detectTPMsPlatform uses the Windows TBS (TPM Base Services) API
// via go-tpm's cross-platform transport.OpenTPM() to detect TPM.
//
// No elevation required for detection -- TBS allows unprivileged
// access to read TPM properties.
func detectTPMsPlatform() []DetectedTPM {
	tpmDevice, err := transport.OpenTPM()
	if err != nil {
		return nil
	}
	defer tpmDevice.Close()

	return queryTPMProperties(tpmDevice, "tbs")
}
