//go:build darwin

package enclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework IOKit
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdlib.h>

// check_secure_enclave_available returns 1 if the Secure Enclave is available
// on this Mac (Apple Silicon or T2 chip), 0 otherwise.
//
// We probe by looking for the AppleSEPManager IOService which is present
// on all Macs with a Secure Enclave Processor (SEP).
//
// MACH_PORT_NULL is used instead of kIOMasterPortDefault / kIOMainPortType
// for SDK compatibility across macOS 10.x through 15.x.
static int check_secure_enclave_available() {
  io_service_t sep_service = IOServiceGetMatchingService(
    MACH_PORT_NULL,
    IOServiceMatching("AppleSEPManager")
  );
  if (sep_service != IO_OBJECT_NULL) {
    IOObjectRelease(sep_service);
    return 1;
  }
  return 0;
}
*/
import "C"

import "runtime"

// DetectSecureEnclave checks if Apple Secure Enclave is available on this Mac.
func DetectSecureEnclave() []DetectedSecureEnclave {
  enclave_is_available := C.check_secure_enclave_available() == 1

  if !enclave_is_available {
    return []DetectedSecureEnclave{{
      Type:             "secure_enclave",
      Status:           "not_available",
      Platform:         "darwin/" + runtime.GOARCH,
      HasSecureEnclave: false,
      ErrorDetail:      "No Secure Enclave found (requires Apple Silicon or T2 chip)",
    }}
  }

  return []DetectedSecureEnclave{{
    Type:             "secure_enclave",
    Status:           "ready",
    Platform:         "darwin/" + runtime.GOARCH,
    HasSecureEnclave: true,
  }}
}

