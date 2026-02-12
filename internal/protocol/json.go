// Package protocol handles JSON input/output for SDK communication.
//
// When the binary runs with --json, all output is structured JSON on stdout.
// Errors are also JSON with an error_code and error fields.
// Human-readable output goes to stderr (so JSON on stdout stays clean).
package protocol

import (
	"encoding/json"
	"fmt"
	"os"
)

// SuccessResponse writes a JSON success response to stdout.
// The data parameter is serialized as the top-level JSON object.
func SuccessResponse(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		// If we can't even encode JSON, write a raw error
		fmt.Fprintf(os.Stderr, "FATAL: could not encode JSON response: %v\n", err)
		os.Exit(2)
	}
}

// ErrorResponse writes a JSON error response to stdout and exits with code 1.
func ErrorResponse(errorCode string, message string) {
	response := map[string]string{
		"error_code": errorCode,
		"error":      message,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(response)
	os.Exit(1)
}

// HumanMessage prints a message to stderr (visible in human mode,
// hidden from JSON-parsing SDKs that only read stdout).
func HumanMessage(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
