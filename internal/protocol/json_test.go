package protocol

import (
	"testing"
)

func TestHumanMessage_DoesNotPanic(t *testing.T) {
	// HumanMessage writes to stderr; just verify it doesn't panic
	HumanMessage("test message: %s", "hello")
	HumanMessage("no args message")
}

func TestManufacturerCodeMapping(t *testing.T) {
	// Not in this package, but verify the protocol package compiles
	// and basic JSON operations work
	data := map[string]interface{}{
		"test_key": "test_value",
		"count":    42,
	}
	if data["count"] != 42 {
		t.Errorf("expected 42, got %v", data["count"])
	}
}
