package tpm

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestComputeAMDEKHash(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  []byte
		wantLen int // hex string length (16 bytes = 32 hex chars)
	}{
		{
			name:    "ECC P-256 public key",
			pubKey:  []byte{0x04, 0x9c, 0xe8, 0x77, 0x85, 0xd5, 0x8d, 0x90, 0x1d, 0x0a, 0x06, 0xe0, 0x15, 0xa2, 0x8b, 0x4f, 0x6f, 0x8d, 0xa1, 0xfd, 0xd5, 0x9c, 0xee, 0x2a, 0xe1, 0x0c, 0x9b, 0x2b, 0xc5, 0xeb, 0x23, 0xf8, 0x8e, 0x2e, 0x28, 0x60, 0x5d, 0x12, 0x6a, 0x32, 0xd0, 0x7c, 0xc4, 0xf1, 0x1a, 0x81, 0x08, 0x1e, 0x7c, 0x2d, 0xff, 0xf2, 0x79, 0x40, 0xd1, 0x85, 0xb9, 0x3f, 0x66, 0xa1, 0x40, 0xb9, 0xa6, 0x89, 0x58},
			wantLen: 32,
		},
		{
			name:    "empty public key",
			pubKey:  []byte{},
			wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeAMDEKHash(tt.pubKey)
			if len(result) != tt.wantLen {
				t.Errorf("computeAMDEKHash() = %q (len=%d), want len=%d", result, len(result), tt.wantLen)
			}
		})
	}
}

func TestComputeAMDEKHash_Format(t *testing.T) {
	// Hash should be hex-encoded (only 0-9, a-f)
	result := computeAMDEKHash([]byte{0x04, 0x01, 0x02})
	for _, c := range result {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("computeAMDEKHash() contains non-hex char: %c", c)
		}
	}
}

func TestComputeAMDEKHash_Deterministic(t *testing.T) {
	pubKey := []byte{0x04, 0x9c, 0xe8, 0x77}
	hash1 := computeAMDEKHash(pubKey)
	hash2 := computeAMDEKHash(pubKey)
	if hash1 != hash2 {
		t.Errorf("computeAMDEKHash not deterministic: %q != %q", hash1, hash2)
	}
}

func TestFetchFromAMDServer_Success(t *testing.T) {
	// Start a test server that simulates AMD's response
	certContent := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(certContent))
	}))
	defer server.Close()

	// Save original URL and restore after test
	originalURL := amdEKCertServerURL
	amdEKCertServerURL = server.URL
	defer func() { amdEKCertServerURL = originalURL }()

	result, err := fetchFromAMDServer("testhash")
	if err != nil {
		t.Fatalf("fetchFromAMDServer() error = %v", err)
	}
	if string(result) != certContent {
		t.Errorf("fetchFromAMDServer() = %q, want %q", string(result), certContent)
	}
}

func TestFetchFromAMDServer_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	originalURL := amdEKCertServerURL
	amdEKCertServerURL = server.URL
	defer func() { amdEKCertServerURL = originalURL }()

	_, err := fetchFromAMDServer("nonexistent")
	if err == nil {
		t.Error("fetchFromAMDServer() expected error for 404")
	}
}

func TestFetchFromAMDServer_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	originalURL := amdEKCertServerURL
	amdEKCertServerURL = server.URL
	defer func() { amdEKCertServerURL = originalURL }()

	_, err := fetchFromAMDServer("errorhash")
	if err == nil {
		t.Error("fetchFromAMDServer() expected error for 500")
	}
}
