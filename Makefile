# Makefile for oneid-enroll -- 1id.com HSM Identity Enrollment Helper
#
# IMPORTANT: go-piv (PIV/YubiKey) requires CGo (it calls into PCSC).
# CGO_ENABLED=1 is mandatory for every build. Cross-compilation needs
# the target platform's C toolchain + PCSC headers installed.
#
# Recommended build strategy (see 001_readme.md for full details):
#   Windows amd64  — build natively on RoG (CGO_ENABLED=1, Strawberry gcc)
#   macOS amd64    — build natively on moonmac
#   macOS arm64    — cross-compile on moonmac (Apple clang handles both)
#   Linux amd64    — build in WSL (needs libpcsclite-dev)
#   Linux arm64    — cross-compile in WSL (needs aarch64-linux-gnu toolchain)
#
# Quick single-platform build: make build
# Build current platform only: make build CGO_ENABLED=1
#
# Usage:
#   make build         Build for current platform (CGo enabled)
#   make sign          SHA-256 hash + GPG detached-sign all binaries in build/
#   make verify        Verify all GPG signatures in build/
#   make clean         Remove build artifacts
#
# The signing key (Ed25519, passwordless) lives in signing/gpg/ so that
# "git pull" on any machine gives full signing capability.

VERSION     ?= 0.5.0
BINARY_NAME  = oneid-enroll
MODULE       = github.com/1id-com/oneid-enroll
CMD_DIR      = ./cmd/oneid-enroll
BUILD_DIR    = ./build
SIGNING_DIR  = ./signing
GPG_HOME     = $(SIGNING_DIR)/gpg
GPG_KEY_ID   = releases@1id.com
LDFLAGS      = -s -w -X main.version=$(VERSION)

# Find gpg (some systems install as gpg2)
GPG_BIN      := $(shell which gpg 2>/dev/null || which gpg2 2>/dev/null || echo "")

# Platform detection for native build
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
UNAME_M := $(shell uname -m 2>/dev/null || echo x86_64)

# Map uname output to Go conventions
ifeq ($(UNAME_S),Linux)
  NATIVE_OS   = linux
  SHA256_CMD  = sha256sum
endif
ifeq ($(UNAME_S),Darwin)
  NATIVE_OS   = darwin
  SHA256_CMD  = shasum -a 256
endif
ifeq ($(UNAME_S),Windows)
  NATIVE_OS   = windows
  SHA256_CMD  = sha256sum
endif

ifeq ($(UNAME_M),x86_64)
  NATIVE_ARCH = amd64
endif
ifeq ($(UNAME_M),aarch64)
  NATIVE_ARCH = arm64
endif
ifeq ($(UNAME_M),arm64)
  NATIVE_ARCH = arm64
endif

# The binary name for this platform
ifeq ($(NATIVE_OS),windows)
  NATIVE_BINARY = $(BUILD_DIR)/$(BINARY_NAME)-$(NATIVE_OS)-$(NATIVE_ARCH).exe
else
  NATIVE_BINARY = $(BUILD_DIR)/$(BINARY_NAME)-$(NATIVE_OS)-$(NATIVE_ARCH)
endif

# =============================================================================
# Targets
# =============================================================================

.PHONY: all build build-all sign verify import-key test clean help
.PHONY: build-windows-amd64 build-linux-amd64 build-linux-arm64
.PHONY: build-darwin-amd64 build-darwin-arm64

all: build

help:
	@echo ""
	@echo "  oneid-enroll build system"
	@echo "  ========================="
	@echo ""
	@echo "  make build           Build for current platform (CGo enabled)"
	@echo "  make sign            SHA-256 + GPG sign all binaries in build/"
	@echo "  make verify          Verify all GPG signatures in build/"
	@echo "  make test            Run Go tests"
	@echo "  make clean           Remove build/"
	@echo ""
	@echo "  NOTE: go-piv requires CGO_ENABLED=1 for all builds."
	@echo "  Cross-compilation needs per-platform C toolchains."
	@echo "  See 001_readme.md for per-platform build instructions."
	@echo ""
	@echo "  Detected: $(NATIVE_OS)/$(NATIVE_ARCH)"
	@echo "  Binary:   $(NATIVE_BINARY)"
	@echo ""

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------

# Build for the current platform only (CGo enabled for go-piv PCSC)
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=$(NATIVE_OS) GOARCH=$(NATIVE_ARCH) go build \
	  -ldflags "$(LDFLAGS)" -o $(NATIVE_BINARY) $(CMD_DIR)
	@echo "Built: $(NATIVE_BINARY)"
	@chmod +x $(NATIVE_BINARY) 2>/dev/null || true

# Build all 5 platforms. Because go-piv requires CGo and platform-specific
# PCSC libraries, this target only works if ALL cross-compilation toolchains
# are installed. In practice, build each platform on its native machine
# (or with the correct cross-compiler). This target is here for reference.
build-all: build-windows-amd64 build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64
	@echo ""
	@echo "All binaries:"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)-* 2>/dev/null || dir $(BUILD_DIR)
	@echo ""

build-windows-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

build-linux-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)

build-linux-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

build-darwin-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)

build-darwin-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" \
	  -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

# ---------------------------------------------------------------------------
# Sign targets -- hash + GPG detached signature for each binary
# ---------------------------------------------------------------------------

sign:
	@if [ -z "$(GPG_BIN)" ]; then \
	  echo "ERROR: gpg not found. Install gnupg to sign binaries."; \
	  exit 1; \
	fi
	@echo "Signing binaries in $(BUILD_DIR)/ ..."
	@if [ ! -d "$(GPG_HOME)" ]; then \
	  echo "ERROR: GPG keyring not found at $(GPG_HOME)/"; \
	  echo "       Run 'git pull' to get the signing key material."; \
	  exit 1; \
	fi
	@for bin in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
	  case "$$bin" in \
	    *.sha256|*.asc) continue ;; \
	  esac; \
	  echo "  Hashing:  $$bin"; \
	  $(SHA256_CMD) "$$bin" > "$$bin.sha256"; \
	  echo "  Signing:  $$bin.sha256"; \
	  GNUPGHOME="$(GPG_HOME)" $(GPG_BIN) --batch --yes --detach-sign --armor \
	    --default-key "$(GPG_KEY_ID)" "$$bin.sha256"; \
	done
	@echo ""
	@echo "Done. Each binary now has:"
	@echo "  .sha256      SHA-256 checksum"
	@echo "  .sha256.asc  GPG detached signature of the checksum"
	@echo ""

# ---------------------------------------------------------------------------
# Verify targets -- check all signatures
# ---------------------------------------------------------------------------

# Import the public key into the local GPG keyring (needed for GPG 2.0.x
# which cannot read the .kbx format). Idempotent -- safe to run repeatedly.
import-key:
	@if [ -z "$(GPG_BIN)" ]; then \
	  echo "SKIP: gpg not found -- cannot import key."; \
	else \
	  echo "Importing release signing public key..."; \
	  GNUPGHOME="$(GPG_HOME)" $(GPG_BIN) --batch --yes --import \
	    "$(SIGNING_DIR)/release-signing-key.pub.asc" 2>&1 || true; \
	fi

verify: import-key
	@if [ -z "$(GPG_BIN)" ]; then \
	  echo "SKIP: gpg not found on this machine. Install gnupg to verify signatures."; \
	else \
	  echo "Verifying signatures in $(BUILD_DIR)/ ..."; \
	  all_ok=true; \
	  for sig in $(BUILD_DIR)/$(BINARY_NAME)-*.sha256.asc; do \
	    hashfile="$${sig%.asc}"; \
	    echo "  Verifying: $$hashfile"; \
	    if GNUPGHOME="$(GPG_HOME)" $(GPG_BIN) --batch --verify "$$sig" "$$hashfile" 2>&1; then \
	      echo "    OK"; \
	    else \
	      echo "    FAILED"; \
	      all_ok=false; \
	    fi; \
	  done; \
	  if $$all_ok; then \
	    echo ""; \
	    echo "All signatures valid."; \
	  else \
	    echo ""; \
	    echo "WARNING: Some signatures FAILED!"; \
	    exit 1; \
	  fi; \
	fi

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test:
	go test -v ./...

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
