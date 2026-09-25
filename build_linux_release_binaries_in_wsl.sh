#!/bin/bash
# Build the Linux amd64 + arm64 release binaries of oneid-enroll in WSL.
# Prerequisites are set up per 001_readme.md "Build: Linux amd64/arm64 (on WSL)":
# Go 1.24 in ~/go-sdk, libpcsclite in /tmp/pcsclite, the aarch64 cross
# compiler in /tmp/arm64cc and arm64 PCSC in /tmp/arm64pcsc (WSL /tmp is lost
# on WSL restart -- re-run those readme steps if a check below fails).
# Usage (from Git Bash): MSYS_NO_PATHCONV=1 wsl -e bash -lc 'cd /mnt/c/.../sdk/oneid-enroll && ./build_linux_release_binaries_in_wsl.sh 2.1.0'
set -euo pipefail
VERSION="${1:?usage: $0 VERSION}"
GO=~/go-sdk/go/bin/go
for required in "$GO" /tmp/pcsclite/usr/include /tmp/arm64cc/usr/bin/aarch64-linux-gnu-gcc-9 /tmp/arm64pcsc/usr/include; do
  [ -e "$required" ] || { echo "missing $required -- see 001_readme.md 'Build: Linux'"; exit 1; }
done
LDFLAGS="-s -w -X main.version=${VERSION}"

PKG_CONFIG_PATH=/tmp/pcsclite/usr/lib/x86_64-linux-gnu/pkgconfig \
CGO_ENABLED=1 CGO_CFLAGS="-I/tmp/pcsclite/usr/include" CGO_LDFLAGS="-L/tmp/pcsclite/usr/lib/x86_64-linux-gnu" \
  GOOS=linux GOARCH=amd64 "$GO" build -ldflags "$LDFLAGS" -o build/oneid-enroll-linux-amd64 ./cmd/oneid-enroll/

LD_LIBRARY_PATH=/tmp/arm64cc/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-} \
PKG_CONFIG_PATH=/tmp/arm64pcsc/usr/lib/aarch64-linux-gnu/pkgconfig \
CC=/tmp/arm64cc/usr/bin/aarch64-linux-gnu-gcc-9 \
CGO_ENABLED=1 \
CGO_CFLAGS="-I/tmp/arm64pcsc/usr/include -I/usr/lib/gcc/x86_64-linux-gnu/9/include -I/tmp/arm64cc/usr/aarch64-linux-gnu/include" \
CGO_LDFLAGS="-L/tmp/arm64pcsc/usr/lib/aarch64-linux-gnu -L/tmp/arm64cc/usr/aarch64-linux-gnu/lib -L/tmp/arm64cc/usr/lib/gcc-cross/aarch64-linux-gnu/9 --sysroot=/tmp/arm64cc" \
  GOOS=linux GOARCH=arm64 "$GO" build -ldflags "$LDFLAGS" -o build/oneid-enroll-linux-arm64 ./cmd/oneid-enroll/

file build/oneid-enroll-linux-amd64 build/oneid-enroll-linux-arm64 | cut -c1-110
./build/oneid-enroll-linux-amd64 version --json | tr -d '\n '; echo
