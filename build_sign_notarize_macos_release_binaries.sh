#!/bin/bash
# On moonmac (Intel Mac, Go in ~/go-sdk, Xcode Swift): build every macOS
# release binary -- oneid-enroll darwin amd64 + arm64 AND the Secure Enclave
# helper oneid-se-helper (x86_64, Intel Macs with a T2) + oneid-se-helper-arm64
# (Apple silicon) -- codesign each with the Developer ID (hardened runtime +
# timestamp), notarize each with notarytool, and REFUSE to finish unless
# Gatekeeper reports every binary as "Notarized Developer ID" (Chris: never
# publish anything unsigned; OWN-041 -- until 2.2.0 the SE helper was never
# built here and old ad-hoc copies were re-uploaded).
# Leaves build/oneid-enroll-darwin-{amd64,arm64}[.zip] and
# build/oneid-se-helper{,-arm64}. Standalone Mach-O binaries cannot be stapled
# (Error 73); Gatekeeper checks notarization online. Run from the source copy:
#   NOTARY_KEY_PATH=... NOTARY_KEY_ID=... NOTARY_ISSUER_ID=... ./build_sign_notarize_macos_release_binaries.sh 2.2.0
# (identifiers: 001_readme.md "Mac (codesign + notarization)"; never commit them)
set -euo pipefail
VERSION="${1:?usage: $0 VERSION}"
: "${NOTARY_KEY_PATH:?}" "${NOTARY_KEY_ID:?}" "${NOTARY_ISSUER_ID:?}"
TEAM_ID=XQYBH3CT45
IDENTITY="Developer ID Application: Christopher Drake (${TEAM_ID})"
KEYCHAIN=~/Library/Keychains/aura_signing.keychain-db
export PATH=~/go-sdk/go/bin:$PATH
mkdir -p build
security unlock-keychain -p "" "$KEYCHAIN"

sign_notarize_and_require_gatekeeper_acceptance() {
  local binary="$1"
  codesign --force --options runtime --timestamp -s "$IDENTITY" --keychain "$KEYCHAIN" "$binary"
  codesign --verify --strict --verbose=2 "$binary"
  rm -f "${binary}.zip"
  ditto -c -k --keepParent "$binary" "${binary}.zip"
  xcrun notarytool submit "${binary}.zip" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" \
    --issuer "$NOTARY_ISSUER_ID" --team-id "$TEAM_ID" --wait 2>&1 | grep -E "status:|id:" | tail -2
  local assessment
  assessment=$(spctl -a -vv -t install "$binary" 2>&1 || true)
  echo "$assessment" | sed 's/^/    /'
  echo "$assessment" | grep -q "source=Notarized Developer ID" \
    || { echo "REFUSING: $binary is not accepted as Notarized Developer ID"; exit 1; }
}

for arch in amd64 arm64; do
  binary="build/oneid-enroll-darwin-${arch}"
  CGO_ENABLED=1 GOOS=darwin GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" -o "$binary" ./cmd/oneid-enroll/
  sign_notarize_and_require_gatekeeper_acceptance "$binary"
done

# Secure Enclave helper (CryptoKit SecureEnclave.P256; macOS 11+). The
# arm64 build is cross-compiled on this Intel Mac.
for se_arch in x86_64 arm64; do
  if [ "$se_arch" = arm64 ]; then se_binary=build/oneid-se-helper-arm64; else se_binary=build/oneid-se-helper; fi
  swiftc -O -target "${se_arch}-apple-macos11" -o "$se_binary" ./cmd/oneid-se-helper/main.swift
  sign_notarize_and_require_gatekeeper_acceptance "$se_binary"
  rm -f "${se_binary}.zip"   # the release ships the raw SE helper binaries
done

file build/oneid-enroll-darwin-amd64 build/oneid-enroll-darwin-arm64 build/oneid-se-helper build/oneid-se-helper-arm64 | cut -c1-100
./build/oneid-enroll-darwin-amd64 version --json | tr -d '\n '; echo
