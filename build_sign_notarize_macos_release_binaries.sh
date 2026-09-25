#!/bin/bash
# On moonmac (Intel Mac, Go in ~/go-sdk): build darwin amd64 + arm64,
# codesign with the Developer ID (hardened runtime + timestamp), notarize both
# with notarytool, and leave build/oneid-enroll-darwin-{amd64,arm64}[.zip].
# Standalone Mach-O binaries cannot be stapled (Error 73); Gatekeeper checks
# notarization online. Run from the source copy on moonmac:
#   NOTARY_KEY_PATH=... NOTARY_KEY_ID=... NOTARY_ISSUER_ID=... ./build_sign_notarize_macos_release_binaries.sh 2.1.0
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
for arch in amd64 arm64; do
  binary="build/oneid-enroll-darwin-${arch}"
  CGO_ENABLED=1 GOOS=darwin GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" -o "$binary" ./cmd/oneid-enroll/
  codesign --force --options runtime --timestamp -s "$IDENTITY" --keychain "$KEYCHAIN" "$binary"
  codesign --verify --verbose=2 "$binary"
  rm -f "${binary}.zip"
  ditto -c -k --keepParent "$binary" "${binary}.zip"
  xcrun notarytool submit "${binary}.zip" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" \
    --issuer "$NOTARY_ISSUER_ID" --team-id "$TEAM_ID" --wait 2>&1 | grep -E "status:|id:" | tail -2
done
file build/oneid-enroll-darwin-amd64 build/oneid-enroll-darwin-arm64 | cut -c1-100
./build/oneid-enroll-darwin-amd64 version --json | tr -d '\n '; echo
