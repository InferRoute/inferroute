#!/bin/sh
# Build and AD-HOC sign the VM runner on a Mac. Development and pre-release use.
#
#   sh native/macos/build_runner.sh [output-dir]
#
# Needs only the Xcode Command Line Tools (swiftc, codesign). An ad-hoc signature carries the
# virtualization entitlement, which is what lets the binary use Virtualization.framework at all; it says
# nothing about WHO built it. That is established elsewhere — by the runner's sha256 being pinned in the
# vendor-signed runtime manifest — and a Developer ID signature plus notarization remain a release gate.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/build"}
[ "$(uname -s)" = "Darwin" ] || { echo "build_runner: this builds on macOS only" >&2; exit 78; }
mkdir -p "$OUT"
# DEV_CONSOLE=1 builds a DEVELOPMENT runner that copies the guest's console to stderr. Never ship one.
FLAGS=""
[ "${DEV_CONSOLE:-0}" = "1" ] && FLAGS="-D PROBANT_DEV_CONSOLE" && echo "DEVELOPMENT build: guest console -> stderr"
/usr/bin/swiftc -O $FLAGS -target arm64-apple-macos12.0 -o "$OUT/ProbantVM" "$HERE/ProbantVM.swift"
/usr/bin/codesign --force --sign - --entitlements "$HERE/runner.entitlements.plist" "$OUT/ProbantVM"
/usr/bin/codesign --verify --strict "$OUT/ProbantVM"
echo "built:   $OUT/ProbantVM"
echo "sha256:  $(/usr/bin/shasum -a 256 "$OUT/ProbantVM" | cut -d' ' -f1)"
/usr/bin/codesign -d --entitlements - "$OUT/ProbantVM" 2>/dev/null | grep -c "com.apple.security.virtualization" \
  | sed 's/^/virtualization entitlement present (1 = yes): /'
