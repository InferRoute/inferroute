#!/bin/sh
# DEVELOPMENT ONLY. One tarball with everything a Mac needs to build the runner and run the synthetic
# end-to-end session: the two client packages, the native sources, the dev driver, and the arm64 guest.
#
#   sh tests/dev/make_mac_bundle.sh <guest-arm64-out-dir> <bundle.tgz>
#
# On the Mac:   tar -xzf bundle.tgz && cd probant-vm-dev
#               sh native/macos/build_runner.sh runtime
#               python3 tests/dev/run_linux_vm_e2e.py --mac-runtime runtime      (Python 3.10 or newer)
set -eu
GUEST=$1; OUT=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/probant-vm-dev"; mkdir -p "$D/runtime" "$D/tests"
tar -C "$ROOT" --exclude='__pycache__' --exclude='*.pyc' --exclude='macos_runtime' --exclude='native/macos/guest/pi' \
    -cf - inferroute_cli inferroute_local native tests/dev | tar -C "$D" -xf -
cp "$GUEST/kernel" "$GUEST/initrd" "$GUEST/guest-manifest.json" "$D/runtime/"
tar -C "$STAGE" -czf "$OUT" probant-vm-dev
echo "bundle: $OUT ($(du -h "$OUT" | cut -f1))"
