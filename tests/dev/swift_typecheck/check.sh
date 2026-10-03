#!/bin/sh
# DEVELOPMENT ONLY — type-check native/macos/ProbantVM.swift on Linux, with a real Swift compiler.
#
#   sh tests/dev/swift_typecheck/check.sh          (needs docker; pulls swift:6.0-jammy, about 2.5 GB, once)
#
# What this is: the Swift compiler's own parser and type checker, run over the runner's source in both its
# builds. It finds Swift-language errors — a type that does not fit, a missing label, a `var` captured
# across queues — before a Mac is at hand.
#
# What this is NOT: a build. Apple's Virtualization and CryptoKit modules do not exist off a Mac, so the
# three files beside this one stand in for them, written from the SDK's documented signatures — the same
# understanding the runner was written from. If that understanding is wrong about the real framework, this
# check passes and the Mac build fails. Only `native/macos/build_runner.sh` on a Mac settles it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$HERE"/*.swift "$HERE/../../../native/macos/ProbantVM.swift" "$WORK/"
chmod -R a+rwX "$WORK"
docker run --rm -v "$WORK:/w" -w /w swift:6.0-jammy sh -c '
  set -e
  for m in Virtualization CryptoKit Darwin; do
    swiftc -emit-module -module-name $m -parse-as-library $m.swift -o $m.swiftmodule
  done
  status=0
  for flags in "" "-D PROBANT_DEV_CONSOLE"; do
    out=$(swiftc -typecheck -I . $flags ProbantVM.swift 2>&1) || status=1
    n=$(printf "%s\n" "$out" | grep -cE "(error|warning):" || true)
    echo "typecheck ${flags:-(release)}: $n diagnostics"
    [ "$n" = "0" ] || { printf "%s\n" "$out"; status=1; }
  done
  exit $status'
