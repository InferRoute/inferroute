#!/bin/sh
# DEVELOPMENT ONLY — the first boot on a real Mac, in one command.
#
#   tar -xzf probant-vm-dev.tgz && cd probant-vm-dev && sh tests/dev/mac_bringup.sh
#
# 1. says what this Mac is;  2. compiles the runner twice (release, and a development build whose guest
# console goes to stderr);  3. runs one synthetic session through a real Virtualization.framework machine
# with the development runner, then again with the release runner.
# Nothing is installed outside this folder except, if no Python 3.10+ exists, `uv` (into ~/.local/bin) and
# the Python it downloads for itself (into ~/.local/share/uv). The system Python is not touched.
# Everything is kept in ./bringup.log — send that file back whatever happens.
set -u
cd "$(dirname "$0")/../.."
LOG=bringup.log
: > "$LOG"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
run() { say "\$ $*"; "$@" >> "$LOG" 2>&1; rc=$?; say "  -> exit $rc"; return $rc; }

say "== this Mac =="
{ sw_vers; uname -m; sysctl -n machdep.cpu.brand_string; sysctl kern.hv_support; sysctl -n hw.memsize; } 2>&1 | tee -a "$LOG"
[ "$(uname -m)" = "arm64" ] || { say "STOP: this needs an Apple-silicon Mac (arm64)."; exit 1; }

say "== toolchain =="
if ! /usr/bin/xcrun --find swiftc >> "$LOG" 2>&1; then
  say "STOP: no Swift compiler. Install the Command Line Tools (a system dialog; about 1 GB), then run this again:"
  say "      xcode-select --install"
  exit 1
fi
/usr/bin/swiftc --version 2>&1 | tee -a "$LOG"

say "== build the runner =="
run sh native/macos/build_runner.sh runtime-release || { say "STOP: the release runner did not compile. The compiler's words are in $LOG."; tail -40 "$LOG"; exit 1; }
DEV_CONSOLE=1 run sh native/macos/build_runner.sh runtime-dev || { say "STOP: the development runner did not compile."; tail -40 "$LOG"; exit 1; }
for d in runtime-release runtime-dev; do cp runtime/kernel runtime/initrd "$d/"; done
say "release runner sha256: $(/usr/bin/shasum -a 256 runtime-release/ProbantVM | cut -d' ' -f1)"

say "== a Python that can run the client (3.10 or newer) =="
PYRUN=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then PYRUN="$c"; break; fi
done
if [ -z "$PYRUN" ]; then
  UV=""
  for c in uv "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do command -v "$c" >/dev/null 2>&1 && { UV="$c"; break; }; done
  if [ -z "$UV" ]; then
    say "no Python 3.10+ and no uv: installing uv into ~/.local/bin (it brings its own Python; the system one is untouched)"
    run sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh' || { say "STOP: could not install uv."; exit 1; }
    UV="$HOME/.local/bin/uv"
  fi
  PYRUN="$UV run --no-project --python 3.12 python"
fi
say "using: $PYRUN"

attempt() {
  say "== one synthetic session through a real VM: $1 runner =="
  $PYRUN tests/dev/run_linux_vm_e2e.py --mac-runtime "runtime-$1" > "session-$1.log" 2>&1
  say "  -> exit $?"
  grep -E '^\[|PROBANT_|refused|Traceback|Error' "session-$1.log" | tee -a "$LOG"
  { echo "---- full output, $1 runner ----"; cat "session-$1.log"; } >> "$LOG"
  grep -q "every check held: True" "session-$1.log"
}
PASSED=""
attempt dev && PASSED="$PASSED dev"
# The release runner is the one that would ship. Its guest console is discarded, so it is tried second:
# if only this one fails, the development run above already holds what the guest said.
attempt release && PASSED="$PASSED release"

say ""
say "RESULT: passed with:${PASSED:- nothing}"
if [ "$PASSED" = " dev release" ]; then
  say "Both runners booted the guest and ran a whole session."
else
  say "Not everything passed. Send back bringup.log."
  exit 1
fi
