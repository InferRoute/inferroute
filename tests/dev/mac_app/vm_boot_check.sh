#!/bin/sh
# DEVELOPMENT ONLY: a check run by hand on a Mac against a built Probant.app (see native/macos/README.md, ad-hoc app).
# 1. The bundle's own client authenticates the signed runtime IN PLACE (runtime.locate(), the product path)
#    and stages its private copy. 2. The repo's synthetic e2e harness (tests/dev/run_linux_vm_e2e.py, no
#    model, no network) boots THAT verified copy with the real Virtualization.framework runner, importing
#    the BUNDLE's client code (no repo packages beside it), and runs one synthetic session to agent_end.
set -u
APP=$1; WORK=$2
PY="$APP/Contents/Resources/python/bin/python3"
mkdir -p "$WORK/home" "$WORK/h/tests/dev"
cp "$(cd "$(dirname "$0")/.." && pwd)/run_linux_vm_e2e.py" "$WORK/h/tests/dev/"
cd /
STAGED=$(env -i HOME="$WORK/home" PATH=/usr/bin:/bin TMPDIR="$TMPDIR" "$PY" -I -B -c '
from inferroute_local.macos_vm import runtime
import inferroute_local, sys
r = runtime.locate()
print("locate(): signed manifest verified, tier", runtime.signing_tier(runtime.trusted_policy()), "client from", inferroute_local.__file__, file=sys.stderr)
print(r.directory)')
echo "staged: $STAGED ($(ls "$STAGED" | tr '\n' ' '))"
env -i HOME="$WORK/home" PATH=/usr/bin:/bin TMPDIR="$TMPDIR" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/caffeinate -i "$PY" -B "$WORK/h/tests/dev/run_linux_vm_e2e.py" --mac-runtime "$STAGED" > "$WORK/session.log" 2>&1
echo "harness exit: $?"
rm -rf "$STAGED"
grep -E '^\[|every check|answer through|import from|Traceback|Error|refused' "$WORK/session.log" | head -40
