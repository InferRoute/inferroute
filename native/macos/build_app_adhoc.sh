#!/bin/sh
# Build the AD-HOC signed Probant.app and its .dmg on an Apple-silicon Mac. Prepare-only: it publishes nothing,
# reads no private key, and installs nothing outside OUT.
#
#   sh native/macos/build_app_adhoc.sh INPUTS OUT
#
# INPUTS holds the files named in pins.json (the python-build-standalone archive, the signed release's client
# wheel, runtime wheel and hash lock); each is refused unless its sha256 matches. Needs the Command Line Tools
# (swiftc, codesign) and hdiutil; network access to PyPI for the locked libraries (each checked by hash).
#
# What is signed, and how (all ad-hoc: there is no Apple Developer ID, so nothing here names a builder):
#   * every Mach-O in the bundled Python EXCEPT the VM runner: ad-hoc; python3.12 with the hardened runtime and
#     one entitlement (python.entitlements.plist: disable-library-validation, see the comment there);
#   * the VM runner (ProbantVM) is NOT touched: its bytes, and its ad-hoc signature with the virtualization
#     entitlement, are pinned by the vendor-signed runtime.json, and any re-signing would break that pin;
#   * the outer app: ad-hoc, hardened runtime, no entitlements.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$#" -eq 2 ] || { echo "usage: build_app_adhoc.sh INPUTS OUT" >&2; exit 64; }
IN=$(cd "$1" && pwd); OUT=$2
[ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ] || { echo "build_app_adhoc: needs an Apple-silicon Mac" >&2; exit 78; }
[ ! -e "$OUT" ] || { echo "build_app_adhoc: $OUT exists; refusing to build over it" >&2; exit 73; }
PINS="$HERE/pins.json"
pin() { /usr/bin/plutil -extract "$1" raw -o - "$PINS"; }
sha() { /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1; }
check() {   # key: refuse unless INPUTS/<file> has the pinned sha256
  f="$IN/$(pin "$1.file")"; want=$(pin "$1.sha256")
  [ -f "$f" ] || { echo "missing input: $f" >&2; exit 66; }
  got=$(sha "$f")
  [ "$got" = "$want" ] || { echo "REFUSED: $f sha256 $got, pinned $want" >&2; exit 65; }
  echo "pinned ok: $(basename "$f")  $got"
}
for k in python client_wheel runtime_wheel lock; do check "$k"; done
VERSION=$(pin app.version); BUNDLE_ID=$(pin app.bundle_id); MINOS=$(pin app.minimum_macos)
RUNNER_SHA=$(pin runner_sha256)

mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
APP="$OUT/Probant.app"; RES="$APP/Contents/Resources"
mkdir -p "$APP/Contents/MacOS" "$RES"
echo "== bundled Python =="
/usr/bin/tar -xzf "$IN/$(pin python.file)" -C "$RES"          # -> Resources/python
PY="$RES/python/bin/python3"
"$PY" -I -c 'import platform, sys; assert sys.version_info[:2] == (3, 12) and platform.machine() == "arm64"; print(sys.version)'
# pip reads config files even under -I: none of the builder's pip configuration may steer this install.
export PIP_CONFIG_FILE=/dev/null PIP_NO_INPUT=1 PIP_DISABLE_PIP_VERSION_CHECK=1
echo "== locked libraries (every file checked by hash; wheels only, nothing compiled here) =="
"$PY" -I -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r "$IN/$(pin lock.file)"
OWN="$OUT/own-requirements.txt"
printf '%s\n' \
  "inferroute @ file://$IN/$(pin client_wheel.file) --hash=sha256:$(pin client_wheel.sha256)" \
  "inferroute-macos-vm-runtime @ file://$IN/$(pin runtime_wheel.file) --hash=sha256:$(pin runtime_wheel.sha256)" > "$OWN"
"$PY" -I -m pip install --no-cache-dir --require-hashes --no-deps -r "$OWN"
"$PY" -I -m pip check
"$PY" -I -m pip freeze --all > "$OUT/bundled-packages.txt"
"$PY" -I -m pip uninstall -y pip > /dev/null                   # the app installs nothing at run time
# The client keeps state under ~/.inferroute (even `--version` refreshes a cached model catalog there): every
# client run in this build gets a throwaway home, so the builder's own Probant state is never read or written.
CLIENT_HOME="$OUT/client-home"; mkdir -m 700 "$CLIENT_HOME"
GOT=$(HOME="$CLIENT_HOME" INFERROUTE_HOME="$CLIENT_HOME/.inferroute" "$PY" -I -m inferroute_cli --version | awk '{print $NF}')
[ "$GOT" = "$VERSION" ] || { echo "REFUSED: bundled client reports $GOT, not $VERSION" >&2; exit 65; }
SITE=$("$PY" -I -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
RUNNER="$SITE/inferroute_macos_vm_runtime/ProbantVM"
[ "$(sha "$RUNNER")" = "$RUNNER_SHA" ] || { echo "REFUSED: runner is not the pinned one" >&2; exit 65; }
# Console scripts carry the build path in their #! line; make them find the Python beside them instead
# (pip's own relocatable form). `ir` matters: the page offers <python's folder>/ir for the audit command.
for f in "$RES/python/bin/"*; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  if head -c 2 "$f" | grep -q '^#!' && head -n 1 "$f" | grep -q "^#!$RES/python/bin/python"; then
    tail -n +2 "$f" > "$f.tmp"
    { printf '%s\n' '#!/bin/sh' "'''exec' \"\$(dirname -- \"\$0\")/python3.12\" \"\$0\" \"\$@\"" "' '''"; cat "$f.tmp"; } > "$f"
    rm "$f.tmp"
  fi
done
! grep -rl "$OUT" "$RES/python/bin" 2>/dev/null || { echo "REFUSED: a script still names the build folder" >&2; exit 65; }
# pip records where each local wheel came from (the build folder, so the builder's user name): not shipped.
rm -f "$SITE"/inferroute-*.dist-info/direct_url.json "$SITE"/inferroute_macos_vm_runtime-*.dist-info/direct_url.json
# Bytecode now, once: the app never writes inside its own (sealed) bundle. unchecked-hash: valid wherever the
# bundle is copied, whatever the file times. -s/-p: the file names inside the bytecode say where the app is
# installed, not the build folder. A few stdlib files are not meant to compile (lib2to3 grammar tests).
"$PY" -I -m compileall -q -f -j 0 --invalidation-mode unchecked-hash -s "$RES/python" \
  -p "/Applications/Probant.app/Contents/Resources/python" "$RES/python/lib/python3.12" > "$OUT/compileall.log" 2>&1 || true
HOME="$CLIENT_HOME" INFERROUTE_HOME="$CLIENT_HOME/.inferroute" "$PY" -I -c "from inferroute_local.macos_vm import runtime; r = runtime.locate(); print('runtime verifies in place:', runtime.signing_tier(runtime.trusted_policy())); r.close()"

echo "== app shell =="
cp "$HERE/app_entry.py" "$RES/app_entry.py"
/usr/bin/swiftc -O -target "arm64-apple-macos$MINOS" -o "$APP/Contents/MacOS/Probant" "$HERE/AppMain.swift"
/usr/bin/plutil -create xml1 "$APP/Contents/Info.plist"
for kv in CFBundleExecutable=Probant CFBundleIdentifier="$BUNDLE_ID" CFBundleName=Probant CFBundleDisplayName=Probant \
          CFBundlePackageType=APPL CFBundleShortVersionString="$VERSION" CFBundleVersion="$VERSION" \
          LSMinimumSystemVersion="$MINOS" CFBundleInfoDictionaryVersion=6.0; do
  /usr/bin/plutil -insert "${kv%%=*}" -string "${kv#*=}" "$APP/Contents/Info.plist"
done
/usr/bin/plutil -insert LSArchitecturePriority -array "$APP/Contents/Info.plist"
/usr/bin/plutil -insert LSArchitecturePriority.0 -string arm64 "$APP/Contents/Info.plist"
/usr/bin/plutil -insert NSHighResolutionCapable -bool true "$APP/Contents/Info.plist"
/usr/bin/plutil -lint "$APP/Contents/Info.plist"
# Nothing shipped may name the build folder or the builder's home (a user name is personal data).
! grep -rl -e "$OUT" -e "$HERE" -e "$HOME/" "$APP" || { echo "REFUSED: the files above name the build machine's folders" >&2; exit 65; }

echo "== ad-hoc signatures =="
find "$RES/python" -type f | while read -r f; do
  [ "$f" = "$RUNNER" ] && continue
  /usr/bin/file -b "$f" | grep -q '^Mach-O' || continue
  case "$f" in
    "$RES/python/bin/python3.12")
      /usr/bin/codesign --force --sign - --timestamp=none --options runtime \
        --entitlements "$HERE/python.entitlements.plist" "$f" ;;
    *) /usr/bin/codesign --force --sign - --timestamp=none "$f" ;;
  esac
done
echo "Mach-O files in the bundled Python: $(find "$RES/python" -type f -exec /usr/bin/file -b {} + | grep -c '^Mach-O'); all re-signed ad-hoc except the runner, left as released"
/usr/bin/codesign --force --sign - --timestamp=none --options runtime --identifier "$BUNDLE_ID" "$APP"
[ "$(sha "$RUNNER")" = "$RUNNER_SHA" ] || { echo "REFUSED: signing changed the runner" >&2; exit 65; }
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
# Built from public inputs only and no key is read here; this catches a PEM private key that got in anyway.
! grep -rIlx -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$APP" || { echo "REFUSED: a PEM private key is in the bundle" >&2; exit 65; }

echo "== disk image =="
DMG="$OUT/Probant-$VERSION.dmg"; STAGE="$OUT/dmg-stage"
mkdir "$STAGE"
/usr/bin/ditto "$APP" "$STAGE/Probant.app"
ln -s /Applications "$STAGE/Applications"
sed "s/@VERSION@/$VERSION/g" "$HERE/dmg-README.txt" > "$STAGE/README.txt"
/usr/bin/hdiutil create -quiet -fs HFS+ -format UDZO -volname "Probant $VERSION" -srcfolder "$STAGE" "$DMG"
rm -rf "$STAGE"
/usr/bin/hdiutil verify -quiet "$DMG"
(cd "$OUT" && /usr/bin/shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256" && cat "$(basename "$DMG").sha256")
echo "built: $APP"
echo "built: $DMG"
