#!/bin/bash
# Wrap the ad-hoc Probant.app from a release .dmg into an unsigned installer .pkg (no Developer ID).
# Why: files that Installer places carry no com.apple.quarantine, so after ONE "Open Anyway" on the .pkg,
# neither the app nor its bundled python3.12 meets Gatekeeper again. The app bytes are copied unchanged.
# Usage: build_pkg_from_dmg.sh Probant-<V>.dmg OUTDIR     (on any Mac; uses only /usr/bin tools)
set -euo pipefail
DMG=$1; OUT=$2; W=$(mktemp -d); trap 'hdiutil detach "$M" -quiet 2>/dev/null; rm -rf "$W"' EXIT
M=$(hdiutil attach -nobrowse -readonly "$DMG" | awk -F'\t' '/Volumes/{print $NF}')
V=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$M/Probant.app/Contents/Info.plist")
mkdir -p "$W/root/Applications"; ditto --noqtn "$M/Probant.app" "$W/root/Applications/Probant.app"
codesign --verify --deep --strict "$W/root/Applications/Probant.app"
cat > "$W/comp.plist" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><dict>
  <key>RootRelativeBundlePath</key><string>Applications/Probant.app</string>
  <key>BundleIsRelocatable</key><false/>
  <key>BundleIsVersionChecked</key><false/>
  <key>BundleHasStrictIdentifier</key><true/>
  <key>BundleOverwriteAction</key><string>upgrade</string>
</dict></array></plist>
PL
pkgbuild --root "$W/root" --component-plist "$W/comp.plist" --identifier ai.inferroute.probant.pkg --version "$V" \
  --install-location / "$W/probant-component.pkg"
cat > "$W/dist.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Probant $V</title>
  <options customize="never" require-scripts="false" hostArchitectures="arm64"/>
  <volume-check><allowed-os-versions><os-version min="12.0"/></allowed-os-versions></volume-check>
  <domains enable_localSystem="true" enable_currentUserHome="true" enable_anywhere="false"/>
  <choices-outline><line choice="probant"/></choices-outline>
  <choice id="probant" visible="false"><pkg-ref id="ai.inferroute.probant.pkg"/></choice>
  <pkg-ref id="ai.inferroute.probant.pkg" version="$V" onConclusion="none">probant-component.pkg</pkg-ref>
</installer-gui-script>
XML
mkdir -p "$OUT"; productbuild --distribution "$W/dist.xml" --package-path "$W" "$OUT/Probant-$V.pkg"
shasum -a 256 "$OUT/Probant-$V.pkg"; ls -l "$OUT/Probant-$V.pkg"
