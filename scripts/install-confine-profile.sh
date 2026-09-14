#!/usr/bin/env bash
# Install the AppArmor profile that lets the attested `ir pi` launcher confine the agent's egress by
# ADDRESS (an empty network namespace), on Ubuntu-family systems that restrict unprivileged user
# namespaces. One time, needs sudo. Idempotent. Prints what it did and how to undo it.
#
# It does NOT run anything as the agent, open any network, or touch the user's home. It copies one
# AppArmor profile into place and loads it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/apparmor/ir-pi-bwrap"
dst="/etc/apparmor.d/ir-pi-bwrap"

if [ ! -f "$src" ]; then
    echo "profile not found at $src" >&2
    exit 1
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
    echo "apparmor_parser not found — this system does not use AppArmor; nothing to install." >&2
    exit 1
fi
if [ ! -x /usr/bin/bwrap ]; then
    echo "bubblewrap (/usr/bin/bwrap) is not installed. Install it first: sudo apt install bubblewrap" >&2
    exit 1
fi

restrict="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
echo "kernel.apparmor_restrict_unprivileged_userns = ${restrict}"
if [ "${restrict}" != "1" ]; then
    echo "Unprivileged user namespaces are not restricted on this machine; the launcher can already"
    echo "confine by address without this profile. Installing it anyway does no harm."
fi

echo "Installing $dst (needs sudo)…"
sudo install -m 0644 "$src" "$dst"
sudo apparmor_parser -r -W "$dst"
echo "Loaded. Verify:  aa-status | grep ir-pi-bwrap"
echo
echo "Quick check that bubblewrap can now make an empty netns:"
if bwrap --unshare-net --dev-bind / / true 2>/dev/null; then
    echo "  OK — address-level confinement is available. Run: ir pi"
else
    echo "  bwrap still cannot create a netns. A reboot or 'systemctl reload apparmor' may be needed,"
    echo "  or another policy is in the way. The launcher will fall back to port-level confinement."
fi
echo
echo "To undo:  sudo rm $dst && sudo systemctl reload apparmor"
