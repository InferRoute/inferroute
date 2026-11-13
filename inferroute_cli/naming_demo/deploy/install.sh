#!/usr/bin/env bash
# Install the naming backend on THIS host from a git ref: an installed copy under ~/.local/share/anteriora-names,
# data files read-only, user units in place. Usage: install.sh <repo> <ref> <index.sqlite> <com.npy> <net.npy> <index_sha256>
# The data step refuses an index whose sha256 is not the one given, so no host serves an index the others don't have.
# REF "keep" leaves the installed code as it is and replaces only the data (the weekly index).
set -euo pipefail
REPO=$1 REF=$2 IDX=$3 COM=$4 NET=$5 WANT=$6
B=$HOME/.local/share/anteriora-names
mkdir -p "$B/data" "$HOME/.config/anteriora-names" "$HOME/.config/systemd/user"
if [ "$REF" = keep ]; then
  SHA=$(basename "$(readlink "$B/current")")
else
  SHA=$(git -C "$REPO" rev-parse --short=12 "$REF")
  mkdir -p "$B/releases/$SHA"
  git -C "$REPO" archive "$REF" inferroute_cli tools | tar -x -C "$B/releases/$SHA"
fi
GOT=$(sha256sum "$IDX" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "index sha mismatch: $GOT != $WANT" >&2; exit 1; }
for f in "$IDX:index.sqlite" "$COM:com.npy" "$NET:net.npy"; do
  src=${f%%:*} dst=$B/data/${f##*:}
  if [ ! -e "$dst" ] || ! cmp -s "$src" "$dst"; then chmod u+w "$dst" 2>/dev/null || true; cp "$src" "$dst.tmp" && mv "$dst.tmp" "$dst"; fi
  chmod 444 "$dst"
done
ln -sfn "releases/$SHA" "$B/current"
D=$B/current/inferroute_cli/naming_demo/deploy
cp "$D"/anteriora-names.service "$D"/anteriora-names-watchdog.service "$D"/anteriora-names-watchdog.timer \
   "$D"/anteriora-names-weekly.service "$D"/anteriora-names-weekly.timer "$HOME/.config/systemd/user/"  # weekly: enabled on mgld only
E=$HOME/.config/anteriora-names/env
[ -f "$E" ] || { umask 077; printf 'NAMES_SECRET=%s\n' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" > "$E"; }
chmod 600 "$E"
systemctl --user daemon-reload
echo "installed $SHA; index $WANT"
