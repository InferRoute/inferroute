#!/usr/bin/env bash
# Weekly: build the server-side TM index (fail-closed), roll it out to ft then mgld, compute the watch delta.
# Runs from the installed release. Under mgld's heavy-job lock (the build peaks near 10 GB). Keeps the last 3 builds.
set -euo pipefail
R=$HOME/.local/share/anteriora-names/current
W=$HOME/anteriora-tmdata/weekly
PREV=$HOME/.local/share/anteriora-names/data/index.sqlite
TODAY=$(date -u +%F); NEW=$W/index-${TODAY//-/}.sqlite
cd "$R"
flock /home/henry/.cache/locks/mgld-heavy.lock nice -n 10 python3 tools/weekly_tm_build.py --out-dir "$W" --prev "$PREV" --today "$TODAY"
# keep a copy of the outgoing index for the watch diff before the installer replaces it
OLD=$W/served-before-${TODAY//-/}.sqlite; cp "$PREV" "$OLD"
bash "$R/inferroute_cli/naming_demo/deploy/weekly_install.sh" "$NEW"
mkdir -p "$HOME/anteriora-tmdata/watch"
python3 tools/tm_watch.py diff "$OLD" "$NEW" "$HOME/anteriora-tmdata/watch/delta-${TODAY//-/}.sqlite"
rm -f "$OLD"
# Name watch: export from the site, match, post alerts. Skips itself until NAMES_WATCH_*_URL are set in the env file.
set -a; . "$HOME/.config/anteriora-names/env"; set +a
python3 tools/watch_sync.py "$HOME/anteriora-tmdata/watch/delta-${TODAY//-/}.sqlite"
ls -1t "$W"/index-*.sqlite | tail -n +4 | while read -r f; do rm -f "$f" "$f.sha256" "${f%.sqlite}.report.json"; done
