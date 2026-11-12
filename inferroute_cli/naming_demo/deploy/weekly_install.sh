#!/usr/bin/env bash
# Roll a PASSED weekly index out to the naming backend on ft, then mgld; one host keeps serving throughout.
# Usage (on mgld): weekly_install.sh /path/index-YYYYMMDD.sqlite
# Refuses an index without the .sha256 that weekly_tm_build.py writes only when every check passed. Stops before
# mgld if ft does not come back healthy on the new index, so mgld keeps serving the previous one.
set -euo pipefail
IDX=$1
SUMF="$IDX.sha256"
[ -f "$SUMF" ] || { echo "no $SUMF: this index did not pass its checks" >&2; exit 1; }
WANT=$(cut -d' ' -f1 "$SUMF")
GOT=$(sha256sum "$IDX" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "sha mismatch on mgld copy" >&2; exit 1; }
B=.local/share/anteriora-names
INST=$HOME/$B/current/inferroute_cli/naming_demo/deploy/install.sh
health() {  # $1: ssh prefix or empty
  for i in $(seq 1 30); do
    if $1 curl -fsS -m 20 http://127.0.0.1:8770/health 2>/dev/null | grep -q "\"index\": \"$WANT\""; then return 0; fi
    sleep 4
  done
  return 1
}
# ft first
rsync -a "$IDX" henry-ft:"$B/data/index.sqlite.incoming"
ssh henry-ft "D=\$HOME/$B/data; bash \$HOME/$B/current/inferroute_cli/naming_demo/deploy/install.sh - keep \$D/index.sqlite.incoming \$D/com.npy \$D/net.npy $WANT && rm -f \$D/index.sqlite.incoming && systemctl --user restart anteriora-names.service"
health "ssh henry-ft" || { echo "ft did not come back healthy on $WANT; mgld left on the previous index" >&2; exit 1; }
echo "ft serving $WANT"
D=$HOME/$B/data
bash "$INST" - keep "$IDX" "$D/com.npy" "$D/net.npy" "$WANT"
systemctl --user restart anteriora-names.service
health "" || { echo "mgld did not come back healthy on $WANT (ft is serving it)" >&2; exit 1; }
echo "mgld serving $WANT"
