#!/usr/bin/env bash
# One-time, on mgld, AFTER Henry has run `cloudflared tunnel login` (writes ~/.cloudflared/cert.pem for inferroute.ai).
# Creates the tunnel, routes the hostname to it, and writes the same config + credentials on mgld and ft (two replicas
# of one tunnel). The watchdog on each host then starts the connector while the local backend is healthy.
set -euo pipefail
NAME=anteriora-names HOST=anteriora-names.inferroute.ai
CF=$HOME/.local/bin/cloudflared C=$HOME/.config/anteriora-names
[ -f "$HOME/.cloudflared/cert.pem" ] || { echo "run: cloudflared tunnel login (Henry, once)" >&2; exit 1; }
$CF tunnel info "$NAME" >/dev/null 2>&1 || $CF tunnel create "$NAME"
ID=$($CF tunnel list -o json | python3 -c "import json,sys; print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='$NAME'))")
$CF tunnel route dns "$NAME" "$HOST"
install -m 600 "$HOME/.cloudflared/$ID.json" "$C/tunnel-credentials.json"
cat > "$C/tunnel.yml" <<YML
tunnel: $ID
credentials-file: $C/tunnel-credentials.json
ingress:
  - hostname: $HOST
    service: http://127.0.0.1:8770
  - service: http_status:404
YML
chmod 600 "$C/tunnel.yml"
scp -q -p "$C/tunnel-credentials.json" "$C/tunnel.yml" henry-ft:.config/anteriora-names/
for h in "" "ssh henry-ft"; do $h systemctl --user daemon-reload; done
echo "tunnel $NAME ($ID) -> $HOST; the watchdogs start the connectors within 20 s"
