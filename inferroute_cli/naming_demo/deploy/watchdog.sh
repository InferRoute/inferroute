#!/usr/bin/env bash
# Stops this host's tunnel connector while the local backend fails /health, and starts it again when it recovers.
# cloudflared itself does not health-check its origin, so without this a hung backend would keep taking traffic.
set -u
CONNECTOR=${NAMES_CONNECTOR:-anteriora-names-tunnel.service}
[ -f "$HOME/.config/anteriora-names/tunnel.yml" ] || exit 0  # tunnel not set up yet (tunnel_setup.sh)
if curl -fsS -m 20 http://127.0.0.1:8770/health >/dev/null 2>&1; then
  if ! systemctl --user is-active -q "$CONNECTOR" && systemctl --user cat "$CONNECTOR" >/dev/null 2>&1; then
    systemctl --user start "$CONNECTOR" && logger -t anteriora-names-watchdog "healthy: started $CONNECTOR"
  fi
else
  if systemctl --user is-active -q "$CONNECTOR"; then
    systemctl --user stop "$CONNECTOR" && logger -t anteriora-names-watchdog "unhealthy: stopped $CONNECTOR"
  fi
fi
