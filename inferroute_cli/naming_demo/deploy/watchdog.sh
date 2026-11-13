#!/usr/bin/env bash
# Stops this host's tunnel connector while the local backend fails /health, and starts it again when it recovers.
# cloudflared itself does not health-check its origin, so without this a hung backend would keep taking traffic.
# Also alerts Henry (voice-report, where installed: mgld) when the naming key's account is out of AI credit.
set -u
CONNECTOR=${NAMES_CONNECTOR:-anteriora-names-tunnel.service}
[ -f "$HOME/.config/anteriora-names/tunnel.yml" ] || exit 0  # tunnel not set up yet (tunnel_setup.sh)
H=$(curl -fsS -m 20 http://127.0.0.1:8770/health 2>/dev/null); rc=$?
if [ $rc -eq 0 ]; then
  if ! systemctl --user is-active -q "$CONNECTOR" && systemctl --user cat "$CONNECTOR" >/dev/null 2>&1; then
    systemctl --user start "$CONNECTOR" && logger -t anteriora-names-watchdog "healthy: started $CONNECTOR"
  fi
else
  if systemctl --user is-active -q "$CONNECTOR"; then
    systemctl --user stop "$CONNECTOR" && logger -t anteriora-names-watchdog "unhealthy: stopped $CONNECTOR"
  fi
fi
# Model credit: a 402 from the proxy means every run fails on every host. Alert at most every 6 h.
V=$HOME/.local/bin/voice-report M=$HOME/.cache/anteriora-names-credit-alert
if [[ $H == *'"model_credit": "out"'* ]] && [ -x "$V" ] && { [ ! -f "$M" ] || [ -n "$(find "$M" -mmin +360)" ]; }; then
  mkdir -p "$(dirname "$M")"; touch "$M"
  logger -t anteriora-names-watchdog "model credit out: alerting Henry"
  "$V" -c "anteriora naming: AI credit is empty, free runs are failing" \
    "The naming page's AI key has run out of credit, so every free run on the naming page now fails. Please top up the InferRoute account that holds the anteriora naming key. Nothing else is affected." >/dev/null 2>&1 &
fi
