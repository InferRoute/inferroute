#!/usr/bin/env bash
# Alert Henry when the free naming page nears its overall ceiling (Henry, 13 Nov "go 1 2"): reads today's count of all
# free runs from the site (one number, behind the naming shared secret) and sends one Telegram message per UTC day at
# 80 %, and one when the ceiling is reached. State: ~/.local/state/anteriora-names/usage-alerts (day:level lines).
set -euo pipefail
set -a; . "$HOME/.config/anteriora-names/env"; set +a
J=$(curl -sS -m 20 https://anteriora.inferroute.ai/api/anteriora/names/usage -H "x-anteriora-names-secret: $NAMES_SECRET")
read -r DAY RUNS CAP < <(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["day"], d["runs"], d["cap"])' <<<"$J")
S=$HOME/.local/state/anteriora-names; mkdir -p "$S"; F=$S/usage-alerts; touch "$F"
send() { grep -qx "$DAY:$1" "$F" && return 0; "$HOME/.local/bin/tg-send" "$2" && echo "$DAY:$1" >> "$F"; }
if [ "$RUNS" -ge "$CAP" ]; then
  send full "Name page: today's ceiling of $CAP free runs is reached ($RUNS). New visitors see 'today's free runs' until midnight UTC. If this is real demand rather than abuse, reply 'raise to N'."
elif [ $((RUNS * 100)) -ge $((CAP * 80)) ]; then
  send 80 "Name page: $RUNS of today's $CAP free runs used (80%). Possibly a busy post, or abuse. Nothing changes until the ceiling; reply 'raise to N' to lift it for today and after."
fi
