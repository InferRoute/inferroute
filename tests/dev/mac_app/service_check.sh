#!/bin/sh
# DEVELOPMENT ONLY: a check run by hand on a Mac against a built Anteriora.app (see native/macos/README.md, ad-hoc app).
# Start the bundled service exactly as AppMain does (same argv, same environment), but with the browser
# suppressed and HOME a throwaway folder; check the page answers on loopback; stop it with SIGINT.
set -u
APP=$1; TH=$2; LOG=$3
R="$APP/Contents/Resources"
mkdir -p "$TH"
cd /
env -i HOME="$TH" PATH=/usr/bin:/bin IR_ATTESTED_CONFINE=require PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
  PYTHONDONTWRITEBYTECODE=1 TMPDIR="$TMPDIR" IR_PROBANT_NO_BROWSER=1 \
  "$R/python/bin/python3" -I -B "$R/app_entry.py" > "$LOG" 2>&1 &
PID=$!
URL=""
for i in $(seq 1 60); do
  URL=$(sed -n 's/.*Probant home:  *\(http:\/\/127\.0\.0\.1:[0-9]*\/[^ ]*\).*/\1/p' "$LOG" | head -1)
  [ -n "$URL" ] && break; sleep 0.5
done
echo "service pid $PID, started after ~$((i/2)) s, url: ${URL%%#*}#k=<token>"
BASE=${URL%%#*}
sleep 1
code=$(curl -s -o "$LOG.page" -w '%{http_code}' "$BASE")
echo "GET / -> HTTP $code, $(wc -c < "$LOG.page") bytes, title: $(grep -o '<title>[^<]*' "$LOG.page" | head -1)"
TOKEN=${URL##*#k=}
echo "GET /api/overview without key -> HTTP $(curl -s -o /dev/null -w '%{http_code}' "${BASE}api/overview")"
echo "GET /api/overview with key    -> HTTP $(curl -s -o "$LOG.api" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "${BASE}api/overview"), $(head -c 160 "$LOG.api")"
lsof -nP -a -p $PID -iTCP -sTCP:LISTEN | tail -n +2 | awk '{print "listening:", $9}'
kill -INT $PID
for i in $(seq 1 30); do kill -0 $PID 2>/dev/null || break; sleep 0.5; done
kill -0 $PID 2>/dev/null && echo "still running after SIGINT" || { wait $PID; echo "service exited after SIGINT, rc=$?"; }
codesign --verify --deep --strict "$APP" && echo "bundle seal still valid after the run"
find "$APP" -name '*.pyc' -newer "$LOG" | head -3
