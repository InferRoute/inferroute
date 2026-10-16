#!/bin/sh
# DEVELOPMENT ONLY: a check run by hand on a Mac against a built Anteriora.app (see native/macos/README.md, ad-hoc app).
# Launch the real app through LaunchServices (`open`), with its home redirected to a throwaway folder
# (CFFIXED_USER_HOME, which NSHomeDirectory() honours; the app passes that to the service as HOME).
# The browser DOES open (that is what is being checked). Then optionally reopen, then quit with SIGTERM.
set -u
APP=$1; TH=$2; REOPEN=${3:-no}
mkdir -p "$TH"
CAT0=$(stat -f %m ~/.inferroute/catalog.json)
open -g -n --env CFFIXED_USER_HOME="$TH" "$APP" || { echo "open failed"; exit 1; }
APID=""; CPID=""
for i in $(seq 1 40); do
  APID=$(pgrep -f "^$APP/Contents/MacOS/Anteriora" | head -1)
  [ -n "$APID" ] && CPID=$(pgrep -P "$APID" | head -1)
  [ -n "$CPID" ] && break; sleep 0.25
done
echo "app pid $APID, service pid $CPID"
ps -o pid,ppid,pgid,command -p "$APID","$CPID" | cut -c1-200
ps eww -p "$CPID" | tr ' ' '\n' | grep -E '^(HOME|TMPDIR|PATH|PYTHON[A-Z]*|IR_[A-Z_]*)=' | sed 's/^/  service env: /'
PORT=""
for i in $(seq 1 60); do
  PORT=$(lsof -nP -a -p "$CPID" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {sub(/.*:/,"",$9); print $9; exit}')
  [ -n "$PORT" ] && break; sleep 0.5
done
echo "service listening on 127.0.0.1:$PORT after ~$((i/2)) s"
sleep 4
echo "connections to the page from other processes (the browser opening it):"
lsof -nP -iTCP@127.0.0.1:"$PORT" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $2 != "'"$CPID"'" {print "  ", $1, $2}' | sort -u
echo "GET / -> HTTP $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/")"
if [ "$REOPEN" = reopen ]; then
  N0=$(lsof -nP -iTCP@127.0.0.1:"$PORT" 2>/dev/null | wc -l)
  open -g "$APP"; sleep 4
  N1=$(lsof -nP -iTCP@127.0.0.1:"$PORT" 2>/dev/null | wc -l)
  echo "second open of the running app: app pids now: $(pgrep -f "^$APP/Contents/MacOS/Anteriora" | tr '\n' ' '); sockets on the port before/after: $N0/$N1"
fi
T0=$(date +%s)
kill -TERM "$APID"
for i in $(seq 1 200); do kill -0 "$APID" 2>/dev/null || break; sleep 0.5; done
echo "after SIGTERM to the app: app alive=$(kill -0 "$APID" 2>/dev/null && echo yes || echo no), service alive=$(kill -0 "$CPID" 2>/dev/null && echo yes || echo no), group members=$(pgrep -g "$CPID" | wc -l | tr -d ' '), took $(( $(date +%s) - T0 )) s"
codesign --verify --deep --strict "$APP" && echo "bundle seal still valid after the run"
[ "$(stat -f %m ~/.inferroute/catalog.json)" = "$CAT0" ] && echo "real ~/.inferroute/catalog.json untouched"
ls -A "$TH" "$TH/.inferroute/confidential" 2>/dev/null | tr '\n' ' '; echo
