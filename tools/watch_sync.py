"""Weekly name-watch hand-off with the site (contract agreed with inferroute-44, 13 Nov 2026).

    python tools/watch_sync.py DELTA.sqlite [--dry-run WATCHES.jsonl]

1. GET  $NAMES_WATCH_EXPORT_URL  -> JSONL {"id","name","classes","countries"} (active, confirmed watches; no email)
2. tm_watch.match against this week's delta (alerts queued once per watch and mark; state in ~/anteriora-tmdata/watch)
3. POST $NAMES_WATCH_ALERTS_URL  <- this run's alert lines (the site stores them idempotently and emails)
Both requests carry x-anteriora-names-secret = $NAMES_SECRET. With no URLs configured this does nothing (the watch is
not switched on until Henry approves the weekly timer). --dry-run reads watches from a local file and posts nothing.
"""
import argparse
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tm_watch  # noqa: E402

STATE = Path.home() / "anteriora-tmdata" / "watch"


def _req(url: str, data: bytes | None = None) -> bytes:
    h = {"x-anteriora-names-secret": os.environ["NAMES_SECRET"]}
    if data is not None:
        h["content-type"] = "application/x-ndjson"
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h), timeout=120) as r:
        return r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("delta", type=Path)
    ap.add_argument("--dry-run", type=Path, help="local watches.jsonl; nothing is fetched or posted")
    a = ap.parse_args()
    export, post = os.environ.get("NAMES_WATCH_EXPORT_URL"), os.environ.get("NAMES_WATCH_ALERTS_URL")
    if not a.dry_run and not (export and post):
        print("watch not configured (no export/alerts URL): skipped")
        return
    STATE.mkdir(parents=True, exist_ok=True)
    stem = a.delta.stem.replace("delta-", "")
    watches = a.dry_run or STATE / f"watches-{stem}.jsonl"
    if not a.dry_run:
        watches.write_bytes(_req(export))
    alerts = STATE / (f"alerts-{stem}{'-dry' if a.dry_run else ''}.jsonl")
    state = STATE / ("sent-dry.jsonl" if a.dry_run else "sent.jsonl")
    print(tm_watch.match(a.delta, watches, alerts, state))
    # The WHOLE week's file is posted, not just this run's lines: the site stores by (watch, week, mark) idempotently,
    # so a failed post is repaired by re-running, although match() has already marked those alerts as queued.
    week = alerts.read_bytes() if alerts.exists() else b""
    lines = week.count(b"\n")
    if len(week) > 1_000_000:
        sys.exit("alerts exceed the 1 MB the site accepts; not posting (split before enabling at this volume)")
    if a.dry_run:
        print(f"dry run: {lines} alert lines in {alerts}, nothing posted")
    elif week:
        _req(post, week)
        print(f"posted {lines} alert lines")
    if not a.dry_run:
        watches.unlink()  # the export holds watched names: kept only for the run


if __name__ == "__main__":
    main()
