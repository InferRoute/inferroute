"""`ir data` — inspect, export, or wipe your LOCAL recorded corpus.

Everything the recorder writes lives under ~/.inferroute (or
$INFERROUTE_RECORD_DIR) on your own machine — the corpus is never uploaded.
(inferroute keeps only a one-way hash of each turn — a fingerprint, never the
text.) These verbs make the local-corpus promise verifiable:

    ir data show            what's been recorded (counts, models, size)
    ir data export <dir>    copy the shareable (metadata) layer somewhere
    ir data wipe            delete all recorded data

`export` deliberately copies ONLY the event stream + derived features (no raw
blobs / prompt text), so it's safe to hand off if you ever opt into improving a
shared model. Raw blobs never leave via `export`.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path


def _base() -> Path:
    d = os.environ.get("INFERROUTE_RECORD_DIR")
    return Path(d) if d else Path.home() / ".inferroute"


def cmd_data(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir data", description="Manage your local recorded corpus.")
    sub = ap.add_subparsers(dest="action")
    sub.add_parser("show", help="Summarize what's recorded.")
    sub.add_parser("cost", help="Per-session cost (measured server cost + estimated).")
    w = sub.add_parser("wipe", help="Delete all recorded data.")
    w.add_argument("--yes", "-y", action="store_true", help="Don't prompt.")
    e = sub.add_parser("export", help="Copy the metadata layer to a directory.")
    e.add_argument("dest", help="Destination directory.")
    ns = ap.parse_args(rest)

    if ns.action == "show":
        return _show()
    if ns.action == "cost":
        return _cost()
    if ns.action == "wipe":
        return _wipe(ns.yes)
    if ns.action == "export":
        return _export(Path(ns.dest))
    ap.print_help()
    return 2


def _dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _show() -> int:
    base = _base()
    events_dir = base / "events"
    if not events_dir.exists():
        print(f"\n  No recorded data at {base}.")
        print("  Turn on recording with: ir add recording\n")
        return 0

    kinds: dict[str, int] = {}
    sessions: set[str] = set()
    models: dict[str, int] = {}
    first_ts = last_ts = None
    files = sorted(events_dir.glob("events-*.jsonl"))
    for f in files:
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                kinds[ev.get("kind", "?")] = kinds.get(ev.get("kind", "?"), 0) + 1
                if ev.get("session_id"):
                    sessions.add(ev["session_id"])
                if ev.get("kind") == "choice" and ev.get("chosen_model"):
                    m = ev["chosen_model"]
                    models[m] = models.get(m, 0) + 1
                if ev.get("kind") == "turn" and ev.get("served_model"):
                    m = ev["served_model"]
                    models[m] = models.get(m, 0) + 1
                ts = ev.get("ts")
                if isinstance(ts, (int, float)):
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
        except OSError:
            continue

    print(f"\n  Local recorded corpus — {base}")
    print(f"  (corpus stays on this machine; inferroute keeps only one-way hashes, never text)\n")
    print(f"    days on disk     {len(files)}")
    print(f"    sessions         {len(sessions)}")
    print(f"    turns (ingested) {kinds.get('turn', 0)}")
    print(f"    choices          {kinds.get('choice', 0)}")
    print(f"    outcomes         {kinds.get('outcome', 0)}")
    print(f"    signals          {kinds.get('signal', 0)}")
    if first_ts and last_ts:
        from datetime import datetime, timezone
        fmt = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d")
        print(f"    range            {fmt(first_ts)} → {fmt(last_ts)}")
    print(f"    events size      {_fmt_bytes(_dir_size(events_dir))}")
    print(f"    blobs size       {_fmt_bytes(_dir_size(base / 'blobs'))}")
    if models:
        print("\n    model choices:")
        for m, c in sorted(models.items(), key=lambda kv: -kv[1]):
            print(f"      {c:>6}  {m}")
    print("\n  Manage:  ir data export <dir>   |   ir data wipe\n")
    return 0


def _cost() -> int:
    """Per-session inferroute cost — the REAL amount inferroute billed.

    The only cost inferroute tracks is its own: the server-reported `usage.cost`
    on ROUTED turns (captured by the daemon as outcome events). Native Claude
    turns aren't served by inferroute, so they carry no inferroute cost — we do
    NOT estimate them against anyone else's price list. Nothing is computed from
    a local price table.
    """
    base = _base()
    events_dir = base / "events"
    if not events_dir.exists():
        print(f"\n  No recorded data at {base}.\n")
        return 0

    sess: dict[str, dict] = {}

    def _s(sid: str) -> dict:
        return sess.setdefault(sid, {"turns": 0, "cost": 0.0, "models": set()})

    for f in sorted(events_dir.glob("events-*.jsonl")):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            sid = ev.get("session_id") or "(unknown)"
            kind = ev.get("kind")
            if kind == "turn":
                rec = _s(sid)
                rec["turns"] += 1
                if ev.get("served_model"):
                    rec["models"].add(ev["served_model"])
            elif kind == "outcome":
                c = ev.get("cost_usd")
                if isinstance(c, (int, float)) and not isinstance(c, bool) and c > 0:
                    _s(sid)["cost"] += float(c)

    if not sess:
        print(f"\n  No turns or outcomes recorded yet at {base}.\n")
        return 0

    rows = sorted(sess.items(), key=lambda kv: -kv[1]["cost"])
    total = sum(r["cost"] for _, r in rows)

    print(f"\n  inferroute cost by session — {base}")
    print("  cost = what inferroute billed (routed turns, real server usage.cost).")
    print("  Native Claude turns aren't served by inferroute → no inferroute cost.\n")
    print(f"    {'session':<24} {'turns':>5} {'cost (inferroute)':>18}  models")
    print(f"    {'-'*24} {'-'*5} {'-'*18}  {'-'*6}")
    for sid, rec in rows[:50]:
        models = ",".join(sorted(rec["models"]))[:40] or "-"
        print(f"    {sid[:24]:<24} {rec['turns']:>5} {rec['cost']:>17.4f}$  {models}")
    if len(rows) > 50:
        print(f"    … and {len(rows) - 50} more sessions")
    print(f"    {'-'*24} {'-'*5} {'-'*18}")
    print(f"    {'TOTAL':<24} {'':>5} {total:>17.4f}$")
    print()
    return 0


def _wipe(skip_prompt: bool) -> int:
    base = _base()
    targets = [base / "events", base / "blobs", base / "derived"]
    present = [p for p in targets if p.exists()]
    if not present:
        print(f"\n  Nothing to wipe at {base}.\n")
        return 0
    print(f"\n  This permanently deletes your local recorded corpus under {base}:")
    for p in present:
        print(f"    {p}  ({_fmt_bytes(_dir_size(p))})")
    if not skip_prompt:
        try:
            ans = input("\n  Delete it all? [y/N] ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return 1
        if ans not in {"y", "yes"}:
            print("  Aborted — nothing deleted.\n")
            return 1
    for p in present:
        shutil.rmtree(p, ignore_errors=True)
    print("  Done. Recorded data deleted.\n")
    return 0


def _export(dest: Path) -> int:
    base = _base()
    events_dir = base / "events"
    if not events_dir.exists():
        print(f"\n  No recorded data at {base} to export.\n")
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    # Copy ONLY the metadata layer — event stream + derived features. Never the
    # raw blob store (which may contain prompt text).
    shutil.copytree(events_dir, dest / "events", dirs_exist_ok=True)
    derived = base / "derived"
    if derived.exists():
        shutil.copytree(derived, dest / "derived", dirs_exist_ok=True)
    print(f"\n  Exported the metadata layer (no raw prompt text) to {dest}")
    print(f"    events size      {_fmt_bytes(_dir_size(dest / 'events'))}\n")
    return 0
