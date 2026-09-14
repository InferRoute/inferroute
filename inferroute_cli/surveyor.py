"""`ir surveyor` — the attorney entry to the attested prior-art assistant. One matter at a time, in a
folder confined to that matter, with the date bound and approvals held where the agent cannot reach them.

    ir surveyor new <client> <matter> [--priority-date YYYY-MM-DD]   create a matter (default bound = today)
    ir surveyor set-date <client>/<matter> YYYY-MM-DD                 change the date bound (human, out of session)
    ir surveyor open <client>/<matter>                               open the attested session on the matter
    ir surveyor list                                                 list matters

The split that keeps it safe (decision record S1/S2):
  WORKSPACE  ~/Surveyor/<client>/<matter>/  — disclosure.md and working files. Writable in-session; the
             launcher trusts NOTHING read from it.
  RECORD     ~/.inferroute/confidential/matters/<client>/<matter>.json — client, ref, date bound, created,
             workspace path. Under confidential/, where the filesystem confinement denies the agent writes.
Creation and every change to the date bound happen OUTSIDE any session, by the human, through this
unconfined launcher — never by an in-session command. The per-matter cutoff, state and record are passed
to that matter's verifier as arguments, never through the shared search.json (S2).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

# Cloud-sync roots: a matter placed here is copied out by a backup daemon that sits outside the
# confinement, so we refuse it (decision record B).
SYNC_MARKERS = ("OneDrive", "iCloud", "Library/Mobile Documents", "Dropbox", "Google Drive", "GoogleDrive", "pCloud")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


class SurveyorError(ValueError):
    pass


def _home() -> Path:
    return Path.home()


def _irhome() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (_home() / ".inferroute"))


def surveyor_root() -> Path:
    return Path(os.environ.get("IR_SURVEYOR_ROOT") or (_home() / "Surveyor"))


def matters_dir() -> Path:
    return _irhome() / "confidential" / "matters"


def sanitize(component: str, what: str) -> str:
    """A client or matter name is a single path component. Reject anything that could escape or hide:
    slashes, '..', a leading dot, control characters. check_workspace is a backstop, not this (S3)."""
    name = (component or "").strip()
    if "/" in name or "\\" in name or name in ("", ".", "..") or name.startswith(".") \
            or any(ord(c) < 0x20 for c in name) or not _NAME_RE.match(name):
        raise SurveyorError(f"invalid {what} {component!r}: use letters, digits, space, dot, dash or underscore; "
                            "no slashes, no leading dot, 1–64 characters.")
    return name


def record_path(client: str, matter: str) -> Path:
    return matters_dir() / client / f"{matter}.json"


def workspace_path(client: str, matter: str) -> Path:
    return surveyor_root() / client / matter


def state_path(client: str, matter: str) -> Path:
    return matters_dir() / client / f"{matter}.state.json"


def record_file(client: str, matter: str) -> Path:
    return matters_dir() / client / f"{matter}.record.json"


def _under_sync_root(p: Path) -> str | None:
    s = str(p)
    for m in SYNC_MARKERS:
        if m in s:
            return m
    return None


def _today() -> str:
    return dt.date.today().isoformat()


def _to_yyyymmdd(iso: str) -> int:
    try:
        return int(dt.date.fromisoformat(iso).strftime("%Y%m%d"))
    except ValueError as e:
        raise SurveyorError(f"bad date {iso!r}: use YYYY-MM-DD") from e


def load_record(client: str, matter: str) -> dict:
    p = record_path(client, matter)
    if not p.exists():
        raise SurveyorError(f"no such matter {client}/{matter}. Create it: ir surveyor new {client} {matter}")
    return json.loads(p.read_text())


def _write_record(client: str, matter: str, rec: dict) -> None:
    p = record_path(client, matter)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec, indent=1) + "\n")
    os.replace(tmp, p)


def _split_matter(spec: str) -> tuple[str, str]:
    if "/" not in spec:
        raise SurveyorError(f"give the matter as <client>/<matter>, not {spec!r}")
    client, matter = spec.split("/", 1)
    return sanitize(client, "client"), sanitize(matter, "matter")


def cmd_new(client: str, matter: str, priority_date: str | None) -> int:
    client, matter = sanitize(client, "client"), sanitize(matter, "matter")
    if record_path(client, matter).exists():
        raise SurveyorError(f"matter {client}/{matter} already exists")
    ws = workspace_path(client, matter)
    sync = _under_sync_root(ws)
    if sync:
        raise SurveyorError(f"refusing to create the matter under a cloud-sync folder ({sync}): a backup daemon "
                            "outside the confinement would copy the disclosure. Put ~/Surveyor on local disk "
                            "(or set IR_SURVEYOR_ROOT).")
    bound = priority_date or _today()
    _to_yyyymmdd(bound)                                      # validate
    ws.mkdir(parents=True, exist_ok=True)
    disclosure = ws / "disclosure.md"
    if not disclosure.exists():
        disclosure.write_text("# Disclosure\n\nDescribe the invention here, then open the matter and ask for a "
                              "prior-art survey.\n")
    rec = {"schema": "inferroute.surveyor.matter/1", "client": client, "matter": matter,
           "date_bound": bound, "pre_filing_default": priority_date is None,
           "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "workspace": str(ws.resolve()), "changes": []}
    _write_record(client, matter, rec)
    print(f"created matter {client}/{matter}")
    print(f"  workspace   {ws}")
    print(f"  date bound  {bound}" + (" (pre-filing default = today; set the real priority date with "
                                      "`ir surveyor set-date`)" if priority_date is None else ""))
    print(f"  open it:    ir surveyor open {client}/{matter}")
    return 0


def cmd_set_date(spec: str, date: str) -> int:
    client, matter = _split_matter(spec)
    rec = load_record(client, matter)
    old = rec.get("date_bound")
    _to_yyyymmdd(date)
    rec["date_bound"], rec["pre_filing_default"] = date, False
    rec.setdefault("changes", []).append(
        {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "field": "date_bound",
         "old": old, "new": date})
    _write_record(client, matter, rec)
    print(f"{client}/{matter} date bound: {old} → {date}")
    return 0


def cmd_list() -> int:
    root = matters_dir()
    if not root.exists():
        print("no matters yet — create one: ir surveyor new <client> <matter>")
        return 0
    for cdir in sorted(root.iterdir()):
        if not cdir.is_dir():
            continue
        for f in sorted(cdir.glob("*.json")):
            if f.name.endswith(".state.json") or f.name.endswith(".record.json"):
                continue
            try:
                r = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            print(f"  {r.get('client')}/{r.get('matter'):<20} date bound {r.get('date_bound')}  {r.get('workspace')}")
    return 0


def cmd_open(spec: str) -> int:
    client, matter = _split_matter(spec)
    rec = load_record(client, matter)
    ws = Path(rec["workspace"])
    if not ws.is_dir():
        raise SurveyorError(f"the matter workspace is missing: {ws}")
    sync = _under_sync_root(ws)
    if sync:
        raise SurveyorError(f"the matter workspace is under a cloud-sync folder ({sync}); refusing to open it.")
    if (ws / ".git").exists():
        raise SurveyorError(f"the matter workspace {ws} contains a .git repository. Its hooks would run "
                            "outside the sandbox — remove it; a matter folder is not a code repo.")
    # Per-matter cutoff/state/record, passed to THIS matter's verifier as arguments via env (S2) — never
    # the shared search.json. All three live under confidential/, write-denied to the agent (S1).
    os.environ["IR_MATTER_CUTOFF"] = str(_to_yyyymmdd(rec["date_bound"]))
    os.environ["IR_MATTER_STATE_FILE"] = str(state_path(client, matter))
    os.environ["IR_MATTER_RECORD_FILE"] = str(record_file(client, matter))
    os.environ["IR_ATTESTED_CONFINE"] = os.environ.get("IR_ATTESTED_CONFINE") or "require"   # attorney: address-level
    os.chdir(ws)
    print(f"opening {client}/{matter} — date bound {rec['date_bound']} (held here, not the model's to change)")
    from . import confidential as confidential_mod
    return confidential_mod.launch([], agent="pi")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ir surveyor", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new"); n.add_argument("client"); n.add_argument("matter"); n.add_argument("--priority-date", default=None)
    d = sub.add_parser("set-date"); d.add_argument("matter"); d.add_argument("date")
    o = sub.add_parser("open"); o.add_argument("matter")
    sub.add_parser("list")
    a = p.parse_args(argv)
    try:
        if a.cmd == "new":
            return cmd_new(a.client, a.matter, a.priority_date)
        if a.cmd == "set-date":
            return cmd_set_date(a.matter, a.date)
        if a.cmd == "open":
            return cmd_open(a.matter)
        if a.cmd == "list":
            return cmd_list()
    except SurveyorError as e:
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0
