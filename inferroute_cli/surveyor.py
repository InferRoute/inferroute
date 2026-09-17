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
TEMPLATE_DISCLOSURE = ("# Disclosure\n\nDescribe the invention here, then open the matter and ask for a "
                       "prior-art survey.\n")


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


def records_dir(client: str, matter: str) -> Path:
    # One directory per matter under confidential/attested-records; each session writes its own file
    # here (Q2). The export (step 6) lists them all. Under confidential/, write-denied to the agent.
    return _irhome() / "confidential" / "attested-records" / client / matter


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
        disclosure.write_text(TEMPLATE_DISCLOSURE)
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


def disclosure_has_content(workspace: Path) -> bool:
    """True if the matter's disclosure.md holds a real invention description, not just the template stub
    `ir surveyor new` writes. The enclave prewarms on session-open only when this is true (L3); otherwise it
    waits for the first search, so a firm never pays for a container while the workspace is still empty."""
    p = Path(workspace) / "disclosure.md"
    try:
        body = p.read_text()
    except OSError:
        return False
    # Strip the template's own words; anything of substance left means the attorney has written a disclosure.
    stripped = body.replace(TEMPLATE_DISCLOSURE, "")
    for line in stripped.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line != "Describe the invention here, then open the matter and ask for a prior-art survey.":
            return True
    return False


def usage_ledger_path() -> Path:
    return _irhome() / "confidential" / "azure-usage.jsonl"


def _read_jsonl(p: Path) -> list:
    rows = []
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows


def cmd_export(spec: str, out_path: str | None, anchor: bool = False) -> int:
    """The one-directory record: see surveyor_export. Refuses the workspace and sync roots (plaintext invention)."""
    from . import surveyor_export
    client, matter = _split_matter(spec)
    load_record(client, matter)                              # exists?
    surveyor_export.write_bundle(client, matter, out_path, anchor=anchor)
    return 0


def cmd_verify_export(bundle_dir: str) -> int:
    """Run the bundle's own independent verifier over it (convenience; the bundle needs no `ir` to verify)."""
    from . import surveyor_export
    return surveyor_export.verify_bundle(bundle_dir)


def cmd_open(spec: str, dev_unconfined: bool = False) -> int:
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
    os.environ["IR_MATTER_RECORD_DIR"] = str(records_dir(client, matter))     # per-session record files (Q2)
    os.environ["IR_REPORT_MATTER"] = f"{client}/{matter}"                     # labels on the rendered search report
    os.environ["IR_REPORT_FIRM"] = client
    # F1: an attorney session is confined at address level, FULL STOP — never inherit a leftover
    # IR_ATTESTED_CONFINE=off from the shell (that would silently run unconfined and, under trusted state,
    # trust forgeable approvals). Force require. The only way down is an explicit developer override, which
    # is banner-loud, recorded as unconfined, and (in the verifier) never granted trusted state.
    if dev_unconfined:
        os.environ["IR_ATTESTED_CONFINE"] = "off"
        os.environ["IR_SURVEYOR_DEV_UNCONFINED"] = "1"
        sys.stderr.write("\n  ⚠  DEVELOPER OVERRIDE: opening this matter UNCONFINED. The agent is NOT sandboxed;\n"
                         "     approvals are NOT persisted/trusted; this is recorded as an unconfined session.\n"
                         "     Never use this on a real client matter.\n\n")
    else:
        os.environ["IR_ATTESTED_CONFINE"] = "require"
    os.chdir(ws)
    print(f"opening {client}/{matter} — date bound {rec['date_bound']} (held here, not the model's to change)")
    from . import confidential as confidential_mod
    return confidential_mod.launch([], agent="pi", surveyor={"matter": f"{client}/{matter}", "date_bound": rec["date_bound"]})


def latest_session_record(client: str, matter: str) -> dict | None:
    """The newest host-written session record for this matter (never an agent-writable file)."""
    files = sorted(p for p in records_dir(client, matter).glob("*.json") if not p.name.endswith(".searches.json"))
    for p in reversed(files):
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            continue
    return None


def cmd_proof(spec: str) -> int:
    """The technical detail behind the plain card: the matter's last session, as recorded on this computer,
    and a fresh live check of the search machine."""
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from . import pi_attested
    client, matter = _split_matter(spec)
    rec = load_record(client, matter)
    console = Console()
    console.print(Text(f"\nTechnical proof · {client}/{matter} · date bound {rec['date_bound']}", style="bold"))
    last = latest_session_record(client, matter)
    if last is None:
        console.print(Text("  No session has been opened on this matter yet.", style="grey58"))
    else:
        model = last.get("model_lane") or {}
        console.print(Text(f"\nAI machine — last session {last.get('session_id', '')[:8]}, started {last.get('started_at', '')}", style="bold"))
        receipt_path = model.get("receipt")
        shown = False
        if receipt_path and Path(receipt_path).is_file():
            from inferroute_local.confidential import display, receipt as receipt_mod
            display.render_panel(receipt_mod.Receipt.load(Path(receipt_path)), console)
            shown = True
        if not shown:
            t = Table(box=None, show_header=False, pad_edge=False)
            for c in model.get("check_list") or []:
                t.add_row(Text("✓" if c.get("ok") else "✗", style="spring_green3" if c.get("ok") else "red"),
                          Text(str(c.get("label", "")), style="bold"), Text(str(c.get("why", "")), style="grey58"))
            console.print(t)
        conf = last.get("confinement")
        if conf:
            console.print(Text.assemble(("\nThis computer  ", "bold"), (str(conf), "grey58")))
    console.print(Text("\nSearch machine — checked now", style="bold"))
    with console.status("checking the search machine from this computer…"):
        live = pi_attested.verify_search_once()
    if live is None:
        console.print(Text("  Search is not set up on this computer.", style="grey58"))
        return 0
    t = Table(box=None, show_header=False, pad_edge=False)
    for st in live.get("steps") or []:
        t.add_row(Text("✓" if st.get("ok") else "✗", style="spring_green3" if st.get("ok") else "red"),
                  Text(str(st.get("step", "")), style="bold"), Text(str(st.get("detail", "")), style="grey58"))
    console.print(t)
    if not live.get("ok"):
        console.print(Text(f"  Not verified: {live.get('refusal')}", style="bold red"))
    console.print(Text("\nEvery line above was computed on this computer. The record you export carries the same "
                       "evidence, and its verifier re-checks it without trusting InferRoute.\n", style="grey58"))
    return 0 if live.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ir surveyor", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new"); n.add_argument("client"); n.add_argument("matter"); n.add_argument("--priority-date", default=None)
    d = sub.add_parser("set-date"); d.add_argument("matter"); d.add_argument("date")
    o = sub.add_parser("open"); o.add_argument("matter")
    o.add_argument("--dev-unconfined", action="store_true",
                   help="developer override: open UNCONFINED (no sandbox, no trusted state). Never for a real matter.")
    x = sub.add_parser("export"); x.add_argument("matter"); x.add_argument("-o", "--out", default=None)
    x.add_argument("--anchor", action="store_true", help="OpenTimestamps-anchor MANIFEST.json (publishes only a hash)")
    ve = sub.add_parser("verify-export"); ve.add_argument("bundle")
    rf = sub.add_parser("reference", help="operator: issue and sign the out-of-band reference that makes a record say InferRoute")
    rf.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("list")
    pf = sub.add_parser("proof", help="the technical detail behind the plain card: last session + a live search check")
    pf.add_argument("matter")
    a = p.parse_args(argv)
    try:
        if a.cmd == "new":
            return cmd_new(a.client, a.matter, a.priority_date)
        if a.cmd == "set-date":
            return cmd_set_date(a.matter, a.date)
        if a.cmd == "open":
            return cmd_open(a.matter, dev_unconfined=a.dev_unconfined)
        if a.cmd == "export":
            return cmd_export(a.matter, a.out, anchor=a.anchor)
        if a.cmd == "verify-export":
            return cmd_verify_export(a.bundle)
        if a.cmd == "reference":
            from . import reference as reference_mod
            return reference_mod.main(a.args)
        if a.cmd == "list":
            return cmd_list()
        if a.cmd == "proof":
            return cmd_proof(a.matter)
    except SurveyorError as e:
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0
