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
import html
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


def _load_sessions(client: str, matter: str) -> list:
    """Each attested session's host-written disclosure record, plus its verbatim signed statements."""
    rdir = records_dir(client, matter)
    sessions = []
    if rdir.is_dir():
        for f in sorted(rdir.glob("*.json")):
            if f.name.endswith(".tmp"):
                continue
            try:
                rec = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            sid = f.stem
            statements = _read_jsonl(rdir / f"{sid}.statements.jsonl")
            sessions.append({"session_id": sid, "record": rec, "statements": statements})
    return sessions


_EXPOSURE_WORD = {
    "this_session": "surfaced by this session's search",
    "earlier_session": "surfaced by an earlier session's search",
    "not_surfaced": "not surfaced by any search on this matter",
    "unknown_prior": "not in this session's results (earlier sessions not consulted)",
}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def build_export_html(client: str, matter: str) -> str:
    rec = load_record(client, matter)
    ws = Path(rec["workspace"])
    try:
        state = json.loads(state_path(client, matter).read_text())
    except (OSError, ValueError):
        state = {}
    sessions = _load_sessions(client, matter)
    disclosure_md = ""
    dp = ws / "disclosure.md"
    if dp.exists():
        try:
            disclosure_md = dp.read_text()
        except OSError:
            disclosure_md = ""
    usage = [r for r in _read_jsonl(usage_ledger_path()) if r.get("matter") == f"{client}/{matter}"]

    out: list = []
    A = out.append
    A("<!doctype html><html lang=en><head><meta charset=utf-8>")
    A(f"<title>Prior-art record — {_e(client)}/{_e(matter)}</title>")
    A("<style>"
      "body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
      "h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.15rem;border-bottom:2px solid #eee;padding-bottom:.2rem;margin-top:2rem}"
      ".sub{color:#666}table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}"
      "th{background:#f6f6f6}code,pre{font-family:ui-monospace,Menlo,monospace}pre{background:#f6f8fa;padding:.8rem;border-radius:6px;overflow:auto;font-size:12px}"
      ".ok{color:#127a2b}.warn{color:#b25000;font-weight:600}.bad{color:#b00020;font-weight:600}"
      ".pill{display:inline-block;background:#eef;border-radius:10px;padding:.05rem .5rem;font-size:12px}"
      ".note{color:#666;font-size:13px}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}"
      "</style></head><body>")

    A(f"<h1>Prior-art research record</h1>")
    A(f"<div class=sub>{_e(client)} / {_e(matter)}</div>")
    A("<h2>Matter</h2><table>")
    A(f"<tr><th>Date bound (priority date)</th><td>{_e(rec.get('date_bound'))}"
      f"{' <span class=note>(pre-filing default = creation date; not yet set to a real priority date)</span>' if rec.get('pre_filing_default') else ''}</td></tr>")
    A(f"<tr><th>Created</th><td>{_e(rec.get('created_at'))}</td></tr>")
    A(f"<tr><th>Workspace</th><td class=mono>{_e(rec.get('workspace'))}</td></tr>")
    if rec.get("changes"):
        rows = "".join(f"<li>{_e(c.get('at'))}: date bound {_e(c.get('old'))} → {_e(c.get('new'))}</li>" for c in rec["changes"])
        A(f"<tr><th>Date-bound changes</th><td><ul>{rows}</ul></td></tr>")
    A("</table>")
    A("<p class=note>Every statement below is a fact this device checked or recorded, not a promise. A sealed "
      "prior-art search surfaces related art; it does not certify novelty or the absence of prior art.</p>")

    A("<h2>Disclosure</h2>")
    A(f"<pre>{_e(disclosure_md) or '<span class=note>(no disclosure.md in the workspace)</span>'}</pre>")

    A("<h2>Relevance marks</h2>")
    marks = state.get("marks") or {}
    if not marks:
        A("<p class=note>No relevance marks were recorded for this matter.</p>")
    else:
        A("<table><tr><th>Publication</th><th>Mark</th><th>Exposure</th><th>By</th><th>When</th><th>History</th></tr>")
        for k in sorted(marks):
            latest = (marks[k] or {}).get("latest") or {}
            hist = (marks[k] or {}).get("history") or []
            rank = f" (rank {_e(latest.get('rank'))})" if latest.get("rank") else ""
            hist_s = "; ".join(f"{_e(h.get('value'))} @ {_e(h.get('at'))}" for h in hist)
            A(f"<tr><td class=mono>{_e(k)}</td><td>{_e(latest.get('value'))}</td>"
              f"<td>{_e(_EXPOSURE_WORD.get(latest.get('surfaced'), latest.get('surfaced')))}{rank}</td>"
              f"<td>{_e(latest.get('actor'))}</td><td>{_e(latest.get('at'))}</td><td class=note>{hist_s}</td></tr>")
        A("</table>")
        A("<p class=note>Marks are the attorney's own judgements, typed at this machine. The model cannot make "
          "one. 'Exposure' records whether this matter's search actually returned the document.</p>")

    A("<h2>Attested sessions</h2>")
    if not sessions:
        A("<p class=note>No attested sessions were recorded for this matter yet.</p>")
    for s in sessions:
        r = s["record"]
        conf = r.get("confinement") or "(not recorded)"
        conf_cls = "bad" if "unconfined" in str(conf) else "ok"
        model = r.get("model_lane") or {}
        search = r.get("search_lane") or {}
        contract = r.get("contract") or {}
        hrs = sum(float(u.get("hours", 0)) for u in usage if u.get("event") == "stop")
        A(f"<h3>Session <span class=mono>{_e(s['session_id'])}</span></h3><table>")
        A(f"<tr><th>Started</th><td>{_e(r.get('started_at'))}</td></tr>")
        A(f"<tr><th>Confinement</th><td class={conf_cls}>{_e(conf)}</td></tr>")
        A(f"<tr><th>Model enclave verified</th><td class={'ok' if model.get('verified') else 'bad'}>"
          f"{'yes' if model.get('verified') else 'no'} <span class=note>{_e(model.get('checks'))}</span></td></tr>")
        if contract.get("modified"):
            A("<tr><th>Contract</th><td class=warn>modified from the pinned version</td></tr>")
        searches = search.get("searches") or []
        if searches:
            rows = "".join(
                f"<tr><td>{_e(x.get('at'))}</td><td>{_e(x.get('hits'))}</td>"
                f"<td class=mono>{_e((x.get('measurement') or '')[:24])}…</td>"
                f"<td class=mono>{_e((x.get('policy') or '')[:24])}…</td><td>{_e(x.get('index'))}</td></tr>"
                for x in searches)
            A(f"<tr><th>Sealed searches</th><td><table><tr><th>at</th><th>hits</th><th>utility VM</th><th>policy</th><th>index</th></tr>{rows}</table></td></tr>")
        else:
            A("<tr><th>Sealed searches</th><td class=note>none</td></tr>")
        surf = r.get("which_surface_saw_what") or {}
        if surf:
            rows = "".join(f"<tr><td>{_e(k.replace('_',' '))}</td><td>{_e(v)}</td></tr>" for k, v in surf.items())
            A(f"<tr><th>Which surface saw what</th><td><table>{rows}</table></td></tr>")
        A("</table>")

    A("<h2>Enclave-signed statements (verbatim)</h2>")
    any_stmt = False
    for s in sessions:
        for st in s["statements"]:
            any_stmt = True
            stmt = st.get("statement") or {}
            A(f"<p class=note>Session <span class=mono>{_e(s['session_id'])}</span>, recorded {_e(st.get('at'))}. "
              f"Ed25519 signature over the canonical JSON below (minus <code>sig</code>), by the key the enclave's "
              f"hardware report committed to:</p>")
            A(f"<p class=note>signer key <span class=mono>{_e(st.get('signer_pub'))}</span></p>")
            A(f"<pre>{_e(json.dumps(stmt, indent=1, ensure_ascii=False))}</pre>")
    if not any_stmt:
        A("<p class=note>No enclave-signed statements were recorded (no sealed search completed).</p>")

    A("<h2>This device's record</h2>")
    A("<p class=note>This file was assembled on the attorney's own machine from records it wrote itself, held "
      "where the agent could not reach them. The verification of each remote enclave was performed here, by "
      "this device, not by the model — and never sent to the model. The date bound was held here, not the "
      "model's to change.</p>")
    A(f"<p class=note>Generated {_e(dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))}.</p>")
    A("</body></html>")
    return "".join(out)


def cmd_export(spec: str, out_path: str | None) -> int:
    client, matter = _split_matter(spec)
    load_record(client, matter)                              # exists?
    htmltext = build_export_html(client, matter)
    dest = Path(out_path) if out_path else (Path.cwd() / f"{client}-{matter}-prior-art-record.html")
    dest.write_text(htmltext)
    print(f"wrote {dest}")
    return 0


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
    return confidential_mod.launch([], agent="pi")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ir surveyor", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new"); n.add_argument("client"); n.add_argument("matter"); n.add_argument("--priority-date", default=None)
    d = sub.add_parser("set-date"); d.add_argument("matter"); d.add_argument("date")
    o = sub.add_parser("open"); o.add_argument("matter")
    o.add_argument("--dev-unconfined", action="store_true",
                   help="developer override: open UNCONFINED (no sandbox, no trusted state). Never for a real matter.")
    x = sub.add_parser("export"); x.add_argument("matter"); x.add_argument("-o", "--out", default=None)
    sub.add_parser("list")
    a = p.parse_args(argv)
    try:
        if a.cmd == "new":
            return cmd_new(a.client, a.matter, a.priority_date)
        if a.cmd == "set-date":
            return cmd_set_date(a.matter, a.date)
        if a.cmd == "open":
            return cmd_open(a.matter, dev_unconfined=a.dev_unconfined)
        if a.cmd == "export":
            return cmd_export(a.matter, a.out)
        if a.cmd == "list":
            return cmd_list()
    except SurveyorError as e:
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0
