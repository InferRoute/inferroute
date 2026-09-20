"""`ir probant` — the attorney entry to the attested prior-art assistant. One matter at a time, in a
folder confined to that matter, with the date bound and approvals held where the agent cannot reach them.

    ir probant new <client> <matter> [--priority-date YYYY-MM-DD]   create a matter (default bound = today)
    ir probant set-date <client>/<matter> YYYY-MM-DD                 change the date bound (human, out of session)
    ir probant open <client>/<matter>                               open the attested session on the matter
    ir probant list                                                 list matters

The split that keeps it safe (decision record S1/S2):
  WORKSPACE  ~/Probant/<client>/<matter>/  — disclosure.md and working files. Writable in-session; the
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


class ProbantError(ValueError):
    pass


def _home() -> Path:
    return Path.home()


def _irhome() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (_home() / ".inferroute"))


def probant_root() -> Path:
    """Where matters live. `~/Probant` for a new install — but an existing `~/Surveyor` KEEPS BEING USED:
    the matter records hold absolute workspace paths, so renaming the folder without rewriting them would
    strand every matter already on this machine. Migration is a deliberate act, not a side effect of a
    product being renamed."""
    named = os.environ.get("IR_PROBANT_ROOT") or os.environ.get("IR_SURVEYOR_ROOT")
    if named:
        return Path(named)
    new, old = _home() / "Probant", _home() / "Surveyor"
    return old if old.is_dir() and not new.is_dir() else new


def matters_dir() -> Path:
    return _irhome() / "confidential" / "matters"


def sanitize(component: str, what: str) -> str:
    """A client or matter name is a single path component. Reject anything that could escape or hide:
    slashes, '..', a leading dot, control characters. check_workspace is a backstop, not this (S3)."""
    name = (component or "").strip()
    if "/" in name or "\\" in name or name in ("", ".", "..") or name.startswith(".") \
            or any(ord(c) < 0x20 for c in name) or not _NAME_RE.match(name):
        raise ProbantError(f"invalid {what} {component!r}: use letters, digits, space, dot, dash or underscore; "
                            "no slashes, no leading dot, 1–64 characters.")
    return name


def record_path(client: str, matter: str) -> Path:
    return matters_dir() / client / f"{matter}.json"


def workspace_path(client: str, matter: str) -> Path:
    return probant_root() / client / matter


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
        raise ProbantError(f"bad date {iso!r}: use YYYY-MM-DD") from e


def load_record(client: str, matter: str) -> dict:
    p = record_path(client, matter)
    if not p.exists():
        raise ProbantError(f"no such matter {client}/{matter}. Create it: ir probant new {client} {matter}")
    return json.loads(p.read_text())


def _write_record(client: str, matter: str, rec: dict) -> None:
    p = record_path(client, matter)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec, indent=1) + "\n")
    os.replace(tmp, p)


def _split_matter(spec: str) -> tuple[str, str]:
    if "/" not in spec:
        raise ProbantError(f"give the matter as <client>/<matter>, not {spec!r}")
    client, matter = spec.split("/", 1)
    return sanitize(client, "client"), sanitize(matter, "matter")


def make_private(client: str, matter: str) -> None:
    """Owner-only access to everything that holds a matter's words: the workspace (the disclosure), and the
    host-side records, state and receipts under confidential/. A folder at 0700 keeps other accounts on this
    computer out of every file inside it, whatever mode an editor gave that file. Applied on `new` and on every
    `open`, so a matter created before this existed is tightened the next time it is used."""
    for d in (probant_root(), probant_root() / client, workspace_path(client, matter),
              _irhome(), _irhome() / "confidential", matters_dir(), matters_dir() / client,
              records_dir(client, matter).parent, records_dir(client, matter)):
        try:
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        except OSError:
            pass


def cmd_new(client: str, matter: str, priority_date: str | None) -> int:
    client, matter = sanitize(client, "client"), sanitize(matter, "matter")
    if record_path(client, matter).exists():
        raise ProbantError(f"matter {client}/{matter} already exists")
    ws = workspace_path(client, matter)
    sync = _under_sync_root(ws)
    if sync:
        raise ProbantError(f"refusing to create the matter under a cloud-sync folder ({sync}): a backup daemon "
                            "outside the confinement would copy the disclosure. Put ~/Probant on local disk "
                            "(or set IR_PROBANT_ROOT).")
    bound = priority_date or _today()
    _to_yyyymmdd(bound)                                      # validate
    ws.mkdir(parents=True, exist_ok=True)
    make_private(client, matter)
    disclosure = ws / "disclosure.md"
    if not disclosure.exists():
        disclosure.write_text(TEMPLATE_DISCLOSURE)
    rec = {"schema": "inferroute.probant.matter/1", "client": client, "matter": matter,
           "date_bound": bound, "pre_filing_default": priority_date is None,
           "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "workspace": str(ws.resolve()), "changes": []}
    _write_record(client, matter, rec)
    print(f"created matter {client}/{matter}")
    print(f"  workspace   {ws}")
    print(f"  date bound  {bound}" + (" (pre-filing default = today; set the real priority date with "
                                      "`ir probant set-date`)" if priority_date is None else ""))
    print(f"  open it:    ir probant open {client}/{matter}")
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
    shown = 0
    for cdir in (sorted(root.iterdir()) if root.exists() else []):
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
            shown += 1
    if not shown:
        # An emptied directory used to print nothing at all, which reads as a broken command.
        print("no matters yet — create one: ir probant new <client> <matter> --priority-date YYYY-MM-DD")
    return 0


def disclosure_has_content(workspace: Path) -> bool:
    """True if the matter's disclosure.md holds a real invention description, not just the template stub
    `ir probant new` writes. The enclave prewarms on session-open only when this is true (L3); otherwise it
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
    """The one-directory record: see probant_export. Refuses the workspace and sync roots (plaintext invention)."""
    from . import probant_export
    client, matter = _split_matter(spec)
    load_record(client, matter)                              # exists?
    probant_export.write_bundle(client, matter, out_path, anchor=anchor)
    return 0


def cmd_verify_export(bundle_dir: str) -> int:
    """Run the bundle's own independent verifier over it (convenience; the bundle needs no `ir` to verify)."""
    from . import probant_export
    return probant_export.verify_bundle(bundle_dir)


def cmd_open(spec: str, dev_unconfined: bool = False, web: bool = False) -> int:
    client, matter = _split_matter(spec)
    rec = load_record(client, matter)
    ws = Path(rec["workspace"])
    if not ws.is_dir():
        raise ProbantError(f"the matter workspace is missing: {ws}")
    make_private(client, matter)
    try:
        os.chmod(ws, 0o700)                                  # the recorded workspace, wherever it lives
    except OSError:
        pass
    sync = _under_sync_root(ws)
    if sync:
        raise ProbantError(f"the matter workspace is under a cloud-sync folder ({sync}); refusing to open it.")
    if (ws / ".git").exists():
        raise ProbantError(f"the matter workspace {ws} contains a .git repository. Its hooks would run "
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
        os.environ["IR_PROBANT_DEV_UNCONFINED"] = "1"
        sys.stderr.write("\n  ⚠  DEVELOPER OVERRIDE: opening this matter UNCONFINED. The agent is NOT sandboxed;\n"
                         "     approvals are NOT persisted/trusted; this is recorded as an unconfined session.\n"
                         "     Never use this on a real client matter.\n\n")
    else:
        os.environ["IR_ATTESTED_CONFINE"] = "require"
    os.chdir(ws)
    print(f"opening {client}/{matter} — date bound {rec['date_bound']} (held here, not the model's to change)")
    from . import confidential as confidential_mod
    probant = {"matter": f"{client}/{matter}", "date_bound": rec["date_bound"]}
    if web:
        probant["web"] = True
    return confidential_mod.launch([], agent="pi", probant=probant)


def cmd_intake(path: str, web: bool = False) -> int:
    """Read a long document in a sealed session and collect the matters it proposes.

    No matter is open, so nothing here has a date bound, a state file or a search tool: the session reads the
    staged document and calls `propose_matter`. The professional creates matters afterwards, from what it
    proposed, with `ir probant from-proposal`.
    """
    from . import probant_intake as I
    # Either a document to stage, or one already staged (the home page stages what it was given, then
    # starts this): both name the same run, so the page and the terminal cannot drift apart.
    src = Path(path).expanduser()
    if src.is_dir() and (src / "meta.json").is_file():
        meta = json.loads((src / "meta.json").read_text())
    else:
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise ProbantError(f"could not read {src}: {e.strerror or e}")
        meta = I.stage(text, src.name)
    d = I.path_of(meta["id"])
    print(f"reading {meta['source_name']} — {meta['chars']:,} characters, {meta['lines']:,} lines")
    print(f"  {d}")
    os.environ["IR_INTAKE_DIR"] = str(d)
    os.environ["IR_ATTESTED_CONFINE"] = "require"
    for name in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR", "IR_REPORT_MATTER", "IR_REPORT_FIRM"):
        os.environ.pop(name, None)
    os.chdir(d)
    from . import confidential as confidential_mod
    probant = {"matter": f"document · {meta['source_name']}", "mode": "intake", "intake": meta["id"]}
    if web:
        probant["web"] = True
    rc = confidential_mod.launch([], agent="pi", probant=probant)
    print()
    return cmd_proposals(meta["id"]) if rc == 0 else rc


def cmd_proposals(ident: str) -> int:
    """What a reading session proposed, and how to turn one into a matter."""
    from . import probant_intake as I
    rows = I.read_proposals(ident)
    dropped = I.dropped_count(ident)
    if not rows:
        print(f"no matters proposed from this document ({ident})")
        if dropped:
            print(f"  {dropped} proposal(s) were discarded: their quote was not in the document")
        return 0
    print(f"{len(rows)} matter(s) proposed from {I.meta_of(ident)['source_name']}:\n")
    for i, r in enumerate(rows):
        print(f"  [{i}] {r['title']}" + (f"   (priority date {r['priority_date']})" if r["priority_date"] else ""))
        print(f"      {r['summary'][:300]}{'…' if len(r['summary']) > 300 else ''}")
        print(f"      from the document: “{r['quote'][:160]}{'…' if len(r['quote']) > 160 else ''}”\n")
    if dropped:
        print(f"  ({dropped} further proposal(s) discarded: the quote was not in the document)\n")
    print(f"  open one:  ir probant from-proposal {ident} 0 <client> <matter>")
    return 0


def cmd_from_proposal(ident: str, index: int, client: str, matter: str, date: str | None = None) -> int:
    from . import probant_intake as I
    made = I.create_matter(ident, client, matter, index, date)
    print(f"  opened {made} from proposal {index}; its disclosure is the proposal, with the passage it came from.")
    print(f"  open it:    ir probant open {made}")
    return 0


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
    # Everything a Probant command writes, and everything it starts (the search verifier, Pi), is created
    # owner-only: records hold search text and results, receipts and state hold the matter's history. A
    # common default umask (0002 or 0022) would leave them readable by every other account on this computer.
    os.umask(0o077)
    p = argparse.ArgumentParser(prog="ir probant", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new"); n.add_argument("client"); n.add_argument("matter"); n.add_argument("--priority-date", default=None)
    d = sub.add_parser("set-date"); d.add_argument("matter"); d.add_argument("date")
    o = sub.add_parser("open"); o.add_argument("matter")
    o.add_argument("--dev-unconfined", action="store_true",
                   help="developer override: open UNCONFINED (no sandbox, no trusted state). Never for a real matter.")
    o.add_argument("--web", action="store_true",
                   help="work in a local browser page instead of the terminal (same checks, same sandbox)")
    x = sub.add_parser("export"); x.add_argument("matter"); x.add_argument("-o", "--out", default=None)
    x.add_argument("--anchor", action="store_true", help="OpenTimestamps-anchor MANIFEST.json (publishes only a hash)")
    ve = sub.add_parser("verify-export"); ve.add_argument("bundle")
    rf = sub.add_parser("reference", help="operator: issue and sign the out-of-band reference that makes a record say InferRoute")
    rf.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("list")
    ik = sub.add_parser("intake", help="read a long document in a sealed session and propose matters from it")
    ik.add_argument("document")
    ik.add_argument("--web", action="store_true", help="read it in a local browser page instead of the terminal")
    pf = sub.add_parser("portfolio", help="read a folder of documents and cluster what it contains until it settles")
    pf.add_argument("folder")
    pf.add_argument("--max-docs", type=int, default=0, help="read only the first N documents (a trial run)")
    pf.add_argument("--budget", type=int, default=0, help="characters per reading job (default 60000)")
    pf.add_argument("--only", default="", help="only documents whose name contains this")
    pf.add_argument("--reader", default="", help="model for reading (its mistakes are checked: quotes, coverage, recall)")
    pf.add_argument("--thinker", default="", help="model for the synthesis (nothing can check its judgement)")
    pf.add_argument("--resume", default="", help="a portfolio id: read only the documents that produced nothing")
    pr2 = sub.add_parser("portfolio-report", help="the themes a portfolio run settled on")
    pr2.add_argument("id")
    pr = sub.add_parser("proposals", help="what a reading session proposed")
    pr.add_argument("id")
    fp = sub.add_parser("from-proposal", help="open a matter from one of a reading session's proposals")
    fp.add_argument("id"); fp.add_argument("index", type=int); fp.add_argument("client"); fp.add_argument("matter")
    fp.add_argument("--priority-date", default=None)
    dl = sub.add_parser("delete", help="delete a matter: restorable from Probant home for 30 days, then erased")
    dl.add_argument("matter"); dl.add_argument("--yes", action="store_true", help="do not ask to type the matter name")
    hm = sub.add_parser("home", help="the home page in your browser: every matter, past sessions, new matters and sessions, help")
    hm.add_argument("--no-browser", action="store_true", help="print the link instead of opening the browser")
    pf = sub.add_parser("proof", help="the technical detail behind the plain card: last session + a live search check")
    pf.add_argument("matter")
    a = p.parse_args(argv)
    try:
        if a.cmd == "new":
            return cmd_new(a.client, a.matter, a.priority_date)
        if a.cmd == "set-date":
            return cmd_set_date(a.matter, a.date)
        if a.cmd == "open":
            return cmd_open(a.matter, dev_unconfined=a.dev_unconfined, web=a.web)
        if a.cmd == "export":
            return cmd_export(a.matter, a.out, anchor=a.anchor)
        if a.cmd == "verify-export":
            return cmd_verify_export(a.bundle)
        if a.cmd == "reference":
            from . import reference as reference_mod
            return reference_mod.main(a.args)
        if a.cmd == "list":
            return cmd_list()
        if a.cmd == "intake":
            return cmd_intake(a.document, web=a.web)
        if a.cmd == "portfolio":
            return cmd_portfolio(a.folder, max_docs=a.max_docs, budget=a.budget, only=a.only,
                                 reader=a.reader, thinker=a.thinker, resume=a.resume)
        if a.cmd == "portfolio-report":
            return cmd_portfolio_report(a.id)
        if a.cmd == "proposals":
            return cmd_proposals(a.id)
        if a.cmd == "from-proposal":
            return cmd_from_proposal(a.id, a.index, a.client, a.matter, a.priority_date)
        if a.cmd == "delete":
            from . import probant_delete
            return probant_delete.cmd_delete(a.matter, yes=a.yes)
        if a.cmd == "proof":
            return cmd_proof(a.matter)
        if a.cmd == "home":
            from . import probant_home
            return probant_home.run(open_browser=not a.no_browser)
    except ProbantError as e:
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0


def cmd_portfolio(path: str, max_docs: int = 0, budget: int = 0, only: str = "",
                  reader: str = "", thinker: str = "", resume: str = "") -> int:
    """Slice 1: read a portfolio and record what it asserts, with a verbatim quote for every assertion.

    One sealed session per reading job, planned host-side. No clustering, no rounds: see
    docs/portfolio-analysis-proposal.md for why the loop was dropped.
    """
    import time
    from . import probant_portfolio as PF
    src = Path(path).expanduser()
    files = sorted(p for p in (src.rglob("*") if src.is_dir() else [src])
                   if p.is_file() and p.suffix.lower() in (".md", ".txt", ".json", ".text"))
    if only:
        wanted = [w.strip().lower() for w in only.split(",") if w.strip()]
        files = [p for p in files if any(w in p.name.lower() for w in wanted)]
    if max_docs:
        files = files[:max_docs]
    if resume:
        # A re-run is a delta: keep what was found, read only what produced nothing. The corpus a portfolio
        # staged is fixed at staging, so resuming judges recall against the same denominator as the original.
        meta = PF.meta_of(resume)
        d = PF.path_of(resume)
        jobs = PF.plan_unread(resume, budget or PF.JOB_CHARS)
        print(f"resuming {resume}: {len(PF.unread(resume))} document(s) still unread, {len(jobs)} job(s)")
        if not jobs:
            print("  every document has at least one finding; nothing to resume")
            return cmd_portfolio_report(resume)
    else:
        meta = PF.stage(files, src.name)
        d = PF.path_of(meta["id"])
        jobs = PF.plan(meta["id"], budget or PF.JOB_CHARS)
    dup = len(meta.get("duplicates") or []) if not resume else 0
    print(f"portfolio {meta['id']}: {len(meta['documents'])} distinct document(s), {meta['bytes'] / 1e6:.2f} MB, "
          f"{len(jobs)} reading job(s)"
          + (f"  ({dup} exact duplicate(s) of another file, read once)" if dup else ""))
    # What the run is about to spend, by where the material lives, so a folder of process logs is a visible
    # choice rather than a surprise on the bill.
    import collections
    by_top = collections.Counter()
    size_top = collections.Counter()
    for doc in meta["documents"]:
        top = Path(doc["from"]).relative_to(src).parts[0] if src.is_dir() else doc["name"]
        by_top[top] += 1
        size_top[top] += doc["bytes"]
    for top, n in by_top.most_common():
        print(f"      {top[:40]:40s} {n:4d} file(s)  {size_top[top] / 1000:7.0f} KB")
    started = time.time()
    register = src / "portfolio" / "corpus.json" if (src / "portfolio" / "corpus.json").is_file() else None
    if register:
        # Kept with the run: the answer key this run is judged against must be the one it was judged against,
        # not whatever the register says months later.
        # Through the one writer that unlocks before writing: this is the third artefact the host
        # regenerates and leaves 0400, and the second to crash a run on its own previous copy.
        PF._write_readonly(d / "register.json", Path(register).read_text(encoding="utf-8"))
    empty_jobs = []
    for i, job in enumerate(jobs, 1):
        span = job.get("bytes") or (job["end"] - job["start"])
        what = (f"{len(job['documents'])} document(s)" if job.get("whole")
                else f"{job['document']} {job['start']}-{job['end']}")
        PF.brief(meta["id"], register)          # what has been found so far, before this session reads
        t0 = time.time()
        before = len(PF.candidates(meta["id"]))
        text = PF.instruction_for(job)
        rc = _portfolio_round(d, text, out={"IR_INTAKE_OUT": str(d / PF.CANDIDATES)}, cwd=d, model=reader)
        after = len(PF.candidates(meta["id"]))
        got = after - before
        PF.record_job(meta["id"], job, first=before, last=after, seconds=time.time() - t0, exit_code=rc,
                      model=reader or "(lane default)", prompt=text)
        print(f"  [{i}/{len(jobs)}] {what} ({span / 1000:.0f} KB): {got} item(s) in {time.time() - t0:.0f}s"
              + (f" (exit {rc})" if rc else ""), flush=True)
        # A job that records nothing is a FAILURE until shown otherwise: the two ways this pipeline broke
        # (a denied write, a wrong path) both ended in a clean turn with nothing recorded, indistinguishable
        # from a document that says nothing. Never let it average into a total that looks fine.
        if got == 0:
            empty_jobs.append(what)
    if empty_jobs:
        print(f"\n  ⚠ {len(empty_jobs)} job(s) recorded NOTHING — treat as failed, not as empty documents:")
        for w in empty_jobs[:10]:
            print(f"      {w}")
    # The step that sees the WHOLE portfolio: not its 9.8 MB of text, which no context on this lane holds,
    # but every finding drawn from it, in one session.
    shape = PF.write_findings(meta["id"])
    if shape["n"]:
        print(f"\n  synthesis: {shape['n']} finding(s) from {shape['documents']} document(s), "
              f"~{shape['tokens_roughly'] / 1000:.0f}k tokens — one session, all of them", flush=True)
        t0 = time.time()
        _portfolio_round(d, PF.SYNTHESIS.format(n=shape["n"], docs=shape["documents"]),
                         out={"IR_CLUSTER_OUT": str(d / PF.THEMES)}, cwd=d, model=thinker)
        print(f"    done in {time.time() - t0:.0f}s")
    kept, drop = PF.candidates(meta["id"]), PF.dropped(meta["id"])
    print(f"\n  {len(kept)} item(s) kept, {drop} dropped (a quote not in the document it names), "
          f"{time.time() - started:.0f}s total")
    return cmd_portfolio_report(meta["id"])


def cmd_portfolio_report(ident: str) -> int:
    """Counts and coverage to the terminal; the analysis itself to a file.

    Deliberately: the findings and themes are the client's confidential material, and whoever runs this may
    be an agent whose transcript leaves this machine. The terminal gets arithmetic — how many, how covered,
    how thin — and the reading happens in the Probant page or the file, not in a console someone is piping.
    """
    from . import probant_portfolio as PF
    kept = PF.candidates(ident)
    drawn = PF.themes(ident)
    if drawn["themes"]:
        print(f"\n  {len(drawn['themes'])} theme(s) over {drawn['findings']} finding(s):")
        for t in drawn["themes"]:
            print(f"      {t['findings']:3d} finding(s) across {t['documents']:3d} document(s)  {t['label'][:70]}")
        if drawn["uncited"]:
            print(f"    {len(drawn['uncited'])} finding(s) were in no theme.")
        if drawn["unknown"]:
            print(f"    {len(drawn['unknown'])} citation(s) named findings that do not exist — dropped.")
    cov = PF.coverage(ident)
    print(f"\n  what each document actually evidenced (largest span no quote falls in):\n")
    for row in cov:
        bar = "·" * 0 if row["items"] else ""
        print(f"  {row['largest_unevidenced_share'] * 100:5.1f}% unevidenced  {row['items']:3d} item(s)  "
              f"{row['bytes'] / 1000:6.0f} KB  {row['document']}{bar}")
    thin = [r for r in cov if r["largest_unevidenced_share"] > 0.4]
    if thin:
        print(f"\n  {len(thin)} document(s) have a span over 40% of their length with nothing quoted from it: "
              f"read them again with a smaller budget, or treat their items as partial.")
    # The question that decides whether this run can be trusted or must be done again. Precision is checkable
    # by construction; recall is not — except against what we already know is in there.
    reg = PF.path_of(ident) / "register.json"
    if reg.is_file():
        # The verdict is for a run that read everything it staged; otherwise the register is the wrong
        # denominator and the number is informational.
        complete = not PF.unread(ident)
        r = PF.recall_against_register(ident, reg, complete=complete)
        verdict = ("ACCEPTED" if r["accepted"] else "NOT ACCEPTED — read it again") if complete else \
                  f"no verdict: {len(PF.unread(ident))} document(s) unread"
        print(f"\n  recall against the register: {r['found']}/{r['known']} known items surfaced "
              f"({r['recall'] * 100:.0f}%, floor {r['floor'] * 100:.0f}%) — {verdict}")
        for m in r["misses"][:8]:
            print(f"      missed {m['register']}")
        print(f"    {r['note']}")
    prov = PF.provenance(ident)
    print(f"\n  the run: {prov['jobs']} job(s), {prov['empty_jobs']} that found nothing, "
          f"{prov['seconds']}s, model(s) {', '.join(prov['models'])}")
    print(f"  {len(kept)} item(s): {PF.path_of(ident) / PF.CANDIDATES}")
    return 0


def _portfolio_round(portfolio_dir: Path, instruction: str, out: dict, cwd: Path, model: str = "") -> int:
    """One sealed session, one turn, no search tool, ending itself when its turn ends.

    It works in the PORTFOLIO directory, not in documents/: the sandbox lets a session write where it works,
    and the file its tool appends to lives here. Pointing the tool at a parent directory is a write the
    sandbox denies — which is how the first run produced nothing at all, with no error anywhere.
    """
    os.environ["IR_INTAKE_DIR"] = str(portfolio_dir)
    os.environ["IR_ATTESTED_CONFINE"] = "require"
    for k in ("IR_INTAKE_OUT", "IR_CLUSTER_OUT"):
        os.environ.pop(k, None)
    os.environ["IR_ROUND_LOG"] = str(portfolio_dir / "rounds.jsonl")
    os.environ.update(out)
    os.chdir(cwd)
    from . import confidential as confidential_mod
    # The model is per STEP, not per run: extraction's mistakes are caught by the host (a dropped quote, an
    # unevidenced span, a missed register row), so it can be a cheap model checked hard. Synthesis has no
    # such check — nothing can verify that a theme is the right theme — so it gets the best judgement
    # available. Quality is spent where failure would be invisible.
    args = ["--model", model] if model else []
    return confidential_mod.launch(args, agent="pi", probant={
        "matter": f"portfolio · {portfolio_dir.name}", "mode": "intake", "web": True,
        "oneshot": True, "instruction": instruction})
