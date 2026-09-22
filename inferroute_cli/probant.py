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
from typing import List, Optional
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


def cmd_new(client: str, matter: str, priority_date: str | None, from_corpus: str = "") -> int:
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
    if from_corpus:
        # Created BY the recipient while reading a delivery — tied to it, never one of its matters. The
        # distinction is the point: someone else's claims must not acquire your authorship, or yours theirs.
        from . import probant_share as SH
        SH.note_corpus_origin(client, matter, from_corpus, how="created here while reading this corpus")
        print(f"  tied to corpus {from_corpus} (created here, not part of it)")
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
    n.add_argument("--from-corpus", default="", help="tie this matter to a corpus you received, without making it part of it")
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
    idy = sub.add_parser("identity", help="your sharing fingerprint, contact card, and who you can share with")
    idy.add_argument("--add", default="", help="record a contact under this name")
    idy.add_argument("--card", dest="card_file", default="", help="their contact card file")
    sh = sub.add_parser("share", help="seal a corpus of claims to another Probant user")
    sh.add_argument("to")
    sh.add_argument("--matter", action="append", default=[], help="a matter to include (repeatable)")
    sh.add_argument("--portfolio", action="append", default=[], help="a portfolio run's claims (repeatable)")
    sh.add_argument("--all", dest="every", action="store_true", help="every matter on this installation")
    sh.add_argument("--no-copy", dest="keep_copy", action="store_false",
                    help="do not seal a copy to yourself (you then cannot reopen what you sent)")
    sh.add_argument("--file", action="append", default=[],
                    help="a document describing the whole corpus, sealed with it (repeatable)")
    sh.add_argument("--corpus-name", default="", help="what to call this delivery")
    sh.add_argument("--note", default=""); sh.add_argument("-o", "--out", default="")
    osh = sub.add_parser("open-share", help="open a share sealed to you: every matter in it, as your own")
    osh.add_argument("file"); osh.add_argument("client")
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
    pf.add_argument("--holes", action="store_true",
                    help="with --resume: read again the stretches no quote evidences, not whole documents")
    pf.add_argument("--workers", type=int, default=1, help="reading sessions to run at once")
    pf.add_argument("--slice", dest="slice_of", default="", help=argparse.SUPPRESS)
    pr2 = sub.add_parser("portfolio-report", help="the themes a portfolio run settled on")
    pr2.add_argument("id")
    pm = sub.add_parser("portfolio-matters", help="the matter list a portfolio run produced, as plain text")
    pm.add_argument("id")
    pm.add_argument("-o", "--out", default="", help="where to write it (default: MATTERS.txt in the run)")
    pm.add_argument("--guide", action="store_true",
                    help="the reading guide instead: where in each filing each invention's evidence sits")
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
            return cmd_new(a.client, a.matter, a.priority_date, a.from_corpus)
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
        if a.cmd == "identity":
            return cmd_identity(add=a.add, card_file=a.card_file)
        if a.cmd == "share":
            return cmd_share(a.to, out=a.out, matters=a.matter, portfolios=a.portfolio,
                             every=a.every, note=a.note, keep_copy=a.keep_copy, files=a.file, corpus_name=a.corpus_name)
        if a.cmd == "open-share":
            return cmd_open_share(a.file, a.client)
        if a.cmd == "intake":
            return cmd_intake(a.document, web=a.web)
        if a.cmd == "portfolio":
            return cmd_portfolio(a.folder, max_docs=a.max_docs, budget=a.budget, only=a.only,
                                 reader=a.reader, thinker=a.thinker, resume=a.resume,
                                 workers=a.workers, slice_of=a.slice_of, holes=a.holes)
        if a.cmd == "portfolio-report":
            return cmd_portfolio_report(a.id)
        if a.cmd == "portfolio-matters":
            return cmd_portfolio_matters(a.id, a.out, a.guide)
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
    except ImportError as e:
        # Probant's own dependencies live in the `confidential` extra, so a base install crashes on the
        # FIRST command a new user runs — `ir probant identity`, the one that makes the key card they have
        # to send before anyone can share anything with them. A traceback there is the worst possible first
        # impression of a product whose subject is careful handling. The package already keeps `click` core
        # for exactly this reason; this is the same treatment for the rest.
        missing = getattr(e, "name", "") or "a dependency"
        sys.stderr.write(
            f"\n  Probant needs {missing}, which is not installed.\n\n"
            "      pip install 'inferroute[confidential]'\n\n"
            "  That brings the sealed lane, the key handling and the local page. Nothing was changed.\n\n")
        return 2
    return 0


def cmd_identity(add: str = "", card_file: str = "") -> int:
    """This installation's identity, and the people it can share with."""
    from . import probant_share as SH
    if add:
        try:
            card = json.loads(Path(card_file).expanduser().read_text())
        except (OSError, ValueError) as e:
            raise ProbantError(f"could not read that contact card: {e}")
        got = SH.add_contact(add, card)
        print(f"  added {add} — fingerprint {got['fingerprint']}")
        print("  CONFIRM that fingerprint with them by voice before you share anything: a card that reached")
        print("  you by the same channel as an impostor's is worth what the channel is worth.")
        return 0
    me = SH.identity()
    print(f"\n  Your Probant fingerprint:  {me['fingerprint']}")
    print("  Read it to whoever shares with you, and check theirs the same way.\n")
    card = SH.public_card(me)
    out = Path.home() / f"probant-contact-{me['fingerprint']}.json"
    out.write_text(json.dumps(card, indent=1))
    print(f"  Your contact card (public keys only, safe to send): {out}")
    known = SH.contacts()
    if known:
        print("\n  You can share with:")
        for name, c in known.items():
            print(f"      {name:20s} {c['fingerprint']}   added {c.get('added_at', '')[:10]}")
    else:
        print("\n  No contacts yet. Add one:  ir probant identity --add <name> --card <their-card.json>")
    return 0


def cmd_share(to: str, out: str = "", matters: Optional[List[str]] = None, portfolios: Optional[List[str]] = None,
              every: bool = False, note: str = "", keep_copy: bool = True,
              files: Optional[List[str]] = None, corpus_name: str = "") -> int:
    """Seal a corpus of matters to another Probant user, signed so they know it is yours."""
    from . import probant_share as SH
    known = SH.contacts()
    if to not in known:
        raise ProbantError(f"no contact called {to!r}. Add them: ir probant identity --add {to} --card <file>")
    me = SH.identity()
    entries = []
    for spec in (matters or []):
        client, m = _split_matter(spec)
        entries.append(SH.matter_payload(client, m))
    for ident in (portfolios or []):
        entries.append(SH.portfolio_payload(ident))
    if every:
        seen = {e["matter"] for e in entries}
        for row in _every_matter():
            if row not in seen:
                client, m = _split_matter(row)
                entries.append(SH.matter_payload(client, m))
    if not entries:
        raise ProbantError("say what to share: --matter <client>/<matter> (repeatable), --portfolio <id>, or --all")
    # Side documents travel INSIDE the seal. A matter list and a reading guide quote every filing and the
    # unfiled surplus; as email attachments they would be the disclosure this product exists to prevent.
    extra = SH.corpus_files([Path(f).expanduser() for f in (files or [])])
    payload = SH.build_share(entries, note=note, files=extra, corpus_name=corpus_name)
    if extra:
        print(f"  including {len(extra)} corpus document(s): "
              f"{', '.join(f['name'] for f in extra)} ({sum(f['bytes'] for f in extra) // 1000} KB)")
    cards = [known[to]] + ([SH.public_card(me)] if keep_copy else [])
    blob = SH.seal_to(cards, payload, me)
    dest = Path(out).expanduser() if out else Path.home() / f"probant-corpus-for-{to}-{_stamp()}{SH.SUFFIX}"
    dest.write_bytes(blob)
    os.chmod(dest, 0o600)
    claims = sum(len(e.get("claims") or []) for e in entries)
    print(f"  {len(entries)} matter(s), {claims} claim(s) sealed to {to} ({known[to]['fingerprint']}), "
          f"signed as {me['fingerprint']}")
    for e in entries:
        print(f"      {e['matter']}" + (f"  date bound {e['date_bound']}" if e.get("date_bound") else ""))
    print(f"  {dest}")
    print("  Only that fingerprint can open it" + (" — and you, since a copy is sealed to you as well."
                                                   if keep_copy else "."))
    return 0


def _every_matter() -> List[str]:
    out = []
    root = matters_dir()
    for cdir in (sorted(root.iterdir()) if root.is_dir() else []):
        if cdir.is_dir():
            out += [f"{cdir.name}/{f.stem}" for f in sorted(cdir.glob("*.json"))
                    if not f.name.endswith(".state.json")]
    return out


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def S_safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "share"


def cmd_open_share(path: str, client: str) -> int:
    from . import probant_share as SH
    try:
        blob = Path(path).expanduser().read_bytes()
    except OSError as e:
        raise ProbantError(f"could not read that share: {e}")
    payload = SH.open_sealed(blob)
    who = payload.get("from_name") or "an UNKNOWN sender"
    entries = payload.get("matters") or []
    corpus = payload.get("corpus") or {}
    print(f"\n  Signed by {who} — fingerprint {payload.get('from_fingerprint')}")
    if not payload.get("from_known"):
        print("  This fingerprint is not in your contacts. The signature proves the matters are as that key")
        print("  wrote them; it does not say whose key it is. Confirm it by voice before relying on this.")
    print(f"  {len(entries)} matter(s):")
    for e in entries:
        print(f"      {e.get('matter')}  ·  {len(e.get('claims') or [])} claim(s)"
              f"{'  ·  date bound ' + e['date_bound'] if e.get('date_bound') else ''}")
    if corpus.get("files"):
        print(f"  {len(corpus['files'])} corpus document(s) describing the whole delivery:")
        for f in corpus["files"]:
            print(f"      {f.get('name')}  ({int(f.get('bytes') or 0) // 1000} KB)")
    made = SH.create_matters_from_share(payload, client)
    written = SH.write_corpus(payload, client)
    print(f"\n  opened {len(made)} matter(s) under {client}:")
    for m in made:
        print(f"      ir probant open {m}")
    if written.get("written"):
        print(f"\n  corpus documents written to {written['dir']}:")
        for n in written["written"]:
            print(f"      {n}")
        print(f"\n  This delivery is corpus {written['id']}. A matter you create yourself while reading it")
        print(f"  can be tied to it without becoming part of it:")
        print(f"      ir probant new <client> <matter> --from-corpus {written['id']}")
    return 0


def cmd_portfolio(path: str, max_docs: int = 0, budget: int = 0, only: str = "", reader: str = "",
                  thinker: str = "", resume: str = "", workers: int = 1, slice_of: str = "",
                  holes: bool = False) -> int:
    """Slice 1: read a portfolio and record what it asserts, with a verbatim quote for every assertion.

    One sealed session per reading job, planned host-side. No clustering, no rounds: see
    docs/portfolio-analysis-proposal.md for why the loop was dropped.
    """
    import time
    from . import probant_portfolio as PF
    # Before anything is staged or any session is launched: a host already near the wall cannot run this,
    # and on a machine without ECC an out-of-memory kill is a reset rather than a failed job. A worker
    # checks too — it is the one that actually launches sessions.
    PF.refuse_if_memory_is_short(workers)
    src = Path(path).expanduser()
    files = sorted(p for p in (src.rglob("*") if src.is_dir() else [src])
                   if p.is_file() and p.suffix.lower() in PF.READABLE)
    # The register is the ANSWER KEY, never one of the documents. A bundle keeps its index beside its
    # filings, and staging it would make the recall gate circular: a session that reads corpus.json can
    # report its entries as findings and score full recall having learnt nothing from the filings.
    files = [p for p in files if p.name != "corpus.json"]
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
        jobs = (PF.plan_holes(resume, budget or PF.JOB_CHARS) if holes
                else PF.plan_unread(resume, budget or PF.JOB_CHARS))
        if holes:
            print(f"resuming {resume}: re-reading {len(jobs)} unevidenced stretch(es) of documents already read")
        never, gave_nothing = PF.unread(resume), PF.barren(resume)
        print(f"resuming {resume}: {len(never)} document(s) never read, "
              f"{sum(1 for r in gave_nothing if not r['give_up'])} read but empty and worth another go, "
              f"{len(jobs)} job(s)")
        if not jobs:
            print("  nothing left to read: every document has been read, and those that gave nothing back "
                  f"have had their {PF.MAX_ATTEMPTS} attempts")
            # …but "nothing to READ" is not "nothing to DO". If the synthesis has never run, this is exactly
            # the moment it should: returning the report here left a fully-read corpus with no matter list
            # and no way to ask for one (21 Sep).
            if (d / PF.THEMES).exists():
                return cmd_portfolio_report(resume)
            print("  the synthesis has not run over these findings yet — doing that now", flush=True)
    else:
        # What was staged, recorded with the run: the register's verdict is only meaningful over a corpus
        # that could contain the register's material. A 15-document subset of prior art and specs cannot
        # surface P2-P4, which live in the filings folder it never staged — and the gate said 20% as if it
        # could (20 Sep).
        picked = ", ".join(x for x in ([f"first {max_docs}"] if max_docs else []) + ([f"only {only}"] if only else []))
        meta = PF.stage(files, src.name, selection=picked or "whole corpus")
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
    # Several sessions at once, each taking every Nth job and appending to its OWN findings file. One file
    # shared by parallel sessions is a write race, and a lost line is a finding nobody knows was found.
    # Sequential, the corpus measures 24 s/KB on the reader that actually reads it — 55 hours for 8.3 MB.
    if workers > 1 and not slice_of:
        return _portfolio_workers(meta["id"], src, workers, reader, thinker, budget, len(jobs), holes)
    if slice_of:
        i, n = (int(x) for x in slice_of.split("/"))
        jobs = jobs[i::n]
        print(f"  worker {i + 1}/{n}: {len(jobs)} job(s)", flush=True)
    out_file = d / (f"candidates-{slice_of.replace('/', '-')}.jsonl" if slice_of else PF.CANDIDATES)
    register = next((c for c in (src / "portfolio" / "corpus.json", src / "corpus.json") if c.is_file()), None)
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
        rc = _portfolio_round(d, text, out={"IR_INTAKE_OUT": str(out_file)}, cwd=d, model=reader,
                              label=what)
        after = len(PF.candidates(meta["id"]))
        got = after - before
        # A round that made no tool call never got a usable answer — 62 of 76 empty rounds in the first
        # full pass were exactly that, two silent turns and no text. Retry once before believing it.
        # The cap resets: wait it out rather than stopping the run or hammering it. Doubling waits, and a
        # ceiling far past any window we have seen, so a genuinely dead account still ends the run.
        waited = 0.0
        for wait in (120, 300, 600, 900, 1800):
            if not PF.last_round_blocked(meta["id"]):
                break
            print(f"      the model account is refusing (usage cap); waiting {wait // 60} min", flush=True)
            time.sleep(wait)
            waited += wait
            rc = _portfolio_round(d, text, out={"IR_INTAKE_OUT": str(out_file)}, cwd=d, model=reader,
                              label=what)
            after = len(PF.candidates(meta["id"]))
            got = after - before
        if PF.last_round_blocked(meta["id"]):
            print(f"\n  STOPPED: the account refused every attempt over {waited / 60:.0f} minutes.\n"
                  f"  {len(PF.candidates(meta['id']))} finding(s) are kept; resume with\n"
                  f"    ir probant portfolio <folder> --resume {meta['id']}", flush=True)
            return 3
        if got == 0 and not PF.last_round_worked(meta["id"]):
            time.sleep(20)
            rc = _portfolio_round(d, text, out={"IR_INTAKE_OUT": str(out_file)}, cwd=d, model=reader,
                              label=what)
            after = len(PF.candidates(meta["id"]))
            got = after - before
        PF.record_job(meta["id"], job, first=before, last=after, seconds=time.time() - t0, exit_code=rc,
                      model=reader or "(lane default)", prompt=text,
                      # Whether the session got a usable answer at all, so that a zero from a failed call is
                      # not filed as "this document holds nothing".
                      worked=PF.last_round_worked(meta["id"]),
                      # A killed round is not a reading of the document: see attempts().
                      aborted=PF.last_round_aborted(meta["id"]))
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
    if slice_of:                      # a worker stops here; the parent synthesises over everyone's findings
        print(f"  worker {slice_of} done", flush=True)
        return 0
    # The step that sees the WHOLE portfolio: not its 9.8 MB of text, which no context on this lane holds,
    # but every finding drawn from it, in one session.
    shape = PF.write_findings(meta["id"])
    if shape["n"]:
        print(f"\n  synthesis: {shape['n']} finding(s) from {shape['documents']} document(s), "
              f"~{shape['tokens_roughly'] / 1000:.0f}k tokens — one session, all of them", flush=True)
        t0 = time.time()
        # With a register, the synthesis produces the MATTER LIST — the inventions, mapped onto the filings
        # and candidates the portfolio already indexes, which gives the host a denominator to check it
        # against. Without one there is nothing to map to, so it draws themes as before.
        reg = d / "register.json"
        if reg.is_file():
            known = PF.matter_list(meta["id"])["register"]
            instruction = PF.MATTERS.format(
                n=shape["n"], docs=shape["documents"],
                filed=sum(1 for k in known if k["kind"] == "filed"),
                surplus=sum(1 for k in known if k["kind"] == "surplus"))
        else:
            instruction = PF.SYNTHESIS.format(n=shape["n"], docs=shape["documents"])
        _portfolio_round(d, instruction, label="synthesis",
                         out={"IR_CLUSTER_OUT": str(d / PF.THEMES)}, cwd=d, model=thinker)
        print(f"    done in {time.time() - t0:.0f}s")
    kept, drop = PF.candidates(meta["id"]), PF.dropped(meta["id"])
    print(f"\n  {len(kept)} item(s) kept, {drop} dropped (a quote not in the document it names), "
          f"{time.time() - started:.0f}s total")
    return cmd_portfolio_report(meta["id"])


def cmd_portfolio_matters(ident: str, out: str = "", guide: bool = False) -> int:
    """The matter list as plain text, to a file by default.

    To a FILE, not a console: this is the client's material and whoever runs this may be an agent whose
    transcript leaves the machine — the same rule the rest of this pipeline keeps.
    """
    from . import probant_portfolio as PF
    text = PF.render_highlights(ident) if guide else PF.render_matters(ident)
    dest = (Path(out).expanduser() if out else
            PF.path_of(ident) / ("READING-GUIDE.txt" if guide else "MATTERS.txt"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        os.chmod(dest, 0o600)
    dest.write_text(text, encoding="utf-8")
    os.chmod(dest, 0o600)
    m = PF.matter_list(ident)
    print(f"{len(m['matters'])} matter(s), {m['covered']}/{m['known']} register entries accounted for, "
          f"{len(m['uncited'])} of {m['findings']} findings in no matter")
    if m["missing"]:
        print(f"  NOT covered: {', '.join(k['id'] for k in m['missing'])}")
    print(f"  written to {dest}")
    return 0


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
    # Three states, kept apart. A document never handed to a session and a document read twice that gave
    # nothing back both show "100% unevidenced, 0 items", and reading them as the same thing is how this
    # report said 327 documents were barely evidenced when most of them had simply not been reached yet.
    waiting, empty = PF.unread(ident), PF.barren(ident)
    skip = {r["document"] for r in empty} | set(waiting)
    cov = [r for r in PF.coverage(ident) if r["document"] not in skip]
    print(f"\n  what each document actually evidenced (largest span no quote falls in):\n")
    for row in cov:
        print(f"  {row['largest_unevidenced_share'] * 100:5.1f}% unevidenced  {row['items']:3d} item(s)  "
              f"{row['bytes'] / 1000:6.0f} KB  {row['document']}")
    thin = [r for r in cov if r["largest_unevidenced_share"] > 0.4]
    if thin:
        print(f"\n  {len(thin)} document(s) have a span over 40% of their length with nothing quoted from it: "
              f"read them again with a smaller budget, or treat their items as partial.")
    if waiting:
        print(f"\n  {len(waiting)} document(s) have not been read at all yet — resume to reach them.")
    if empty:
        done = [r for r in empty if r["give_up"]]
        big = [r for r in empty if r["bytes"] > 8000]
        print(f"\n  {len(empty)} document(s) were read and gave nothing back. Whether that is right, this "
              f"cannot tell: an empty result is a document with no technical assertion in it OR a call that "
              f"failed. Size and attempts are what a reader has to go on.")
        for r in big[:12]:
            print(f"      {r['bytes'] / 1000:6.0f} KB  {r['attempts']} attempt(s)  {r['document']}")
        if len(big) > 12:
            print(f"      … and {len(big) - 12} more over 8 KB")
        print(f"    {len(empty) - len(big)} of them are under 8 KB (receipts, checksums, stubs — emptiness "
              f"is unremarkable there); {len(big)} are larger, and those are worth a look.")
        if done:
            print(f"    {len(done)} reached {PF.MAX_ATTEMPTS} attempts and will not be read again by a resume.")
    # The question that decides whether this run can be trusted or must be done again. Precision is checkable
    # by construction; recall is not — except against what we already know is in there.
    reg = PF.path_of(ident) / "register.json"
    if reg.is_file():
        # The verdict is for a run with nothing left to do over the whole corpus; otherwise the register is
        # the wrong denominator and the number is informational. "Nothing left to do" is what a resume would
        # still plan — not "every document produced a finding", which a corpus holding one checksums file can
        # never reach, and which kept this verdict permanently withheld.
        owed = PF.plan_unread(ident)
        complete = not owed and PF.meta_of(ident).get("selection", "whole corpus") == "whole corpus"
        r = PF.recall_against_register(ident, reg, complete=complete)
        verdict = ("ACCEPTED" if r["accepted"] else "NOT ACCEPTED — read it again") if complete else (
            f"no verdict: {len(owed)} job(s) still owed" if owed else
            f"no verdict: this run staged {PF.meta_of(ident).get('selection')}, not the whole corpus")
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


def _portfolio_workers(ident: str, src: Path, workers: int, reader: str, thinker: str, budget: int,
                       total_jobs: int, holes: bool = False) -> int:
    """Run the reading jobs in N sessions at once, then synthesise once over what they all found."""
    import subprocess
    import time
    n = max(1, min(workers, total_jobs))
    print(f"  {n} worker(s) over {total_jobs} job(s)", flush=True)
    started = time.time()
    procs = []
    for i in range(n):
        argv = [sys.executable, "-m", "inferroute_cli", "probant", "portfolio", str(src), "--resume", ident,
                "--slice", f"{i}/{n}", "--reader", reader or "", "--thinker", thinker or ""]
        argv += ["--budget", str(budget)] if budget else []
        # WITHOUT this the worker plans with the ordinary planner, finds nothing and exits in a second,
        # while the parent reports "25 jobs" — each side correct, the seam wrong (21 Sep).
        argv += ["--holes"] if holes else []
        procs.append(subprocess.Popen([a for a in argv if a != ""], env=dict(os.environ, IR_PROBANT_NO_BROWSER="1"),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
    for p in procs:
        p.wait()
    from . import probant_portfolio as PF
    print(f"  workers finished in {time.time() - started:.0f}s; {len(PF.candidates(ident))} finding(s) kept, "
          f"{len(PF.unread(ident))} document(s) never read", flush=True)
    # Back through the front door to synthesise over everyone's findings. NOT with holes: the workers have
    # just done that pass, and re-planning the stretches they narrowed would read for ever in one process.
    return cmd_portfolio(str(src), resume=ident, reader=reader, thinker=thinker, budget=budget)


def _portfolio_round(portfolio_dir: Path, instruction: str, out: dict, cwd: Path, model: str = "",
                     label: str = "") -> int:
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
    os.environ["IR_ROUND_LABEL"] = label        # which job the round log is about
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
