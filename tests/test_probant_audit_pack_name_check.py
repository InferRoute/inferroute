"""The audit pack of a NAME CHECK (3 Nov, reproduced on 0.9.125).

The panel offers "Have your own AI audit it" on a trademark name check, and promises the names, the product
notes and the searches stay behind. write_audit_pack read `searches.json` unconditionally, which a name-check
record does not have, so the button failed with "[Errno 2] No such file or directory: '.../searches.json'".

A name check's pack carries what such a record can evidence — its AI-session receipts, the evidence they name
and the receipt re-checker — and nothing that could say what the product is or what it might be called. With
no receipt there is nothing for an auditor to check, and it refuses, saying what is missing.
"""
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_audit_results as R
from inferroute_cli import probant_export as E
from inferroute_cli import tm_search

_spec = importlib.util.spec_from_file_location(
    "check_report_under_test", Path(E.__file__).resolve().parent / "pi_attested" / "check_report.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

SID_A = "20261103T083327Z-3f3bf16d"
SID_B = "20261103T090000Z-77aa00bb"
# Everything a name check holds that the pack must not: the names, the product notes, the searches' marks,
# the report, and the matter's own name and client.
NAMES = ("Tidevell", "Lumora")
NOTES = "A reusable insulated bottle for trail runners"
REPORT = "Lumora: three US marks spell LUMORA exactly."
SECRETS = (*NAMES, "LUMORA", "TIDEVELL", NOTES, "trail runners", REPORT, "Acme", "bottle")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    return tmp_path


def _receipt_file(home: Path, sid: str, *, evidence: bool = True) -> Path:
    """A receipt as the AI lane leaves it on this device: its absolute path inside, and (optionally) one
    machine's evidence row content-addressed under evidence/."""
    d = home / "ir" / "confidential" / "receipts"
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    rp = d / f"{sid}.json"
    att = {"quote": "AAAA", "attested_body": "e30=", "checked_with": {"challenge": "c" * 64, "e2e_pubkey": "k" * 32}}
    raw = json.dumps(att, sort_keys=True).encode()
    sha = hashlib.sha256(raw).hexdigest()
    if evidence:
        (d / "evidence" / f"{sha}.json").write_bytes(raw)
    rp.write_text(json.dumps({
        "schema": "inferroute.confidential.receipt/1", "session_id": f"{sid}:glm-5.2", "verdict": "confidential",
        "written_by": "ir 0.9.125", "started_at": "2026-11-03T08:33:19Z", "attestation": att,
        "instance": {"mrtd": "ab" * 48}, "counters": {"requests": 2},
        "served_by": [{"at": "2026-11-03T08:33:27Z", "attestation_sha256": sha, "requests": 2}],
        "path": str(rp)}))
    return rp


def _record(home: Path, sids=(SID_A,), receipts=(SID_A,), searches: int = 2) -> Path:
    """A name-check record of the matter `name_matter` made, written by the real exporter: names, notes,
    trademark searches, a report, and a receipt for each session in `receipts`."""
    assert S.load_record("Acme", "bottle").get("kind") == "name"
    ws = S.workspace_path("Acme", "bottle")
    (ws / "disclosure.md").write_text(f"Names being considered:\n- {NAMES[0]}\n- {NAMES[1]}\n\n{NOTES}.\n")
    (ws / S.NAME_CHECK).write_text(f"# Name check\n\n{REPORT}\n")
    rdir = S.records_dir("Acme", "bottle")
    rdir.mkdir(parents=True, exist_ok=True)
    for sid in sids:
        lane = {"verified": True, "checks": "16/16", "model": "glm-5.2"}
        if sid in receipts:
            lane["receipt"] = str(_receipt_file(home, sid))
        (rdir / f"{sid}.json").write_text(json.dumps({
            "schema": "inferroute.attested-session/1", "session_id": sid, "written_by": "host", "mode": "names",
            "surface": "browser", "started_at": "2026-11-03T08:33:00Z", "ended_at": "2026-11-03T08:40:00Z",
            "model_lane": lane}))
    with (rdir / tm_search.SEARCH_LOG).open("a") as fh:
        for i in range(searches):
            n = NAMES[i % 2]
            fh.write(json.dumps({"at": "2026-11-03T08:3%d:00Z" % i, "session_id": sids[0], "name": n, "classes": ["21"],
                                 "hits": [{"text": n.upper(), "register": "USPTO", "number": str(i),
                                           "status": "registered"}], "more": 0}) + "\n")
    out = E.write_bundle("Acme", "bottle", str(home / "exports" / "record"))
    m = json.loads((out / "MANIFEST.json").read_text())
    assert m["kind"] == "name-check" and not (out / "searches.json").exists()
    return out


@pytest.fixture
def name_matter(home):
    from fastapi.testclient import TestClient
    from inferroute_cli import probant_home as H
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    r = c.post("/api/matters", json={"client": "Acme", "matter": "bottle", "kind": "name",
                                     "disclosure": f"Names being considered:\n- {NAMES[0]}\n- {NAMES[1]}\n\n{NOTES}.\n"})
    assert r.status_code == 200, r.text
    return home


def _capped(pack: Path) -> set:
    m = json.loads((pack / "MANIFEST.json").read_text())
    return {int(n) for n, cap in m["claim_ceilings"].items() if cap}


def _pack_bytes(pack: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(pack.rglob("*")) if p.is_file())


# ── the bug ────────────────────────────────────────────────────────────────────────────────────────────────

def test_a_name_check_record_makes_an_evidence_only_pack(name_matter):
    rec = _record(name_matter)
    # the record itself holds every secret the pack must not (otherwise the absence test below proves nothing)
    whole = b"".join(p.read_bytes() for p in rec.iterdir() if p.is_file())
    for s in (*NAMES, REPORT):
        assert s.encode() in whole, s

    pack = E.write_audit_pack(rec, name_matter / "pack")
    names = sorted(p.relative_to(pack).as_posix() for p in pack.rglob("*") if p.is_file())
    receipt = f"session-{SID_A}.receipt.json"
    att = [n for n in names if n.endswith(".attestation.json")]
    assert receipt in names and len(att) == 1, names
    assert set(names) == {"AUDIT.md", "MANIFEST.json", "SHA256SUMS", "REPORT-TEMPLATE.md", "record.html",
                          "verify_ai_receipt.py", "stationery/check_report.py", receipt, *att}, names
    # The re-checker is THIS installation's, and the evidence travels byte for byte.
    here = Path(E.__file__).resolve().parent / "pi_attested"
    assert (pack / "verify_ai_receipt.py").read_bytes() == (here / "verify_ai_receipt.py").read_bytes()
    assert (pack / att[0]).read_bytes() == (rec / att[0]).read_bytes()
    carried = json.loads((pack / receipt).read_text())
    assert carried["verdict"] == "confidential" and carried["withheld"] == ["path"] and "path" not in carried

    # WITHHELD: no name, no product note, no search, no report, no matter or client name — anywhere, in any file.
    blob = _pack_bytes(pack)
    for secret in SECRETS:
        assert secret.lower().encode() not in blob.lower(), secret
    for absent in ("trademark-searches.json", "searches.json", "verify_record.py", f"report-{S.NAME_CHECK}"):
        assert absent not in names, absent

    m = json.loads((pack / "MANIFEST.json").read_text())
    assert m["kind"] == "name-check" and m["schema"] == "inferroute.name-check-audit-pack/1"
    assert "client" not in m and "matter" not in m and "trademark_searches" not in m
    assert m["derived_from_manifest_sha256"] == hashlib.sha256((rec / "MANIFEST.json").read_bytes()).hexdigest()
    assert m["contents"]["session_receipts"] == 1
    assert [c["title"] for c in m["audit_claims"]] == [t for _, t in E.name_audit_claims()]
    assert m["claim_totals"] == {str(n): 1 for n, _ in E.name_audit_claims()}
    r = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=pack, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (pack / "AUDIT.md").read_text() == E.NAME_AUDIT_MD


def test_the_pack_is_chosen_by_what_the_record_says_it_is_not_by_its_files(name_matter, tmp_path):
    """A name-check record that somehow also holds a searches.json is still a name check, and its searches.json
    does not travel; a record that does not say it is a name check and has no searches.json is refused in words,
    not with a file-not-found."""
    rec = _record(name_matter)
    (rec / "searches.json").write_text(json.dumps([{"query_text": NOTES}]))
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    assert not (pack / "searches.json").exists() and NOTES.encode() not in _pack_bytes(pack)

    other = tmp_path / "unknown"
    other.mkdir()
    (other / "MANIFEST.json").write_text(json.dumps({"files": {}}))
    with pytest.raises(S.ProbantError, match="does not say it is a name check"):
        E.write_audit_pack(other, tmp_path / "pack-2")
    assert not (tmp_path / "pack-2").exists()


def test_several_receipts_all_travel_and_every_claim_counts_them(name_matter, tmp_path):
    rec = _record(name_matter, sids=(SID_A, SID_B), receipts=(SID_A, SID_B), searches=0)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    for sid in (SID_A, SID_B):
        assert (pack / f"session-{sid}.receipt.json").is_file()
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert set(m["claim_totals"].values()) == {2} and m["contents"]["session_receipts"] == 2
    assert {r["session"]: r["receipt"] for r in m["sessions"]} == {
        sid: f"session-{sid}.receipt.json" for sid in (SID_A, SID_B)}


# ── nothing to audit ───────────────────────────────────────────────────────────────────────────────────────

def test_a_name_check_with_no_receipt_is_refused_and_says_why(name_matter, tmp_path):
    rec = _record(name_matter, receipts=())
    with pytest.raises(S.ProbantError) as e:
        E.write_audit_pack(rec, tmp_path / "pack")
    msg = str(e.value)
    assert "no AI-session receipt" in msg and "nothing for an auditor to check" in msg
    assert "None of its 1 session(s) has a receipt" in msg and "session with the assistant" in msg
    assert "searches.json" not in msg and "Errno" not in msg
    assert not (tmp_path / "pack").exists(), "it must refuse BEFORE creating the folder"


def test_a_receipt_this_computer_could_not_read_is_named_as_that(name_matter, tmp_path):
    rec = _record(name_matter)
    m = json.loads((rec / "MANIFEST.json").read_text())
    (rec / f"session-{SID_A}.receipt.json").unlink()
    m["sessions"] = [{"session": SID_A, "receipt": "named but unreadable"}]
    (rec / "MANIFEST.json").write_text(json.dumps(m))
    with pytest.raises(S.ProbantError, match="could not read when it exported the record"):
        E.write_audit_pack(rec, tmp_path / "pack")
    m["sessions"] = []
    (rec / "MANIFEST.json").write_text(json.dumps(m))
    with pytest.raises(S.ProbantError, match="lists no session at all"):
        E.write_audit_pack(rec, tmp_path / "pack")


# ── the brief tells the truth about THIS kind of record ────────────────────────────────────────────────────

def test_the_name_check_brief_borrows_nothing_false_from_the_prior_art_brief():
    md = E.NAME_AUDIT_MD
    for wrong in ("prior-art search record", "patent", "disclosure", "invention", "AMD", "SEV-SNP",
                  "searches.json", "trust-anchors", "query text", "Chutes", "chutes"):
        assert wrong not in md, wrong
    # the searches are named for what they are: local, signed by nothing outside the computer
    assert "they\nran on the computer that made the record, and nothing outside it signed them" in md
    assert "the full record could not prove them either" in md
    assert "Do not try to recover any of them" in md
    # the claims the brief says cannot be VERIFIED are exactly the ones the pack caps
    capped = [n for n, cap in E.NAME_CLAIM_CEILINGS.items() if cap]
    assert capped == [1, 4] and "Claim 4 can never be VERIFIED" in md
    assert "claim 1 cannot when any machine's evidence here\nlacks Intel's collateral" in md
    assert E.NAME_CLAIM_CEILING_WHEN_COLLATERAL_MISSING == (1,)
    # claim 1 names its standard, and it is the verifier's
    import importlib.util as _u
    spec = _u.spec_from_file_location("_v", Path(E.__file__).resolve().parent / "pi_attested" / "verify_ai_receipt.py")
    v = _u.module_from_spec(spec)
    spec.loader.exec_module(v)
    assert v.ACCEPTED_TCB == ("UpToDate", "SWHardeningNeeded")
    assert "each `UpToDate` or `SWHardeningNeeded`" in md
    assert "`counters.continuity_switches`" in md and "`earlier_leg_receipts`" in md
    assert "switches_followed" not in md
    assert sorted(E.NAME_CLAIM_CEILINGS) == [n for n, _ in E.name_audit_claims()]


# ── what consumes the pack afterwards ──────────────────────────────────────────────────────────────────────

def _filled(pack: Path, verdict_for) -> str:
    m = json.loads((pack / "MANIFEST.json").read_text())
    text = (pack / "REPORT-TEMPLATE.md").read_text()
    text = text.replace("# Audit report — <pack folder name>", f"# Audit report — {pack.name}")
    text = text.replace("Auditor: <who you are> · Date: <date> · Verifier exit code: <code>",
                        "Auditor: a model · Date: 2026-11-03 · Verifier exit code: 4")
    for c in m["audit_claims"]:
        n, total = c["id"], C.claim_total(m, c["id"])
        v = verdict_for(n)
        neither = "none" if v == "VERIFIED" else "the online answers at the time"
        block = re.compile(rf"(## Claim {n} — .*?)\*\*Verdict:\*\* _\(.*?\)_\n\n\*\*Covered by:\*\* _\(.*?\)_\n\n"
                           r"\*\*What I computed myself:\*\* \n\n\*\*What I could not reach, and why:\*\* \n", re.S)
        assert block.search(text), n
        text = block.sub(lambda mo: f"{mo.group(1)}**Verdict:** {v}\n\n**Covered by:** tool: {total} of {total} receipts · "
                                    f"my own recomputation: 1 of {total} · neither: {neither}\n\n"
                                    "**What I computed myself:** Re-derived the key binding.\n\n"
                                    f"**What I could not reach, and why:** {'Nothing.' if v == 'VERIFIED' else neither}\n",
                         text, count=1)
    for heading, body in (("About this audit", "A model on a laptop."),
                          ("The verifier, and an independent copy of it", "Exit 4."),
                          ("One plain statement about confidentiality", "The claims differ in what could be reached."),
                          ("Exact statement established, and its limits", "The session was sealed.\n\nNot more.")):
        text = re.sub(rf"(## {re.escape(heading)}\n\n)<.*?>\n", lambda mo: mo.group(1) + body + "\n", text, count=1, flags=re.S)
    return text


def test_the_checker_and_the_client_accept_a_report_on_a_name_check_pack(name_matter, tmp_path):
    rec = _record(name_matter)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    tmpl = (pack / "REPORT-TEMPLATE.md").read_text()
    for n, title in E.name_audit_claims():
        assert f"## Claim {n} — {title}" in tmpl
    assert "verify_record.py" not in tmpl and "recipient-match" not in tmpl
    # The structured form inside the template is this pack's: its claims and their counts in receipts.
    form = json.loads(re.search(r"```json\n(.*?)\n```", tmpl, re.S)[1])
    assert form["pack"] == R.identity(pack)
    assert [(c["id"], c["coverage"]["total"]) for c in form["claims"]] == [(n, 1) for n, _ in E.name_audit_claims()]

    capped = _capped(pack)
    assert capped == {1, 4}          # the synthetic receipts keep no Intel collateral
    report = tmp_path / "REPORT.md"
    report.write_text(_filled(pack, lambda n: "VERIFIED IN PART" if n in capped else "VERIFIED"))
    problems, info = C.check_report(str(pack), str(report))
    assert problems == [], problems
    data = C.make_json(str(pack), str(report), "an auditor", "kimi-k2.6")
    assert C.check_result(str(pack), data) == [] and C.cross_check(info, data) == []
    accepted = R.validate(copy.deepcopy(data), pack, R.identity(pack))
    assert [c["verdict"] for c in accepted["claims"]] == ["VERIFIED IN PART", "VERIFIED", "VERIFIED", "VERIFIED IN PART"]
    # The ceilings bind in both places: VERIFIED on claim 1 is refused by the checker and by the client.
    report.write_text(_filled(pack, lambda n: "VERIFIED"))
    problems, _ = C.check_report(str(pack), str(report))
    assert any(w == "claim 1" and "cannot establish claim 1 fully" in what for w, what, _ in problems), problems
    over = C.make_json(str(pack), str(report), "an auditor", "kimi-k2.6")
    with pytest.raises(ValueError, match="claim 1 is VERIFIED, but this pack cannot establish it fully"):
        R.validate(over, pack, R.identity(pack))
    # And the result file is found beside the pack, the way the panel looks for it.
    (pack.parent / f"AUDIT-RESULT-{pack.name}.json").write_text(json.dumps(data))
    got = R.collect(pack, R.identity(pack))
    assert not got["rejected"] and got["results"][0]["auditor"]["model"] == "kimi-k2.6"


def test_the_checker_shipped_in_the_pack_runs_alone_on_it(name_matter, tmp_path):
    pack = E.write_audit_pack(_record(name_matter), tmp_path / "pack")
    report = tmp_path / "REPORT.md"
    capped = _capped(pack)
    report.write_text(_filled(pack, lambda n: "VERIFIED IN PART" if n in capped else "VERIFIED"))
    r = subprocess.run([sys.executable, "-I", str(pack / "stationery" / "check_report.py"), str(report)],
                       cwd=pack, capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("OK"), r.stdout + r.stderr


def test_the_receipt_rechecker_runs_from_inside_the_pack(name_matter, tmp_path):
    """The brief tells the auditor to run it in the folder. On a synthetic receipt it finds failures — the point is
    that it runs on what the pack holds, finds the receipt and its evidence, and does not crash."""
    pytest.importorskip("cryptography")
    pack = E.write_audit_pack(_record(name_matter), tmp_path / "pack")
    r = subprocess.run([sys.executable, "-I", "verify_ai_receipt.py", "."], cwd=pack, capture_output=True, text=True)
    assert r.returncode in (0, 1, 4), r.stdout + r.stderr
    assert f"session-{SID_A}.receipt.json" in r.stdout and "Traceback" not in r.stderr
    assert "attestation.json hashes to the sha256 the receipt names" in r.stdout


def test_a_saved_name_check_audit_is_restored_for_its_matter(name_matter, tmp_path):
    """The panel remembers the last pack per matter. Restoring it compared searches.json in the pack and the
    record, which neither has for a name check."""
    rec = _record(name_matter)
    exports = S.probant_root() / "Acme" / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    bundle = exports / "record"
    rec.rename(bundle)
    pack = E.write_audit_pack(bundle)
    assert pack.parent.parent == E.audit_packs_root()
    rdir = S.records_dir("Acme", "bottle")
    R.remember(rdir, pack, bundle)
    got = R.restore(rdir, "Acme/bottle")
    assert got == {"pack": str(pack), "pack_identity": R.identity(pack)}, got
    # a pack made from a DIFFERENT record of the matter is not attached to this one
    (bundle / "MANIFEST.json").write_text((bundle / "MANIFEST.json").read_text() + " ")
    assert "restore_error" in R.restore(rdir, "Acme/bottle")


def test_the_panel_prepares_a_name_check_pack_and_reads_its_results(name_matter, tmp_path, monkeypatch):
    """The whole button: /api/audit-pack writes the pack from the record this page exported, /api/audit-results
    reads the results beside it; and a record with nothing to audit comes back as the refusal, in words."""
    from fastapi.testclient import TestClient
    from inferroute_cli import probant_web as W
    rec = _record(name_matter)
    made = {"path": rec}
    b = W.Bridge(matter="Acme/bottle", date_bound="", workspace=S.workspace_path("Acme", "bottle"),
                 summary={"verdict": "private"}, search_endpoint=None, receipt=lambda: None,
                 rebuild_summary=lambda: {}, export=lambda: made["path"], mode="names")
    b.port = 43210
    monkeypatch.setattr(W, "can_open_terminal", lambda: False)
    c = TestClient(b.app(), base_url="http://127.0.0.1:43210")
    c.headers.update({"authorization": f"Bearer {b.token}"})
    r = c.post("/api/audit-pack", json={})
    assert r.status_code == 200, r.text
    pack = Path(r.json()["path"])
    assert pack.parent.parent == E.audit_packs_root() and (pack / f"session-{SID_A}.receipt.json").is_file()
    got = c.get("/api/audit-results").json()
    assert got["prepared"] and got["pack"] == R.identity(pack) and got["results"] == [] and got["rejected"] == []

    bare = _bare_name_record(tmp_path)
    made["path"] = bare
    b2 = W.Bridge(matter="Acme/bottle", date_bound="", workspace=S.workspace_path("Acme", "bottle"),
                  summary={"verdict": "private"}, search_endpoint=None, receipt=lambda: None,
                  rebuild_summary=lambda: {}, export=lambda: bare, mode="names")
    b2.port = 43210
    c2 = TestClient(b2.app(), base_url="http://127.0.0.1:43210")
    c2.headers.update({"authorization": f"Bearer {b2.token}"})
    r = c2.post("/api/audit-pack", json={})
    assert r.status_code == 500 and "no AI-session receipt" in r.json()["error"]
    assert "searches.json" not in r.json()["error"]


def _bare_name_record(tmp_path: Path) -> Path:
    """The shape of the real failing bundle with its receipt taken away: a name-check MANIFEST, an empty
    trademark-searches.json, a page and a session row whose receipt is 'none'."""
    d = tmp_path / "bare-name-record"
    d.mkdir()
    (d / "record.html").write_text("<html>Lumora</html>")
    (d / "trademark-searches.json").write_text("[]")
    (d / "MANIFEST.json").write_text(json.dumps({
        "schema": "inferroute.name-check-record/1", "kind": "name-check", "client": "Acme", "matter": "bottle",
        "sessions": [{"session": SID_A, "receipt": "none"}], "trademark_searches": 0, "files": {}}))
    return d


# ── review of 9eecef6: a conversation that moved machines ──────────────────────────────────────────────────

def _leg(d: Path, stamp: str, sid: str, *, start: str, last: str, prev: str = "", att_extra=None,
         carried_switches=()) -> Path:
    """One leg's receipt under the device's receipts folder, named the way receipt.py names them. A leg with `prev`
    was switched into at `start` (its own `switched` event) and carries the earlier legs' switches."""
    d.mkdir(parents=True, exist_ok=True)
    rows = [{"at": start, "attestation_sha256": "11" * 32, "requests": 1}]
    events = [{"ts": start, "kind": "pinned", "detail": "in — opened"}]
    if prev:
        rows = [{"at": start, "attestation_sha256": "22" * 32, "requests": 3, "from_previous_session": prev}] + rows
        events = ([{"ts": ts, "kind": "switched", "detail": "x", "from_previous_session": leg} for leg, ts in carried_switches]
                  + events + [{"ts": start, "kind": "switched", "detail": "y"}])
    p = d / f"{stamp}-{sid[:8]}-{hashlib.sha256(sid.encode()).hexdigest()[:6]}.json"
    p.write_text(json.dumps({"schema": "inferroute.confidential.receipt/1", "session_id": sid, "verdict": "confidential",
                             "model_short": sid.split(":")[-1], "checks": {"quote": {"ok": True, "label": f"quote of {sid[:4]}"}},
                             "started_at": start, "last_activity_at": last, "served_by": rows, "events": events,
                             "attestation": {"quote": "AAAA", **(att_extra or {})}, "path": str(p)}))
    return p


def test_the_exporter_follows_a_model_switch_to_the_receipt_the_conversation_ended_on(name_matter, tmp_path):
    d = name_matter / "ir" / "confidential" / "receipts"
    first = _leg(d, "2026-11-03T08-33-19Z", "aaaa1111-0000:glm-5.2", start="2026-11-03T08:33:19Z", last="2026-11-03T08:40:00Z")
    _leg(d, "2026-11-03T08-34-00Z", "bbbb2222-0000:kimi-k2.6", start="2026-11-03T08:34:00Z", last="2026-11-03T09:00:00Z",
         prev="aaaa1111-0000:glm-5.2")
    last = _leg(d, "2026-11-03T08-50-00Z", "cccc3333-0000:deepseek", start="2026-11-03T08:50:00Z",
                last="2026-11-03T09:10:00Z", prev="bbbb2222-0000:kimi-k2.6",
                carried_switches=[("bbbb2222-0000:kimi-k2.6", "2026-11-03T08:34:00Z")])
    # Another conversation's leg that names the same predecessor but lies outside the window is never read.
    _leg(d, "2026-11-09T10-00-00Z", "dddd4444-0000:x", start="2026-11-09T10:00:00Z", last="2026-11-09T10:00:00Z",
         prev="aaaa1111-0000:glm-5.2")
    assert E.last_leg(first) == (last, 2)
    assert E.last_leg(last) == (last, 0)

    # The name-check record names the FIRST leg (written at launch). The export carries EVERY leg, each as its own
    # receipt: the last under the session's usual name, the earlier ones as .leg-<k>, in order.
    rdir = S.records_dir("Acme", "bottle")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{SID_A}.json").write_text(json.dumps({"schema": "inferroute.attested-session/1", "session_id": SID_A,
                                                    "written_by": "host", "mode": "names",
                                                    "model_lane": {"receipt": str(first)}}))
    rec = E.write_bundle("Acme", "bottle", str(tmp_path / "rec"))
    sid_of = lambda n: json.loads((rec / n).read_text())["session_id"]          # noqa: E731
    assert sid_of(f"session-{SID_A}.receipt.json") == "cccc3333-0000:deepseek"
    assert sid_of(f"session-{SID_A}.leg-1.receipt.json") == "aaaa1111-0000:glm-5.2"
    assert sid_of(f"session-{SID_A}.leg-2.receipt.json") == "bbbb2222-0000:kimi-k2.6"
    assert not any("dddd" in sid_of(p.name) for p in rec.glob("session-*.receipt.json"))
    row = json.loads((rec / "MANIFEST.json").read_text())["sessions"][0]
    assert row["receipt"] == f"session-{SID_A}.receipt.json"
    assert row["earlier_leg_receipts"] == [f"session-{SID_A}.leg-1.receipt.json", f"session-{SID_A}.leg-2.receipt.json"]
    # The page describes the last leg's receipt and says there is one per leg, each checked on its own.
    html = (rec / "record.html").read_text()
    assert "model deepseek" in html and "moved between machines 2 times, so it ran in 3 legs" in html
    assert "each receipt is checked on its own" in html
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert m["contents"]["session_receipts"] == 3 and set(m["claim_totals"].values()) == {3}
    assert sorted(p.name for p in pack.glob("session-*.receipt.json")) == sorted(
        [f"session-{SID_A}.receipt.json", *row["earlier_leg_receipts"]])
    md = (pack / "AUDIT.md").read_text()
    assert "Each receipt is judged on its own leg." in md and "earlier_leg_receipts" in md
    assert "switches_followed" not in md and "window" not in md.split("## What no audit")[1]


def test_a_prior_art_record_ships_every_leg_even_when_its_record_names_the_last(home, tmp_path):
    """A record repointed at the last leg (the launcher does that on a switch) still ships the earlier legs: they are
    found backwards through the from_previous_session ids the last leg carries."""
    assert S.cmd_new("Acme", "cooling", "2026-01-15") == 0
    d = home / "ir" / "confidential" / "receipts"
    _leg(d, "2026-11-03T08-33-19Z", "aaaa1111-0000:glm-5.2", start="2026-11-03T08:33:19Z", last="2026-11-03T08:40:00Z")
    last = _leg(d, "2026-11-03T08-34-00Z", "bbbb2222-0000:kimi-k2.6", start="2026-11-03T08:34:00Z",
                last="2026-11-03T09:00:00Z", prev="aaaa1111-0000:glm-5.2")
    rdir = S.records_dir("Acme", "cooling")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "sess1.json").write_text(json.dumps({"session_id": "sess1", "surface": "browser",
                                                 "model_lane": {"verified": True, "receipt": str(last)}}))
    rec = E.write_bundle("Acme", "cooling", str(tmp_path / "out"))
    assert json.loads((rec / "session-sess1.receipt.json").read_text())["session_id"] == "bbbb2222-0000:kimi-k2.6"
    assert json.loads((rec / "session-sess1.leg-1.receipt.json").read_text())["session_id"] == "aaaa1111-0000:glm-5.2"
    assert json.loads((rec / "MANIFEST.json").read_text())["sessions"][0]["earlier_leg_receipts"] == [
        "session-sess1.leg-1.receipt.json"]
    html = (rec / "record.html").read_text()
    assert "quote of bbbb" in html and "quote of aaaa" not in html and "so it ran in 2 legs" in html


def test_the_launcher_points_a_name_record_at_the_receipt_a_switch_moved_to(tmp_path):
    from types import SimpleNamespace
    from inferroute_cli import pi_attested as P
    a = SimpleNamespace(path=str(tmp_path / "a.json"), checks={"x": {"ok": True}}, is_confidential=True,
                        model_short="glm-5.2", instance={"id": "in_a"})
    b = SimpleNamespace(path=str(tmp_path / "b.json"), checks={"x": {"ok": True}}, is_confidential=True,
                        model_short="kimi-k2.6", instance={"id": "in_b"})
    rec = P.begin_host_session_record(tmp_path / "records", SID_A, P.host_session_record(
        sess_id=SID_A, receipt=a, surface="browser", confinement="x", mode="names"))
    P.update_host_session_receipt(rec, b)
    lane = json.loads(rec.read_text())["model_lane"]
    assert lane["receipt"] == b.path and lane["model"] == "kimi-k2.6" and lane["earlier_receipts"] == [a.path]
    P.update_host_session_receipt(rec, b)                       # idempotent: no second copy of anything
    assert json.loads(rec.read_text())["model_lane"]["earlier_receipts"] == [a.path]
    src = (Path(P.__file__).resolve().parent / "confidential.py").read_text()
    assert 'if kind == "switched":\n                            pi_attested.update_host_session_receipt(' in src
    assert "pi_attested.update_host_session_receipt(host_record, session.receipt)\n                pi_attested.end_host_session_record(" in src


# ── review of 9eecef6: where the pack is written ───────────────────────────────────────────────────────────

def test_a_pack_is_written_alone_outside_the_matters_tree(name_matter):
    rec = _record(name_matter)
    pack = E.write_audit_pack(rec)
    root = E.audit_packs_root()
    assert root == name_matter / "ir" / "audit-packs" and pack.parent.parent == root
    assert not str(pack).startswith(str(S.probant_root()))
    for word in ("Acme", "bottle", "exports", *NAMES):
        assert word.lower() not in str(pack).lower(), word
    assert [p.name for p in pack.parent.iterdir()] == [pack.name]           # nothing else in the auditor's `..`
    assert all((p.stat().st_mode & 0o777) == 0o700 for p in (root, pack.parent, pack))
    # Two packs never share a folder, so one auditor's `..` never lists another's.
    other = E.write_audit_pack(rec)
    assert other.parent != pack.parent
    # The prior-art writer uses the same place.
    src = Path(E.__file__).read_text()
    assert src.count("dest = Path(out_dir) if out_dir else _default_pack_dest(stamp)") == 2
    # and the cloud-sync refusal still holds there
    import inferroute_cli.probant as P
    orig = P._under_sync_root
    try:
        P._under_sync_root = lambda p: "Dropbox"
        with pytest.raises(S.ProbantError, match="cloud-sync"):
            E.write_audit_pack(rec)
    finally:
        P._under_sync_root = orig


def test_deleting_the_matter_takes_its_audit_packs_and_restoring_brings_them_back(name_matter):
    from inferroute_cli import probant_delete as D
    rec = _record(name_matter)
    exports = S.probant_root() / "Acme" / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    bundle = exports / "bottle-name-check-record-20261103T083450Z"
    rec.rename(bundle)
    pack = E.write_audit_pack(bundle)
    (pack.parent / f"REPORT-{pack.name}.md").write_text("a report")
    holder = pack.parent
    assert holder in D._exports_of("Acme", "bottle")
    out = D.delete("Acme", "bottle")
    # the record went too: it used to stay behind, because delete read matter.json after moving it
    assert not holder.exists() and not bundle.exists()
    assert D.restore(out["id"]) == "Acme/bottle"
    assert (holder / f"REPORT-{pack.name}.md").read_text() == "a report"


# ── review of 9eecef6: claim 1's ceiling, the template's caution, the checker's words ─────────────────────

def test_claim_one_is_capped_only_when_a_machine_s_evidence_lacks_intel_collateral(name_matter, tmp_path):
    rec = _record(name_matter)
    assert _capped(E.write_audit_pack(rec, tmp_path / "p1")) == {1, 4}
    full = {"intel": {"tcb_info": "{}"}}
    for f in [*rec.glob("*.attestation.json"), *rec.glob("session-*.receipt.json")]:
        doc = json.loads(f.read_text())
        (doc.get("attestation") if f.name.startswith("session-") else doc)["collateral"] = full
        f.write_text(json.dumps(doc))
    pack = E.write_audit_pack(rec, tmp_path / "p2")
    assert _capped(pack) == {4}
    assert "for at least one machine here" not in (pack / "REPORT-TEMPLATE.md").read_text()


def test_the_name_template_cautions_the_confidentiality_statement(name_matter, tmp_path):
    t = (E.write_audit_pack(_record(name_matter), tmp_path / "p") / "REPORT-TEMPLATE.md").read_text()
    section = t.split("## One plain statement about confidentiality", 1)[1].split("## ", 1)[0]
    assert "Do not call\nthe conversation private or confidential" in section
    assert "is\nthe words of the client that wrote it, not evidence" in section


def test_the_checker_and_the_client_count_receipts_in_a_name_pack(name_matter, tmp_path):
    pack = E.write_audit_pack(_record(name_matter), tmp_path / "p")
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert C.unit_of(m) == "receipts" and C.unit_of({}) == "operations"
    report = tmp_path / "R.md"
    report.write_text(_filled(pack, lambda n: "VERIFIED IN PART").replace("tool: 1 of 1 receipts", "tool: 1 of 3 receipts", 1))
    problems, _ = C.check_report(str(pack), str(report))
    said = " | ".join(what for _, what, _ in problems)
    assert "says 3 receipts; this pack has 1" in said and "operations" not in said
    data = json.loads(re.search(r"```json\n(.*?)\n```", (pack / "REPORT-TEMPLATE.md").read_text(), re.S)[1])
    data.update(auditor={"name": "a", "model": "b"}, completed_at="2026-11-03T12:00:00Z", verified_statement="x",
                limitations=["y"])
    for c in data["claims"]:
        c.update(verdict="COULD NOT CHECK", evidence="e", limitations=["l"])
        c["coverage"].update(tool=0, independent=0, total=5)
    with pytest.raises(ValueError, match="this pack holds 1 receipts for this claim"):
        R.validate(data, pack, R.identity(pack))


# ── review of a14e349: legs numbered by their place, missing legs named, recurring ids ────────────────────────

def test_a_missing_middle_leg_keeps_the_others_numbered_by_their_place_and_is_named(name_matter, tmp_path):
    d = name_matter / "ir" / "confidential" / "receipts"
    _leg(d, "2026-11-03T08-33-19Z", "aaaa1111-0000:glm-5.2", start="2026-11-03T08:33:19Z", last="2026-11-03T08:40:00Z")
    mid = _leg(d, "2026-11-03T08-34-00Z", "bbbb2222-0000:kimi-k2.6", start="2026-11-03T08:34:00Z",
               last="2026-11-03T09:00:00Z", prev="aaaa1111-0000:glm-5.2")
    last = _leg(d, "2026-11-03T08-50-00Z", "cccc3333-0000:deepseek", start="2026-11-03T08:50:00Z",
                last="2026-11-03T09:10:00Z", prev="bbbb2222-0000:kimi-k2.6",
                carried_switches=[("bbbb2222-0000:kimi-k2.6", "2026-11-03T08:34:00Z")])
    doc = json.loads(last.read_text())                       # setdefault keeps leg 1's id on rows carried through leg 2
    doc["served_by"].insert(0, {"at": "2026-11-03T08:33:19Z", "attestation_sha256": "33" * 32, "requests": 1,
                                "from_previous_session": "aaaa1111-0000:glm-5.2"})
    last.write_text(json.dumps(doc))
    mid.unlink()
    rdir = S.records_dir("Acme", "bottle")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{SID_A}.json").write_text(json.dumps({"schema": "inferroute.attested-session/1", "session_id": SID_A,
                                                    "written_by": "host", "mode": "names",
                                                    "model_lane": {"receipt": str(last)}}))
    rec = E.write_bundle("Acme", "bottle", str(tmp_path / "rec"))
    row = json.loads((rec / "MANIFEST.json").read_text())["sessions"][0]
    assert row["earlier_leg_receipts"] == [f"session-{SID_A}.leg-1.receipt.json"]
    assert row["missing_leg_receipts"] == [{"leg": 2, "why": "no receipt of this leg was found on this computer"}]
    assert json.loads((rec / f"session-{SID_A}.leg-1.receipt.json").read_text())["session_id"] == "aaaa1111-0000:glm-5.2"
    assert "leg_evidence_missing" in row                      # the fixtures name evidence files that are not on disk


def test_a_session_id_that_recurs_in_a_later_launch_does_not_join_the_two_conversations(name_matter, tmp_path):
    d = name_matter / "ir" / "confidential" / "receipts"
    a1 = _leg(d, "2026-11-03T09-00-00Z", "SAME0000:m1", start="2026-11-03T09:00:00Z", last="2026-11-03T09:10:00Z")
    b1 = _leg(d, "2026-11-03T09-01-10Z", "SAME0000:m2", start="2026-11-03T09:10:00Z", last="2026-11-03T09:15:00Z",
              prev="SAME0000:m1")
    a2 = _leg(d, "2026-11-03T10-00-00Z", "SAME0000:m1", start="2026-11-03T10:00:00Z", last="2026-11-03T10:10:00Z")
    b2 = _leg(d, "2026-11-03T10-01-10Z", "SAME0000:m2", start="2026-11-03T10:10:00Z", last="2026-11-03T10:15:00Z",
              prev="SAME0000:m1")
    assert E.conversation_legs(b1) == [a1, b1] and E.conversation_legs(b2) == [a2, b2]
    assert E.last_leg(a1) == (b1, 1) and E.last_leg(a2) == (b2, 1)
    # a seed that belongs to the other launch is dropped
    assert E.conversation_legs(b1, seeds=[str(a2)]) == [a1, b1]


def test_the_exporter_numbers_two_switches_in_the_same_second_as_two_legs(name_matter, tmp_path):
    """Review of 24f5c42: legs were placed by their switch's TIME, so two switches in one second put two legs in one
    slot (the second was dropped) and the next leg was named missing. They are placed by time and detail, which names
    the move. Here leg 2 is promoted at 08:40:00, fails at once, and leg 3 is promoted in the same second."""
    d = name_matter / "ir" / "confidential" / "receipts"
    T = "2026-11-03T08:40:00Z"
    _leg(d, "2026-11-03T08-33-19Z", "aaaa1111-0000:m1", start="2026-11-03T08:33:19Z", last=T)
    legs = {"b": ("bbbb2222-0000:m2", "aaaa1111-0000:m1", "m1 -> m2 (timeout)", T, "2026-11-03T08-34-00Z"),
            "c": ("cccc3333-0000:m3", "bbbb2222-0000:m2", "m2 -> m3 (timeout)", T, "2026-11-03T08-35-00Z"),
            "e": ("eeee5555-0000:m4", "cccc3333-0000:m3", "m3 -> m4 (fleet)", "2026-11-03T08:50:00Z", "2026-11-03T08-36-00Z")}
    paths = {}
    for k, (sid, prev, detail, at, stamp) in legs.items():
        p = _leg(d, stamp, sid, start=at, last="2026-11-03T09:00:00Z", prev=prev)
        doc = json.loads(p.read_text())
        for e in doc["events"]:
            if e["kind"] == "switched" and not e.get("from_previous_session"):
                e["detail"] = detail
        doc["started_at"] = "2026-11-03T08:39:00Z"
        p.write_text(json.dumps(doc))
        paths[k] = p
    last = json.loads(paths["e"].read_text())          # the last leg carries every earlier switch, in order
    last["events"][:0] = [{"ts": T, "kind": "switched", "detail": "m1 -> m2 (timeout)", "from_previous_session": legs["b"][0]},
                          {"ts": T, "kind": "switched", "detail": "m2 -> m3 (timeout)", "from_previous_session": legs["c"][0]}]
    last["served_by"][:0] = [{"at": "2026-11-03T08:33:19Z", "attestation_sha256": "33" * 32, "requests": 1,
                              "from_previous_session": "aaaa1111-0000:m1"},
                             {"at": T, "attestation_sha256": "44" * 32, "requests": 0,
                              "from_previous_session": legs["b"][0]}]
    paths["e"].write_text(json.dumps(last))
    rdir = S.records_dir("Acme", "bottle")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{SID_A}.json").write_text(json.dumps({"schema": "inferroute.attested-session/1", "session_id": SID_A,
                                                    "written_by": "host", "mode": "names",
                                                    "model_lane": {"receipt": str(paths["e"])}}))
    rec = E.write_bundle("Acme", "bottle", str(tmp_path / "rec"))
    row = json.loads((rec / "MANIFEST.json").read_text())["sessions"][0]
    assert row["earlier_leg_receipts"] == [f"session-{SID_A}.leg-{k}.receipt.json" for k in (1, 2, 3)], row
    assert row["missing_leg_receipts"] == []
    sid_of = lambda n: json.loads((rec / n).read_text())["session_id"]          # noqa: E731
    assert [sid_of(f"session-{SID_A}.leg-{k}.receipt.json") for k in (1, 2, 3)] == [
        "aaaa1111-0000:m1", legs["b"][0], legs["c"][0]]
