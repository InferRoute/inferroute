"""A session that did not run says so; a name check's session counts, keeps and shows what it did.

From the 0.9.124 end-to-end test (23 Oct): the assistant program exited 127 as three sessions began, and each
looked healthy everywhere — "A session is open… Running since", then "Session closed. Nothing was asked", then
"✓ checked · 0 searches" in the list. A name check that ran eight trademark searches was listed as
"0 searches · 0 documents", and reopening it said its conversation is not kept.
"""
import asyncio
import collections
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_home as H
from inferroute_cli import probant_web as W
from inferroute_cli import tm_search

STATIC = Path(H.__file__).resolve().parent / "probant_web"
NAME_SID = "20261023T160900Z-0a1b2c3d"
OTHER_SID = "20261023T170000Z-ffffffff"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    from fastapi.testclient import TestClient
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    return h, c, tmp_path


def _host_record(rdir: Path, sid: str, **ending) -> None:
    rdir.mkdir(parents=True, exist_ok=True)
    rec = {"schema": "inferroute.attested-session/1", "session_id": sid, "written_by": "host", "mode": "names",
           "surface": "browser", "started_at": f"{sid[:4]}-{sid[4:6]}-{sid[6:8]}T{sid[9:11]}:{sid[11:13]}:{sid[13:15]}Z",
           "confinement": "require, address-level (empty network namespace)",
           "model_lane": {"verified": True, "checks": "16/16", "model": "kimi-k2.6"}}
    rec.update(ending)
    (rdir / f"{sid}.json").write_text(json.dumps(rec))


# ── 1. a session whose assistant crashed as it started ──

def test_an_assistant_that_stops_by_itself_is_a_failure_and_one_that_was_ended_is_not():
    f = W.agent_failure(127, turns=0, asked_to_stop=False)
    assert f and f["exit_code"] == 127 and "nothing was asked" in f["message"] and "not found" in f["message"]
    assert W.agent_failure(0, turns=0, asked_to_stop=False)                       # closed by itself, never answered
    assert W.agent_failure(1, turns=3, asked_to_stop=False)                       # crashed mid-session
    assert W.agent_failure(0, turns=2, asked_to_stop=False) is None               # worked, then ended cleanly
    assert W.agent_failure(-15, turns=0, asked_to_stop=True) is None              # the person ended it
    assert W.agent_failure(None, turns=0, asked_to_stop=False) is None            # still running


def _bridge(**kw):
    return W.Bridge(matter="Acme/names", date_bound="", workspace=Path("/nonexistent"), summary={},
                    search_endpoint=None, receipt=lambda: SimpleNamespace(counters={"requests": 0}),
                    rebuild_summary=lambda: {}, export=lambda: Path("."), **kw)


class _Stdout:
    async def read(self, n):
        return b""


def test_the_session_page_is_told_the_session_failed_not_that_nothing_was_asked():
    b = _bridge()
    proc = SimpleNamespace(stdout=_Stdout(), stdin=None, returncode=None)

    async def wait():
        proc.returncode = 127
        return 127
    proc.wait = wait

    async def run():
        return await b.pump(proc)
    assert asyncio.run(run()) == 127
    ended = [e for e in b.history if e["kind"] == "ended"][-1]["summary"]
    assert ended["failed"]["exit_code"] == 127 and ended["failed"]["turns"] == 0
    js = (STATIC / "app.js").read_text()
    assert "summary.failed" in js and "The session didn't run." in js


def test_the_home_page_reports_a_failed_start_after_the_link_printed():
    url = "http://127.0.0.1:41234/#k=" + "k" * 30
    lines = ["opening Acme/names — name check, searched on this computer\n",
             f"Open this session in your browser:  {url}\n",
             "Error: EACCES: permission denied, mkdir '/home/someone/.inferroute/pi-attested'\n",
             "    at mkdirSync (node:fs:1370:26)\n",
             f"{W.AGENT_STOPPED_MARK} (exit code 1, 0 answers)\n",
             "🔒 Confidential session closed  ·  0 requests\n",
             f"{W.ENDED_MARK} Press Enter here to close it\n"]
    L = H.Launches()
    it = {"id": "x", "matter": "Acme/names", "started": 0, "state": "starting", "url": None, "message": "",
          "tail": collections.deque(maxlen=60), "proc": SimpleNamespace(stdout=iter(lines), wait=lambda: 0, poll=lambda: None)}
    L.items["x"] = it
    L._follow(it)
    assert it["state"] == "failed"
    assert "nothing was asked" in it["message"] and "permission denied" in it["message"]
    assert "Error: EACCES" in it["detail"] and "/home/someone" not in it["detail"]
    assert L.running_for("Acme/names") is None                 # never "A session is open… Running since"


def test_the_list_never_says_checked_for_a_session_that_did_not_run(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "names", "kind": "name"})
    rdir = S.records_dir("Acme", "names")
    _host_record(rdir, NAME_SID, ended_at="2026-10-23T16:09:05Z", exit_code=127, turns=0, ended_by="itself")
    _host_record(rdir, OTHER_SID, ended_at="2026-10-23T17:10:00Z", exit_code=0, turns=3, ended_by="person")
    rows = {r["id"]: r for r in c.get("/api/matter", params={"id": "Acme/names"}).json()["sessions"]}
    assert rows[NAME_SID]["failed"] and rows[NAME_SID]["checked"] is False and "code 127" in rows[NAME_SID]["failure"]
    assert not rows[OTHER_SID]["failed"] and rows[OTHER_SID]["checked"] is True
    detail = c.get("/api/session", params={"id": "Acme/names", "sid": NAME_SID}).json()
    assert detail["failed"] and detail["checked"] is False
    js = (STATIC / "home.js").read_text()
    assert "s.failed ? el(\"span\", \"bad-text\"" in js and "This session didn't run." in js


@pytest.mark.parametrize("code,failed", [(127, True), (1, True), (0, False), (-15, False), (143, False)])
def test_a_record_from_before_it_said_who_ended_it_reads_its_exit_code(code, failed):
    rec = {"exit_code": code}
    assert bool(H.session_failure(rec)) is failed
    assert H.session_failure({}) == ""                         # no ending yet: still running, or a search-verifier record


# ── 4. a name check's searches are counted as trademark searches ──

def _log(rdir: Path, *entries):
    with (rdir / tm_search.SEARCH_LOG).open("a") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def test_a_name_session_counts_its_own_trademark_searches_and_names(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "names", "kind": "name"})
    rdir = S.records_dir("Acme", "names")
    _host_record(rdir, NAME_SID, ended_at="2026-10-23T16:30:00Z", exit_code=0, turns=2, ended_by="person")
    _host_record(rdir, OTHER_SID, ended_at="2026-10-23T17:30:00Z", exit_code=0, turns=1, ended_by="person")
    hit = {"text": "LUMORA", "register": "USPTO", "number": "1"}
    _log(rdir,
         # written before searches carried a session id: placed by the session's start and end
         {"at": "2026-10-23T16:10:00Z", "name": "Lumora", "classes": ["21"], "hits": [hit], "more": 3},
         *({"at": "2026-10-23T16:1%d:00Z" % i, "session_id": NAME_SID, "name": n, "classes": ["11"], "hits": [], "more": 0}
           for i, n in enumerate(["Lumora", "Tidevell", "Tidevell", "Lumora", "Tide vell", "Lumora"], 1)),
         # since grouping: one hit and five more are six names, with 53 filings under them
         {"at": "2026-10-23T16:17:00Z", "session_id": NAME_SID, "name": "Tidevell", "classes": ["11"], "hits": [hit],
          "more": 5, "filings": 53},
         {"at": "2026-10-23T17:05:00Z", "session_id": OTHER_SID, "name": "Aquelia", "classes": [], "hits": [], "more": 0})
    rows = {r["id"]: r for r in c.get("/api/matter", params={"id": "Acme/names"}).json()["sessions"]}
    assert rows[NAME_SID]["kind"] == "names" and rows[NAME_SID]["tm_searches"] == 8 and rows[NAME_SID]["names"] == 3
    assert rows[OTHER_SID]["tm_searches"] == 1 and rows[OTHER_SID]["names"] == 1
    detail = c.get("/api/session", params={"id": "Acme/names", "sid": NAME_SID}).json()
    tm = detail["trademark_searches"]
    assert len(tm) == 8 and tm[0]["name"] == "Lumora" and tm[0]["marks"] == 4 and tm[0]["n"] == 1
    # a search logged before grouping counted filings as marks and has no "filings"; a grouped one counts both
    assert "filings" not in tm[0] and tm[7]["marks"] == 6 and tm[7]["filings"] == 53
    js = (STATIC / "home.js").read_text()
    assert '"trademark search", "trademark searches"' in js and "No trademark search ran in this session." in js


def test_a_trademark_search_is_logged_with_the_session_that_ran_it(tmp_path):
    tm_search.log_search(tmp_path, {"name": "Kwench", "classes": [], "hits": []}, "20261023T160900Z-0a1b2c3d")
    tm_search.log_search(tmp_path, {"name": "Other", "classes": [], "hits": []})
    rows = [json.loads(x) for x in (tmp_path / tm_search.SEARCH_LOG).read_text().splitlines()]
    assert rows[0]["session_id"] == "20261023T160900Z-0a1b2c3d" and "session_id" not in rows[1]
    got = tm_search.session_searches(tmp_path, "20261023T160900Z-0a1b2c3d")
    assert [r["name"] for r in got] == ["Kwench"]


# ── 5. a name check keeps its conversation ──

def test_a_name_check_keeps_its_conversation_under_its_own_record(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    from inferroute_cli import pi_attested
    monkeypatch.setattr(pi_attested, "LAST_SESSION_ID", None)
    kept = W.conversation_file_for({"mode": "names", "record_session_id": NAME_SID}, "Acme", "names", None)
    assert kept == S.records_dir("Acme", "names") / f"{NAME_SID}.conversation.jsonl"
    monkeypatch.setattr(pi_attested, "LAST_SESSION_ID", OTHER_SID)
    assert W.conversation_file_for({}, "Acme", "cool", "http://127.0.0.1:1").name == f"{OTHER_SID}.conversation.jsonl"
    assert W.conversation_file_for({"mode": "intake"}, "", "", None) is None
    js = (STATIC / "home.js").read_text()
    assert "A name check's conversation isn't kept." not in js


def test_the_launcher_names_the_record_before_the_searches_and_the_page_use_it():
    src = (Path(W.__file__).resolve().parent / "confidential.py").read_text()
    assert 'probant["record_session_id"] = names_sid' in src and "session_id=names_sid" in src
    assert "rec_sid = names_sid or" in src
    # the record says how the session ended, so the list can tell a crash from a session someone ended
    assert 'ended_by="person" if page.bridge.stop_requested else "itself"' in src


# ── 9. the footer counts the conversation, not only the machine serving it now ──

def test_the_footer_counts_every_machine_the_conversation_used():
    retired = [SimpleNamespace(receipt=SimpleNamespace(counters={"requests": 3, "plaintext_bytes_sealed_here": 30_000}))]
    lane = SimpleNamespace(receipt=SimpleNamespace(counters={"requests": 1, "plaintext_bytes_sealed_here": 63_000}),
                           retired=retired)
    c = W.conversation_counters(lane)
    assert c["requests"] == 4 and c["plaintext_bytes_sealed_here"] == 93_000
    assert W.conversation_counters(SimpleNamespace(receipt=SimpleNamespace(counters={"requests": 2})))["requests"] == 2
    b = _bridge(counters=lambda: c)
    assert b.session_end()["requests"] == 4


# ── 2. a wrong or withdrawn key is never a dead end ──

REVOKED = ["the carrier answered 401 while listing confidential models",
           "router · {\"error\":\"invalid key\"}",
           "Nothing was sent; your InferRoute key was refused — run `ir login`."]


def test_a_refused_key_is_told_apart_from_a_missing_one_and_never_says_ir_login():
    refused = H.failure_message(REVOKED)
    assert refused == H.KEY_REFUSED_WORDS and "Replace key" in refused and "No InferRoute key is saved" not in refused
    missing = H.failure_message(["no InferRoute key (run `ir login`) and no IR_OPERATOR_API_KEY for direct mode"])
    assert missing == H.KEY_MISSING_WORDS
    for tail in (REVOKED, ["no InferRoute key (run `ir login`)"], ["cannot reach the carrier (ConnectError)"]):
        assert "ir login" not in H.failure_message(tail)
    L = H.Launches()
    it = {"id": "k", "matter": "Acme/x", "started": time.time(), "state": "failed", "url": None, "message": "",
          "tail": collections.deque(REVOKED), "proc": None}
    assert L.view(it)["key_problem"] == "refused"


def test_replace_key_is_offered_in_the_failure_and_in_the_settings():
    js = (STATIC / "home.js").read_text()
    assert "if (l.key_problem) box.append(replaceKeyButton(" in js
    assert 'el("summary", "", "Settings")' in js and "replaceKeyButton(() => refresh())" in js
    assert '"Replace your InferRoute key"' in js


# ── 3. a name check's exported record is a name check's ──

def _name_matter(c, rdir_sid=NAME_SID):
    c.post("/api/matters", json={"client": "Acme", "matter": "bottle", "kind": "name",
                                 "disclosure": "Names being considered:\n- Tidevell\n- Lumora\n\nA reusable bottle."})
    ws = S.workspace_path("Acme", "bottle")
    (ws / S.NAME_CHECK).write_text("# Name check\n\nLumora: three US marks spell LUMORA exactly.\n")
    rdir = S.records_dir("Acme", "bottle")
    _host_record(rdir, rdir_sid, ended_at="2026-10-23T16:30:00Z", exit_code=0, turns=2, ended_by="person")
    _log(rdir, *({"at": "2026-10-23T16:1%d:00Z" % i, "session_id": rdir_sid, "name": n, "classes": ["21"],
                  "hits": [{"text": n.upper(), "register": "USPTO", "number": str(i), "status": "registered"}], "more": 2,
                  **({"filings": 7} if i == 0 else {})}
                 for i, n in enumerate(["Lumora", "Tidevell"] * 4)),
         {"at": "2026-10-23T18:00:00Z", "session_id": OTHER_SID, "name": "Elsewhere", "classes": [], "hits": []})
    return ws


def test_a_name_check_record_is_titled_and_worded_for_a_name_check(home):
    from inferroute_cli import probant_export as E
    h, c, _ = home
    _name_matter(c)
    r = c.post("/api/export", json={"id": "Acme/bottle"})
    assert r.status_code == 200, r.text
    folder = Path(c.get("/api/matter", params={"id": "Acme/bottle"}).json()["exports"][0]["folder"])
    assert "-name-check-record-" in folder.name and "prior-art" not in folder.name
    html = (folder / "record.html").read_text()
    assert "<h1>Name check record</h1>" in html and "Prior-art" not in html
    for wrong in ("sealed search", "priority date", "Date bound", "contract ?", "preamble ?", "?</span>", "enclave"):
        assert wrong not in html, wrong
    assert "8 trademark searches for 2 names" in html and "three US marks spell LUMORA" in html
    assert "no outside machine signed" in html and "free to use" in html
    # names, then filings in brackets; a search logged before grouping has only its filings
    assert "<th>Similar names (filings)</th>" in html and "<td>3 (7)</td>" in html and "<td>(3)</td>" in html
    rows = json.loads((folder / "trademark-searches.json").read_text())
    assert len(rows) == 8 and {r["session_id"] for r in rows} == {NAME_SID}
    assert (folder / f"report-{S.NAME_CHECK}").read_text().startswith("# Name check")
    manifest = json.loads((folder / "MANIFEST.json").read_text())
    assert manifest["kind"] == "name-check" and manifest["trademark_searches"] == 8
    assert E.record_folder_kind({"kind": "name"}) == "name-check-record"


def test_checking_a_name_check_record_says_what_it_can_and_cannot_show(home):
    h, c, _ = home
    _name_matter(c)
    c.post("/api/export", json={"id": "Acme/bottle"})
    e = c.get("/api/matter", params={"id": "Acme/bottle"}).json()["exports"][0]
    out = c.post("/api/check", json={"id": "Acme/bottle", "name": e["name"]}).json()
    assert out["verdict"] == "unchanged" and out["headline"] == "The record's files are unchanged since it was exported."
    assert "Nothing to check yet" not in json.dumps(out) and "Run a search" not in json.dumps(out)
    assert "8 trademark searches" in out["groups"][0]["answer"] and "nothing outside it signed" in out["explainer"]
    (Path(e["folder"]) / "record.html").write_text("changed")
    bad = c.post("/api/check", json={"id": "Acme/bottle", "name": e["name"]}).json()
    assert bad["verdict"] == "failed" and "record.html" in bad["failed"]
    common = (STATIC / "common.js").read_text()
    assert 'unchanged: "○ Files unchanged"' in common and "r.repeat ||" in common


# ── 6. a group with lines not checked does not wear a tick ──

def test_a_group_with_unchecked_lines_reads_passed_with_limits():
    from inferroute_cli import probant_check as C
    text = ("  PASS manifest: every file matches\n"
            "  PASS something else: fine\n"
            "  SKIP enclave-wide counter (observation): 3 of them (9, 10, 11) are not in this record\n"
            "RESULT: no failing record checks\n")
    out = C.parse(text, 0)
    other = next(g for g in out["groups"] if g["key"] == "other")
    assert other["status"] == "limited" and other["answer"] == "Passed, with limits noted below."
    assert other["answer"] != "Everything else passed." and out["headline"] == "Checked out, with limits noted below."
    css = (STATIC / "app.css").read_text()
    assert ".check-group.limited .check-q::before" in css


# ── 7. one state for the matter page ──

def test_the_matter_page_reads_one_launch_state_that_survives_a_refresh(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    it = {"id": "f1", "matter": "Acme/cooling", "intake_id": "", "started": time.time(), "state": "failed", "url": None,
          "message": "The session didn't start.", "detail": "", "tail": collections.deque(),
          "proc": SimpleNamespace(poll=lambda: 0)}
    h.launches.items["f1"] = it
    running = c.get("/api/matter", params={"id": "Acme/cooling"}).json()["running"]
    assert running["state"] == "failed" and running["id"] == "f1"
    it["started"] -= 3600                                   # an old failure is not shown for ever
    assert c.get("/api/matter", params={"id": "Acme/cooling"}).json()["running"] is None
    js = (STATIC / "home.js").read_text()
    assert 'runState === "starting" ? button("Starting…"' in js and 'runState === "failed" ? null' in js
    assert '} else if (runState === "ready") {\n        p.append(el("p", "", "The assistant is checking your names now.' in js
    assert 'if (l.state !== "failed") onChange();' not in js


# ── 8. records belong to the matter they were made from ──

def test_a_new_matter_does_not_take_an_older_same_named_matters_records(home):
    from inferroute_cli import probant_delete
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "heat-pipe-bottle"})
    root = S.probant_root() / "Acme" / "exports"
    old = root / "heat-pipe-bottle-prior-art-record-20261021T185631Z"
    old.mkdir(parents=True)
    (old / "record.html").write_text("x")
    (old / "MANIFEST.json").write_text(json.dumps({"generated_at": "2026-10-21T18:56:31Z"}))   # before manifests named the matter
    other = root / "heat-pipe-bottle-prior-art-record-20991021T185631Z"
    other.mkdir()
    (other / "record.html").write_text("x")
    (other / "MANIFEST.json").write_text(json.dumps({"generated_at": "2099-10-21T18:56:31Z",
                                                     "matter_created_at": "2001-01-01T00:00:00Z"}))
    assert c.get("/api/matter", params={"id": "Acme/heat-pipe-bottle"}).json()["exports"] == []
    c.post("/api/export", json={"id": "Acme/heat-pipe-bottle"})
    mine = c.get("/api/matter", params={"id": "Acme/heat-pipe-bottle"}).json()["exports"]
    assert len(mine) == 1 and mine[0]["name"] not in (old.name, other.name)
    manifest = json.loads((Path(mine[0]["folder"]) / "MANIFEST.json").read_text())
    assert manifest["matter_created_at"] == S.load_record("Acme", "heat-pipe-bottle")["created_at"]
    assert [p.name for p in probant_delete._exports_of("Acme", "heat-pipe-bottle")] == [mine[0]["name"]]
