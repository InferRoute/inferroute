"""The Probant home page: what its server refuses, what it reads and writes, and what its page never does.

Same rules as a session's page (install_guard), plus the home page's own: it writes only a new matter, the
disclosure and an export, each on request; it opens only links this computer made; a past session is read
from the host-side records and the conversation kept beside them.
"""
import json
import re
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_home as H

STATIC = Path(H.__file__).resolve().parent / "probant_web"
SID = "20260917T163734Z-f973d8c0"


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


def _session_fixture(client="Acme", matter="cooling", *, conversation=True, surface="browser"):
    rdir = S.records_dir(client, matter)
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{SID}.json").write_text(json.dumps({
        "session_id": "pi-1", "surface": surface, "confinement": "require, address-level (empty network namespace)",
        "model_lane": {"verified": True, "checks": "15/15", "model": "kimi-k2.6"}}))
    hit = lambda k: {"key": k, "year": 2019, "title": f"Title of {k}"}   # noqa: E731
    (rdir / f"{SID}.searches.jsonl").write_text("\n".join(json.dumps(x) for x in [
        {"at": "2026-09-17T16:38:00Z", "query_text": "a wrist device", "statement": {"sig": "aa", "cutoff_date": 20200101},
         "result": {"hits": [hit("WO-1-A1"), hit("US-2-B2")]}},
        {"kind": "unanswered", "at": "2026-09-17T16:39:00Z"},
        {"at": "2026-09-17T16:40:00Z", "query_text": "unsigned", "statement": {}, "result": {"hits": [hit("EP-9-A1")]}},
    ]) + "\n")
    if conversation:
        (rdir / f"{SID}.conversation.jsonl").write_text("\n".join(json.dumps(x) for x in [
            {"kind": "user", "text": "Run a survey"}, {"kind": "search", "ok": True, "search_no": 1, "documents": 2},
            {"kind": "assistant", "text": "**Two** documents."}]) + "\n")


# ── who may talk to it ──

def test_the_home_page_follows_the_session_page_rules(home):
    h, c, _ = home
    assert c.get("/api/overview", headers={"authorization": ""}).status_code == 401
    assert c.get("/api/overview", headers={"host": "evil.example:45678"}).status_code == 421
    assert c.post("/api/matters", json={"client": "A", "matter": "b"}, headers={"origin": "https://evil.example"}).status_code == 403
    r = c.get("/", headers={"authorization": ""})
    assert r.status_code == 200 and "default-src 'none'" in r.headers["content-security-policy"]


def test_no_route_beyond_what_the_page_needs(home):
    h, c, _ = home
    paths = {r.path for r in h.app().routes}
    assert paths == {"/", "/home.js", "/common.js", "/app.css", "/api/overview", "/api/matters", "/api/matter",
                     "/api/disclosure", "/api/sessions", "/api/launch", "/api/session", "/api/export",
                     "/api/check", "/record",
                     # deleting a matter (19 Sep): restorable for 30 days, then erased
                     "/api/matter/delete", "/api/deleted", "/api/deleted/restore", "/api/deleted/erase",
                     # reading a document and proposing matters from it (20 Sep)
                     "/api/intake", "/api/intakes", "/api/intake/create"}


# ── matters ──

def test_create_a_matter_with_its_disclosure_and_list_it(home):
    h, c, tmp = home
    r = c.post("/api/matters", json={"client": "Acme", "matter": "cooling", "priority_date": "2020-01-01",
                                     "disclosure": "A wrist device measuring glucose with light."})
    assert r.json() == {"ok": True, "id": "Acme/cooling"}
    ws = S.workspace_path("Acme", "cooling")
    assert (ws / "disclosure.md").read_text().startswith("# Disclosure\n\nA wrist device")
    assert stat.S_IMODE(ws.stat().st_mode) == 0o700
    m = c.get("/api/overview").json()["matters"][0]
    assert m["id"] == "Acme/cooling" and m["date_bound"] == "2020-01-01" and m["disclosure_words"] == 7


@pytest.mark.parametrize("client,matter,date", [("../x", "m", ""), ("A", "a/b", ""), (".hidden", "m", ""), ("A", "m", "01/02/2020")])
def test_bad_names_and_dates_are_refused_before_any_path_is_built(home, client, matter, date):
    h, c, tmp = home
    r = c.post("/api/matters", json={"client": client, "matter": matter, "priority_date": date})
    assert r.status_code == 400
    assert not (tmp / "Probant").exists() or not any((tmp / "Probant").rglob("disclosure.md"))


def test_the_disclosure_round_trips_without_the_template(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    assert c.get("/api/disclosure", params={"id": "Acme/cooling"}).json()["text"] == ""
    assert c.post("/api/disclosure", json={"id": "Acme/cooling", "text": "Light through tissue."}).json()["words"] == 3
    assert c.get("/api/disclosure", params={"id": "Acme/cooling"}).json()["text"] == "Light through tissue."


# ── past sessions ──

def test_a_past_session_shows_signed_searches_marks_and_the_kept_conversation(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    _session_fixture()
    S.state_path("Acme", "cooling").write_text(json.dumps({"marks": {"WO-1-A1": {"latest": {"value": "relevant"}}}}))
    m = c.get("/api/matter", params={"id": "Acme/cooling"}).json()
    assert m["sessions"][0] == {"id": SID, "started_at": "2026-09-17T16:37:34Z", "surface": "browser", "searches": 1,
                                "documents": 2, "ai_verified": True, "boxed": True, "conversation": True}
    d = c.get("/api/session", params={"id": "Acme/cooling", "sid": SID}).json()
    assert [x["query"] for x in d["searches"]] == ["a wrist device"]          # the unsigned row is not a search
    assert d["unanswered"] == 1 and d["marks"] == {"WO-1-A1": "relevant"}
    assert [r["kind"] for r in d["conversation"]] == ["user", "search", "assistant"]


def test_a_terminal_session_has_no_conversation_and_says_so(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    _session_fixture(conversation=False, surface="terminal")
    d = c.get("/api/session", params={"id": "Acme/cooling", "sid": SID}).json()
    assert d["conversation"] is None and d["surface"] == "terminal"


@pytest.mark.parametrize("sid", ["../../etc/passwd", "20260917T163734Z-f973d8c0.json", "x"])
def test_a_session_id_that_is_not_a_session_id_reads_nothing(home, sid):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    assert c.get("/api/session", params={"id": "Acme/cooling", "sid": sid}).status_code == 404


# ── starting a session ──

class FakeProc:
    def __init__(self, lines, rc=0):
        self.stdout = iter(lines)
        self.rc = rc
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self):
        self.returncode = self.rc
        return self.rc


def test_start_runs_the_same_open_command_and_offers_its_link(home, monkeypatch):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    seen = {}
    url = "http://127.0.0.1:40123/#k=" + "k" * 43

    def fake_popen(argv, **kw):
        seen["argv"], seen["env"] = argv, kw["env"]
        p = FakeProc([f"Open this session in your browser:  {url}\n"])
        p.wait = lambda: time.sleep(0.5) or 0                               # still running when polled
        return p
    monkeypatch.setattr(H.subprocess, "Popen", fake_popen)
    first = c.post("/api/sessions", json={"id": "Acme/cooling"}).json()
    assert seen["argv"][-4:] == ["probant", "open", "Acme/cooling", "--web"] and seen["env"]["IR_PROBANT_NO_BROWSER"] == "1"
    for _ in range(40):
        v = c.get("/api/launch", params={"id": first["id"]}).json()
        if v["state"] == "ready":
            break
        time.sleep(0.05)
    assert v["state"] == "ready" and v["url"] == url


def test_a_session_that_fails_to_open_is_explained_plainly(home, monkeypatch):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    monkeypatch.setattr(H.subprocess, "Popen", lambda argv, **kw: FakeProc(["│ This session was NOT opened. Nothing was sent. │\n"], rc=3))
    first = c.post("/api/sessions", json={"id": "Acme/cooling"}).json()
    for _ in range(40):
        v = c.get("/api/launch", params={"id": first["id"]}).json()
        if v["state"] == "failed":
            break
        time.sleep(0.05)
    assert v["state"] == "failed" and "could not be verified" in v["message"] and "nothing was sent" in v["message"]


# ── records ──

def test_a_record_opens_only_with_its_own_link_and_sandboxed(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    d = S.probant_root() / "Acme" / "exports" / "cooling-prior-art-record-20260917T160005Z"
    d.mkdir(parents=True)
    (d / "record.html").write_text("<h1>record</h1>")
    e = c.get("/api/matter", params={"id": "Acme/cooling"}).json()["exports"][0]
    r = c.get(e["view"], headers={"authorization": ""})
    assert r.status_code == 200 and "sandbox" in r.headers["content-security-policy"] and "record" in r.text
    assert c.get(e["view"].replace("&v=", "&v=0"), headers={"authorization": ""}).status_code == 403
    other = e["view"].replace("cooling-prior-art-record-20260917T160005Z", "cooling-prior-art-record-20990101T000000Z")
    assert c.get(other, headers={"authorization": ""}).status_code == 403


def test_a_record_can_be_checked_from_the_page_and_only_a_real_one(home, monkeypatch):
    h, c, tmp_path = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling"})
    d = S.probant_root() / "Acme" / "exports" / "cooling-prior-art-record-20260917T160005Z"
    d.mkdir(parents=True)
    (d / "record.html").write_text("<h1>record</h1>")
    # The bundle's OWN verifier is what runs — the same file a stranger would run, not a copy of the verdict.
    (d / "verify_record.py").write_text("import sys\nprint('  PASS MANIFEST.json: 1 file')\n"
                                        "print('RESULT: every check PASSED under production roots')\nsys.exit(0)\n")
    from inferroute_cli import pi_attested
    monkeypatch.setattr(pi_attested, "search_config_path", lambda: tmp_path / "none.json")
    r = c.post("/api/check", json={"id": "Acme/cooling", "name": d.name})
    assert r.status_code == 200 and r.json()["verdict"] == "passed"
    assert r.json()["groups"][0]["question"].startswith("Is the record whole")
    assert c.post("/api/check", json={"id": "Acme/cooling", "name": "../../etc"}).status_code == 404
    assert c.post("/api/check", json={"id": "Acme/nope", "name": d.name}).status_code == 404
    assert c.post("/api/check", json={"id": "Acme/cooling", "name": d.name},
                  headers={"authorization": ""}).status_code == 401


# ── the bridge keeps the conversation ──

def test_the_session_page_keeps_its_conversation_privately(tmp_path):
    from inferroute_cli import probant_web as W
    f = tmp_path / f"{SID}.conversation.jsonl"
    b = W.Bridge(matter="A/b", date_bound="", workspace=tmp_path, summary={}, search_endpoint=None,
                 receipt=lambda: SimpleNamespace(counters={}), rebuild_summary=dict, export=lambda: tmp_path,
                 conversation_file=f)
    b.publish({"kind": "user", "text": "hello"})
    b.publish({"kind": "assistant_delta", "text": "he"})
    b.publish({"kind": "assistant_end", "text": "hi there"})
    b.publish({"kind": "status", "key": "k", "text": "🔒"})
    b.publish({"kind": "tool_end", "tool": "prior_art_search", "ok": True, "details": {"ok": True, "searchNo": 2, "feature": "light", "docs": [{}, {}]}})
    rows = [json.loads(x) for x in f.read_text().splitlines()]
    assert [r["kind"] for r in rows] == ["user", "assistant", "search"]
    assert rows[2]["search_no"] == 2 and rows[2]["feature"] == "light" and rows[2]["documents"] == 2
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


# ── the page's code ──

def test_the_home_page_builds_text_only_and_opens_only_links_this_computer_made():
    js = (STATIC / "home.js").read_text()
    code = re.sub(r"//[^\n]*", "", js)
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                      "DOMParser", "srcdoc", ".href", ".src", "location.assign", "location.href ="):
        assert forbidden not in code, forbidden
    for tag in ("a", "img", "iframe", "script", "link", "object", "embed"):
        assert f'createElement("{tag}")' not in code and f'el("{tag}"' not in code, tag
    assert code.count("window.open(") == 1
    opener = code[code.index("function openLocal"):code.index("function toast")]
    assert "window.open(" in opener and "SESSION_LINK.test(url)" in opener and "RECORD_LINK.test(url)" in opener


def test_the_help_page_covers_the_whole_path_and_the_limits():
    js = (STATIC / "home.js").read_text()
    for heading in ("How Probant works", "Create a matter", "Start a session", "Research with the assistant",
                    "Mark what matters", "Keep the record", "What stays private", "What it can't prove", "Limits right now"):
        assert heading in js, heading
    html = (STATIC / "home.html").read_text()
    assert "http://" not in html and "https://" not in html and re.search(r"\son[a-z]+=", html) is None


# ── a start that fails says why, and the reason stays on screen ──
#
# 19 Sep: Henry clicked "Start a session" and saw "Starting a session…" for two seconds, then nothing. The
# child had printed "`pi` not found on PATH" (the home page ran as a service with a minimal PATH); the home
# page turned that into "The session did not start. See the terminal where Probant home runs" — a terminal
# that did not exist — and then refreshed the page, which dropped even that.

def test_the_agent_program_missing_from_path_is_named_plainly():
    msg = H.failure_message([" ❌ `pi` not found on PATH.", "    Pi is an open-source agent: `npm install -g …`",
                              "opening Demo/glucose — date bound 2020-01-01"])
    # Still names the program, but the answer is an install, never "open a terminal" (20 Sep).
    assert "is not installed on this computer" in msg and "Nothing was sent" in msg
    assert "npm install -g" in msg and "pi --version" not in msg


def test_an_unrecognised_failure_shows_what_it_said_instead_of_pointing_at_a_terminal():
    msg = H.failure_message(["opening Demo/glucose — date bound 2020-01-01", "something unexpected happened here"])
    assert "something unexpected happened here" in msg
    assert "See the terminal" not in msg                 # often there is no terminal: a service, a shortcut
    assert H.failure_message([]) == "It stopped before printing anything. Nothing was sent."


def test_a_failed_start_is_not_refreshed_off_the_screen():
    js = (STATIC / "home.js").read_text()
    assert 'if (l.state !== "failed") onChange();' in js
    assert 'button("Try again", "primary"' in js and 'button("Dismiss", "ghost"' in js


def test_a_session_that_has_ended_is_not_offered_as_open_and_does_not_block_a_new_one(tmp_path):
    """19 Sep: the home page listed two sessions with "Open the session"; both opened onto "Session closed".
    Their assistants had ended; only their pages stayed up, for exporting. The home page counted a session as
    running while its process lived — and so "Start a session" on those matters returned the ENDED one."""
    import io
    from rich.console import Console
    from inferroute_cli import probant_web as W
    # What a session really prints when it ends, through the same console, as a pipe sees it (80 columns).
    buf = io.StringIO()
    page = W.Page(SimpleNamespace(closed=None), SimpleNamespace(should_exit=False), None)
    console = Console(file=buf, width=80, force_terminal=True)
    async def run():
        import asyncio
        page.bridge.closed = asyncio.Event()
        page.bridge.stop_streams = lambda: None
        page.bridge.closed.set()                              # closes at once
        async def done():
            return None
        page.task = asyncio.ensure_future(done())
        await page.linger(console, seconds=0.01)
    import asyncio
    asyncio.run(run())
    printed = buf.getvalue()
    lines = ["opening Demo/glucose — date bound 2020-01-01\n",
             "Open this session in your browser:  http://127.0.0.1:41234/#k=" + "k" * 30 + "\n", *printed.splitlines(True)]
    L = H.Launches()
    it = {"id": "x", "matter": "Demo/glucose", "started": 0, "state": "starting", "url": None, "message": "",
          "tail": __import__("collections").deque(maxlen=60),
          "proc": SimpleNamespace(stdout=iter(lines), wait=lambda: None)}
    L.items["x"] = it
    # _follow reads to the end; the process "still lives" in reality — what matters is the state it reached
    # from the output alone, before exit is ever seen.
    real_wait = it["proc"].wait
    states = []
    it["proc"].wait = lambda: states.append(it["state"])
    L._follow(it)
    assert states == ["ended"], "the ended line must be recognised from the output, before the process exits"
    assert L.running_for("Demo/glucose") is None           # so "Start a session" starts a new one


def test_the_page_is_the_version_the_server_started_with_and_says_when_a_newer_one_waits(home, monkeypatch, tmp_path):
    """19 Sep: the home page read its JS fresh from disk, so after an update it showed "Delete matter" to a server
    started before that route existed, and the button failed with a bare 404. The page is now the snapshot taken
    when the server started, and the overview says when the installed code has changed since."""
    import shutil
    from fastapi.testclient import TestClient
    import inferroute_cli.probant_web as W
    static = tmp_path / "static"
    shutil.copytree(W.STATIC, static)
    monkeypatch.setattr(W, "STATIC", static)
    monkeypatch.setattr(H, "STATIC", static)                  # imported by name there too
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    before = c.get("/home.js").content
    assert c.get("/api/overview").json()["update_waiting"] is False
    (static / "home.js").write_text("// a newer page, with a button this server has no route for\n")
    assert c.get("/home.js").content == before                    # still the page the server started with
    assert c.get("/api/overview").json()["update_waiting"] is True
    assert b"A newer version of Probant is installed." in before


def test_a_session_starts_from_a_page_whose_PATH_never_saw_node(monkeypatch, tmp_path):
    """Henry, 20 Sep: "I don't want the user to have to do anything in the terminal". A home page started as
    a service has a PATH that a terminal does not, and every session refused with advice to go and use a
    terminal. The launcher looks where these programs install instead."""
    from inferroute_cli import agents
    fake_nvm = tmp_path / ".nvm" / "versions" / "node"
    for version in ("v18.1.0", "v22.22.3"):
        b = fake_nvm / version / "bin"
        b.mkdir(parents=True)
        (b / "pi").write_text("#!/bin/sh\n")
        (b / "pi").chmod(0o755)
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("NVM_DIR", str(tmp_path / ".nvm"))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    found = agents.find_agent("pi")
    assert found == str(fake_nvm / "v22.22.3" / "bin" / "pi")     # the newest install, not the first found
    assert agents.find_agent("definitely-not-installed") is None
    # An explicit override wins, for a machine that keeps it somewhere else entirely.
    other = tmp_path / "elsewhere" / "pi"
    other.parent.mkdir()
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    monkeypatch.setenv("IR_PI_BIN", str(other))
    assert agents.find_agent("pi") == str(other)


def test_when_pi_really_is_absent_the_page_says_install_it_not_use_a_terminal():
    msg = H.failure_message(["`pi` is not installed on this computer (PATH and the usual install directories were checked)."])
    assert "npm install -g @earendil-works/pi-coding-agent" in msg
    assert "terminal" not in msg.lower()


def test_the_child_gets_the_node_that_sits_beside_its_agent(tmp_path):
    """`pi` is a node script; started with a service's PATH it found node 18 and died with a syntax error.
    The directory the command was FOUND in holds the right node — following the symlink does not."""
    from inferroute_cli import agents
    binary = tmp_path / "nvm" / "bin" / "pi"
    real = tmp_path / "nvm" / "lib" / "node_modules" / "pi" / "cli.js"
    real.parent.mkdir(parents=True)
    real.write_text("#!/usr/bin/env node\n")
    binary.parent.mkdir(parents=True)
    (binary.parent / "node").write_text("")
    binary.symlink_to(real)
    env = agents.put_agent_on_path(str(binary), {"PATH": "/usr/bin:/bin"})
    assert env["PATH"].split(":")[0] == str(binary.parent)          # where node is, not where the link goes
    assert str(real.parent) not in env["PATH"]
    assert agents.put_agent_on_path(str(binary), dict(env))["PATH"] == env["PATH"]   # not added twice
