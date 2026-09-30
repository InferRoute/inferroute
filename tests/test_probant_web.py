"""The local browser page for a Probant session: what its bridge refuses, and what its page never does.

The agent's sandbox has no network; the browser does. These tests pin the properties that keep the page
from becoming the agent's way out, or another site's way in.
"""
import datetime as dt
import asyncio
import json
import os
import stat
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import probant_web as W

STATIC = Path(W.__file__).resolve().parent / "probant_web"


class FakeStdin:
    def __init__(self):
        self.lines = []
        self.closed = False

    def write(self, b):
        self.lines.append(json.loads(b.decode()))

    async def drain(self):
        return None

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True


def _bridge(tmp_path, search_endpoint="http://127.0.0.1:9"):
    (tmp_path / "disclosure.md").write_text("# Disclosure\n\nA wrist device measuring glucose with light.\n")
    b = W.Bridge(matter="Acme/cooling", date_bound="2020-01-01", workspace=tmp_path,
                 summary={"verdict": "private", "items": [], "limits": []}, search_endpoint=search_endpoint,
                 receipt=lambda: SimpleNamespace(counters={"requests": 2, "plaintext_bytes_sealed_here": 2048}),
                 rebuild_summary=lambda: {"verdict": "private"}, export=lambda: tmp_path / "record")
    b.port = 43210
    b.proc = SimpleNamespace(stdin=FakeStdin(), returncode=None)
    return b


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    b = _bridge(tmp_path)
    c = TestClient(b.app(), base_url="http://127.0.0.1:43210")
    c.headers.update({"authorization": f"Bearer {b.token}"})
    return b, c


# ── the bridge: who may talk to it ──

def test_the_page_itself_needs_no_key_but_carries_a_strict_policy(client):
    b, c = client
    r = c.get("/", headers={"authorization": ""})
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "http" not in csp
    assert r.headers["referrer-policy"] == "no-referrer" and r.headers["x-frame-options"] == "DENY"


def test_every_api_call_without_the_session_key_is_refused(client):
    b, c = client
    for path in ("/api/session", "/api/events", "/api/marks"):
        assert c.get(path, headers={"authorization": ""}).status_code == 401
        assert c.get(path, headers={"authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/api/prompt", json={"text": "hi"}, headers={"authorization": ""}).status_code == 401
    assert b.proc.stdin.lines == []


def test_a_rebound_host_name_is_refused_even_with_the_key(client):
    # DNS rebinding: evil.example resolving to 127.0.0.1 still sends Host: evil.example.
    b, c = client
    assert c.get("/api/session", headers={"host": "evil.example:43210"}).status_code == 421
    assert c.get("/", headers={"host": "evil.example:43210"}).status_code == 421


def test_a_cross_origin_request_is_refused_even_with_the_key(client):
    b, c = client
    r = c.post("/api/prompt", json={"text": "hi"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    assert b.proc.stdin.lines == []


# ── the bridge: what it lets reach the agent ──

def test_only_prompt_abort_and_dialog_answers_ever_reach_the_agent(client):
    b, c = client
    assert c.post("/api/prompt", json={"text": "survey the disclosure"}).json() == {"ok": True}
    assert c.post("/api/abort", json={}).status_code == 200
    # Something shaped like an RPC command in the body is just text of a prompt, never a command.
    c.post("/api/prompt", json={"text": "x", "type": "bash", "command": "curl evil"})
    types = {line["type"] for line in b.proc.stdin.lines}
    assert types == {"prompt", "abort"}
    assert all(set(line) <= {"type", "message", "streamingBehavior"} for line in b.proc.stdin.lines)


def test_no_route_exposes_shell_model_or_session_commands(client):
    b, c = client
    paths = {r.path for r in b.app().routes}
    assert paths == {"/", "/common.js", "/app.js", "/app.css", "/api/session", "/api/disclosure", "/api/events", "/api/prompt", "/api/abort",
                     "/api/dialog", "/api/marks", "/api/mark", "/api/recheck", "/api/export", "/api/prove", "/api/audit-pack",
                     # Opens a terminal on the prepared pack. The ONLY route here that starts a program, and
                     # it takes a choice from two agents — never a command. See the launcher's own test.
                     "/api/audit-launch",
                     "/api/close", "/api/end"}


def test_a_dialog_can_only_be_answered_if_the_agent_opened_it_and_only_once(client):
    b, c = client
    assert c.post("/api/dialog", json={"id": "made-up", "confirmed": True}).status_code == 404
    b.publish({"kind": "dialog", "id": "d1", "method": "confirm", "title": "Allow?", "message": "m", "options": []})
    assert c.post("/api/dialog", json={"id": "d1", "confirmed": True}).status_code == 200
    assert c.post("/api/dialog", json={"id": "d1", "confirmed": True}).status_code == 404
    assert b.proc.stdin.lines == [{"type": "extension_ui_response", "id": "d1", "confirmed": True}]


def test_a_confirm_is_allowed_only_by_an_explicit_true(client):
    b, c = client
    b.publish({"kind": "dialog", "id": "d2", "method": "confirm", "title": "", "message": "", "options": []})
    c.post("/api/dialog", json={"id": "d2", "confirmed": "yes"})
    assert b.proc.stdin.lines[-1]["confirmed"] is False


def _store(state):
    """A host verifier that records the mark and answers with the state, as the real one does."""
    calls = []

    def call(ep, path, body=None, timeout=60.0):
        calls.append((path, body))
        if path == "/matter/mark" and body and body.get("mark") in W.MARKS:
            state.setdefault("marks", {})[body["key"]] = {"latest": {"value": body["mark"]}}
        return state
    return calls, call


def test_marks_are_validated_and_go_to_the_host_verifier(client, monkeypatch):
    b, c = client
    state = {"marks": {}}
    calls, call = _store(state)
    monkeypatch.setattr(W, "_search_call", call)
    assert c.post("/api/mark", json={"key": "US-7000-B2; rm -rf", "mark": "relevant"}).status_code == 400
    assert c.post("/api/mark", json={"key": "US-7000-B2", "mark": "novel"}).status_code == 400
    assert c.post("/api/mark", json={"key": "us-7000-b2", "mark": "relevant"}).json()["key"] == "US-7000-B2"
    assert calls == [("/matter/mark", {"key": "US-7000-B2", "mark": "relevant"})]
    assert b.proc.stdin.lines == []                       # a mark never passes through the agent


def test_a_mark_can_be_taken_back_off(client, monkeypatch):
    """Henry, 25 Sep: "there is no way to just remove the selection and not keep something selected".
    Whichever of the three you pressed first, the document stayed marked as SOMETHING — and "not relevant"
    is a judgement, not the absence of one.

    Clearing is not a delete. The store is append-only because a changed mind is signal, so this records a
    new human row saying the opinion was withdrawn; what the PAGE must show is no mark at all."""
    b, c = client
    state = {"marks": {}}
    calls, call = _store(state)
    monkeypatch.setattr(W, "_search_call", call)

    assert c.post("/api/mark", json={"key": "US-7000-B2", "mark": "relevant"}).status_code == 200
    assert c.get("/api/marks").json()["marks"] == {"US-7000-B2": "relevant"}

    r = c.post("/api/mark", json={"key": "US-7000-B2", "mark": "cleared"})
    assert r.status_code == 200 and r.json()["cleared"] is True
    # The store keeps the row; the page must not show it as a mark of any kind.
    assert state["marks"]["US-7000-B2"]["latest"]["value"] == "cleared"
    assert c.get("/api/marks").json()["marks"] == {}


def test_the_page_refuses_to_report_a_mark_the_store_did_not_take(client, monkeypatch):
    """The verifier used to ignore a value it did not recognise and still answer 200 with the unchanged
    state. A client that trusted the status code would report a judgement the store never took — the page
    lying about a human judgement, which is the one thing this layer must never do.

    sealed-research now answers 400 on an unknown value (25 Sep, at my request). This read-back is the
    second instrument, and it is the one that survives a professional running an older verifier."""
    b, c = client
    state = {"marks": {"US-7000-B2": {"latest": {"value": "relevant"}}}}

    def deaf(ep, path, body=None, timeout=60.0):
        return state                                       # accepts nothing, answers 200 — the old shape
    monkeypatch.setattr(W, "_search_call", deaf)

    r = c.post("/api/mark", json={"key": "US-7000-B2", "mark": "cleared"})
    assert r.status_code == 409, r.text
    assert "did not accept" in r.json()["error"] and "still 'relevant'" in r.json()["error"]
    # And it must not claim success for a mark that never landed on a document with no mark at all.
    assert c.post("/api/mark", json={"key": "US-9999-B2", "mark": "relevant"}).status_code == 409


def test_the_deep_row_stops_offering_a_press_that_would_repeat(tmp_path):
    """Henry, 25 Sep: "this recommendation is still showing right after i just did the deep search and
    changed nothing about the relevant selections".

    The extension had already stopped SUGGESTING it — and the page added it back one line later, because
    the deep row is the one action the page guarantees is reachable. Each side was checked and the seam
    between them was not, so the fix that shipped did nothing where it shows."""
    import shutil, subprocess
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "deep_step_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    # The sim reports WHICH sentence the row offers, or None when it offers nothing.
    assert out["beforeAnyPress"] == "deep", "a session that has never pressed must be offered the first press"
    assert out["afterPress"] is None, "the row still offers a press that would put the same queries"
    # Marking changes what the press would put, so the row returns — and it returns asking for the
    # FOLLOW-UP, not repeating the first press's own words. Henry, 25 Sep: after marking, "it still shows
    # this message instead of the updated one".
    assert out["afterMarkingRelevant"] == "focused"
    assert out["afterSecondPress"] is None
    # A mark that is not a relevance mark does not change the queries, so it must not bring the row back.
    assert out["afterMarkingKnown"] is None
    # Taking a relevance mark off IS a change — the press would walk outward from one document fewer.
    assert out["afterClearingTheRelevantMark"] == "focused"
    # Neither a refusal nor a failure covered these marks, so neither may arm the suppression — and with no
    # press behind it, the row asks for a first press rather than a follow-up to one that never ran.
    assert out["afterRefusedRepeat"] == "deep"
    assert out["afterFailedPress"] == "deep"
    # Order is not a change: the planner walks outward from a SET, so the same two marks in either order
    # describe the same press. Without this the row returns for a press that puts identical queries.
    assert out["afterTwoRelevant"] is None
    assert out["sameTwoMarkedInTheOtherOrder"] is None
    assert out["afterAThirdRelevant"] == "focused"


def test_the_session_view_carries_no_disclosure_text(client):
    b, c = client
    s = c.get("/api/session").json()
    assert s["disclosure"]["disclosure_words"] == 7
    assert "glucose" not in json.dumps(s)


def test_an_empty_template_disclosure_counts_as_empty(tmp_path):
    (tmp_path / "disclosure.md").write_text("# Disclosure\n\nDescribe the invention here, then open the matter and ask for a prior-art survey.\n")
    assert W.disclosure_info(tmp_path)["disclosure_words"] == 0


# ── events from the agent ──

def test_unknown_or_dangerous_rpc_events_are_dropped_not_passed_through():
    assert W.normalize({"type": "bash_execution_update", "delta": "secret"}) == []
    assert W.normalize({"type": "session_switched", "path": "/x"}) == []
    assert W.normalize({"type": "message_update", "assistantMessageEvent": {"type": "thinking_delta", "delta": "t"}}) == []


def test_status_and_dialog_text_arrive_without_terminal_colour_codes():
    ev = W.normalize({"type": "extension_ui_request", "id": "s", "method": "setStatus", "statusKey": "k",
                      "statusText": "\x1b[38;2;181;189;104m🔒 AI: sealed machine\x1b[39m"})
    assert ev == [{"kind": "status", "key": "k", "text": "🔒 AI: sealed machine"}]


def test_pump_splits_on_newline_only_and_ends_with_a_summary(tmp_path):
    b = _bridge(tmp_path)
    got = []

    async def run():
        reader = asyncio.StreamReader()
        text = "line still the same record"
        reader.feed_data((json.dumps({"type": "message_end", "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}}) + "\n").encode())
        reader.feed_data(b'{"type": "agent_settled"}\r\n')
        reader.feed_eof()

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=0)
        b.subscribers.append(q := asyncio.Queue())
        rc = await b.pump(proc)
        while not q.empty():
            got.append(q.get_nowait())
        return rc
    assert asyncio.run(run()) == 0
    assert got[0]["kind"] == "assistant_end" and got[0]["text"] == "line still the same record"
    assert got[-1]["kind"] == "ended" and got[-1]["summary"]["plaintext_left"] == 0


# ── a turn that never ends ──
#
# On 17 Sep a session went silent part-way through an answer: the page said "The assistant is working…"
# for 25 minutes, Stop did nothing, and a new message was accepted and never delivered. The agent was idle
# — it held no connection and no request — so nothing was going to arrive, ever. These pin the three
# things that were wrong, none of which depend on knowing WHY the agent went quiet.

def test_the_page_is_told_when_the_assistant_goes_silent_mid_turn(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "STALL_SECONDS", 0.05)
    b = _bridge(tmp_path)
    got = []

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type": "agent_start"}\n')            # busy, and then nothing at all

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=None)
        b.subscribers.append(q := asyncio.Queue())
        pump = asyncio.ensure_future(b.pump(proc))
        await asyncio.sleep(0.3)
        stalled = b.stalled
        reader.feed_eof()                                          # the agent exits; the pump finishes
        proc.returncode = 0
        await pump
        while not q.empty():
            got.append(q.get_nowait())
        return stalled
    assert asyncio.run(run()) is True
    stall = [e for e in got if e["kind"] == "stall"]
    assert stall and stall[0]["value"] is True


def test_the_stall_notice_is_withdrawn_the_moment_the_assistant_speaks_again(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "STALL_SECONDS", 0.05)
    b = _bridge(tmp_path)
    got = []

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type": "agent_start"}\n')

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=None)
        b.subscribers.append(q := asyncio.Queue())
        pump = asyncio.ensure_future(b.pump(proc))
        await asyncio.sleep(0.3)
        assert b.stalled is True
        reader.feed_data(b'{"type": "agent_settled"}\n')            # it was slow, not dead
        await asyncio.sleep(0.1)
        alive = not b.stalled
        reader.feed_eof()
        proc.returncode = 0
        await pump
        while not q.empty():
            got.append(q.get_nowait())
        return alive
    assert asyncio.run(run()) is True
    assert [e["value"] for e in got if e["kind"] == "stall"] == [True, False]


def test_stop_says_whether_the_turn_actually_stopped(client, monkeypatch):
    b, c = client
    monkeypatch.setattr(W, "ABORT_GRACE", 0.05)
    b.busy = True                                                   # nothing will clear it: the agent is wedged
    r = c.post("/api/abort", json={})
    assert r.status_code == 200 and r.json()["settled"] is False
    assert b.proc.stdin.lines == [{"type": "abort"}]                # it was still asked, properly


def test_a_message_is_refused_while_the_assistant_is_not_responding(client):
    b, c = client
    b.busy, b.stalled = True, True
    r = c.post("/api/prompt", json={"text": "any news?"})
    assert r.status_code == 409 and "not responding" in r.json()["error"]
    assert b.proc.stdin.lines == []                                 # not accepted and quietly dropped


def test_ending_a_wedged_session_escalates_until_the_agent_is_gone(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "END_GRACE", 0.05)
    monkeypatch.setattr(W, "KILL_GRACE", 0.05)
    b = _bridge(tmp_path)
    acts = []

    async def run():
        done = asyncio.get_running_loop().create_future()

        def terminate():
            acts.append("terminate")                                # a wedged agent ignores this too

        def kill():
            acts.append("kill")
            proc.returncode = -9
            done.set_result(-9)

        async def waiter():
            return proc.returncode if proc.returncode is not None else await done
        proc = SimpleNamespace(stdin=FakeStdin(), wait=waiter, returncode=None, terminate=terminate, kill=kill)
        b.proc = proc
        return await b.stop_agent()
    assert asyncio.run(run()) == "killed"
    assert acts == ["terminate", "kill"] and b.proc.stdin.closed


def test_the_event_stream_lets_go_when_the_page_is_shutting_down(tmp_path):
    """The stream is a long poll that never ends on its own, and uvicorn's graceful shutdown waits for open
    requests. Without this the launcher waits for the browser tab to be closed before it can exit — which is
    why `kill` on a wedged session looked like SIGTERM being ignored and needed SIGKILL."""
    b = _bridge(tmp_path)

    async def run():
        b.subscribers.append(q := asyncio.Queue())
        b.stop_streams()
        assert b.shutdown.is_set()
        # Woken at once, not left parked in its 15-second wait.
        return await asyncio.wait_for(q.get(), 0.2)
    assert asyncio.run(run())["kind"] == "ping"


def test_an_event_the_page_has_no_word_for_is_counted_by_name_for_the_session_summary(tmp_path):
    b = _bridge(tmp_path)

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type": "some_future_event", "detail": "a secret the trail must not carry"}\n')
        reader.feed_eof()

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=0)
        await b.pump(proc)
        return b.ended
    end = asyncio.run(run())
    assert end["unrecognised"] == {"some_future_event": 1}
    assert "secret" not in json.dumps(end)


# ── the page's code ──

@pytest.mark.parametrize("script", ["app.js", "common.js"])
def test_the_page_code_never_parses_markup_or_makes_links_or_resources(script):
    js = (STATIC / script).read_text()
    code = re.sub(r"//[^\n]*", "", js)                  # the header comment names these constructs on purpose
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                      "DOMParser", "createContextualFragment", ".href", ".src", "srcdoc",
                      "location.assign", "location.href ="):
        assert forbidden not in code, forbidden
    # The ONE place a page may leave itself: back to the home page that started this session, and only to an
    # address this computer made. Never to anything from the conversation.
    assert code.count("window.open(") == (1 if script == "app.js" else 0)
    if script == "app.js":
        opener = js[js.index("function goHome"):js.index("function renderTrust")]
        assert "window.open(" in opener and "HOME_LINK.test(homeUrl)" in opener
    for tag in ("a", "img", "iframe", "script", "link", "object", "embed", "video", "audio", "source", "form"):
        assert f'createElement("{tag}")' not in code and f'el("{tag}"' not in code, tag
    assert re.search(r'setAttribute\("(href|src|action|formaction|style|on\w+)"', code) is None


def test_the_page_loads_nothing_from_outside():
    html = (STATIC / "index.html").read_text()
    assert "http://" not in html and "https://" not in html
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S)
    assert scripts and all(re.fullmatch(r'\s*src="/[a-z]+\.js"\s*(defer)?\s*', attrs) and not body.strip()
                           for attrs, body in scripts)                             # local files only, no inline code
    assert re.search(r"\son[a-z]+=", html) is None                            # no inline handlers
    css = (STATIC / "app.css").read_text()
    assert "url(" not in css and "@import" not in css


def test_the_browser_summary_states_what_the_page_guarantees_and_what_it_cannot():
    from inferroute_cli import probant_trust as T
    from inferroute_local import netns
    from tests.test_probant_trust import _receipt, _search
    s = T.build(_receipt(), _search(reference={"ok": True}), netns.ADDRESS_LEVEL_LABEL, surface="browser")
    assert T.BROWSER_POINT in next(i for i in s["items"] if i["key"] == "computer")["points"]
    assert any("Browser extensions" in lim for lim in s["limits"])
    terminal = T.build(_receipt(), _search(reference={"ok": True}), netns.ADDRESS_LEVEL_LABEL)
    assert not any("Browser extensions" in lim for lim in terminal["limits"])


def test_a_tool_that_never_finishes_is_a_stall_even_when_the_turn_is_not_busy(tmp_path, monkeypatch):
    """Henry, 18 Sep: "the first search gives results directly, then the others stall, just checking the
    search machine". The agent had gone silent with a search tool call outstanding — and `busy` was not set,
    so the watchdog never armed and the page showed "checking the search machine…" for ever. He had to ask a
    human why it was stuck, which is the exact failure the stall notice exists to prevent."""
    monkeypatch.setattr(W, "STALL_SECONDS", 0.05)
    b = _bridge(tmp_path)
    got = []

    async def run():
        reader = asyncio.StreamReader()
        # A tool starts. No agent_start, so `busy` stays False — and then nothing ever comes back.
        reader.feed_data(b'{"type": "tool_execution_start", "toolCallId": "c1", "toolName": "prior_art_search"}\n')

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=None)
        b.subscribers.append(q := asyncio.Queue())
        pump = asyncio.ensure_future(b.pump(proc))
        await asyncio.sleep(0.3)
        assert b.busy is False, "the premise: no turn is in flight, only a tool"
        stalled = b.stalled
        reader.feed_eof()
        proc.returncode = 0
        await pump
        while not q.empty():
            got.append(q.get_nowait())
        return stalled
    assert asyncio.run(run()) is True
    assert [e["value"] for e in got if e["kind"] == "stall"] == [True]


def test_a_tool_that_finishes_leaves_nothing_outstanding(tmp_path, monkeypatch):
    # The control: a completed tool must not keep the session looking busy for ever.
    monkeypatch.setattr(W, "STALL_SECONDS", 0.05)
    b = _bridge(tmp_path)

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type": "tool_execution_start", "toolCallId": "c1", "toolName": "prior_art_search"}\n')
        reader.feed_data(b'{"type": "tool_execution_end", "toolCallId": "c1", "toolName": "prior_art_search", "result": {}}\n')

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=None)
        pump = asyncio.ensure_future(b.pump(proc))
        await asyncio.sleep(0.3)
        out = (dict(b.running_tools), b.stalled)
        reader.feed_eof()
        proc.returncode = 0
        await pump
        return out
    running, stalled = asyncio.run(run())
    assert running == {} and stalled is False


def test_every_element_the_page_reaches_for_exists_in_the_html():
    """`$("outline-list")` on an id that is not in index.html fails silently in a browser — the feature
    simply does nothing, and no test that only reads the page's source would notice. Cross-check the two
    files against each other instead."""
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    wanted = set(re.findall(r'\$\("([a-z0-9-]+)"\)', js))
    present = set(re.findall(r'id="([a-z0-9-]+)"', html))
    assert wanted, "the page must look up something"
    assert wanted <= present, f"app.js reaches for ids that index.html does not define: {sorted(wanted - present)}"


def test_the_search_card_folds_and_the_session_has_an_index():
    """Henry, 18 Sep: "it would be good if this view could be collapsable and expandable and perhaps
    auto-collapse smartly ... to not make the feed/trace unreadable because too expanded", and "on the left
    an index of the conversation to click and go back while having an overview"."""
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "app.css").read_text()
    html = (STATIC / "index.html").read_text()
    for fn in ("function setCollapsed", "function autoCollapse", "function refreshCardSummary",
               "function outlineAdd", "function outlineDrop"):
        assert fn in js, fn
    assert 'id="outline-list"' in html and 'id="outline-empty"' in html
    # A fold must never hide a refusal, and must never override a deliberate click.
    assert "entry.failed = true" in js and "if (!e.byUser && !e.failed" in js
    # Selecting the text of a head must not also fold it — one click doing two jobs.
    assert "sel.isCollapsed" in js and "head.contains(sel.anchorNode)" in js
    assert ".outline { display: none; }" in css
    for cls in (".card-toggle", ".card.collapsed"):
        assert cls in css, cls


def test_a_row_in_the_index_says_what_the_search_WAS_not_how_many_it_found():
    """Henry, 18 Sep: "search six, seven, eight doesn't say anything ... it would be much better if we could
    have a description of what the search is. So fifty documents, it's taking a lot of space and it doesn't
    give a lot of information." The count was overwriting the one line that told them apart."""
    js = (STATIC / "app.js").read_text()
    # outlineUpdate carries the search number and your marking; it must not touch the description.
    body = js[js.index("function outlineUpdate"):js.index("function outlineUpdate") + 700]
    assert "rec.note.textContent = note" in body
    assert "rec.text" not in body, "outlineUpdate must never rewrite the description"
    assert 'document${docs.length === 1 ? "" : "s"}`)' not in js.replace("\n", " "), "no document count in the index"


def test_the_index_never_stacks_a_control_on_top_of_its_text():
    """Henry, 18 Sep: "it's overlapping, the text is being cut, and the selection versus expanding
    collapsing is also overlapping with the clicks". The cause was an absolutely positioned fold button
    over the row's text; flex cells cannot overlap."""
    css = (STATIC / "app.css").read_text()
    outline = css[css.index("/* the index down the left"):css.index("/* trust panel */")]
    assert "position: absolute" not in outline, "nothing in the index may be positioned over text"
    assert ".o-row { display: flex" in outline and "flex: 0 0 auto" in outline
    # A text cell that cannot shrink below its content is what pushes a row wider than the rail and gets
    # its text sliced by the border.
    assert "min-width: 0" in outline and "overflow-wrap: anywhere" in outline
    assert "-webkit-line-clamp: 2" in outline


def test_the_index_hangs_each_search_under_the_question_that_caused_it():
    """Henry, 18 Sep: searches should "be collapsed under the You turns or at least appear as smaller to
    take less space and differentiate with the You, which the user is mapping in his head with each new
    request". The question is the heading; what it caused hangs under it, quieter."""
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "app.css").read_text()
    assert 'if (item.kind === "you")' in js and 'el("ol", "o-children")' in js
    assert '(currentTurn ? currentTurn.kids : $("outline-list")).append(row)' in js
    assert 'fold.hidden = true' in js and 'currentTurn.fold.hidden = false' in js
    for cls in (".o-children", ".o-fold", ".o-you"):
        assert cls in css, cls
    # Children must read as smaller and quieter than their heading, or the nesting carries no signal.
    assert ".o-children .o-text { font-size: 12px; color: var(--muted)" in css


def test_every_class_the_page_uses_has_a_style():
    """18 Sep: rewriting the index's styles sliced app.css between two section markers — and the whole chat
    (messages, search cards, composer, the stall panel, the column layout) sat between them. 41 classes lost
    every rule; every test passed, because each checked only that SOME selector it cared about existed.
    Henry saw it at once: "a chat that seems to have lost its css". Check the page against its stylesheet."""
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    css = (STATIC / "app.css").read_text()
    used = set()
    for m in re.finditer(r'\bel\("[a-z0-9]+",\s*"([^"]+)"', js):
        used |= set(m.group(1).split())
    for m in re.finditer(r'class="([^"]+)"', html):
        used |= set(m.group(1).split())
    used = {c for c in used if not c.endswith("-")}                    # `m-${value}`: a prefix, not a class
    styled = set(re.findall(r"\.([a-zA-Z][a-zA-Z0-9_-]*)", css))
    # Deliberately unstyled: a bare container, the lock glyph, and a button that inherits the global style.
    allowed = {"card-body", "lock", "deeper"}
    missing = sorted(used - styled - allowed)
    assert not missing, f"classes the page uses with no rule in app.css: {missing}"


def test_ideas_wait_for_a_conversation_and_never_presume_one():
    """Henry, 19 Sep: "I'm seeing both the beginning-of-chat recommendation buttons and the IDEAS ones, but since
    the conversation is empty the IDEAS one shouldn't show." The behaviour — ideas only once the conversation
    has started, mark steps at once, nothing to summarise before a search — is now DRIVEN through the page's
    real code in test_one_next_steps_panel_counts_and_covers_by_action (cases s1, s6, s7). What remains here is
    the hand-over: when the welcome goes, the panel must take its place, or the box is left empty."""
    js = (STATIC / "app.js").read_text()
    hide = js[js.index("function hideWelcome"):js.index("function hideWelcome") + 300]
    assert "renderMarkSteps()" in hide

def test_a_search_reports_its_step_and_only_a_step_name_reaches_the_page():
    """Henry, 19 Sep: "where we have 'checking the search machine…' could we have a progress indicator or
    at least a timer? maybe the expected wait?" The tool reports which step it is on; the bridge forwards
    the NAME only, from a fixed list, never the partial result itself."""
    ev = W.normalize({"type": "tool_execution_update", "toolCallId": "c1", "toolName": "prior_art_search",
                      "partialResult": {"content": [{"type": "text", "text": "secret query"}], "details": {"phase": "searching"}}})
    assert ev == [{"kind": "tool_progress", "call": "c1", "phase": "searching"}]
    assert "secret" not in json.dumps(ev)
    assert W.normalize({"type": "tool_execution_update", "toolCallId": "c1",
                        "partialResult": {"details": {"phase": "<img src=x>"}}}) == []
    ts = (Path(W.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    for p in W.TOOL_PHASES:
        assert f'phase("{p}")' in ts, p
    js = (STATIC / "app.js").read_text()
    # The clock counts the machine's time, not the seconds spent reading the approval prompt.
    assert 'entry.phase === "approval" ? now - entry.phaseAt : 0' in js and "entry.approvalMs" in js
    assert "slower than usual (" in js and "no timings on this computer yet" in js


def test_an_open_approval_prompt_is_never_reported_as_a_stall(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "STALL_SECONDS", 0.05)
    b = _bridge(tmp_path)

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"type": "agent_start"}\n')
        reader.feed_data(b'{"type": "extension_ui_request", "id": "d1", "method": "confirm", "title": "Allow?", "message": "m"}\n')

        async def wait():
            return 0
        proc = SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=None)
        pump = asyncio.ensure_future(b.pump(proc))
        await asyncio.sleep(0.3)                 # far past STALL_SECONDS, with the person reading the prompt
        stalled = b.stalled
        reader.feed_eof()
        proc.returncode = 0
        await pump
        return stalled
    assert asyncio.run(run()) is False


def test_the_back_arrow_replaces_the_home_button():
    """Henry, 19 Sep: "now that we have the left button too, let's just replace it with an arrow going left
    before this text" (the matter's name)."""
    html = (STATIC / "index.html").read_text()
    js = (STATIC / "app.js").read_text()
    assert 'id="back"' in html and 'id="top-home"' not in html
    assert '$("top-home")' not in js, "the labelled top-bar home button must be gone"
    assert 'back.addEventListener("click", () => goHome(`/matter/${matterId}`))' in js


# ── statistics for the progress view ──
#
# Henry, 19 Sep: "we need better statistics for informing the progress view", then "when I reload, the time
# counters in the progress views also reset — that's not right". Both were real.

def _search_events(b, *, k=10, approval=False, ok=True):
    b.publish({"kind": "tool_start", "call": "c1", "tool": "prior_art_search", "args": {"text": "x" * 30, "k": k}}, agent=True)
    b.publish({"kind": "tool_progress", "call": "c1", "phase": "verifying"}, agent=True)
    if approval:
        b.publish({"kind": "tool_progress", "call": "c1", "phase": "approval"}, agent=True)
    b.publish({"kind": "tool_progress", "call": "c1", "phase": "searching"}, agent=True)
    b.publish({"kind": "tool_end", "call": "c1", "tool": "prior_art_search", "ok": ok,
               "details": {"ok": ok, "docs": []}}, agent=True)


def test_every_event_carries_the_servers_time_so_a_reload_does_not_reset_the_clocks(tmp_path):
    b = _bridge(tmp_path)
    b.publish({"kind": "user", "text": "hi"})
    assert isinstance(b.history[-1]["at"], int) and b.history[-1]["at"] > 1_700_000_000_000
    js = (STATIC / "app.js").read_text()
    # Durations are computed from the stamps, never from when the page happened to receive an event.
    assert "performance.now()" not in js


def test_a_completed_search_records_its_wait_per_step_and_its_result_is_not_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    b = _bridge(tmp_path)
    _search_events(b, k=50)
    kinds = [e["kind"] for e in b.history]
    # The statistics follow the result, numbered after it: numbered before, the page would skip the result.
    assert kinds.index("search_timing") == kinds.index("tool_end") + 1
    seqs = [e["seq"] for e in b.history]
    assert seqs == sorted(seqs)
    from inferroute_cli import probant_timing as T
    rows = [json.loads(l) for l in T.waits_path().read_text().splitlines()]
    assert rows[0]["bucket"] == "broad" and rows[0]["k"] == 50
    assert set(rows[0]) == {"at", "bucket", "k", "verifying_ms", "searching_ms"}      # numbers only
    assert oct(T.waits_path().stat().st_mode & 0o777) == "0o600"


def test_a_refused_search_measures_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    b = _bridge(tmp_path)
    _search_events(b, ok=False)
    from inferroute_cli import probant_timing as T
    assert not T.waits_path().exists()


def test_the_approval_prompt_is_the_persons_time_not_the_machines(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    b = _bridge(tmp_path)
    clock = iter([1000, 1000, 1400, 61400, 61900, 61900, 70000, 70000])     # 60 s spent reading the prompt
    monkeypatch.setattr(W.time, "time", lambda: next(clock) / 1000)
    _search_events(b, approval=True)
    from inferroute_cli import probant_timing as T
    row = json.loads(T.waits_path().read_text().splitlines()[0])
    assert row["verifying_ms"] == 400 and row["searching_ms"] == 500        # not 60 900


def test_expectations_are_per_depth_and_say_where_they_come_from(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    from inferroute_cli import probant_timing as T
    # With no waits recorded, the searching step is seeded from the machine's own signed times — per depth,
    # and labelled "machine", because that is part of the wait, not all of it.
    rec = tmp_path / "ir" / "confidential" / "attested-records" / "A" / "m"
    rec.mkdir(parents=True)
    rows = [{"statement": {"sig": "s", "k": 10, "search_seconds": 0.4}}] * 6 + \
           [{"statement": {"sig": "s", "k": 50, "search_seconds": 1.7}}] * 6 + \
           [{"statement": {"k": 10, "search_seconds": 99}}] * 6                 # unsigned: not evidence
    (rec / "s.searches.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    s = T.stats()
    assert s["verifying"] is None                                           # nothing measured: say nothing
    assert s["searching"]["quick"] == {"n": 6, "median_ms": 400.0, "p90_ms": 400.0, "source": "machine"}
    assert s["searching"]["broad"]["median_ms"] == 1700.0
    # Once enough real waits exist for a depth, they replace the seed for that depth only.
    for _ in range(5):
        T.record_wait(k=10, verifying_ms=300, searching_ms=900)
    s = T.stats()
    assert s["searching"]["quick"]["source"] == "wait" and s["searching"]["quick"]["median_ms"] == 900.0
    assert s["searching"]["broad"]["source"] == "machine"
    assert s["verifying"]["median_ms"] == 300.0


def test_assistant_prompts_wait_in_line_instead_of_replacing_each_other():
    """19 Sep, caught by the event recorder: five parallel searches raised five approval prompts within 10 ms.
    The page has one dialog; each prompt replaced the last on screen, the last was answered, and the other four
    searches hung at "waiting for your approval" with nothing left to click — the stall of 18 Sep, explained."""
    js = (STATIC / "app.js").read_text()
    assert 'case "dialog": queueDialog(ev); break;' in js
    assert 'case "dialog_closed": dropDialog(ev.id); break;' in js
    body = js[js.index("function showNextDialog"):js.index("function showNextDialog") + 400]
    assert "if (openDialog || !$(\"dialog\").hidden || ended) return;" in body   # one at a time, never on top
    ts = (Path(W.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    # And at the source: searches issued at once share ONE approval question per machine.
    assert "const approvals = new Map<string, Promise<boolean>>();" in ts
    assert "let pending = approvals.get(measurement);" in ts


def test_the_activity_bar_has_a_step_clock_and_a_since_you_asked_clock():
    """Henry, 19 Sep: "it would be good if 'The assistant is working…' also had a timer so we know when it
    started processing something new". The step clock restarts whenever the words on the bar change (a new
    step); the turn clock runs from when the assistant took up the message. Both come from the server's
    stamps, so — like the search clock — a reload does not start them again at zero."""
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    assert 'id="activity-time"' in html
    assert "if (ev.at) lastEventAt = ev.at;" in js
    assert "if (text !== stepText) { stepText = text; stepAt = lastEventAt || serverNow(); }" in js
    assert "turnAt = busy ? (ev.at || serverNow()) : null;" in js
    assert "since you asked" in js and "performance.now()" not in js


def test_a_document_seen_before_names_the_search_by_what_it_was_about():
    """Henry, 19 Sep: "instead of 'also in search 2' let's say also in 'Routing by permission'". Runs the
    page's real shortAbout(), which both the per-document pill and the folded head use."""
    import shutil, subprocess
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "card_head_sim.js")], cwd=root, capture_output=True, text=True, timeout=60)
    naming = json.loads(r.stdout.strip().splitlines()[-1])["naming"]
    assert naming["known"] == "‘Routing by permission’"
    assert naming["long"].endswith("…’") and len(naming["long"]) <= 44          # cut to one line
    assert naming["unknown"] == "search 9"                                     # only when not on this page
    js = (STATIC / "app.js").read_text()
    assert "doc.alsoIn ? seenIn(doc.alsoIn) : null" in js
    assert "tag.title = `Also returned by search ${no}: ${e.about}`" in js     # the full wording on hover

def test_a_slip_in_an_optional_hint_costs_the_hint_never_the_search():
    """19 Sep: the assistant named a search with an 86-character label; the schema capped it at 80, so Pi
    rejected the WHOLE call — "Validation failed for tool prior_art_search: feature: must not have more than
    80 characters" — and the page showed that raw, with the full request dumped in, in red. The code already
    shortened labels; the schema limit only turned a cosmetic slip into a lost search."""
    ts = (Path(W.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    schema = ts[ts.index('name: "prior_art_search"'):ts.index("async execute(_toolCallId, params, signal, onUpdate, ctx)")]
    for limit in ("maxLength", "minimum", "maximum", "Type.Literal("):
        assert limit not in schema, f"an optional hint carries a hard schema limit again: {limit}"
    assert "const k = Math.min(50, Math.max(1, Math.round(Number(asked) || 10)));" in ts
    assert "if (feature.length > 80) {" in ts
    from inferroute_cli import probant_timing as T
    assert T.k_of({"k": 100}) == 50 and T.k_of({"depth": "Medium"}) == 10 and T.k_of({"depth": "BROAD"}) == 50
    js = (STATIC / "app.js").read_text()
    assert "Validation failed for tool" in js                     # shown as the assistant's slip, quietly
    assert "it corrected it" not in js                            # the page cannot know that


def test_one_next_steps_panel_counts_and_covers_by_action():
    """Henry, 19 Sep: "we have NEXT STEPS and FROM YOUR MARKS … polish the double to look more together and
    adapt counts in a smart way". Drives the page's real code (tests/steps_panel_sim.js) through the cases."""
    import shutil, subprocess
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "steps_panel_sim.js")], cwd=root, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-600:]
    R = json.loads(r.stdout.strip().splitlines()[-1])
    deeper = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them"
    deep = "Search deeply: put the whole disclosure, its features, and my marks to the search machine"
    # The deep search is guaranteed by the PAGE once a conversation has started: it is the headline action of
    # this client, and leaving it to the assistant to remember would make it appear or not depending on how an
    # answer happened to end. It rides on its own row and does not take one of the five places — so each case
    # below asserts the steps that case is about, with the deep row as a constant on the end.
    tail = {"title": "", "steps": [deep]}
    # 1. A new session on a matter marked in an earlier one, no answer and no search yet: running the survey
    #    comes first — a new session is its own sitting (Henry, 19 Sep) — then the steps from the marks.
    assert R["s1"] == [{"title": "", "steps": ["Run a prior-art survey of the disclosure"]},
                       {"title": "From your marks", "steps": [deeper, "Find documents like US-A1"]}, tail]
    # 1b. Once this session has searched, the survey is no longer offered on its own account.
    assert R["s1b"] == [{"title": "From your marks", "steps": [deeper, "Find documents like US-A1"]}, tail]
    # 2. The assistant saw that mark and chose its own list — including DROPPING "look deeper". Respected.
    assert len(R["s2"]) == 2 and R["s2"][0]["title"] == "" and deeper not in R["s2"][0]["steps"]
    assert R["s2"][-1] == tail
    # 3. Marks made after it answered are added — and a step that merely DESCRIBES a mark ("…you marked
    #    relevant") does not count as offering "look deeper".
    assert R["s3"][1] == {"title": "From marks you made since", "steps": ["Find documents like US-B2", deeper]}
    # 4. Five at most, but marks made since always keep a place. The deep row is extra to that count.
    assert len(R["s4"][0]["steps"]) == 4 and R["s4"][1]["steps"] == ["Find documents like US-B2"]
    assert R["s4"][-1] == tail
    # 5. While the assistant works on a new message, the previous answer's steps are stale: nothing shown —
    #    and the guaranteed deep row must not resurrect the panel while a message is in flight.
    assert R["s5"] is None
    # 6-7. No marks, no list: ideas once the conversation has started, nothing before it — including no deep
    #    row before the conversation exists, since there is nothing yet to search deeply.
    assert R["s6"][0]["title"] == "Ideas" and "Summarise what the searches have surfaced so far" not in R["s6"][0]["steps"]
    assert R["s6"][-1] == tail
    assert R["s7"] is None
    # 8. No search machine — which is every client on its first day, before one is set up. The deep button
    #    is not offered at all: the session registers no search tools, so pressing it would send a sentence
    #    the assistant has no way to act on. The ordinary mark steps still stand.
    assert R["s8"] and all(deep not in g["steps"] for g in R["s8"])
    assert any(deeper in g["steps"] for g in R["s8"])


def test_the_unrecognised_events_line_names_only_what_is_new(tmp_path):
    """The closing line lists event types the page has no word for, to catch something NEW. It counted every
    event the page chose to ignore — the professional's own messages, turn boundaries, now the marks note — so
    it would have listed routine noise in every session and buried the one line worth reading."""
    b = _bridge(tmp_path)

    async def run():
        reader = asyncio.StreamReader()
        for ev in ({"type": "message_start", "message": {"role": "user"}}, {"type": "message_end", "message": {"role": "custom"}},
                   {"type": "turn_start"}, {"type": "turn_end"}, {"type": "agent_end"}, {"type": "some_future_event"}):
            reader.feed_data((json.dumps(ev) + "\n").encode())
        reader.feed_eof()

        async def wait():
            return 0
        await b.pump(SimpleNamespace(stdout=reader, stdin=FakeStdin(), wait=wait, returncode=0))
        return b.ended
    assert asyncio.run(run())["unrecognised"] == {"some_future_event": 1}


def test_search_cards_start_folded_and_the_head_carries_the_counts_and_overlap():
    """Henry, 19 Sep: "by default, could you not even expand the search results frames, just update within the
    compacted view what needs to be, and perhaps add notes describing how many appeared in what other search".
    Drives the page's real refreshCardSummary()/shortAbout() (tests/card_head_sim.js)."""
    import shutil, subprocess
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "card_head_sim.js")], cwd=root, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-600:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["withMarks"]["sub"] == "9 documents · 2 new"
    notes = out["withMarks"]["notes"]
    # Largest overlaps first, named by what those searches were about; the rest counted; then your marking.
    assert notes.startswith("3 also in ‘Routing by permission’ · 2 also in ‘Ledger of what has been drawn")
    assert "2 in 2 other searches" in notes and notes.endswith("3 marked, 2 relevant")
    assert out["lone"] == {"sub": "10 documents", "hidden": True}      # nothing to say: no empty line
    js = (STATIC / "app.js").read_text()
    # Folded from the start — every search, including the one running — with a refusal still opening itself.
    assert "      cards.set(ev.call, entry);\n      setCollapsed(entry, true);" in js
    assert "setCollapsed(entry, false);                 // a refusal is short and worth reading" in js


def _fn_body(js: str, name: str) -> str:
    """The source of ONE function, to the start of the next top-level one.

    Three assertions in this file sliced a fixed byte count after `function showError` (1400, 2600). On
    30 Sep a correct change added a comment block inside it and the button they were checking for moved past
    the window, so they failed for a reason unrelated to what they test. A byte count is not a scope."""
    start = js.index(f"function {name}")
    rest = js[start + 1:]
    nxt = rest.find("\n  function ")
    return rest[:nxt] if nxt != -1 else rest


def test_a_failed_answer_offers_a_way_on_that_sends_exactly_its_words():
    """Henry, 19 Sep: "The AI machine couldn't be reached … (4 times)" — "and I don't even have a button to
    retry". The button asks the assistant to continue rather than resending the question, so a failure after
    searches had run does not redo them; and it sends exactly what it says."""
    js = (STATIC / "app.js").read_text()
    body = _fn_body(js, "showError")
    assert 'const again = el("button", "ghost small", RETRY_TEXT);' in body
    assert "send(RETRY_TEXT)" in body
    assert 'const RETRY_TEXT = "Continue where you left off";' in js


def test_when_continuing_fails_too_the_page_offers_a_fresh_session():
    """19 Sep: Henry pressed "Continue where you left off" in a session started before the re-pin fix; it failed
    again, and again — a session's AI-machine side runs the code it started with. When the next try fails too,
    the session is stuck: the page says so and offers the way out, a fresh session, which re-checks from scratch."""
    js = (STATIC / "app.js").read_text()
    body = _fn_body(js, "showError")
    assert "failedTries += 1;" in body and "if (failedTries >= 2) {" in body
    assert "Start a fresh session on this matter" in body and "goHome(`/matter/${matterId}`)" in body
    # Counted per failed ANSWER (repeats inside one answer collapse into "(4 times)"), reset by one that gets
    # through. Bound to the PROPERTY, not to one line: the reset grew a block on 30 Sep when a transient
    # failure started retrying quietly, and an assertion on the old one-liner failed for a reason unrelated
    # to what it was testing.
    reset = js[js.index("function assistantEnd"):js.index("function assistantEnd") + 900]
    assert "if (!ev.stopped && current.text.trim())" in reset and "failedTries = 0;" in reset
    # The counter must be incremented BEFORE the quiet path can return, or showing a failure discreetly
    # would push the fresh-session offer further away than the number of failures warrants.
    quiet_guard = body.index("if (isTransient(detail)")
    assert body.index("failedTries += 1;") < quiet_guard
    assert js.count("failedTries += 1;") == 1, "one failure must count once"


def test_marked_documents_carry_their_titles_from_every_recorded_search(tmp_path):
    """The marks panel shows what each marked document is about — including documents marked in an EARLIER
    session, whose results are not on this page — from every search recorded on the matter."""
    rec = tmp_path / "rec"
    rec.mkdir()
    (rec / "a.searches.jsonl").write_text(json.dumps({"result": {"hits": [{"key": "EP-1-A1", "title": "Sealed ledger"},
                                                                          {"key": "US-2-B2", "title": "Unmarked"}]}}) + "\n")
    (rec / "b.searches.jsonl").write_text("not json\n" + json.dumps({"result": {"hits": [{"key": "WO-3-A1", "title": "Replay"}]}}) + "\n")
    from inferroute_cli.pi_attested import matter_titles
    assert matter_titles(rec, {"EP-1-A1", "WO-3-A1", "XX-9"}) == {"EP-1-A1": "Sealed ledger", "WO-3-A1": "Replay"}
    assert matter_titles(None, {"EP-1-A1"}) == {} and matter_titles(rec, set()) == {}
    # No key filter: every document the matter's searches returned (the launcher hands these to the assistant).
    assert matter_titles(rec) == {"EP-1-A1": "Sealed ledger", "US-2-B2": "Unmarked", "WO-3-A1": "Replay"}
    js = (STATIC / "app.js").read_text()
    # Same three buttons as a search card; changing a mark here re-renders everything that shows it.
    assert "markButtons(k, null, false)" in js and "renderMarksPanel();" in js


def test_next_steps_sit_in_the_conversation_after_the_latest_answer():
    """Henry, 19 Sep, with a screenshot of the framed panel above the message box: "maybe we should blend the
    buttons into the chat". The same panel now follows the latest answer inside the conversation, unframed."""
    js = (STATIC / "app.js").read_text()
    body = js[js.index("function renderSteps"):js.index("function renderMarkSteps")]
    assert "log.append(bar);" in body and "if (log.lastElementChild !== bar)" in body
    assert 'function clearNext() { assistantSteps = []; $("mark-steps").hidden = true; }' in js
    css = (STATIC / "app.css").read_text()
    assert ".mark-steps { margin: -4px 0 0; padding: 0; }" in css          # no frame of its own


def test_the_suggestions_tool_closes_the_turn_instead_of_inviting_a_remark():
    """The model wrote "(The step buttons above are shown on your screen now.)" — against the contract, and
    wrong: they were below. After a tool call the framework asks it to continue, and "Shown." gave it nothing
    to end on."""
    ts = (Path(W.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    assert "end your turn with no further text, and do not refer to the steps or the buttons" in ts
    assert 'text: steps.length ? "Shown."' not in ts


def test_the_protection_panel_is_compact_but_hides_nothing_it_cannot_name():
    """Henry, 19 Sep: "make the private certifications section more compact so that the beginning of your marks
    is visible without scrolling". One line per protection; points and detail behind "More"; the explanation and
    the limits behind labelled toggles — the limits one saying HOW MANY there are."""
    js = (STATIC / "app.js").read_text()
    body = js[js.index("function renderTrust"):js.index("// ── conversation ──")]
    assert "What this can't prove" not in body       # Henry, 19 Sep: not relevant in the panel
    assert 'if (points.length) more.append(el("ul", "item-points"' in body     # points moved behind "More"
    assert '"How a sealed machine keeps this private"' in body
    assert 'head.append(el("ul", "item-points"' not in body                     # no longer shown by default
    # Henry, 19 Sep: "maybe it can be made to look more impressive and good looking". The verdict is a seal
    # (badge, one word, the headline without repeating it, when it was checked) and the protections one chain;
    # "More" moved onto the title line, so the redesign made the panel shorter, not taller.
    assert 'el("span", "seal"' in body and 'el("div", "chain")' in body
    assert "line.startsWith(word)" in body
    css = (STATIC / "app.css").read_text()
    assert ".chain::before" in css and ".more-toggle { grid-column: 3; grid-row: 1;" in css


def test_parallel_malformed_requests_fold_into_one_line_whatever_order_they_fail_in():
    """Henry, 19 Sep: "it only showed this at some point … The assistant's search request was malformed, so
    nothing was sent. (x10)". Ten parallel requests failed; each became its own line. Drives the page's real
    recordSlip() (tests/slip_sim.js): ten cards failing out of order end as ONE line with a count, and a later
    slip after a message starts a new line rather than joining an old one."""
    import shutil, subprocess
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "slip_sim.js")], cwd=root, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["lines"] == 1 and out["count"] == " (10 requests)"
    assert out["afterMessage"] == 2 and out["lateCount"] == ""
    js = (STATIC / "app.js").read_text()
    assert "was not returned by (a|any) search" in js and "recordSlip(card);" in js


def test_the_panel_proves_what_it_claims_with_the_records_own_verifier(client, monkeypatch):
    """Henry, 19 Sep: the panel was "missing the proof". Export and check are one act; the verdict comes from
    probant_check (the bundle's own verifier, its exit code), never from the page."""
    from inferroute_cli import probant_check
    seen = []
    monkeypatch.setattr(probant_check, "check", lambda d: seen.append(str(d)) or
                        {"verdict": "passed", "headline": "Everything checked out.", "groups": [], "checks": 7, "output": "raw"})
    b, c = client
    r = c.post("/api/prove", json={}).json()
    assert r["ok"] and r["check"]["verdict"] == "passed" and r["check"]["checks"] == 7
    assert seen == [r["path"]]                      # the check ran on the record that was just exported
    assert "output" not in r["check"]               # raw verifier output stays on this computer's side
    js = (STATIC / "app.js").read_text()
    assert 'api("/api/prove", {})' in js and "renderCheck(verdict, r.check || {}, true);" in js
    common = (STATIC / "common.js").read_text()
    assert "function renderCheck(box, r, compact)" in common and 'if (compact && g.status !== "pass") item.open = true;' in common


def test_a_skip_that_applies_to_every_search_is_said_once_with_its_count():
    """A 68-search record printed the same "firmware minimum not pinned" sentence 68 times and buried the answer."""
    from inferroute_cli import probant_check as C
    text = "\n".join(["  PASS hardware report: SNP report version 3, signed"]
                     + ["  SKIP firmware TCB at or above minimum: no minimum pinned for Genoa"] * 68
                     + ["  SKIP debug disabled: other reason"])
    g = next(g for g in C.parse(text, 0)["groups"] if g["key"] == "machine")
    assert g["not_checked"] == ["firmware TCB at or above minimum: no minimum pinned for Genoa (in 68 searches)",
                                "debug disabled: other reason"]


def test_the_audit_pack_is_made_from_the_record_this_page_proved_never_a_path_it_is_sent(client, monkeypatch):
    """The professional's own AI audits an evidence-only copy (Henry, 19 Sep). The page cannot name a folder:
    the pack is made from the record this page exported and checked, or not at all."""
    from inferroute_cli import probant_check, probant_export
    monkeypatch.setattr(probant_check, "check", lambda d: {"verdict": "passed", "groups": [], "checks": 1})
    made = []
    monkeypatch.setattr(probant_export, "write_audit_pack", lambda d: made.append(str(d)) or Path("/tmp/audit-pack-x"))
    b, c = client
    # Offered from the start (Henry, 20 Sep: "integrate this audit thing in the chat page"), so with nothing
    # exported yet it writes the record first — one click, not a sequence the professional must know.
    first = c.post("/api/audit-pack", json={"path": "/etc"})
    assert first.status_code == 200 and len(made) == 1
    proved = c.post("/api/prove", json={}).json()["path"]
    assert proved == made[0]                     # the same record, not a second export
    r = c.post("/api/audit-pack", json={"path": "/etc"}).json()
    assert made == [proved, proved]
    # `ir` reads a bare first word as a subcommand, so its command starts with a flag; an enclave-backed model.
    # --plain since 24 Sep: the pack carries no client words, so there is nothing to seal and
    # the sealed lane would only put a proof card and a keypress before the auditor's work.
    assert r["ir"].startswith("ir --plain --model kimi-k2.6 ") and r["claude"].startswith("claude ")
    # Quoted with shlex, not wrapped in double quotes by hand: the prompt is a literal argument, and a
    # hand-rolled quote breaks the day it contains a " or a $.
    import shlex as _shlex
    from inferroute_cli import probant_export as _E
    assert r["ir"].endswith(_shlex.quote(_E.AUDIT_PROMPT))
    assert r["claude"].endswith(_shlex.quote(_E.AUDIT_PROMPT))
    js = (STATIC / "app.js").read_text()
    assert 'api("/api/audit-pack", {})' in js and "No Claude subscription?" in js
    assert 'auditOffer($("audit"))' in js                     # in the panel, not inside the export result
    assert "ten to fifteen minutes" in js                     # a tester who interrupts it gets nothing


def test_a_reading_round_ends_when_its_work_is_done_not_when_a_turn_ends(client):
    """Measured 20 Sep: reading three documents takes several turns, and the model ends one to say "now the
    next". Closing the session there killed two jobs of seven mid-read, and each reported zero findings —
    indistinguishable from documents that assert nothing. A round with nothing recorded gets ONE reminder."""
    js = (Path(__file__).resolve().parent.parent / "inferroute_cli" / "probant_web.py").read_text()
    body = js[js.index("    async def _end_round"):js.index("    async def open_with")]
    assert "if not self.recorded and not self.nudged:" in body
    assert "self.nudged = True" in body                      # one reminder, never a loop
    assert "record_findings" in body and "stop" in body
    # The counter only moves on a tool that actually records something.
    b, c = client
    assert b.recorded == 0
    for tool, expect in (("read", 0), ("record_findings", 1), ("propose_matter", 2), ("ls", 2)):
        b.publish({"kind": "tool_end", "call": f"x:{tool}", "tool": tool, "ok": True, "text": ""})
        assert b.recorded == expect, tool


def test_a_round_that_records_nothing_leaves_its_reason_behind(client, tmp_path, monkeypatch):
    """Three jobs of seven produced nothing and all I had was a stopwatch reading (20 Sep). A round now
    writes why it ended, how many turns it took and its own last words — to the run directory, never to a
    console, because whoever runs this may be an agent whose transcript leaves the machine."""
    b, c = client
    log = tmp_path / "rounds.jsonl"
    monkeypatch.setenv("IR_ROUND_LOG", str(log))
    b.publish({"kind": "tool_start", "call": "1", "tool": "read", "args": {}})
    b.publish({"kind": "assistant_end", "text": "I could not find the documents directory."})
    b._write_round_log("nothing recorded after a reminder")
    row = json.loads(log.read_text().splitlines()[-1])
    assert row["recorded"] == 0 and row["turns"] == 1 and row["tools"] == {"read": 1}
    assert row["last_words"] == "I could not find the documents directory."
    assert row["ended"] == "nothing recorded after a reminder"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_a_turn_that_stopped_on_an_error_is_recorded_not_left_as_silence(client, tmp_path, monkeypatch):
    """In the first full-corpus pass, 62 of 76 empty rounds made NO tool call and said nothing at all: the
    call failed and the round looked exactly like a document with nothing in it. The round log now carries
    the error and whether the session got a usable answer, so a zero can be retried instead of believed."""
    b, c = client
    log = tmp_path / "rounds.jsonl"
    monkeypatch.setenv("IR_ROUND_LOG", str(log))
    b.publish({"kind": "assistant_end", "text": "", "stopped": "error", "error": "upstream refused the request"})
    b._write_round_log("nothing recorded after a reminder")
    row = json.loads(log.read_text().splitlines()[-1])
    assert row["worked"] is False and row["recorded"] == 0
    assert "upstream refused the request" in row["error"]
    b.publish({"kind": "tool_start", "call": "1", "tool": "read", "args": {}})
    b._write_round_log("work done")
    assert json.loads(log.read_text().splitlines()[-1])["worked"] is True


def test_a_round_says_when_it_happened_and_which_job_it_was(client, tmp_path, monkeypatch):
    """A resumed run on 20 Sep had 195 rounds in its log and not one of them said WHEN. Working out whether
    it was still moving meant reading process start times and file modification times from outside — an
    artefact should not need an outside witness to be read, and "which document went quiet" should be
    answerable from the log rather than by elimination."""
    b, c = client
    log = tmp_path / "rounds.jsonl"
    monkeypatch.setenv("IR_ROUND_LOG", str(log))
    monkeypatch.setenv("IR_ROUND_LABEL", "P3-claims.md 0-40000")
    before = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    b.publish({"kind": "tool_start", "call": "1", "tool": "propose_item", "args": {}})
    b._write_round_log("work done")
    row = json.loads(log.read_text().splitlines()[-1])
    assert row["label"] == "P3-claims.md 0-40000"
    at = dt.datetime.strptime(row["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    assert before <= at <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)
    # A run whose rounds are timestamped can be read as a rate: two rounds, two times, in order.
    b._write_round_log("work done")
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows[0]["at"] <= rows[1]["at"]
    # No label set (a session outside a cluster run) is an empty string, never a missing key.
    monkeypatch.delenv("IR_ROUND_LABEL")
    b._write_round_log("work done")
    assert json.loads(log.read_text().splitlines()[-1])["label"] == ""


def test_the_page_learns_about_the_search_machine_from_the_session_payload():
    """The deep button is gated on whether this session has a search machine, and the panel simulator sets
    that flag directly — so the WIRE between the server's /api/session and the page's variable is checked by
    nothing. Delete the assignment and the button silently never appears again; rename the field on the
    server and the same. Both ends are asserted here, against the same key name."""
    py = Path(W.__file__).resolve().read_text()
    js = (STATIC / "app.js").read_text()
    # The server tells the page, in the session payload, whether a search endpoint is configured.
    assert '"search": bool(bridge.search_endpoint)' in py
    # The page reads THAT key into the flag the steps panel gates on.
    assert "searchOffered = Boolean(s.search);" in js
    assert "started && searchOffered &&" in js, "the guaranteed deep row is no longer gated on it"


# ── launching the audit in a terminal (24 Sep) ──

def test_the_page_picks_an_agent_and_never_a_command():
    """This is the one endpoint on this page that starts a program, so what the page may say is the whole
    security question. It sends a choice from two; the command is composed server-side from the same
    constants the copyable text uses. If a command string from the page could reach the launcher, anything
    that reached the page could run anything on this computer."""
    py = Path(W.__file__).resolve().read_text()
    launcher = py[py.index('@app.post("/api/audit-launch")'):py.index('@app.post("/api/close")')]
    assert 'agent not in ("claude", "ir")' in launcher          # a closed set, rejected otherwise
    # Nothing from the request body may become part of what runs: `agent` is compared, never interpolated.
    for forbidden in ('d.get("command"', 'd.get("cmd"', 'd.get("path"', "shell=True"):
        assert forbidden not in launcher, forbidden
    assert "probant_export.audit_command(agent)" in launcher     # composed there, not assembled here


def test_the_shown_command_and_the_run_command_are_the_same_string():
    """The panel shows a command and the button runs one. Built twice, they drift — and the one place that
    must never lie about what it runs is the panel asking for a second opinion on our own proof."""
    from inferroute_cli import probant_export as E
    py = Path(W.__file__).resolve().read_text()
    for agent in ("claude", "ir"):
        assert f'probant_export.audit_command("{agent}")' in py or "audit_command(agent)" in py
    assert E.audit_command("claude").startswith("claude ")
    assert E.audit_command("ir").startswith("ir --plain --model ")


def test_the_audit_runs_on_the_standard_lane_because_the_pack_holds_no_client_words():
    """Henry, 24 Sep: this one doesn't need the confidential lane, and that way it won't require Enter after
    the proof check. The lane exists to keep an unfiled invention out of the clear, and the pack has none in
    it — query, result and document text are withheld from every row, and the folder name carries no matter
    name. With nothing to seal it buys the auditor nothing and costs them a card and a wait before any work
    starts. This test is the tripwire for that reasoning: if the pack ever carries the words again, the
    withheld list changes and this fails, which is the moment to put it back on the sealed lane."""
    from inferroute_cli import probant_export as E
    assert "--plain" in E.audit_command("ir")
    assert E.WITHHELD_FIELDS == ("query_text", "result", "text")


def test_no_terminal_means_the_offer_falls_back_to_copying(monkeypatch):
    """A machine with no desktop has no terminal to open. The page is told so and keeps the copyable
    command, rather than showing a button that cannot work — the same rule as the deep-search button."""
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(W.sys, "platform", "linux")
    assert W.terminal_argv(Path("/tmp/x.sh")) is None
    js = (STATIC / "app.js").read_text()
    assert "r.can_launch" in js and "Copy (goes to the folder too)" in js


def test_each_terminal_gets_its_own_separator(monkeypatch):
    """They disagree, and the wrong flag opens a window that flashes and closes — which reads as the
    feature being broken rather than the flag being wrong. xfce4-terminal's -e takes ONE string and would
    mangle an argv, so it must get -x; kitty and foot take the command with no flag at all."""
    monkeypatch.setattr(W.sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    seen = {}
    for name, sep in W._TERMINALS:
        seen[name] = sep
    assert seen["gnome-terminal"] == ["--"]
    assert seen["xfce4-terminal"] == ["-x"], "xfce4-terminal -e takes one string, not an argv"
    assert seen["kitty"] == [] and seen["foot"] == []


def test_the_launch_script_runs_in_the_pack_and_is_not_written_into_it(tmp_path):
    """The script goes to a private temp dir. The audit pack is evidence a third party will hash, and a
    script we dropped into it afterwards is one more thing they have to account for."""
    pack = tmp_path / "audit-pack"
    pack.mkdir()
    sh = W.audit_launch_script(pack, "claude 'do the thing'")
    body = sh.read_text()
    assert str(pack) in body and "claude 'do the thing'" in body
    assert sh.parent != pack and not list(pack.iterdir()), "the launcher wrote into the audit pack"
    assert os.access(sh, os.X_OK)
    # The window stays open after the agent exits: a terminal that vanishes takes the verdict with it.
    assert "exec bash" in body


def test_the_page_keys_cards_on_the_field_the_bridge_actually_sends():
    """The deep-survey card sat on "planning the queries…" while six sealed queries ran, finished and were
    reported. It was stored under `ev.toolCallId` — a name the bridge does not send — so the key was
    `undefined`, the result lookup found nothing, and the card never learned it was done.

    `toolCallId` is the bridge's INTERNAL name for that field; on the wire it is `call`. Any use of it in
    the page is a lookup that silently never matches, and nothing about it looks wrong on the screen except
    a card that waits forever."""
    py = Path(W.__file__).resolve().read_text()
    js = (STATIC / "app.js").read_text()
    # The bridge's wire name, at both ends of a tool's life.
    assert '"kind": "tool_start", "call": ev.get("toolCallId")' in py
    assert '"kind": "tool_end", "call": ev.get("toolCallId")' in py
    # The page must never key off the internal name.
    # Comments are stripped first: the line explaining this bug naturally quotes the wrong name, and a
    # guard that trips on its own explanation teaches people to delete the explanation.
    import re as _re
    code = _re.sub(r"^\s*//.*$", "", js, flags=_re.M)
    assert "ev.toolCallId" not in code, "the page reads a field the bridge does not send"
    # And the deep card is stored and found under the same one.
    deep = js[js.index('if (ev.tool === "deep_prior_art_search") {'):]
    assert "cards.set(ev.call, entry)" in deep


def test_a_deep_survey_card_folds_and_reaches_the_outline_like_a_search():
    """It is not a special case. It folds, so a finished survey does not hold the conversation open; and it
    is in the left index, because a press is the largest single thing that happens in a session and was the
    one thing there with no way to jump to it."""
    js = (STATIC / "app.js").read_text()
    deep = js[js.index('if (ev.tool === "deep_prior_art_search") {'):]
    deep = deep[:deep.index("if (ev.tool === \"prior_art_search\")")]
    for must in ("card-toggle", "setCollapsed(entry, true)", "outlineAdd(", "autoCollapse()"):
        assert must in deep, must
    # The head holds the counts you read folded; the body holds what you open it for.
    end = js[js.index('if (ev.tool === "deep_prior_art_search") {', js.index("function toolEnd") if "function toolEnd" in js else 0):]
    assert "e.notes.textContent" in end and "e.body.append" in end


def test_a_survey_reports_its_position_and_the_channel_carries_only_integers():
    """A press is several sealed searches and takes minutes. With only a phase name the card repeats the
    same three words and reads as stalled — Henry, 24 Sep: "it would be nice if it didn't stall for that
    long… instead showed more of the steps."

    Position crosses as two integers and nothing else. The rule it sits under exists because a partial
    result "for another tool could carry anything", and a channel that admits only bounded ints cannot
    become a content channel by accident later. The page composes the words."""
    ev = {"type": "tool_execution_update", "toolCallId": "c1",
          "partialResult": {"details": {"phase": "searching", "step": 3, "steps": 6}}}
    out = W.normalize(ev)
    assert out and out[0]["step"] == 3 and out[0]["steps"] == 6

    # Anything that is not a small int is dropped, including bools and out-of-range values.
    for bad in ({"phase": "searching", "step": "3", "steps": 6},
                {"phase": "searching", "step": True, "steps": 6},
                {"phase": "searching", "step": 400, "steps": 6},
                {"phase": "searching", "step": {"n": 1}, "steps": 6}):
        got = W.normalize({"type": "tool_execution_update", "toolCallId": "c1",
                           "partialResult": {"details": bad}})[0]
        assert "step" not in got, f"{bad['step']!r} reached the page"

    # And no free text rides along, whatever the tool puts there.
    got = W.normalize({"type": "tool_execution_update", "toolCallId": "c1", "partialResult": {"details": {
        "phase": "searching", "step": 1, "steps": 2, "about": "a document's text", "result": "leak"}}})[0]
    assert set(got) == {"kind", "call", "phase", "step", "steps"}

    # The page turns them into words rather than being sent words.
    js = (STATIC / "app.js").read_text()
    assert "search ${ev.step} of ${ev.steps}" in js


def test_a_heartbeat_keeps_the_page_alive_without_hiding_a_slow_search():
    """A survey mode that puts ONE sealed call needs that call to outlive the page's two-minute silence
    budget. The extension owns the phase stream, so it beats while the call is outstanding — and any event
    from the agent resets the stall clock.

    The trap is the obvious implementation: re-running setPhase on every beat restarts `phaseAt`, which is
    what "slower than usual" is measured from. A liveness signal that overwrites a duration would hide
    exactly the slow search the indicator exists to surface. A repeat is a heartbeat, not a transition."""
    ts = (STATIC.parent / "pi_attested" / "ir-attested.ts").read_text()
    js = (STATIC / "app.js").read_text()

    # It beats, it is bounded, and it always stops.
    assert "SEARCH_HEARTBEAT_MS" in ts
    beat = ts[ts.index('o.phase("searching");', ts.index("let out: SearchVerdict;")):]
    beat = beat[:beat.index("const sp = searchProofOf")]
    assert "setInterval(() => o.phase(\"searching\"), SEARCH_HEARTBEAT_MS)" in beat
    assert "finally {" in beat and "clearInterval(beat)" in beat, "a heartbeat that can outlive its call"

    # And a repeat does not restart the step clock.
    fn = js[js.index("function setPhase("):js.index("\n  }", js.index("function setPhase("))]
    assert "const same = entry.phase === phase;" in fn
    assert "if (!same) entry.phaseAt = when;" in fn
    assert 'entry.phase === "approval" && !same' in fn


def test_a_survey_leg_gets_its_documents_its_padding_and_its_own_outline_row():
    """Henry, 24 Sep, on a real press: padding issues, and "the searches from the deep search when clicked
    from the left index are not opening".

    Both had the same cause. A leg was rendered as a COUNT — "Search 3 — 10 document(s)" — so there was
    nothing to open and nothing to mark, and the outline row pointed at the card, which meant clicking
    search 5 sent you to the top of a six-search card. A leg is an ordinary sealed search and gets what one
    gets: its documents, the controls to mark them, and an outline row pointing at itself.

    The padding was the same shape of mistake: `.card-body` carries none of its own — in a search card
    every child brings its own — so bare divs appended to it sat flush against the border."""
    ts = (STATIC.parent / "pi_attested" / "ir-attested.ts").read_text()
    js = (STATIC / "app.js").read_text()
    css = (STATIC / "app.css").read_text()

    # The documents have to leave the tool at all.
    assert "docs: r.sp.docs" in ts, "a leg reports a count but not what it found"

    deep = js[js.index('if (ev.tool === "deep_prior_art_search") {', js.index("e.notes.textContent") - 4000):]
    deep = deep[:deep.index('if (ev.tool !== "prior_art_search")')]
    # Same document rendering and the same marking controls as a search card.
    assert 'el("ol", "docs")' in deep and "markButtons(keyNo, e.card)" in deep
    # The outline row points at the LEG, not at the card.
    assert "outlineAdd({ kind: \"search\", el: block" in deep
    assert "el: e.card" not in deep.split("outlineAdd")[1][:200]
    # Every block this appends to the body carries padding, since the body has none.
    for cls in (".deep-summary", ".deep-leg-head", ".deep-leg-about"):
        at = css.find(f"{cls} {{")
        assert at >= 0, cls
        # The rule's OWN body, not a fixed window: a window spills into the next rule, and this assertion
        # passed against a padding-less rule because the one after it had padding.
        body = css[at:css.index("}", at)]
        assert "padding" in body, f"{cls} has no padding of its own: {body!r}"


def test_the_deep_card_says_where_the_press_did_not_reach(tmp_path):
    """Henry, 24 Sep, asked whether the deep search should get a second autonomous turn. Ruled with
    sealed-research: not yet — an adaptive turn is gated on counsel AND on a change in the shape of the
    approval, because a press-time approval cannot cover queries that do not exist at press time.

    What ships instead reports facts the record already holds and leaves the next move to the professional,
    so no query is ever sent they could not see coming. The two facts: which legs found nothing, and which
    found only documents the other legs had already returned — the second being invisible in a hit count,
    where a leg that contributes nothing looks like the strongest in the press.

    Run against the page's own function, not a copy of its wording."""
    import shutil, subprocess
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "deep_coverage_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    # A press where every leg contributed says nothing: an empty coverage note is noise on a good result.
    assert out["none"] == ""

    assert "1 query found nothing: leg three." in out["empty_only"]
    assert "found only documents the other queries had already returned: leg two" in out["spent_only"]
    # The point of saying it: unsearched and already-covered are different, and only one is a gap.
    assert "covered by what you already have, not unsearched" in out["spent_only"]

    # Both kinds, and the actionable line, on one press.
    assert "found nothing" in out["both"] and "already returned" in out["both"]
    assert "walk outward from it" in out["both"]
    # A failed leg is NOT a coverage gap — it is a failure, reported by the leg itself.
    assert "leg four" not in out["both"]

    # A record written before `added` existed must not be read as "this leg added nothing". Absent and zero
    # are different, and the older packs on this machine have no `added` at all.
    assert out["legacy"] == ""


def test_the_page_claims_contribution_and_not_family_collapsing():
    """"Added nothing new" is the weaker claim, and the only one that is actually computed. Collapsing
    siblings needs the family map, which lives on the search side; guessing family from publication numbers
    misses the cross-jurisdiction siblings that are most of the duplication. Saying "one family" would be a
    claim the page cannot support, in the one place a professional would rely on it."""
    root = Path(__file__).resolve().parent.parent
    js = (root / "inferroute_cli" / "probant_web" / "app.js").read_text()
    start = js.index("  function deepCoverage(d) {")
    body = js[start:js.index("  function seenIn(")]
    assert "l.added === 0" in body, "the page no longer measures contribution the way the extension records it"
    # The comments MUST discuss families — that is where the reason for not claiming them is recorded. It is
    # what the function SAYS that has to stay inside what it can compute, so strip the comments first.
    shown = "\n".join(ln for ln in body.splitlines() if not ln.strip().startswith("//"))
    for forbidden in ("family", "families", "saturat"):
        assert forbidden not in shown.lower(), f"the rendered text claims {forbidden!r}, which is not computed here"
    assert "family" in body.lower(), "the reason for not claiming families is no longer recorded beside the code"


def test_a_deep_survey_s_legs_fold_and_start_folded():
    """Henry, 25 Sep: "the deep search view should also have inner search collapsable within it, and they
    should stay collapsed in the beginning and only expand when clicked".

    A press puts up to eight searches, each with ten documents and its own marking controls. Opened all at
    once that is most of a screen per leg, and the SHAPE of the survey — which parts of the description
    were reached, and by what — is buried somewhere inside it. Folded, the card opens as a readable list
    of what was put.

    The fold is exercised through the page's own toggle rather than asserted on classes in the source: a
    class set at build time and never changed by the handler would pass a source check and be a dead
    control on the screen."""
    import shutil, subprocess
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "deep_leg_fold_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert out["initial"] == {"folded": True, "expanded": "false"}, "a leg does not start folded"
    assert out["afterFirstClick"] == {"folded": False, "expanded": "true"}
    assert out["afterSecondClick"] == {"folded": True, "expanded": "false"}, "the head does not fold it again"
    # The left index must OPEN a folded leg. Being sent to a closed box is not arriving — the same symptom
    # Henry reported on 24 Sep for folded cards, one level further in.
    assert out["afterOutlineClick"] == {"folded": False, "expanded": "true"}
    assert out["afterOpeningTwice"] == {"folded": False, "expanded": "true"}, "opening an open leg closed it"


def test_what_a_folded_leg_hides_is_its_documents_and_not_its_headline():
    """Folding must hide the leg's CONTENTS and keep the line that says what the leg was — the feature, the
    count, and what it contributed. That line is the survey's shape and it is the reason to fold at all."""
    root = Path(__file__).resolve().parent.parent
    js = (root / "inferroute_cli" / "probant_web" / "app.js").read_text()
    start = js.index('const block = el("div", `deep-leg ${leg.status} folded`);')
    block = js[start:js.index("e.body.append(block);", start)]

    # The head is a real control, and it is NOT inside the part that gets hidden.
    assert 'const head = el("button", "deep-leg-head",' in block
    assert 'head.setAttribute("aria-expanded", "false")' in block
    assert "block.append(head, legBody)" in block

    # Everything else goes into the body: the quoted text of what was searched, and the documents.
    assert 'legBody.append(el("div", "deep-leg-about"' in block
    assert "legBody.append(list);" in block
    assert "block.append(list);" not in block, "the documents are still a direct child and would stay visible"

    css = (root / "inferroute_cli" / "probant_web" / "app.css").read_text()
    assert ".deep-leg.folded > .deep-leg-body { display: none; }" in css
    # A caret that says which way it goes, both ways round.
    assert '.deep-leg-head::before { content: "▾ "; }'.replace('{ content', '{ content') in css or \
           '.deep-leg-head::before' in css
    assert '.deep-leg.folded > .deep-leg-head::before { content: "▸ "; }' in css


def test_the_page_offers_to_continue_a_survey_only_once_one_is_on_screen():
    """Henry, 25 Sep: "now im seeing this while the session is still fully empty, thats not right:
    Continue the survey, leaving out what I marked known or not relevant".

    Marks belong to the MATTER and outlive a sitting, so a fresh session opens holding every mark ever
    made. The other mark steps survive that — "find documents like US-X" is a new search, not a
    continuation. This is the only step whose words claim something about what has already happened in the
    room, and it was claiming it in an empty one.

    Run through the page's own markCandidates rather than read off the source: the extension side of this
    had a test and the page side did not, which is why the page is where Henry saw it."""
    import shutil, subprocess
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "mark_steps_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert "continue, leaving out" not in out["emptySession"], \
        "an empty sitting offered to continue a survey that had not started"
    # The steps that stay honest with nothing on screen are still offered.
    assert "Find documents like US-A1" in out["emptySession"]
    assert "look deeper" in out["emptySession"]

    assert "continue, leaving out" in out["afterSearching"], \
        "once a survey is on screen, continuing it is exactly the right offer"
    # And with nothing set aside there is nothing to leave out, searches or not.
    assert "continue, leaving out" not in out["onlyRelevant"]


def test_every_audit_runs_on_its_own_copy_of_the_pack(tmp_path):
    """From the two auditors who ran on one folder at once, 25 Sep. One filled the report template in
    where it lay; the other ran the integrity check at the end, found the record failing, traced the
    writer by pid, and said plainly that had it been the later of the two it would have filed a finding
    about evidence tampering that was really a colleague's scratch edit.

    Its recommendation, adopted: give each auditor its own copy. The copy sits BESIDE the original rather
    than in /tmp, so a report written "one directory up" lands in the exports folder where every other
    report already is."""
    pack = tmp_path / "exports" / "audit-pack-20260925T000000Z"
    pack.mkdir(parents=True)
    (pack / "AUDIT.md").write_text("brief")
    sh = W.audit_launch_script(pack, "claude 'do the thing'")
    body = sh.read_text()

    assert f"cp -r {pack}" in body, "the audit still runs in the evidence folder itself"
    assert str(pack) not in body.split("cd ", 1)[1].splitlines()[0], "it cd's into the original"
    assert "audit-run-audit-pack-20260925T000000Z-" in body
    # Beside the original, so "one directory up" is the exports folder.
    assert f"{pack.parent}/audit-run-" in body
    # The copy has to be writable: the pack's own files are 0600/0400 and a copy of a read-only template
    # cannot be filled in either.
    assert "chmod -R u+w" in body
    # And the auditor is told which they are looking at.
    assert "the original pack is untouched" in body

    # Run it for real and check the original is untouched and the copy is complete.
    import subprocess
    before = {p.name: p.read_bytes() for p in pack.iterdir()}
    r = subprocess.run(["bash", "-c", body.replace("exec bash", "true").replace("claude 'do the thing'", "true")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    after = {p.name: p.read_bytes() for p in pack.iterdir()}
    assert before == after, "the original pack changed"
    runs = sorted(pack.parent.glob("audit-run-*"))
    assert len(runs) == 1 and (runs[0] / "AUDIT.md").read_text() == "brief"


def test_a_verification_refusal_is_never_retried_quietly():
    """Henry, 30 Sep: "we get this too often, it's not looking good — maybe more discreet or even silent."
    Transport failures where nothing left this machine now retry quietly. The line that must NOT move with
    them is a machine that could not be VERIFIED: that refusal is the product working, and retrying it in
    silence would teach the reader to ignore the one message they must always see.

    Behavioural, through the page's own isTransient(): the first version of this guard keyed on the bare
    token "refus" and so read an ordinary "connection refused" as a verification refusal. Two senses of one
    word, and grep could not have told them apart."""
    import shutil, subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "transient_error_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert all(out["transient"]), f"a transport failure was not treated as transient: {out['transient']}"
    assert not any(out["verification"]), \
        f"a VERIFICATION failure would be retried quietly: {out['verification']}"
    # An unrecognised failure is shown, not swallowed: quiet is opt-in, per token, never the default.
    assert not any(out["unknown"]), f"an unknown failure was assumed transient: {out['unknown']}"


def test_the_quiet_retry_still_reaches_the_loud_error_and_the_fresh_session():
    """Discreet must not mean endless. After a bounded number of automatic tries the ordinary error block
    appears, so a failure that never clears is still reported; and every failure counts toward the
    "start a fresh session" offer whether it was shown loudly or quietly."""
    js = (STATIC / "app.js").read_text()
    body = _fn_body(js, "showError")
    assert "AUTO_RETRIES" in js and "autoTries < AUTO_RETRIES" in body, "the quiet path is unbounded"
    # Counted before the quiet path can return, exactly once.
    assert body.index("failedTries += 1;") < body.index("if (isTransient(detail)")
    assert js.count("failedTries += 1;") == 1
    # An answer that gets through clears the muted line and restores a full budget for the next blip.
    reset = _fn_body(js, "assistantEnd")
    assert "autoTries = 0;" in reset and "quietNode" in reset


def test_a_publication_number_is_clickable_from_one_helper_and_never_through_innerhtml():
    """Henry, 30 Sep: "it would be amazing if when we clicked on a patent mentioned in the text it opened".
    One helper renders the affordance everywhere — result rows, the documents panel, and the assistant's
    prose — so the professional does not learn that some numbers open and others do not.

    The prose path walks TEXT NODES. innerHTML there would let any sentence the model produced become markup
    this page executes, which is the one thing a page handling a confidential disclosure must not do."""
    js = (STATIC / "app.js").read_text()
    assert "function docLink(" in js and "function linkifyPubNos(" in js
    # every rendering goes through the one helper
    assert "el(\"span\", \"key\", keyNo)" not in js, "a result row still renders the number unclickably"
    assert "docLink(k)" in js and "docLink(keyNo)" in js
    # a click sends exactly what it says, like every other button here, and the read lands in the record
    assert "const OPEN_DOC = (k) =>" in js and "send(OPEN_DOC(keyNo))" in js
    body = _fn_body(js, "linkifyPubNos")
    assert "createTreeWalker" in body and "createTextNode" in body
    assert "innerHTML" not in body, "model output must never be assigned as markup"
    # only whole, finished numbers: linkifying a streaming paragraph would button half a number
    assert "linkifyPubNos(current.node);" in _fn_body(js, "assistantEnd")


def test_the_documents_panel_appears_as_soon_as_a_search_returns_documents_and_states_its_ordering():
    """Henry, 30 Sep: "a second tab that appears when a deep search was done, with the relevance sorted list
    of patents that can be clicked as well for opening".

    The ordering is STATED in the panel rather than implied. The search machine signs a per-search order and
    does not sign a combined one, so calling this a relevance score would be inventing a number nothing
    attests: it is the best rank a document reached in any one search, then how many searches returned it."""
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    assert 'id="results-panel"' in html and 'id="results-list"' in html
    body = _fn_body(js, "renderResultsPanel")
    # Hidden only while there is nothing to list. It was gated on a DEEP search first, from a literal
    # reading of "a second tab that appears when a deep search was done" — which made it invisible after an
    # ordinary search and read as never built (Henry, 30 Sep). The gate must not come back: a panel nobody
    # sees is indistinguishable from one nobody wrote.
    assert "panel.hidden = best.size === 0;" in body
    assert "deepMarksAtLastPress" not in body, "the deep-search gate is back; the panel will look unbuilt"
    # ordering: best rank, then times seen, then a stable tie-break
    assert "a[1].rank - b[1].rank || b[1].seen - a[1].seen || a[0].localeCompare(b[0])" in body
    assert "Math.min(prev.rank" in body, "a document's position must be its BEST rank across searches"
    # the method is on the page, not only in this test
    assert "best position a document reached in any one search" in html
    assert "not a score from" in html
    # it re-renders when searches land, when a deep search finishes, and when marks change
    assert js.count("renderResultsPanel();") >= 3


def test_a_connection_failure_is_not_shown_as_a_verification_failure():
    """Henry, 30 Sep: a reaped test enclave produced "the search enclave did not verify (… URLError)" — a
    trust verdict about a machine that was not there, and he asked for a better message.

    The composed refusal still carries a "did not verify" prefix, so these branches REPLACE the sentence
    rather than appending to it, and the connection case is matched BEFORE the verification case because
    the string contains both. The property that must survive: a REAL verification failure still says so —
    softening that would be worse than the bug being fixed."""
    import shutil, subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "refusal_wording_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert "isn't running" in out["absent"] and "verif" not in out["absent"].lower(), out["absent"]
    assert "left this computer" in out["absent"], "say plainly that nothing was sent"
    assert "not a sealed search machine" in out["junk"], out["junk"]
    # the one that must NOT be blunted
    assert "could not be verified" in out["real"], out["real"]
    assert "didn't allow" in out["declined"]
    # anything unanticipated still shows the raw text rather than being guessed at
    assert out["unknown"].startswith("The search was not sent:")


def test_no_eligible_machine_is_not_reported_as_unreachable_or_an_expired_key():
    """Measured 2026-09-30: 11 of 12 machines on one fleet failed a check this device makes, so a session
    pinned the only survivor and then had nothing to fall back to. The lane raises "the verified instance
    is gone and no verified alternative is available" as a 503 — and that string contains the word "nonce"
    in its sibling note and arrives with a 503, so it tripped the expired-key and unreachable branches.
    Either sentence sends the reader after the wrong thing; "couldn't be reached" had me looking at the
    network for an hour when nothing was unreachable.

    Also pins a bug found while fixing that: "not verified" does NOT match "could not BE verified", the
    exact phrase the lane raises, so the most serious condition fell through to the blandest sentence in
    the function. A verification failure must never be the quietest message here."""
    import shutil, subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "model_error_wording_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    for k in ("capacity", "capacityNote"):
        assert "capacity limit" in out[k], out[k]
        assert "couldn't be reached" not in out[k] and "one-time key" not in out[k], out[k]
    # the branches it must not have swallowed
    assert "one-time key" in out["nonceOnly"]
    assert "couldn't be reached" in out["unreachable"]
    assert "busy" in out["rateLimited"]
    # the serious one, which was falling through before
    assert "could not be verified" in out["unverified"], out["unverified"]
    assert "didn't answer" not in out["unverified"], "a verification failure got the blandest message"


def test_results_carry_their_relative_strength_and_never_a_bare_score():
    """Henry, 30 Sep: "why is every search returning 10 results as if they all [have] the same-level
    relevance". Because the tool asks for an exact count and the extension DROPPED the engine's score one
    line after receiving it, so the page had nothing to tell ten results apart. Measured on a real search:
    rank 1 scored ~10x rank 12 and 8 of 20 fell below zero, all rendered identically.

    The bar is normalised WITHIN one search and no number is shown, both deliberately. The engine's score
    is a LambdaRank output — an ordering signal, not a calibrated probability — so it is comparable inside
    one query and not across two. A printed figure would imply precision it does not carry, and a bar in
    the cross-search panel would compare things that cannot be compared."""
    js = (STATIC / "app.js").read_text()
    ts = (Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "ir-attested.ts").read_text()

    # the score now survives the trip to the page
    assert "score: h.score" in ts, "the extension still drops the engine's score"
    assert "score?: number }[];" in ts, "the doc type does not carry a score"

    body = _fn_body(js, "relBar")
    assert "hi > lo" in body, "an unnormalisable range must not render a bar"
    assert "Math.max(0.04" in body, "a zero-width bar is invisible and reads as missing data"
    # relative, and said so where the reader sees it
    assert "relative to the other results of this same search" in body
    assert "RELATIVE TO THE OTHERS IN THIS SEARCH" in js, "the card never explains what the bar means"
    # applied in BOTH renderers -- the deep-search legs are the twin that was missed last time
    assert js.count("relBar(") >= 3, "one of the two document renderers has no bar"
    # and NOT in the cross-search panel, where the scores are not comparable
    panel = _fn_body(js, "renderResultsPanel")
    assert "relBar(" not in panel, "a bar in the cross-search panel compares scores across queries"


def test_the_relevance_bar_renders_visibly_different_widths_for_real_scores():
    """Geometry, over the REAL scores of a real sealed search (capture 20260929T221411Z, k=20). Logic
    tests said the bar exists; this says it would actually look like something. Not a pixel check.

    The properties that matter: widths fall monotonically with score, the strongest and weakest are far
    apart rather than all bunched, the weakest is still VISIBLE (a zero-width bar reads as missing data,
    not as a weak match), a search whose results all scored the same renders NO bars because there is
    nothing to convey, and a doc with no score at all degrades to no bar rather than a broken one."""
    import shutil, subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "relbar_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    out = json.loads(r.stdout.strip().splitlines()[-1])

    assert out["monotonic"], f"a weaker result drew a longer bar: {out['widths']}"
    assert out["top"] == 100.0
    assert out["spread"] > 50, f"every bar looks the same; the point was to tell them apart: {out['widths']}"
    assert out["bottom"] >= 4.0, "the weakest bar is invisible and reads as missing data"
    assert out["allEqual"], "identical scores drew bars, implying a difference that is not there"
    assert out["noScore"], "a doc without a score drew a bar"
    assert out["hasLabel"], "the bar is unreadable to a screen reader"


def test_the_disclosure_is_named_and_other_workspace_files_are_reported_not_absorbed(tmp_path):
    """2026-09-30: a matter folder held disclosure.md (11.6 kB, current) and disclosure.md.bak (5.2 kB,
    the previous day's draft). The assistant read BOTH and called the backup "useful matter context", so a
    survey was steered by text the professional had revised away — and the step log said only
    "Read disclosure.md.bak", with nothing marking it superseded. Nothing in this codebase ever wrote that
    file; an editor or outside tool did, and the next one will too.

    Two halves, deliberately in different places. The RULE is in the contract, which is fixed and
    sha-pinned into every session record. The per-folder FACT is a launch notice to the professional —
    putting it in the system prompt would make that prompt vary per session and break the pin it exists
    to provide."""
    from inferroute_cli import pi_attested as P
    import inspect

    ws = tmp_path / "matter"; ws.mkdir()
    (ws / "disclosure.md").write_text("the invention")
    (ws / "disclosure.md.bak").write_text("last week's draft")
    (ws / "notes~").write_text("editor leftover")
    (ws / "disclosure-old.md").write_text("a stale draft with an innocent name")
    (ws / "sketch.png").write_bytes(b"\x89PNG")
    stale, other = P.workspace_extras(str(ws))

    assert "disclosure.md" not in stale and "disclosure.md" not in other, "the disclosure is not an extra"
    assert set(stale) == {"disclosure.md.bak", "notes~"}, stale
    # the case a suffix denylist would MISS entirely: a stale draft with an ordinary name
    assert "disclosure-old.md" in other, other
    assert "sketch.png" not in stale + other, "an ordinary attachment is not flagged as a stale draft"

    # the rule lives in the FIXED contract, and its pin was moved with it
    contract = P._strip_comments(P.CONTRACT_FILE.read_text())
    assert "`disclosure.md` is the disclosure" in contract
    assert "name it and ask" in contract
    assert not P.load_contract()["modified"], "the contract changed without its pin; every session flags"

    # the per-session fact is a notice, NOT the system prompt
    launch = inspect.getsource(__import__("inferroute_cli.confidential", fromlist=["x"]).launch)
    assert "workspace_extras" in launch
    assert "besides disclosure.md this matter folder holds" in launch
