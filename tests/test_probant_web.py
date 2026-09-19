"""The local browser page for a Probant session: what its bridge refuses, and what its page never does.

The agent's sandbox has no network; the browser does. These tests pin the properties that keep the page
from becoming the agent's way out, or another site's way in.
"""
import asyncio
import json
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
                     "/api/dialog", "/api/marks", "/api/mark", "/api/recheck", "/api/export", "/api/close", "/api/end"}


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


def test_marks_are_validated_and_go_to_the_host_verifier(client, monkeypatch):
    b, c = client
    calls = []
    monkeypatch.setattr(W, "_search_call", lambda ep, path, body=None, timeout=60.0: calls.append((path, body)) or {})
    assert c.post("/api/mark", json={"key": "US-7000-B2; rm -rf", "mark": "relevant"}).status_code == 400
    assert c.post("/api/mark", json={"key": "US-7000-B2", "mark": "novel"}).status_code == 400
    assert c.post("/api/mark", json={"key": "us-7000-b2", "mark": "relevant"}).json()["key"] == "US-7000-B2"
    assert calls == [("/matter/mark", {"key": "US-7000-B2", "mark": "relevant"})]
    assert b.proc.stdin.lines == []                       # a mark never passes through the agent


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
    import shutil
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
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "steps_panel_sim.js")], cwd=root, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-600:]
    R = json.loads(r.stdout.strip().splitlines()[-1])
    deeper = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them"
    # 1. A new session on a matter marked in an earlier one, no answer and no search yet: running the survey
    #    comes first — a new session is its own sitting (Henry, 19 Sep) — then the steps from the marks.
    assert R["s1"] == [{"title": "", "steps": ["Run a prior-art survey of the disclosure"]},
                       {"title": "From your marks", "steps": [deeper, "Find documents like US-A1"]}]
    # 1b. Once this session has searched, the survey is no longer offered on its own account.
    assert R["s1b"] == [{"title": "From your marks", "steps": [deeper, "Find documents like US-A1"]}]
    # 2. The assistant saw that mark and chose its own list — including DROPPING "look deeper". Respected.
    assert len(R["s2"]) == 1 and R["s2"][0]["title"] == "" and deeper not in R["s2"][0]["steps"]
    # 3. Marks made after it answered are added — and a step that merely DESCRIBES a mark ("…you marked
    #    relevant") does not count as offering "look deeper".
    assert R["s3"][1] == {"title": "From marks you made since", "steps": ["Find documents like US-B2", deeper]}
    # 4. Five at most, but marks made since always keep a place.
    assert len(R["s4"][0]["steps"]) == 4 and R["s4"][1]["steps"] == ["Find documents like US-B2"]
    # 5. While the assistant works on a new message, the previous answer's steps are stale: nothing shown.
    assert R["s5"] is None
    # 6-7. No marks, no list: ideas once the conversation has started, nothing before it.
    assert R["s6"][0]["title"] == "Ideas" and "Summarise what the searches have surfaced so far" not in R["s6"][0]["steps"]
    assert R["s7"] is None


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
    import shutil
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


def test_a_failed_answer_offers_a_way_on_that_sends_exactly_its_words():
    """Henry, 19 Sep: "The AI machine couldn't be reached … (4 times)" — "and I don't even have a button to
    retry". The button asks the assistant to continue rather than resending the question, so a failure after
    searches had run does not redo them; and it sends exactly what it says."""
    js = (STATIC / "app.js").read_text()
    body = js[js.index("function showError"):js.index("function showError") + 1400]
    assert 'const again = el("button", "ghost small", RETRY_TEXT);' in body
    assert "send(RETRY_TEXT)" in body
    assert 'const RETRY_TEXT = "Continue where you left off";' in js


def test_when_continuing_fails_too_the_page_offers_a_fresh_session():
    """19 Sep: Henry pressed "Continue where you left off" in a session started before the re-pin fix; it failed
    again, and again — a session's AI-machine side runs the code it started with. When the next try fails too,
    the session is stuck: the page says so and offers the way out, a fresh session, which re-checks from scratch."""
    js = (STATIC / "app.js").read_text()
    body = js[js.index("function showError"):js.index("function showError") + 2600]
    assert "failedTries += 1;" in body and "if (failedTries >= 2) {" in body
    assert "Start a fresh session on this matter" in body and "goHome(`/matter/${matterId}`)" in body
    # Counted per failed ANSWER (repeats inside one answer collapse into "(4 times)"), reset by one that gets through.
    assert "if (!ev.stopped && current.text.trim()) failedTries = 0;" in js


def test_marked_documents_carry_their_titles_from_every_recorded_search(tmp_path):
    """The marks panel shows what each marked document is about — including documents marked in an EARLIER
    session, whose results are not on this page — from every search recorded on the matter."""
    rec = tmp_path / "rec"
    rec.mkdir()
    (rec / "a.searches.jsonl").write_text(json.dumps({"result": {"hits": [{"key": "EP-1-A1", "title": "Sealed ledger"},
                                                                          {"key": "US-2-B2", "title": "Unmarked"}]}}) + "\n")
    (rec / "b.searches.jsonl").write_text("not json\n" + json.dumps({"result": {"hits": [{"key": "WO-3-A1", "title": "Replay"}]}}) + "\n")
    assert W.matter_titles(rec, {"EP-1-A1", "WO-3-A1", "XX-9"}) == {"EP-1-A1": "Sealed ledger", "WO-3-A1": "Replay"}
    assert W.matter_titles(None, {"EP-1-A1"}) == {} and W.matter_titles(rec, set()) == {}
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
