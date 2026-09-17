"""The local browser page for a Surveyor session: what its bridge refuses, and what its page never does.

The agent's sandbox has no network; the browser does. These tests pin the properties that keep the page
from becoming the agent's way out, or another site's way in.
"""
import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import surveyor_web as W

STATIC = Path(W.__file__).resolve().parent / "surveyor_web"


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
    assert paths == {"/", "/app.js", "/app.css", "/api/session", "/api/events", "/api/prompt", "/api/abort",
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


# ── the page's code ──

def test_the_page_code_never_parses_markup_or_makes_links_or_resources():
    js = (STATIC / "app.js").read_text()
    code = re.sub(r"//[^\n]*", "", js)                  # the header comment names these constructs on purpose
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                      "DOMParser", "createContextualFragment", ".href", ".src", "srcdoc", "window.open",
                      "location.assign", "location.href ="):
        assert forbidden not in code, forbidden
    for tag in ("a", "img", "iframe", "script", "link", "object", "embed", "video", "audio", "source", "form"):
        assert f'createElement("{tag}")' not in code and f'el("{tag}"' not in code, tag
    assert re.search(r'setAttribute\("(href|src|action|formaction|style|on\w+)"', code) is None


def test_the_page_loads_nothing_from_outside():
    html = (STATIC / "index.html").read_text()
    assert "http://" not in html and "https://" not in html
    assert re.search(r"<script(?![^>]*\bsrc=\"/app\.js\")", html) is None     # no inline script
    assert re.search(r"\son[a-z]+=", html) is None                            # no inline handlers
    css = (STATIC / "app.css").read_text()
    assert "url(" not in css and "@import" not in css


def test_the_browser_summary_states_what_the_page_guarantees_and_what_it_cannot():
    from inferroute_cli import surveyor_trust as T
    from inferroute_local import netns
    from tests.test_surveyor_trust import _receipt, _search
    s = T.build(_receipt(), _search(reference={"ok": True}), netns.ADDRESS_LEVEL_LABEL, surface="browser")
    assert T.BROWSER_POINT in next(i for i in s["items"] if i["key"] == "computer")["points"]
    assert any("Browser extensions" in lim for lim in s["limits"])
    terminal = T.build(_receipt(), _search(reference={"ok": True}), netns.ADDRESS_LEVEL_LABEL)
    assert not any("Browser extensions" in lim for lim in terminal["limits"])
