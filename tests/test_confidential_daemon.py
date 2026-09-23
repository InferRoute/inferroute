"""A confidential session that outlives its command — and stops when it stops being confidential.

The reason `ir goose-cowork` could not be sealed is that it starts the desktop app detached, and the
app outlives the command while the local endpoint does not. A daemon closes that. The whole risk of a
daemon is the obvious one: a port that outlives its evidence.
"""
import asyncio
import json
import os
import types

import pytest
from fastapi.testclient import TestClient

from inferroute_cli import confidential_daemon as D
from inferroute_local.confidential.server import create_app

TOKEN = "ir-daemon-test-key"


class _Receipt:
    def __init__(self, verdict="confidential", refusal=""):
        self.verdict, self.refusal = verdict, refusal
        self.notes = []

    @property
    def is_confidential(self):
        return self.verdict == "confidential"

    def note(self, kind, detail):
        self.notes.append((kind, detail))


class _Session:
    def __init__(self, receipt):
        self.receipt = receipt


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    yield


def test_the_endpoint_stops_serving_when_the_session_stops_being_confidential():
    """THE test. The gate lives in the server rather than the daemon, so a foreground session that loses
    its footing mid-life gets it too."""
    r = _Receipt()
    c = TestClient(create_app(_Session(r), TOKEN), raise_server_exceptions=False)
    auth = {"authorization": f"Bearer {TOKEN}"}
    assert c.post("/v1/messages", json={}, headers=auth).status_code != 503
    r.verdict, r.refusal = "degraded", "the enclave could not be re-verified 3 times in a row"
    res = c.post("/v1/messages", json={}, headers=auth)
    assert res.status_code == 503
    assert "could not be re-verified" in res.text, "it must say why, not just refuse"


def test_the_receipt_stays_readable_after_it_stops():
    """That is where the reason is; refusing it too would leave the user with nothing to read."""
    r = _Receipt(verdict="refused", refusal="no instance verified")
    c = TestClient(create_app(_Session(r), TOKEN), raise_server_exceptions=False)
    assert c.get("/confidential/receipt", headers={"authorization": f"Bearer {TOKEN}"}).status_code != 503


def test_a_stopped_session_still_needs_the_key():
    """Losing confidentiality must not open the door."""
    r = _Receipt(verdict="refused")
    c = TestClient(create_app(_Session(r), TOKEN), raise_server_exceptions=False)
    assert c.get("/confidential/receipt").status_code == 401


def test_the_watchdog_stops_the_server_when_the_heartbeat_says_no(monkeypatch):
    monkeypatch.setattr(D, "WATCH_EVERY_S", 0.01)
    monkeypatch.setattr(D, "GRACE_S", 0.01)
    r = _Receipt(verdict="degraded", refusal="the verified instance is gone")
    s = types.SimpleNamespace(receipt=r, heartbeat=lambda: asyncio.sleep(0, result=False))
    server = types.SimpleNamespace(should_exit=False)
    reason: list = []
    asyncio.run(asyncio.wait_for(D._watch(s, server, reason), timeout=5))
    assert server.should_exit is True
    assert reason == ["the verified instance is gone"]


def test_a_heartbeat_that_cannot_run_is_not_a_pass(monkeypatch):
    """An exception from the heartbeat means we do not know, and not-knowing is not confidential."""
    monkeypatch.setattr(D, "WATCH_EVERY_S", 0.01)
    monkeypatch.setattr(D, "GRACE_S", 0.01)
    r = _Receipt(verdict="refused", refusal="")

    async def boom():
        raise RuntimeError("the operator gateway is unreachable")

    s = types.SimpleNamespace(receipt=r, heartbeat=boom)
    server = types.SimpleNamespace(should_exit=False)
    asyncio.run(asyncio.wait_for(D._watch(s, server, []), timeout=5))
    assert server.should_exit is True
    assert r.notes and r.notes[0][0] == "heartbeat-failed"


def test_a_state_file_whose_endpoint_answers_nothing_is_cleared():
    """pids are reused; a stale file naming a live unrelated process must not read as a session."""
    D.write_state({"schema": D.SCHEMA, "pid": os.getpid(), "port": 9, "token": "x",
                   "session_id": "dead", "model": "kimi-k2.6", "started_at": "now"})
    assert D.read_state() is not None
    assert D.running() is None
    assert D.read_state() is None, "running() must clear what it found to be absent"


def test_the_state_file_is_private():
    D.write_state({"schema": D.SCHEMA, "pid": 1, "port": 1, "token": "secret",
                   "session_id": "s", "model": "m", "started_at": "now"})
    assert oct(D.state_path().stat().st_mode)[-3:] == "600"


def test_the_token_never_reaches_a_command_line(monkeypatch):
    """`xdg-open` already puts one key of ours in the process table. The child mints its own and writes
    it to the state file; the parent only waits for that file."""
    seen = {}

    class _P:
        returncode = 0

        def poll(self):
            return 1                      # exit immediately so start() gives up rather than hanging

    monkeypatch.setattr(D.subprocess, "Popen", lambda argv, **k: (seen.__setitem__("argv", argv), _P())[1])
    D.start("kimi-k2.6")
    # Exact shape, not a heuristic: anything added to this list would be visible in `ps`.
    assert seen["argv"][1:] == ["-m", "inferroute_cli", "confidential", "daemon", "serve",
                                "--model", "kimi-k2.6"], seen["argv"]


def test_goose_cowork_points_at_the_daemon_when_one_is_running(monkeypatch, tmp_path):
    """The reason cowork could not be sealed was that the endpoint died with the command. A daemon that
    outlives it closes that, and the desktop app reads the config we write."""
    from inferroute_cli import cowork
    monkeypatch.setattr(cowork, "_sealed_endpoint", lambda: ("http://127.0.0.1:41999", "ir-live-token"))
    written = {}
    monkeypatch.setattr(cowork, "_write_merged",
                        lambda path, updates, secret: written.setdefault("secret" if secret else "plain", updates))
    creds = type("C", (), {"api_url": "https://api.inferroute.ai", "api_key": "cloud-key", "is_valid": True})()
    host = cowork.configure(creds, model="kimi-k2.6")
    assert host == "http://127.0.0.1:41999"
    assert written["plain"]["OPENAI_BASE_URL"] == "http://127.0.0.1:41999"
    # the daemon's key, not the cloud key: the endpoint refuses anything else
    assert written["secret"]["OPENAI_API_KEY"] == "ir-live-token"
    assert "cloud-key" not in json.dumps(written), "the cloud key must not travel to a sealed endpoint"


def test_goose_cowork_falls_back_and_says_how_to_seal_it(monkeypatch):
    from inferroute_cli import cowork
    monkeypatch.setattr(cowork, "_sealed_endpoint", lambda: None)
    monkeypatch.setattr(cowork, "_write_merged", lambda *a, **k: None)
    monkeypatch.setattr(cowork, "_anthropic_host", lambda creds: "https://api.inferroute.ai")
    creds = type("C", (), {"api_url": "https://api.inferroute.ai", "api_key": "cloud-key", "is_valid": True})()
    assert cowork.configure(creds, model="kimi-k2.6") == "https://api.inferroute.ai"


def test_the_cowork_reason_now_names_the_remedy_not_a_dead_end():
    """It used to say the endpoint "cannot outlive this command" — true when written, and now false.
    A backlog entry that is no longer accurate is worse than none: it stops anyone looking again."""
    from inferroute_cli import lane
    assert "daemon start" in lane.COWORK
    assert "cannot" not in lane.COWORK


def test_a_daemon_that_is_not_serving_is_not_offered_as_sealed(monkeypatch):
    """`running()` reports a daemon that answers but has stopped serving; pointing goose at that would
    configure it against an endpoint returning 503."""
    from inferroute_cli import cowork
    monkeypatch.setattr(D, "running", lambda: {"port": 1, "token": "t", "serving": False})
    assert cowork._sealed_endpoint() is None
