"""The pi lane must send the same caller-supplied header set as the Claude Code lane.

Oracle is EQUALITY on the same ANTHROPIC_CUSTOM_HEADERS input, never a list of names: a fifth header
added tomorrow is covered automatically. The only allowed difference is x-inferroute-session, which is
minted per launch (random, different per lane) — and the CC lane's own ir-* economy tags when economy is on.

Two layers:
  * unit (always runs): the env ir hands to `claude` vs the header map ir configures pi with.
  * wire (IR_WIRE_TESTS=1, needs `pi` and `claude` on PATH): the headers each real client actually sends
    to a local fake upstream. models.json is ir's statement of intent; this is pi's own HTTP client.
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from inferroute_cli import launch

CALLER = "x-inferroute-run-id: run-XYZ\nx-steward-version: v-123\nx-inferroute-no-hedge: 1\nx-inferroute-no-model-fallback: 1\nx-fifth-header: five"
ALLOWED_DIFFERENCES = {"x-inferroute-session"}


def _parse(blob: str) -> dict:
    out = {}
    for line in blob.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip():
            out[k.strip().lower()] = v.strip()
    return out


def _stub(monkeypatch, tmp_path):
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "nouser"))
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "irhome"))
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("IR_GRANT", raising=False)
    monkeypatch.setattr("inferroute_cli.agents.binary_for", lambda a: "/bin/" + a)
    for n in ("_persist_session_link", "_persist_last_model", "_record_launch", "_apply_wire_capture_env"):
        monkeypatch.setattr(f"inferroute_cli.launch.{n}", lambda *a, **k: None)
    monkeypatch.setattr("inferroute_cli.lane.announce", lambda *a, **k: None)
    monkeypatch.setattr("inferroute_cli.launch._recording_daemon_url", lambda: None)
    monkeypatch.setattr("inferroute_cli.launch._require_claude_binary", lambda: "/bin/claude")
    monkeypatch.setattr("inferroute_cli.launch._gate_strip_prefix", lambda *a, **k: "")
    monkeypatch.setattr("inferroute_cli.launch._product_strip_settings_args", lambda *a, **k: [])


def _creds():
    return type("C", (), {"is_valid": True, "api_url": "https://api.inferroute.ai", "api_key": "k"})()


def _cc_set(monkeypatch):
    seen = {}
    monkeypatch.setattr("os.execvpe", lambda b, a, env: seen.update(env=env))
    launch.launch_through_inferroute("kimi-k2.6", _creds(), ["-p", "hi"], why="t")
    return _parse(seen["env"]["ANTHROPIC_CUSTOM_HEADERS"])


def _pi_set(monkeypatch):
    seen = {}
    monkeypatch.setattr("os.execve", lambda b, a, env: seen.update(env=env))
    launch.launch_agent_plain("pi", "kimi-k2.6", _creds(), why="t")
    prov = json.loads(Path(seen["env"]["PI_CODING_AGENT_DIR"], "models.json").read_text())["providers"]["inferroute"]
    return {k.lower(): v for k, v in prov["headers"].items()}


@pytest.mark.parametrize("caller", [CALLER, CALLER + "\nx-sixth: six, with: colon", "", "  x-only :  spaced  "])
def test_pi_lane_forwards_exactly_what_the_claude_code_lane_forwards(tmp_path, monkeypatch, caller):
    _stub(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", caller)
    cc, pi = _cc_set(monkeypatch), _pi_set(monkeypatch)
    strip = lambda d: {k: v for k, v in d.items() if k not in ALLOWED_DIFFERENCES}
    assert strip(pi) == strip(cc), "the two lanes must send the same caller-supplied headers"
    assert strip(pi) == strip(_parse(caller)), "and that set is exactly the caller's, with nothing minted"
    assert cc["x-inferroute-session"] != pi["x-inferroute-session"] and len(pi["x-inferroute-session"]) == 36


# ── wire layer ──────────────────────────────────────────────────────────────────────────────────────

wire = pytest.mark.skipif(os.environ.get("IR_WIRE_TESTS") != "1" or not (shutil.which("pi") and shutil.which("claude")),
                          reason="set IR_WIRE_TESTS=1 with pi and claude on PATH")


def _fake_upstream(rec):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length") or 0))
            rec.append({k.lower(): v for k, v in self.headers.items()})
            body = b'{"type":"invalid_request_error","message":"fake upstream"}'
            self.send_response(400)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_lane(code: str, caller: str | None, port: int) -> None:
    tmp = tempfile.mkdtemp()
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "ANTHROPIC_API_KEY", "ANTHROPIC_CUSTOM_HEADERS")}
    env.update(INFERROUTE_HOME=tmp + "/ir", PI_CODING_AGENT_DIR=tmp + "/nouser", PYTHONPATH=str(Path(launch.__file__).parent.parent))
    if caller is not None:
        env["ANTHROPIC_CUSTOM_HEADERS"] = caller
    pre = ("from inferroute_cli.config import Credentials as C; from inferroute_cli import launch as L; "
           f"L._recording_daemon_url=lambda: None; c=C('http://127.0.0.1:{port}','k-test');")
    subprocess.run([sys.executable, "-c", pre + code], env=env, timeout=120, stdin=subprocess.DEVNULL, capture_output=True, text=True)


@wire
def test_real_pi_and_real_claude_send_the_same_caller_headers_on_the_wire():
    def sent(code, caller):
        rec: list = []
        srv = _fake_upstream(rec)
        try:
            _run_lane(code, caller, srv.server_address[1])
        finally:
            srv.shutdown()
        assert rec, "the client never reached the fake upstream"
        return rec[0]
    cc_code = "L.launch_through_inferroute('kimi-k2.6', c, ['-p','hi'], why='wire')"
    pi_code = "L.launch_agent_plain('pi','kimi-k2.6', c, ['-p','hi'], why='wire')"
    delta = {}
    for lane, code in (("cc", cc_code), ("pi", pi_code)):
        base, withh = sent(code, None), sent(code, CALLER)
        # what the caller's variable ADDED on the wire for this lane = the lane's own contribution, factored out
        delta[lane] = {k: v for k, v in withh.items() if base.get(k) != v and k not in ALLOWED_DIFFERENCES
                       and k not in ("x-claude-code-session-id", "x-stainless-retry-count", "content-length", "user-agent", "host")}
    assert delta["pi"] == delta["cc"], f"wire headers differ: pi={delta['pi']} cc={delta['cc']}"
    assert delta["pi"] == _parse(CALLER)
