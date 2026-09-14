"""`ir pi` attested launch: what Pi is allowed to load, where its model requests may go, and that the
verdict it shows is read locally and never sent to the model.

The integration tests run the real Pi binary against the real local endpoint app (create_app) over a
stub session that records every plaintext request body Pi sends. Skipped when Pi is not installed.
"""
import copy
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import pi_attested as PA

ALIAS = SimpleNamespace(short="kimi-k2.6", model_id="kimi-k2.6", ref_key="fixture/Model-TEE")
INSTANCE_MARK = "5eaf00d5-attested-instance-marker"
RECEIPT_MARK = "/receipts/receipt-marker-q9.json"
PROMPT_MARK = "PROMPT-MARKER-3f1"
PI = shutil.which("pi")


@pytest.fixture
def user_pi(tmp_path, monkeypatch):
    """A user Pi dir holding exactly the things the attested launch must not carry in."""
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "irhome"))
    user = tmp_path / "userpi"
    (user / "extensions").mkdir(parents=True)
    (user / "extensions" / "spy.ts").write_text("export default function () {}\n")
    (user / "settings.json").write_text(json.dumps({"extensions": [str(user / "x.ts")], "httpProxy": "http://127.0.0.1:1"}))
    (user / "models.json").write_text(json.dumps({"providers": {"elsewhere": {"baseUrl": "http://127.0.0.1:2/v1"}}}))
    (user / "auth.json").write_text("{}")
    (user / "sessions").mkdir()
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(user))
    (tmp_path / "proj").mkdir()
    return user


def _argv(env: dict, passthrough=(), base_url="http://127.0.0.1:9") -> list[str]:
    return PA.env_argv(PI or "pi", env, list(passthrough), base_url=base_url, api_key="ir-confidential-local",
                       alias=ALIAS, upstream_name="kimi-k2.6 [confidential]")


def _after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


# ───────────────────────── launch shape ─────────────────────────

def test_launch_disables_discovery_and_loads_only_ours(user_pi):
    argv = _argv({})
    assert "-ne" in argv and "-na" in argv
    assert argv.count("-e") == 1 and _after(argv, "-e") == str(PA.EXTENSION)
    assert PA.EXTENSION.is_file()
    assert "bash" not in _after(argv, "--tools").split(",")
    assert _after(argv, "--provider") == "inferroute"


def test_config_dir_carries_none_of_the_users_code_settings_or_providers(user_pi):
    env: dict = {}
    _argv(env, base_url="http://127.0.0.1:4242")
    cfg = Path(env["PI_CODING_AGENT_DIR"])
    assert cfg != user_pi and not (cfg / "extensions").exists()
    settings = json.loads((cfg / "settings.json").read_text())
    assert "extensions" not in settings and "httpProxy" not in settings and "packages" not in settings
    providers = json.loads((cfg / "models.json").read_text())["providers"]
    assert list(providers) == ["inferroute"]
    assert providers["inferroute"]["baseUrl"] == "http://127.0.0.1:4242/v1"
    links = {p.name for p in cfg.iterdir() if p.is_symlink()}
    assert links == {"sessions"}
    assert not (cfg / "auth.json").exists()


def test_relaunch_drops_state_from_a_previous_launch(user_pi):
    env: dict = {}
    _argv(env)
    cfg = Path(env["PI_CODING_AGENT_DIR"])
    os.symlink(user_pi / "extensions", cfg / "extensions")        # as the old mirroring launcher left it
    _argv({})
    assert not (cfg / "extensions").exists()


def test_loopback_is_never_proxied_under_either_spelling(user_pi):
    env = {"no_proxy": "", "NO_PROXY": "corp.internal", "HTTP_PROXY": "http://127.0.0.1:1"}
    _argv(env)
    for name in ("no_proxy", "NO_PROXY"):
        assert env[name].split(",")[:3] == ["127.0.0.1", "localhost", "::1"]
    env2 = {"NO_PROXY": "corp.internal"}
    _argv(env2)
    assert "corp.internal" in env2["no_proxy"].split(",") and "corp.internal" in env2["NO_PROXY"].split(",")
    assert env["PI_OFFLINE"] == "1"


@pytest.mark.parametrize("flag", ["-e", "--extension=x.ts", "--provider", "--api-key", "--models", "-t", "--tools=bash", "-a", "--approve"])
def test_refuses_flags_that_load_code_reroute_or_widen_tools(user_pi, flag):
    with pytest.raises(PA.Refused):
        _argv({}, passthrough=[flag, "x"])


def test_ordinary_pi_flags_pass_through(user_pi):
    argv = _argv({}, passthrough=["-p", "hello", "--thinking", "high", "--session-id", "abc"])
    assert argv[-6:] == ["-p", "hello", "--thinking", "high", "--session-id", "abc"]


# ───────────────────────── against the real Pi binary ─────────────────────────

needs_pi = pytest.mark.skipif(PI is None, reason="pi is not installed")


def _receipt(verdict="confidential", failing: str | None = None):
    from inferroute_local.confidential import attest
    from inferroute_local.confidential.receipt import Receipt
    r = Receipt(session_id="fixture-session", model_short="kimi-k2.6", upstream_model="fixture/Model-TEE",
                fleet_id="fleet", transport="InferRoute relay (ciphertext only)")
    r.verdict, r.verified_at = verdict, "2026-09-14T07:31:00Z"
    r.refusal = "fixture refusal" if verdict != "confidential" else ""
    r.instance = {"id": INSTANCE_MARK, "gpu_count": 8}
    r.checks = {k: {"ok": k != failing, "why": f"fixture {k}", "label": attest.LABELS[k][0], "explain": attest.LABELS[k][1]}
                for k in attest.REQUIRED + attest.REQUIRED_ONLINE}
    r.e2ee = {"kem": "ML-KEM-768 (FIPS 203)", "aead": "ChaCha20-Poly1305"}
    r.path = "/home/fixture/.inferroute/confidential" + RECEIPT_MARK
    return r


class StubSession:
    """Stands in for ConfidentialSession behind the real local endpoint: records the plaintext body
    Pi sends and answers with a short OpenAI stream."""

    def __init__(self, receipt):
        self.receipt = receipt
        self.bodies: list[dict] = []
        self.model_short = self.shown_model = "kimi-k2.6"
        self.upstream_model = "fixture/Model-TEE"

    async def chat_completions(self, body):
        self.bodies.append(copy.deepcopy(body))
        chunks = [{"id": "c", "object": "chat.completion.chunk", "model": "kimi-k2.6",
                   "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OK"}, "finish_reason": None}]},
                  {"id": "c", "object": "chat.completion.chunk", "model": "kimi-k2.6",
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                   "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}]

        async def gen():
            for c in chunks:
                yield b"data: " + json.dumps(c).encode() + b"\n\n"
            yield b"data: [DONE]\n\n"
        return 200, {"content-type": "text/event-stream"}, gen()


def _run_pi(tmp_path, receipt, *, env_extra=None, mutate=None):
    import uvicorn
    from inferroute_local.confidential.server import create_app
    session = StubSession(receipt)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(session), host="127.0.0.1", port=port, log_level="critical"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    try:
        env = os.environ.copy()
        # A proxy that would swallow the request if loopback were not exempted.
        env.update({"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "no_proxy": ""})
        argv = _argv(env, passthrough=["-p", f"Reply OK. {PROMPT_MARK}"], base_url=f"http://127.0.0.1:{port}")
        env.update(env_extra or {})
        if mutate:
            argv = mutate(argv, env)
        proc = subprocess.run(argv, env=env, cwd=tmp_path / "proj", capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    return proc, session, env


def _proof_entries(env) -> list[dict]:
    out = []
    for f in Path(env["PI_CODING_AGENT_DIR"], "sessions").rglob("*.jsonl"):
        for line in f.read_text().splitlines():
            row = json.loads(line)
            if row.get("type") == "custom" and row.get("customType") == "ir-attested-proof":
                out.append(row["data"])
    return out


def _verdict_strings(receipt) -> list[str]:
    labels = [c["label"] for c in receipt.checks.values()]
    return [INSTANCE_MARK[:8], RECEIPT_MARK, "model enclave", "Model enclave", "checks passed", "fixture refusal", *labels]


@needs_pi
def test_verdict_is_read_locally_and_never_reaches_the_model(tmp_path, user_pi):
    receipt = _receipt()
    proc, session, env = _run_pi(tmp_path, receipt)
    assert proc.returncode == 0, proc.stderr[-800:]
    sent = json.dumps(session.bodies)
    assert session.bodies and PROMPT_MARK in sent, "the capture must see the plaintext Pi sends"
    leaked = [s for s in _verdict_strings(receipt) if s in sent]
    assert leaked == [], f"verdict strings reached the provider payload: {leaked}"
    cards = _proof_entries(env)
    assert cards and cards[0]["ok"] is True and cards[0]["instance"] == INSTANCE_MARK[:8]
    assert cards[0]["passed"] == cards[0]["total"] == 15
    assert cards[0]["receiptPath"].endswith(RECEIPT_MARK)


def _system_message(bodies) -> str:
    for m in bodies[0].get("messages", []):
        if m.get("role") == "system":
            c = m.get("content")
            return c if isinstance(c, str) else json.dumps(c)
    return ""


def test_contract_loader_strips_comments_and_matches_pinned_sha():
    c = PA.load_contract()
    assert c["modified"] is False, "the shipped contract must match its pinned sha"
    assert "<!--" not in c["text"] and "DRAFT" not in c["text"]
    assert c["text"].startswith("# You are a prior-art research assistant")
    assert "from your own knowledge" in c["text"] and "novel" in c["text"]


@needs_pi
def test_the_mission_contract_is_the_system_prompt_and_never_the_coding_persona(tmp_path, user_pi):
    proc, session, env = _run_pi(tmp_path, _receipt())
    assert proc.returncode == 0, proc.stderr[-800:]
    sysmsg = _system_message(session.bodies)
    # the contract is the system prompt: its rules are present, comments and Pi's coding persona are not
    assert "prior-art research assistant" in sysmsg and "from your own knowledge" in sysmsg
    assert "<!--" not in sysmsg and "DRAFT" not in sysmsg
    assert "coding assistant" not in sysmsg.lower() and "you help users by reading" not in sysmsg.lower()
    # stamped in the session record when there is a session id (RPC/print with an id); at minimum the env carries it
    assert env["IR_CONTRACT_MODIFIED"] == "0"
    assert len(env["IR_CONTRACT_SHA"]) == 64 and len(env["IR_CONFIG_HASH"]) == 16


@needs_pi
def test_a_modified_contract_is_flagged_not_silently_run(tmp_path, user_pi, monkeypatch):
    # point the loader at a tampered contract; the launch must carry the modified flag
    tampered = tmp_path / "contract.md"
    tampered.write_text(PA.CONTRACT_FILE.read_text() + "\nAN EXTRA LINE THAT CHANGES THE HASH\n")
    monkeypatch.setattr(PA, "CONTRACT_FILE", tampered)
    proc, session, env = _run_pi(tmp_path, _receipt())
    assert env["IR_CONTRACT_MODIFIED"] == "1"
    assert "AN EXTRA LINE THAT CHANGES THE HASH" in _system_message(session.bodies)


@needs_pi
@pytest.mark.parametrize("verdict,failing", [("refused", None), ("degraded", None), ("confidential", "gpu_verified")])
def test_an_unverified_session_sends_nothing(tmp_path, user_pi, verdict, failing):
    proc, session, env = _run_pi(tmp_path, _receipt(verdict, failing))
    assert session.bodies == []
    assert proc.returncode != 0
    assert "Model request blocked" in proc.stderr
    assert _proof_entries(env)[0]["ok"] is False


@needs_pi
def test_a_model_on_another_provider_is_blocked(tmp_path, user_pi):
    def to_other_provider(argv, env):
        cfg = Path(env["PI_CODING_AGENT_DIR"], "models.json")
        doc = json.loads(cfg.read_text())
        doc["providers"]["other"] = {**doc["providers"]["inferroute"], "name": "other"}
        cfg.write_text(json.dumps(doc))
        argv[argv.index("--provider") + 1] = "other"
        argv[argv.index("--models") + 1] = "other/kimi-k2.6"
        return argv
    proc, session, _ = _run_pi(tmp_path, _receipt(), mutate=to_other_provider)
    assert session.bodies == []
    assert "Model request blocked" in proc.stderr


@needs_pi
def test_a_model_pointed_away_from_the_session_endpoint_is_blocked(tmp_path, user_pi):
    """The provider name is right but the endpoint the extension was given is not the one the model uses."""
    proc, session, _ = _run_pi(tmp_path, _receipt(), env_extra={"IR_ATTESTED_ENDPOINT": "http://127.0.0.1:1"})
    assert session.bodies == []
    assert "Model request blocked" in proc.stderr
