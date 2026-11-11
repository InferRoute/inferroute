"""2026-11-10: every model was declared to Pi/OpenCode at 262,144 tokens. GLM-5.1's window is 202,752, so Pi
never compacted and the session went past the model. Agents are now told the lane's real window."""
import json
from types import SimpleNamespace

from inferroute_cli import agents
from inferroute_cli.confidential import lane_context_window

ALIAS = SimpleNamespace(short="glm-5.1", model_id="GLM-5.1")


def _pi_model(ctx):
    doc = agents.pi_models_json("http://x", "k", ALIAS, "GLM-5.1", context_window=ctx)
    return doc["providers"]["inferroute"]["models"][0]


def test_pi_is_told_the_real_window_minus_the_reply_it_reserves():
    m = _pi_model(202_752)
    assert m["maxTokens"] == 32_768
    # prompt budget: Pi's compaction point plus its max_tokens must stay inside what the server accepts
    assert m["contextWindow"] + m["maxTokens"] <= 202_752


def test_unknown_window_keeps_the_old_default():
    m = _pi_model(0)
    assert (m["contextWindow"], m["maxTokens"]) == (262_144 - 32_768, 32_768)


def test_a_small_window_is_not_swallowed_by_the_reply_reserve():
    m = _pi_model(16_384)
    assert m["maxTokens"] == 4_096 and m["contextWindow"] == 12_288


def test_opencode_gets_the_real_window_as_is():
    cfg = agents.opencode_config("http://x", "k", ALIAS, "GLM-5.1", context_window=202_752)
    assert cfg["provider"]["inferroute"]["models"]["glm-5.1"]["limit"] == {"context": 202_752, "output": 32_768}
    env = {}
    agents.opencode_env_argv("oc", env, [], base_url="http://x", api_key="k", alias=ALIAS, upstream_name="GLM-5.1",
                             context_window=202_752)
    assert json.loads(env["OPENCODE_CONFIG_CONTENT"])["provider"]["inferroute"]["models"]["glm-5.1"]["limit"]["context"] == 202_752


def test_lane_context_window_reads_the_session_or_the_active_continuity_lane():
    assert lane_context_window(SimpleNamespace(context_length=202_752)) == 202_752
    assert lane_context_window(SimpleNamespace(active=SimpleNamespace(context_length=1_048_576))) == 1_048_576
    assert lane_context_window(SimpleNamespace()) == 0


def test_the_confidential_pi_config_carries_the_lane_window(monkeypatch, tmp_path):
    """The path `ir pi` on the confidential lane actually takes (pi_attested.config_dir), not only the helper."""
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    from inferroute_cli import pi_attested
    d = pi_attested.config_dir("http://x", "k", ALIAS, "GLM-5.1 [confidential]", context_window=202_752, quiet=True)
    m = json.loads((d / "models.json").read_text())["providers"]["inferroute"]["models"][0]
    assert m["contextWindow"] + m["maxTokens"] <= 202_752


# ── 2026-11-11: capped at the old default everywhere; the regular lane reads the server's guaranteed window ──

def test_a_known_window_only_ever_lowers_what_the_agent_is_told():
    assert agents.agent_limits(1_048_576) == (262_144, 32_768)       # a 1M lane is NOT raised
    assert agents.agent_limits(196_608) == (196_608, 32_768)
    m = _pi_model(1_048_576)
    assert m["contextWindow"] + m["maxTokens"] == 262_144


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


def _serve(monkeypatch, status=200, body=None, exc=None):
    import httpx
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen.update(url=url, headers=headers, timeout=timeout)
        if exc:
            raise exc
        return _Resp(status, body)
    monkeypatch.setattr(httpx, "get", fake_get)
    return seen


def test_served_context_window_reads_v1_models(monkeypatch):
    seen = _serve(monkeypatch, body={"data": [{"id": "kimi-k2.6", "aliases": ["Kimi-K2.6"], "context_window": 196_608},
                                             {"id": "glm-5.1", "aliases": ["GLM-5.1"], "context_window": 196_608}]})
    assert agents.served_context_window("https://api.example/", "inf_k", "glm-5.1") == 196_608
    assert seen["url"] == "https://api.example/v1/models" and seen["headers"] == {"x-api-key": "inf_k"}
    assert agents.served_context_window("https://api.example", "inf_k", "Kimi-K2.6") == 196_608   # by alias


def test_served_context_window_is_zero_whenever_the_server_does_not_say(monkeypatch):
    import httpx
    _serve(monkeypatch, body={"data": [{"id": "glm-5.1"}]})                      # an older server: no field
    assert agents.served_context_window("http://x", "k", "glm-5.1") == 0
    _serve(monkeypatch, body={"data": []})
    assert agents.served_context_window("http://x", "k", "glm-5.1") == 0
    _serve(monkeypatch, status=401, body={})
    assert agents.served_context_window("http://x", "k", "glm-5.1") == 0
    _serve(monkeypatch, exc=httpx.ConnectTimeout("slow"))
    assert agents.served_context_window("http://x", "k", "glm-5.1") == 0
    _serve(monkeypatch, body={"data": [{"id": "glm-5.1", "context_window": "garbage"}]})
    assert agents.served_context_window("http://x", "k", "glm-5.1") == 0


def test_the_regular_lane_pi_launch_declares_the_served_window(monkeypatch, tmp_path):
    """launch_agent_plain → pi_env_argv → models.json, end to end, with /v1/models faked."""
    import os
    from inferroute_cli import launch
    _serve(monkeypatch, body={"data": [{"id": "glm-5.1", "context_window": 196_608}]})
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "user-pi"))
    captured = {}

    def fake_execve(binary, argv, env):
        captured["dir"] = env["PI_CODING_AGENT_DIR"]
        raise SystemExit(0)
    monkeypatch.setattr(os, "execve", fake_execve)
    monkeypatch.setattr(launch, "_persist_session_link", lambda *a, **k: None)
    monkeypatch.setattr(launch, "_persist_last_model", lambda *a, **k: None)
    monkeypatch.setattr(launch, "_record_launch", lambda *a, **k: None)
    monkeypatch.setattr(agents, "binary_for", lambda agent: "/usr/bin/" + agent)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    from inferroute_cli import lane as _lane
    monkeypatch.setattr(_lane, "announce", lambda *a, **k: None)
    from inferroute_cli.config import Credentials
    import pytest
    with pytest.raises(SystemExit):
        launch.launch_agent_plain("pi", "glm-5.1", Credentials(api_url="https://api.example", api_key="inf_k"),
                                  why="test")
    m = json.loads((__import__("pathlib").Path(captured["dir"]) / "models.json").read_text())["providers"]["inferroute"]["models"][0]
    assert m["contextWindow"] + m["maxTokens"] == 196_608


def test_the_macos_vm_plan_declares_the_capped_lane_window():
    from inferroute_local.macos_vm.plan import build_plan
    for ctx, total in ((202_752, 202_752), (1_048_576, 262_144), (0, 262_144)):
        p = build_plan(alias="glm-5.1", surface_browser_only=True, mode="names", context_window=ctx)
        m = json.loads(p.config["models.json"])["providers"]["inferroute"]["models"][0]
        assert m["contextWindow"] + m["maxTokens"] == total, (ctx, m)
