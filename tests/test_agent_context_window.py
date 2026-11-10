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
