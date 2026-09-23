"""OpenHands and CodeWhale on the sealed lane.

Both speak OpenAI, which the sealed endpoint serves. Both are wired sealed-only: the plaintext lane is
being removed, so a new agent that only works confidentially moves that count the right way.
"""
import os
from pathlib import Path

import pytest

from inferroute_cli import agents, main as M


class _Alias:
    short = "kimi-k2.6"
    model_id = "Kimi-K2.6"
    ref_key = "moonshotai/Kimi-K2.6-TEE"


def test_openhands_is_told_the_dialect_through_the_model_name():
    """LiteLLM decides the wire protocol from the model prefix, so `openai/` is what makes it speak the
    dialect the sealed endpoint serves — and it appends /chat/completions, hence the /v1."""
    env: dict = {}
    argv = agents.openhands_env_argv("openhands", env, ["--foo"], base_url="http://127.0.0.1:4111",
                                     api_key="ir-secret", alias=_Alias())
    assert env["LLM_MODEL"] == "openai/kimi-k2.6"
    assert env["LLM_BASE_URL"] == "http://127.0.0.1:4111/v1"
    assert env["LLM_API_KEY"] == "ir-secret"
    assert argv == ["openhands", "--override-with-envs", "--foo"]


def test_openhands_always_gets_the_flag_that_makes_the_env_count():
    """Without --override-with-envs the LLM_* variables are ignored and OpenHands keeps whatever
    provider was configured before — which on this lane means the session is not sealed at all."""
    argv = agents.openhands_env_argv("openhands", {}, [], base_url="http://x", api_key="k", alias=_Alias())
    assert "--override-with-envs" in argv


def test_codewhale_keeps_the_token_out_of_the_config_file(tmp_path, monkeypatch):
    """The token is per session; a config file in the user's home would keep it after the session it
    belonged to is gone. The file names an env var instead."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    env: dict = {}
    argv = agents.codewhale_env_argv("codewhale", env, [], base_url="http://127.0.0.1:4111",
                                     api_key="ir-secret-token", alias=_Alias())
    cfg = (tmp_path / ".codewhale" / "config.toml").read_text()
    assert "ir-secret-token" not in cfg, "the session token was written to disk"
    assert 'api_key_env = "IR_CODEWHALE_KEY"' in cfg
    assert env["IR_CODEWHALE_KEY"] == "ir-secret-token"
    assert 'base_url = "http://127.0.0.1:4111/v1"' in cfg
    assert argv[:5] == ["codewhale", "--provider", "inferroute", "--model", "kimi-k2.6"]


def test_codewhale_leaves_the_users_own_providers_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    d = tmp_path / ".codewhale"
    d.mkdir()
    (d / "config.toml").write_text('provider = "mine"\n\n[providers.mine]\nbase_url = "http://mine"\n')
    agents.codewhale_env_argv("codewhale", {}, [], base_url="http://x", api_key="k", alias=_Alias())
    cfg = (d / "config.toml").read_text()
    assert '[providers.mine]' in cfg and 'http://mine' in cfg
    assert cfg.count("[providers.inferroute]") == 1


def test_rewriting_the_config_does_not_stack_up_copies(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    for _ in range(3):
        agents.codewhale_env_argv("codewhale", {}, [], base_url="http://x", api_key="k", alias=_Alias())
    cfg = (tmp_path / ".codewhale" / "config.toml").read_text()
    assert cfg.count("[providers.inferroute]") == 1


def test_the_codewhale_config_is_private(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    agents.codewhale_env_argv("codewhale", {}, [], base_url="http://x", api_key="k", alias=_Alias())
    assert oct((tmp_path / ".codewhale" / "config.toml").stat().st_mode)[-3:] == "600"


@pytest.mark.parametrize("cmd", ["openhands", "codewhale"])
def test_the_new_agents_refuse_the_readable_lane_rather_than_taking_it(cmd, capsys, monkeypatch):
    monkeypatch.setattr(M, "_extract_plain", lambda a: (True, a))
    assert M.main([cmd]) == 2
    err = capsys.readouterr().err
    assert "confidential lane only" in err
    assert "kimi-k2.6" in err, "a refusal must name what DOES work"


@pytest.mark.parametrize("cmd", ["openhands", "codewhale"])
def test_an_enclave_model_reaches_the_confidential_launcher(cmd, monkeypatch):
    seen = {}
    from inferroute_cli import confidential
    monkeypatch.setattr(confidential, "launch", lambda args, agent=None: (seen.update(args=args, agent=agent), 0)[1])
    assert M.main([cmd, "--model", "kimi-k2.6", "--verbose"]) == 0
    assert seen["agent"] == cmd
    assert seen["args"] == ["--model", "kimi-k2.6", "--verbose"]


def test_both_are_known_agents_with_a_description():
    for a in ("openhands", "codewhale"):
        assert a in agents.AGENTS
        assert agents._AGENT_DESC.get(a), f"{a} would show a blank row in the picker"
