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


def _cw(env, passthrough, api_key="k"):
    """The launch also calls `codewhale auth set`; tests that are not about that stub it out."""
    import subprocess
    from unittest import mock
    with mock.patch.object(subprocess, "run", lambda *a, **k: None):
        return agents.codewhale_env_argv("codewhale", env, passthrough, base_url="http://127.0.0.1:4111",
                                         api_key=api_key, alias=_Alias())


def test_codewhale_uses_the_builtin_openai_provider_not_a_custom_one():
    """Its docs describe a `[providers.<name>]` table for custom gateways. The real binary (0.10.0)
    answers `--provider inferroute` with "configured custom providers are accepted only by exec and
    fleet", so that design does not work at all — caught by running it, not by reading."""
    env: dict = {}
    argv = _cw(env, ["--foo"], "ir-secret-token")
    assert argv[:5] == ["codewhale", "--provider", "openai", "--model", "kimi-k2.6"]
    assert "inferroute" not in argv, "the binary rejects a custom provider name outright"
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:4111/v1"
    assert "OPENAI_API_KEY" not in env, "measured: it is ignored, so setting it would only mislead"


def test_codewhale_hands_the_key_over_on_stdin_because_the_env_var_is_silently_dropped(monkeypatch):
    """MEASURED: with OPENAI_API_KEY set, CodeWhale 0.10.0 sends NO Authorization header — the request
    arrives with empty auth and the sealed endpoint would 401 every turn. Only `auth set --api-key-stdin`
    delivers it without putting it in the process table."""
    seen = {}
    import subprocess
    monkeypatch.setattr(subprocess, "run",
                        lambda a, **k: seen.update(argv=a, stdin=k.get("input")) or None)
    agents.codewhale_env_argv("codewhale", {}, [], base_url="http://x", api_key="ir-secret-token",
                              alias=_Alias())
    assert seen["argv"] == ["codewhale", "auth", "set", "--provider", "openai", "--api-key-stdin"]
    assert seen["stdin"] == "ir-secret-token"
    assert "ir-secret-token" not in " ".join(seen["argv"])


def test_codewhale_keeps_the_token_off_the_command_line():
    """CodeWhale takes `--api-key` on argv. We do not use it: that is the process table, which is where
    a key of ours already leaks once via xdg-open."""
    argv = _cw({}, [], "ir-secret-token")
    assert "--api-key" not in argv
    assert not any("ir-secret-token" in a for a in argv)


def test_codewhale_writes_no_config_file(tmp_path, monkeypatch):
    """The earlier design wrote ~/.codewhale/config.toml. Pointing by environment means no file, so no
    per-session token can outlive the session on disk."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    _cw({}, [])
    assert not (tmp_path / ".codewhale").exists()


def test_codewhale_suppresses_its_own_telemetry():
    """It reports usage to PostHog by default. We turn an agent's telemetry off on this lane, as we do
    for Pi."""
    argv = _cw({}, [])
    i = argv.index("--telemetry")
    assert argv[i + 1] == "false"


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


def test_every_agent_ir_can_install_is_one_ir_can_run():
    """An installer for an agent the CLI cannot launch would be a dead end, and an agent with no
    installer is a support question. The two lists are kept honest against each other."""
    from inferroute_cli.add import AGENT_INSTALLS
    for name in AGENT_INSTALLS:
        assert name in agents.AGENTS or name == "cline", name
    # cline is the exception on purpose: we cannot write its provider config, so `ir cline` hands the
    # values over rather than launching it. It is installable but not an agent we spawn.
    assert "cline" not in agents.AGENTS


def test_the_install_commands_are_the_ones_that_were_actually_run():
    """These were run on this machine before being written down. A plausible-looking command that does
    not exist is the failure mode: `pip install openhands-ai` gets the LIBRARY, not the CLI."""
    from inferroute_cli.add import AGENT_INSTALLS
    assert AGENT_INSTALLS["openhands"][1] == ["pipx", "install", "openhands"]
    assert AGENT_INSTALLS["codewhale"][1] == ["npm", "install", "-g", "codewhale"]
    assert AGENT_INSTALLS["cline"][1] == ["npm", "install", "-g", "cline"]


def test_the_installer_checks_the_program_appeared_rather_than_the_exit_code(monkeypatch, capsys):
    """A package can install cleanly and put nothing on PATH. Exit code 0 is not the thing we care about."""
    import subprocess

    from inferroute_cli import add
    monkeypatch.setattr(add, "AGENT_INSTALLS", {"codewhale": ("npm", ["npm", "i"], "d")})
    monkeypatch.setattr("shutil.which", lambda t: "/usr/bin/npm")
    monkeypatch.setattr(subprocess, "run", lambda c: type("R", (), {"returncode": 0})())
    from inferroute_cli import agents as A
    monkeypatch.setattr(A, "find_agent", lambda n: None)
    assert add._add_agent("codewhale", yes=True) == 1
    assert "no `codewhale` program was found" in capsys.readouterr().out
