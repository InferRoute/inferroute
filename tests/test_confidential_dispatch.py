"""`ir` lane dispatch: enclave-backed models open confidentially by default for every agent;
`--plain` opts out with a printed note; non-enclave models stay on the standard lane; the agent
adapters produce configs that point at the given endpoint in the agent's NATIVE dialect."""
import json

from inferroute_cli import agents, main as M, models


class _Alias:
    short = "kimi-k2.6"
    model_id = "Kimi-K2.6"
    ref_key = "moonshotai/Kimi-K2.6-TEE"


def _capture(monkeypatch):
    calls = []
    import inferroute_cli.confidential as C
    monkeypatch.setattr(C, "launch", lambda args, agent="claude": calls.append(("confidential", agent, list(args))) or 0)
    monkeypatch.setattr(M.launch, "launch_through_inferroute", lambda *a, **k: calls.append(("plain-claude", a[0])) or 0)
    monkeypatch.setattr(M.launch, "launch_agent_plain", lambda agent, model, creds, extra_args=(): calls.append(("plain", agent, model)) or 0)
    monkeypatch.setattr(M.launch, "launch_goose", lambda *a, **k: calls.append(("plain-goose", a[0])) or 0)
    monkeypatch.setattr(M.config, "load", lambda: type("C", (), {"is_valid": True, "api_url": "u", "api_key": "k"})())
    return calls


def test_enclave_models_default_to_the_confidential_lane_for_every_agent(monkeypatch):
    calls = _capture(monkeypatch)
    M.main(["--model", "glm-5.2", "-p", "hi"])
    M.main(["pi", "--model", "kimi-k2.6", "-p", "x"])
    M.main(["opencode", "--model", "glm-5.2", "run", "x"])
    M.main(["goose", "--model", "kimi-k2.6"])
    assert calls == [("confidential", "claude", ["--model", "glm-5.2", "-p", "hi"]),
                     ("confidential", "pi", ["--model", "kimi-k2.6", "-p", "x"]),
                     ("confidential", "opencode", ["--model", "glm-5.2", "run", "x"]),
                     ("confidential", "goose", ["--model", "kimi-k2.6"])]


def test_plain_opts_out_and_non_enclave_models_stay_plain(monkeypatch, capsys):
    calls = _capture(monkeypatch)
    M.main(["--model", "glm-5.2", "--plain", "-p", "hi"])
    M.main(["pi", "--model", "kimi-k2.6", "--plain"])
    M.main(["--model", "minimax-m3", "-p", "hi"])
    assert calls == [("plain-claude", "glm-5.2"), ("plain", "pi", "kimi-k2.6"), ("plain-claude", "minimax-m3")]
    err = capsys.readouterr().err
    assert "standard lane (--plain)" in err and "not enclave-backed" in err
    assert M._is_confidential_model("kimi-k2.6") and not M._is_confidential_model("minimax-m3") and not M._is_confidential_model("nope")


def test_pi_adapter_declares_an_openai_native_provider_and_keeps_the_users_providers():
    doc = agents.pi_models_json("http://127.0.0.1:5", "k", _Alias(), "Kimi [confidential]", existing={"providers": {"mine": {"baseUrl": "x"}}})
    prov = doc["providers"]["inferroute"]
    assert prov["api"] == "openai-completions" and prov["baseUrl"] == "http://127.0.0.1:5/v1" and prov["apiKey"] == "k"
    assert prov["compat"]["thinkingFormat"] == "deepseek" and prov["models"][0]["id"] == "kimi-k2.6"
    assert doc["providers"]["mine"] == {"baseUrl": "x"}, "the user's own providers survive the merge"


def test_opencode_adapter_uses_the_openai_compatible_sdk_and_disables_sharing_when_confidential():
    cfg = agents.opencode_config("http://127.0.0.1:5", "k", _Alias(), "Kimi [confidential]")
    p = cfg["provider"]["inferroute"]
    assert p["npm"] == "@ai-sdk/openai-compatible" and p["options"]["baseURL"] == "http://127.0.0.1:5/v1"
    assert cfg["model"] == "inferroute/kimi-k2.6" == cfg["small_model"] and cfg["share"] == "disabled"
    plain = agents.opencode_config("https://api.inferroute.ai", "k", _Alias(), "Kimi", headers={"x-inferroute-session": "s"}, confidential=False)
    assert "share" not in plain and plain["provider"]["inferroute"]["options"]["headers"] == {"x-inferroute-session": "s"}
    env = {}
    argv = agents.opencode_env_argv("/bin/opencode", env, ["run", "hi"], base_url="http://127.0.0.1:5", api_key="k", alias=_Alias(), upstream_name="n")
    assert argv == ["/bin/opencode", "run", "hi"] and json.loads(env["OPENCODE_CONFIG_CONTENT"])["model"] == "inferroute/kimi-k2.6"


def test_pi_config_dir_mirrors_the_users_agent_dir_without_touching_it(tmp_path, monkeypatch):
    user = tmp_path / "agent"
    user.mkdir()
    (user / "settings.json").write_text("{}")
    (user / "models.json").write_text(json.dumps({"providers": {"mine": {"baseUrl": "x"}}}))
    (user / "sessions").mkdir()
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(user))
    env = {}
    argv = agents.pi_env_argv("/bin/pi", env, ["-p", "hi"], base_url="http://127.0.0.1:5", api_key="k", alias=_Alias(), upstream_name="n")
    assert argv == ["/bin/pi", "--provider", "inferroute", "--model", "kimi-k2.6", "-p", "hi"]
    d = env["PI_CODING_AGENT_DIR"]
    assert d != str(user) and (tmp_path / "agent" / "models.json").read_text() == json.dumps({"providers": {"mine": {"baseUrl": "x"}}}), "the user's file is untouched"
    merged = json.loads(open(d + "/models.json").read())
    assert set(merged["providers"]) == {"mine", "inferroute"}
    import os
    assert os.path.islink(d + "/settings.json") and os.path.realpath(d + "/sessions") == str(user / "sessions")
    assert models.get("kimi-k2.6") is not None


def test_goose_adapter_points_its_openai_provider_at_the_endpoint_and_honours_run(monkeypatch, tmp_path):
    monkeypatch.setattr("inferroute_cli.launch._write_goose_config", lambda *a, **k: None)
    env = {}
    argv = agents.goose_env_argv("/bin/goose", env, ["run", "-t", "hi", "--no-session"], base_url="http://127.0.0.1:5", api_key="k", alias=_Alias())
    assert argv == ["/bin/goose", "run", "-t", "hi", "--no-session"]
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:5" and env["GOOSE_PROVIDER"] == "openai" and env["GOOSE_MODEL"] == "kimi-k2.6"
    assert agents.goose_env_argv("/bin/goose", {}, ["--name", "x"], base_url="u", api_key="k", alias=_Alias())[:2] == ["/bin/goose", "session"]
