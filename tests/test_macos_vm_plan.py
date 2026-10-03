import base64
import json

import pytest

from inferroute_cli import pi_attested
from inferroute_local.macos_vm.plan import (
    GUEST_CAPABILITY,
    GUEST_EXTENSION,
    GUEST_NODE,
    GUEST_PI_CLI,
    MODEL_PORT,
    SEARCH_PORT,
    PlanRefused,
    build_plan,
)


def plan(**kwargs):
    defaults = {"alias": "kimi-k3", "surface_browser_only": True}
    defaults.update(kwargs)
    return build_plan(**defaults)


def test_matter_plan_uses_fixed_guest_paths_tools_and_fixture_endpoints():
    result = plan(
        host_env={
            "IR_REPORT_FIRM": "Synthetic",
            "IR_REPORT_MATTER": "Synthetic/Matter",
        },
        documents={"US-7000-B2": "Synthetic title"},
    )
    assert result.cwd == "/matter"
    assert result.argv[:5] == (GUEST_NODE, GUEST_PI_CLI, "-ne", "-e", GUEST_EXTENSION)
    assert result.argv[result.argv.index("--mode") + 1] == "rpc"
    assert result.argv[result.argv.index("--no-session")]
    assert result.tools == pi_attested.MATTER_TOOLS + (
        pi_attested.SEARCH_TOOL,
        pi_attested.DEEP_TOOL,
        pi_attested.OPEN_TOOL,
        pi_attested.MARKS_TOOL,
        pi_attested.NEXT_TOOL,
    )
    assert result.env["IR_ATTESTED_CONFINE"] == "require"
    assert result.env["IR_ATTESTED_ENDPOINT"] == f"http://127.0.0.1:{MODEL_PORT}"
    assert result.env["IR_SEARCH_ENDPOINT"] == f"http://127.0.0.1:{SEARCH_PORT}"
    assert result.env["IR_ATTESTED_KEY"] == GUEST_CAPABILITY
    assert result.env["IR_REPORT_FIRM"] == "Synthetic"
    assert result.env["IR_REPORT_MATTER"] == "Synthetic/Matter"
    assert result.env["IR_MATTER_DOCS"] == "/config/matter-docs.json"
    assert "IR_MATTER_STATE_FILE" not in result.env
    assert "IR_MATTER_RECORD_DIR" not in result.env

    models = json.loads(result.config["models.json"])
    provider = models["providers"]["inferroute"]
    assert provider["baseUrl"] == f"http://127.0.0.1:{MODEL_PORT}/v1"
    assert provider["apiKey"] == GUEST_CAPABILITY
    assert provider["models"][0]["id"] == "kimi-k3"
    assert json.loads(result.config["matter-docs.json"]) == {
        "US-7000-B2": "Synthetic title"
    }


def test_request_is_json_serializable_and_contains_guest_config_paths_as_base64():
    result = plan(documents={"US-7000-B2": "Synthetic title"})
    encoded = result.request["files"]["/config/models.json"]
    assert base64.b64decode(encoded) == result.config["models.json"]
    assert json.loads(json.dumps(result.request)) == result.request
    assert all(not path.startswith("/home/") for path in result.request["files"])


def test_intake_create_drafts_has_only_intake_tools_and_no_search_endpoint():
    result = plan(mode="intake", create_drafts=True)
    assert result.tools == ("read", "grep", "find", "ls", "create_draft_matter")
    assert result.env["IR_INTAKE_DIR"] == "/matter"
    assert result.env["IR_INTAKE_OUT"] == "/matter/proposals.jsonl"
    assert result.env["IR_INTAKE_CREATE_DRAFTS"] == "1"
    assert "IR_SEARCH_ENDPOINT" not in result.env
    assert "prior_art_search" not in result.env["IR_ATTESTED_TOOLS"]
    assert (
        result.config["system-prompt.txt"]
        == pi_attested.load_intake_prompt(True)["text"].encode()
    )


def test_intake_proposals_only_keeps_existing_reading_tools_without_search():
    result = plan(mode="intake", create_drafts=False)
    assert result.tools == pi_attested.TOOLS + (
        pi_attested.PROPOSE_TOOL,
        pi_attested.BATCH_TOOL,
    )
    assert result.env["IR_INTAKE_CREATE_DRAFTS"] == "0"
    assert "IR_SEARCH_ENDPOINT" not in result.env
    assert (
        result.config["system-prompt.txt"]
        == pi_attested.load_intake_prompt(False)["text"].encode()
    )


def test_intake_does_not_inherit_matter_report_labels():
    with pytest.raises(PlanRefused, match="matter labels"):
        plan(mode="intake", host_env={"IR_REPORT_FIRM": "Synthetic"})


def test_terminal_surface_refuses_initially():
    with pytest.raises(PlanRefused, match="browser-only"):
        build_plan(alias="kimi-k3")


@pytest.mark.parametrize(
    "args",
    [
        ("--provider", "other"),
        ("--api-key", "synthetic-secret"),
        ("--tools", "bash"),
        ("--resume", "old-session"),
        ("--unknown",),
        ("--mode", "json"),
        ("--mode=rpc",),
        ("--mode", "rpc", "--mode", "rpc"),
        ("/etc/passwd",),
        ("../../sibling.txt",),
        ("~/secret",),
        ("C:\\Users\\private.txt",),
        (".ssh",),
        ("relative/file",),
        ("disclosure.txt",),
        ("@/home/user/secret.txt",),
    ],
)
def test_refuses_unsafe_flags_or_file_like_arguments(args):
    with pytest.raises(PlanRefused):
        plan(passthrough=args)


def test_accepts_rpc_print_and_plain_positional_prompt():
    result = plan(
        passthrough=("--mode", "rpc", "--print", "Summarize the synthetic disclosure")
    )
    assert result.argv.count("--mode") == 1
    assert result.argv[-2:] == ("--print", "Summarize the synthetic disclosure")


@pytest.mark.parametrize(
    "host_env",
    [
        {"IR_ATTESTED_KEY": "real-looking-secret"},
        {"IR_MATTER_STATE_FILE": "/host/state.json"},
        {"IR_CLUSTER_OUT": "/host/cluster"},
        {"HTTP_PROXY": "http://proxy.invalid"},
    ],
)
def test_rejects_host_credentials_paths_and_non_label_environment(host_env):
    with pytest.raises(PlanRefused) as exc:
        plan(host_env=host_env)
    assert "real-looking-secret" not in str(exc.value)
    assert "/host/state.json" not in str(exc.value)


@pytest.mark.parametrize(
    "host_env",
    [
        {"IR_REPORT_FIRM": "/home/henry"},
        {"IR_REPORT_MATTER": "../../matter"},
        {"IR_ROUND_LABEL": "fixture\nsecret"},
    ],
)
def test_rejects_path_or_control_character_labels(host_env):
    with pytest.raises(PlanRefused):
        plan(host_env=host_env)


def test_rejects_invalid_mode_create_drafts_and_alias():
    with pytest.raises(PlanRefused):
        plan(mode="cluster")
    with pytest.raises(PlanRefused):
        plan(mode="matter", create_drafts=True)
    with pytest.raises(PlanRefused):
        plan(alias="../path")


def test_fresh_environment_excludes_ambient_secret_and_proxy_values(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://ambient-proxy.invalid")
    result = plan()
    assert "ANTHROPIC_API_KEY" not in result.env
    assert "ambient-secret" not in json.dumps(result.request)
    assert result.env["no_proxy"] == "127.0.0.1,localhost,::1"
    assert result.env["NO_PROXY"] == "127.0.0.1,localhost,::1"
