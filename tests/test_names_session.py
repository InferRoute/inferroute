"""A name matter's session (Anteriora, 19 Oct): the assistant gets the trademark search and nothing else new.

What has to hold, and cannot be seen from inside a session: a name session offers the trademark search and
no patent search (so nothing goes to a search machine); the trademark search exists in no other kind of
session, on this computer or in the Mac VM; the host route answers only behind the session key and refuses
bad input; and a name matter is created as one, with its own template.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import pi_attested as PA
from inferroute_cli import probant as S
from inferroute_cli import probant_trust as TR
from inferroute_cli import tm_search as T
from inferroute_local.macos_vm.broker import Broker
from inferroute_local.macos_vm.plan import build_plan

ALIAS = SimpleNamespace(short="kimi-k2.6", model_id="kimi-k2.6", ref_key="fixture/Model-TEE")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    monkeypatch.delenv("IR_TM_INDEX", raising=False)
    return tmp_path


def _argv(env, search_endpoint=None):
    return PA.env_argv("pi", env, [], base_url="http://127.0.0.1:9", api_key="k", alias=ALIAS,
                       upstream_name="u", search_endpoint=search_endpoint)


def _tools(argv):
    return argv[argv.index("--tools") + 1].split(",")


def test_a_name_session_offers_the_trademark_search_and_no_patent_search(home):
    env = {"IR_TM_SEARCH": "1"}
    tools = _tools(_argv(env, search_endpoint="http://127.0.0.1:7"))
    assert PA.TM_TOOL in tools and PA.SEARCH_TOOL not in tools and PA.DEEP_TOOL not in tools
    assert "IR_SEARCH_ENDPOINT" not in env                     # even if one was offered, it is dropped
    assert env["IR_CONTRACT_SHA"] == PA.load_names_prompt()["contract_sha"]


def test_no_other_session_offers_the_trademark_search(home):
    assert PA.TM_TOOL not in _tools(_argv({}, search_endpoint="http://127.0.0.1:7"))
    assert PA.TM_TOOL not in _tools(_argv({}))
    for mode in ("matter", "intake"):
        assert PA.TM_TOOL not in build_plan(alias="kimi-k3", surface_browser_only=True, mode=mode).tools


def test_the_vm_plan_for_a_name_session_has_no_search_machine(home):
    plan = build_plan(alias="kimi-k3", surface_browser_only=True, mode="names")
    assert PA.TM_TOOL in plan.tools and PA.SEARCH_TOOL not in plan.tools
    assert plan.env["IR_TM_SEARCH"] == "1" and "IR_SEARCH_ENDPOINT" not in plan.env


def test_the_vm_broker_refuses_the_trademark_search_outside_a_name_session():
    broker = Broker(SimpleNamespace())
    broker.configure({"mode": "matter"}, "http://127.0.0.1:9", "k")
    with pytest.raises(ValueError, match="operation unavailable"):
        list(broker._http("tm.search", {"name": "x"}))     # a generator: the refusal fires when consumed


def test_the_name_prompt_forbids_a_verdict_and_web_search():
    text = PA.load_names_prompt()["text"]
    assert "Do not say a name is available" in text and "Do not search the web" in text
    assert "name-check.md" in text


def test_the_extension_registers_the_tool_only_for_a_name_session():
    ts = (Path(PA.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    block = ts[ts.index('if (process.env.IR_TM_SEARCH === "1")'):]
    assert block.index('name: "trademark_search"') < block.index("/probant/tm/search")


def test_the_host_route_searches_and_refuses_bad_input(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    index = tmp_path / "tm.sqlite"
    T.build(iter([("US", "1", "ANTERIOR", "registered", ["42"], "2024-01-01")]), index, "2026-09-30", ["test"])
    app = FastAPI()
    T.install_route(app, index)
    c = TestClient(app)
    r = c.post("/probant/tm/search", json={"name": "Anteriora", "classes": ["42"]})
    assert r.status_code == 200 and r.json()["hits"][0]["number"] == "1"
    assert c.post("/probant/tm/search", json={"name": ""}).status_code == 400
    assert c.post("/probant/tm/search", json={"name": "x" * 121}).status_code == 400
    missing = FastAPI()
    T.install_route(missing, tmp_path / "absent.sqlite")
    assert TestClient(missing).post("/probant/tm/search", json={"name": "a"}).status_code == 503


def test_a_name_matter_is_created_as_one_and_needs_an_index_to_open(home, capsys):
    assert S.main(["new", "Acme", "brand", "--kind", "name"]) == 0
    rec = S.load_record("Acme", "brand")
    assert rec["kind"] == "name"
    assert "Names being considered" in (S.workspace_path("Acme", "brand") / "disclosure.md").read_text()
    assert S.main(["open", "Acme/brand"]) != 0
    assert "no trademark index is installed" in capsys.readouterr().err
    assert S.main(["new", "Acme", "gadget"]) == 0 and "kind" not in S.load_record("Acme", "gadget")


def test_the_trust_card_says_the_trademark_search_runs_here():
    item = TR.search_item(None, mode="names")
    assert item["title"] == "Trademark search" and "not sent" in item["points"][0]


def test_the_vm_broker_lets_a_name_session_reach_the_trademark_search():
    broker = Broker(SimpleNamespace())
    broker.configure({"mode": "names"}, "http://127.0.0.1:9", "k")
    try:
        list(broker._http("tm.search", {"name": "x"}))     # nothing listens on :9; any failure but the gate's is fine
    except ValueError as e:
        assert "operation unavailable" not in str(e)
    except Exception:
        pass
