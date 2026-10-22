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


def test_the_home_page_creates_a_name_matter_and_reports_the_index(home):
    from fastapi.testclient import TestClient
    from inferroute_cli import probant_home as H
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    r = c.post("/api/matters", json={"client": "Acme", "matter": "brand", "kind": "name",
                                     "priority_date": "2020-01-01", "disclosure": "Names: Zebrafy"}).json()
    assert r == {"ok": True, "id": "Acme/brand"}
    m = c.get("/api/matter?id=Acme/brand").json()
    assert m["kind"] == "name"
    assert (S.workspace_path("Acme", "brand") / "disclosure.md").read_text().startswith("# Names to check")
    assert c.get("/api/overview").json()["matters"][0]["kind"] == "name"
    status = c.get("/api/tm-index").json()
    assert status["installed"] is False and status["download_mb"] > 0 and status["disk_mb"] > status["download_mb"]
    # The page says what the data holds and what it does not, before the download and on every report.
    assert any("USPTO" in x for x in status["searched"]) and any("INPI" in x for x in status["searched"])
    assert "EU trade marks (EUIPO)" in status["not_searched"] and "company and trading names" in status["not_searched"]
    assert c.get("/api/name-check?id=Acme/brand").json()["present"] is False
    (S.workspace_path("Acme", "brand") / "name-check.md").write_text("# Name check\n\nZEBRA (US 7)\n")
    report = c.get("/api/name-check?id=Acme/brand").json()
    assert report["present"] and "ZEBRA" in report["text"] and report["written_at"].endswith("Z")
    from inferroute_cli import tm_search
    tm_search.log_search(S.records_dir("Acme", "brand"), {"name": "Zebrafy", "classes": ["9"], "hits": [], "more": 0})
    assert [x["name"] for x in c.get("/api/name-check?id=Acme/brand").json()["searches"]] == ["Zebrafy"]
    # A second session keeps the first report: it is moved aside before the session starts, and both are shown.
    ws = S.workspace_path("Acme", "brand")
    kept = S.keep_earlier_name_check(ws)
    assert kept and kept.name.startswith("name-check-") and not (ws / "name-check.md").exists()
    report = c.get("/api/name-check?id=Acme/brand").json()
    assert report["present"] is False and "ZEBRA" in report["earlier"][0]["text"]
    (ws / "name-check.md").write_text("# Name check\n\nZEBRO (FR 8)\n")
    report = c.get("/api/name-check?id=Acme/brand").json()
    assert "ZEBRO" in report["text"] and [r["file"] for r in report["earlier"]] == [str(kept)]
    assert S.keep_earlier_name_check(ws) != kept and len(S.earlier_name_checks(ws)) == 2   # same minute: no clash
    assert S.keep_earlier_name_check(ws) is None
    assert c.get("/api/overview").json()["matters"][0]["names"] == ["Zebrafy"]      # the card shows the names
    c.post("/api/matters", json={"client": "Acme", "matter": "gadget", "disclosure": "x"})
    assert c.get("/api/matter?id=Acme/gadget").json()["kind"] == "invention"


def test_a_name_session_that_searched_but_wrote_no_report_is_reminded_once():
    """Measured on a Mac, 19 Oct (0.9.119): seven searches, then "Now writing the report…" and the turn ended with
    no name-check.md. The extension asks for the report once (tests/tm_report_reminder_sim.js runs the real block)."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run([node, str(root / "tests" / "tm_report_reminder_sim.js")], cwd=root,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no loop" in r.stdout, r.stdout


def test_the_names_a_matter_lists_are_read_from_either_template():
    assert S.names_listed(S.TEMPLATE_NAMES) == []                                  # the empty template lists none
    assert S.names_listed("# Names to check\n\n## The product\n\nA bottle.\n\n## Names being considered\n\n"
                          "- Kwench\n- **Aquelia**\n\n## Markets\n\nFrance") == ["Kwench", "Aquelia"]
    assert S.names_listed("The product: a bottle.\n\nNames being considered (one per line):\n- Taxly\n- Setaside\n\n"
                          "Where you will sell it: France") == ["Taxly", "Setaside"]
    assert S.names_listed("Names: Zebrafy, Zebrix") == ["Zebrafy", "Zebrix"]
    assert S.names_listed("The product: labels that print names on bottles.") == []


def test_the_three_name_fields_write_notes_whose_names_are_found_again():
    """22 Oct (Henry: unclear what to put in the "disclosure" for trademarks): a name check asks for names,
    what the product is and where it will be sold, and writes them in the shape names_listed reads."""
    from pathlib import Path
    from inferroute_cli import probant as P
    js = (Path(__file__).resolve().parents[1] / "inferroute_cli" / "probant_web" / "home.js").read_text()
    for head in ("Names being considered (one per line):", "The product, in one or two sentences:",
                 "Where you will sell it (for example France, the EU, the US):"):
        assert head in js
    composed = ("Names being considered (one per line):\n- Kwench\n- Aquelia\n\n"
                "The product, in one or two sentences:\nA bottle.\n\n"
                "Where you will sell it (for example France, the EU, the US):\nFrance\n")
    assert P.names_listed(composed) == ["Kwench", "Aquelia"]


def test_a_name_check_defaults_to_the_model_measured_fastest_with_exact_citations():
    """22 Oct benchmark: kimi-k2.6 wrote name reports in ~70 s with every cited number exact; kimi-k3 took ~14 min.
    Names mode alone switches; reading and drafting keep PROBANT_MODEL."""
    from pathlib import Path
    from inferroute_cli import confidential as C
    assert C.PROBANT_NAMES_MODEL == "kimi-k2.6" and C.PROBANT_MODEL == "kimi-k3"
    src = (Path(__file__).resolve().parents[1] / "inferroute_cli" / "confidential.py").read_text()
    assert 'PROBANT_NAMES_MODEL if probant.get("mode") == "names" else PROBANT_MODEL' in src
