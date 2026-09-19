"""Reading a long document and proposing matters from it (Henry, 19 Sep).

The professional is being asked to trust a summary of a document they have not read closely, so the checks
here are about what a reader CANNOT catch by eye: a proposal whose quote is not in the document, a matter
created by anything other than the professional, and a document left readable by other accounts.
"""
import hashlib
import json
import stat
from pathlib import Path

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_intake as I

DOC = """A cooling jacket for cylindrical battery cells, with COOLANT-MARKER channels moulded between the
cells, so heat leaves the pack through the jacket rather than through the terminals.

Separately, a method of predicting cell swelling from impedance drift, SWELL-MARKER, applied over the first
fifty cycles of a pack's life.
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    return tmp_path


def _propose(ident, **row):
    d = I.path_of(ident)
    with (d / I.PROPOSALS).open("a") as fh:
        fh.write(json.dumps(row) + "\n")


def test_a_staged_document_is_owner_only_and_carries_its_own_hash(home):
    meta = I.stage(DOC, "Acme technical report.pdf")
    d = I.path_of(meta["id"])
    assert (d / I.DOCUMENT).read_text() == DOC
    assert meta["chars"] == len(DOC) and meta["source_name"] == "Acme technical report.pdf"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE((d / I.DOCUMENT).stat().st_mode) == 0o400      # the agent cannot edit what it reads
    assert stat.S_IMODE((d / "meta.json").stat().st_mode) == 0o600
    with pytest.raises(S.ProbantError, match="empty"):
        I.stage("   \n ")
    with pytest.raises(S.ProbantError, match="characters"):
        I.stage("x" * (I.MAX_CHARS + 1))
    with pytest.raises(S.ProbantError, match="no such document"):
        I.path_of("../../etc")


def test_a_proposal_whose_quote_is_not_in_the_document_never_reaches_the_page(home):
    ident = I.stage(DOC, "report")["id"]
    _propose(ident, title="Cooling jacket", summary="A jacket with channels between cells.",
             quote="COOLANT-MARKER channels moulded between the")
    _propose(ident, title="Invented", summary="Something the document does not say.",
             quote="a superconducting flywheel bonded to the chassis")   # not in the document
    _propose(ident, title="Cooling jacket", summary="A duplicate of the first.",
             quote="heat leaves the pack through the jacket")            # same title: kept once
    _propose(ident, title="Too short a quote", summary="ok", quote="cells")
    _propose(ident, title="", summary="no title", quote="COOLANT-MARKER channels moulded between the")
    got = I.read_proposals(ident)
    assert [p["title"] for p in got] == ["Cooling jacket"]
    assert got[0]["where"] > 0 and got[0]["suggested_matter"] == "cooling-jacket"
    assert I.dropped_count(ident) == 4


def test_a_quote_matches_across_the_line_wrapping_of_the_source(home):
    """The agent reads wrapped text and quotes it as a sentence; the check must not fail on the newline."""
    ident = I.stage(DOC, "report")["id"]
    _propose(ident, title="Swelling", summary="Predicting swelling from impedance drift.",
             quote="applied over the first fifty cycles of a pack's life")    # spans a line break in DOC
    assert [p["title"] for p in I.read_proposals(ident)] == ["Swelling"]


def test_only_the_professional_creates_a_matter_and_the_disclosure_names_its_source(home):
    ident = I.stage(DOC, "Acme report")["id"]
    _propose(ident, title="Cooling jacket", summary="A jacket with channels between cells.",
             quote="COOLANT-MARKER channels moulded between the", priority_date="2021-03-01")
    # Nothing exists until this call, which takes the client and matter names from the professional.
    assert not (S.matters_dir() / "Acme").exists()
    assert I.create_matter(ident, "Acme", "battery-cooling", 0) == "Acme/battery-cooling"
    rec = S.load_record("Acme", "battery-cooling")
    assert rec["date_bound"] == "2021-03-01"                    # the date the proposal found, used as given
    text = (S.workspace_path("Acme", "battery-cooling") / "disclosure.md").read_text()
    assert "COOLANT-MARKER" in text and "Acme report" in text and "sha256" in text
    with pytest.raises(S.ProbantError, match="no such proposal"):
        I.create_matter(ident, "Acme", "other", 7)


def test_a_priority_date_the_agent_offers_is_used_only_when_it_is_a_date(home):
    ident = I.stage(DOC, "report")["id"]
    _propose(ident, title="Cooling jacket", summary="channels between cells", priority_date="sometime in 2021",
             quote="COOLANT-MARKER channels moulded between the")
    assert I.read_proposals(ident)[0]["priority_date"] == ""
    I.create_matter(ident, "Acme", "battery-cooling", 0)
    assert S.load_record("Acme", "battery-cooling")["pre_filing_default"] is True   # today, flagged as a default


def test_a_document_edited_after_staging_invalidates_its_proposals(home):
    """The session works in this directory, so it can write here. If it could also rewrite the document, an
    invented quote would check out against the rewrite."""
    ident = I.stage(DOC, "report")["id"]
    _propose(ident, title="Cooling jacket", summary="channels between cells",
             quote="COOLANT-MARKER channels moulded between the")
    assert len(I.read_proposals(ident)) == 1
    doc = I.path_of(ident) / I.DOCUMENT
    doc.chmod(0o600)
    doc.write_text(DOC + "\nA superconducting flywheel bonded to the chassis.\n")
    with pytest.raises(S.ProbantError, match="changed after it was staged"):
        I.read_proposals(ident)


def test_a_reading_session_gets_the_proposal_tool_and_no_search_tool(home, monkeypatch, tmp_path):
    """No search tool exists in this mode: a whole document is in context, and nothing about it may leave for
    a search machine. The prompt that runs is the intake prompt, and the record pins WHICH prompt that was."""
    from inferroute_cli import models as M, pi_attested as PA
    ident = I.stage(DOC, "report")["id"]
    env = {"IR_INTAKE_DIR": str(I.path_of(ident))}
    argv = PA.env_argv("pi", env, [], base_url="http://127.0.0.1:1", api_key="k", alias=M.get("kimi-k2.6"),
                       upstream_name="u", search_endpoint="http://127.0.0.1:2")   # offered, and still not used
    tools = argv[argv.index("--tools") + 1].split(",")
    assert "propose_matter" in tools
    assert not {"prior_art_search", "matter_marks", "suggest_next_steps"} & set(tools)
    assert env["IR_INTAKE_OUT"] == str(I.path_of(ident) / "proposals.jsonl")
    assert env["IR_ATTESTED_TOOLS"] == ",".join(tools)
    prompt = Path(argv[argv.index("--system-prompt") + 1]).read_text()
    assert "propose_matter" in prompt and "verbatim" in prompt
    assert env["IR_CONTRACT_SHA"] == hashlib.sha256(prompt.encode()).hexdigest()
    # Without a document, nothing of intake is left behind for the next session to inherit.
    plain: dict = {"IR_INTAKE_OUT": "/stale"}
    PA.env_argv("pi", plain, [], base_url="http://127.0.0.1:1", api_key="k", alias=M.get("kimi-k2.6"),
                upstream_name="u", search_endpoint="http://127.0.0.1:2")
    assert "IR_INTAKE_OUT" not in plain
    assert "propose_matter" not in plain["IR_ATTESTED_TOOLS"]


def test_the_proposal_tool_records_what_it_says_it_recorded(home, tmp_path):
    """Drives the extension's real propose_matter handler."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    from inferroute_cli import pi_attested as PA
    ts = (Path(PA.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    body = ts[ts.index("\t\t\tasync execute(_toolCallId, params) {", ts.index('name: "propose_matter"')):]
    body = body[:body.index("\n\t\t\t},")]
    out = tmp_path / "proposals.jsonl"
    js = ("import { mkdirSync, writeFileSync } from 'node:fs';\n"
          f"const intakeOut = {json.dumps(str(out))};\n"
          "const run = async (params) => { " + body[body.index("{") + 1:] + " };\n"
          "const tryIt = async (p) => { try { const r = await run(p); return r.details.title; } catch (e) { return 'ERR ' + e.message; } };\n"
          "console.log(JSON.stringify({ ok: await tryIt({ title: 'Cooling jacket', summary: 'channels between cells',"
          " quote: 'COOLANT-MARKER channels moulded between the' }),"
          " short: await tryIt({ title: 'x', summary: 'y', quote: 'too short' }),"
          " bare: await tryIt({ title: '', summary: '', quote: '' }) }));")
    r = subprocess.run([node, "--experimental-strip-types", "--input-type=module-typescript", "-e", js],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "input-type" in r.stderr:
        pytest.skip("this node cannot run TypeScript from -e")
    assert r.returncode == 0, r.stderr[-800:]
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["ok"] == "Cooling jacket"
    assert got["short"].startswith("ERR") and "verbatim quote" in got["short"]
    assert got["bare"].startswith("ERR")
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["title"] == "Cooling jacket" and rows[0]["at"].endswith("Z")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
