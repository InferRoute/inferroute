"""`ir surveyor export` — the one-file record the attorney hands a client: the disclosure (hashed), the
relevance marks with their exposure, every attested session with its confinement stamp and governing
contract, the Form-1503 search report rendered verbatim, the enclave-signed statements with the attestation
evidence that binds each signing key, and an honest per-session note about what was out of the agent's reach.
Built entirely from host-held files under confidential/.
"""
import json
from pathlib import Path

import pytest

from inferroute_cli import surveyor as S


@pytest.fixture
def matter(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_SURVEYOR_ROOT", str(tmp_path / "Surveyor"))
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR"):
        monkeypatch.delenv(k, raising=False)
    assert S.main(["new", "AcmeCorp", "battery-cooling", "--priority-date", "2020-01-15"]) == 0
    (Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"]) / "disclosure.md").write_text(
        "# Disclosure\n\nA battery housing with COOLANT-MARKER channels between cells.\n")
    return tmp_path


def _write_session(sid, record, searches=None):
    rdir = S.records_dir("AcmeCorp", "battery-cooling")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{sid}.json").write_text(json.dumps(record))
    if searches:
        (rdir / f"{sid}.searches.jsonl").write_text("".join(json.dumps(s) + "\n" for s in searches))


def _write_state(marks):
    S.state_path("AcmeCorp", "battery-cooling").write_text(json.dumps({"approved": [], "marks": marks, "surfaced": {}}))


def _full_session():
    _write_session("sess-1", {
        "started_at": "2026-09-14T10:00:00Z",
        "confinement": "require (address-level egress enforced or the session does not start)",
        "model_lane": {"verified": True, "checks": "15/15 passed"},
        "search_lane": {"searches": [{"at": "2026-09-14T10:05:00Z", "hits": 3, "measurement": "a" * 40,
                                      "policy": "b" * 40, "index": "us-2026-09"}]},
        "which_surface_saw_what": {"model_enclave": "saw the conversation, inside a verified enclave"},
        "contract": {"contract_sha": "c0ffee1234567890abcdef", "preamble_sha": "beadfeed1234567890", "modified": False},
    }, searches=[{"at": "2026-09-14T10:05:01Z", "signer_pub": "ed25519-pub-hex",
                  "statement": {"hits_n": 3, "cutoff_date": 20200115, "request": "r1", "sig": "SIGNATUREHEX"},
                  "result": {"hits": [{"key": "US-7000-B2"}]},
                  "report_html": "<!doctype html><html><body>REPORT-BODY-MARKER: US-7000-B2</body></html>",
                  "evidence": {"offer": {"runtime_data": "b64rd", "report": "snp-report-bytes"}},
                  "evidence_sha256": "x"}])
    _write_state({"US-7000-B2": {"latest": {"value": "relevant", "actor": "human", "at": "2026-09-14T10:06:00Z",
                                            "surfaced": "this_session", "rank": 1},
                                 "history": [{"value": "relevant", "at": "2026-09-14T10:06:00Z"}]}})


def test_export_renders_report_statements_evidence_and_marks(matter):
    _full_session()
    out = matter / "out.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    # matter + date bound + disclosure with hash (X5)
    assert "AcmeCorp" in h and "2020-01-15" in h and "COOLANT-MARKER" in h and "sha256" in h
    # the mark with host-computed exposure and human actor
    assert "US-7000-B2" in h and "surfaced by this session" in h and "human" in h
    # X8: the governing contract's sha shown, not only a modified flag
    assert "c0ffee1234567890" in h and "beadfeed12345678" in h
    # X1: the rendered report is embedded (in an isolated frame)
    assert "REPORT-BODY-MARKER" in h and "srcdoc=" in h and "iframe" in h
    # X2: the signed statement verbatim + a referenced evidence bundle + the redoable-checks sentence
    assert "SIGNATUREHEX" in h and "ed25519-pub-hex" in h
    assert ".evidence.json" in h and "REPORT_DATA = sha256(runtime_data)" in h
    # the evidence bundle was written beside the HTML
    sidecars = list(out.parent.glob("*.evidence.json"))
    assert sidecars and "snp-report-bytes" in sidecars[0].read_text()
    # X3: per-session reach note is honest for a require-mode session
    assert "held outside the agent" in h and "write access (require-mode confinement)" in h
    # self-contained: no external resource loads
    assert "<script" not in h and "src=\"http" not in h and "<link " not in h


def test_export_is_honest_about_a_dev_unconfined_session(matter):
    _write_session("sess-dev", {
        "started_at": "2026-09-14T11:00:00Z",
        "confinement": "unconfined (developer override)",
        "model_lane": {"verified": True, "checks": "15/15"},
        "search_lane": {"searches": []},
        "contract": {"contract_sha": "c0ffee", "preamble_sha": "beadfeed"},
    })
    out = matter / "dev.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    assert "class=bad>unconfined (developer override)" in h
    assert "the agent could have altered these records" in h


def test_export_flags_a_missing_confinement_stamp_as_warn(matter):
    _write_session("sess-x", {"started_at": "t", "model_lane": {"verified": True}, "search_lane": {"searches": []}})
    out = matter / "x.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    assert "class=warn>confinement not recorded" in h          # X6: missing is not green


def test_export_refuses_a_path_inside_the_workspace_or_a_sync_root(matter, monkeypatch):
    ws = Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"])
    assert S.main(["export", "AcmeCorp/battery-cooling", "-o", str(ws / "record.html")]) == 2   # X4 workspace
    assert S.main(["export", "AcmeCorp/battery-cooling", "-o", str(matter / "OneDrive" / "r.html")]) == 2  # sync root


def test_export_default_path_is_outside_the_workspace_and_locked_down(matter, capsys):
    assert S.main(["export", "AcmeCorp/battery-cooling"]) == 0
    exports = S.surveyor_root() / "AcmeCorp" / "exports"
    files = list(exports.glob("*.html"))
    assert files and (files[0].stat().st_mode & 0o777) == 0o600
    assert "plain text" in capsys.readouterr().out


def test_export_of_a_matter_with_no_sessions_still_renders(matter):
    out = matter / "empty.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    assert "No attested sessions" in h and "No relevance marks" in h


def test_export_of_unknown_matter_refuses(matter):
    assert S.main(["export", "Nobody/none"]) == 2


def test_disclosure_content_gates_prewarm(matter):
    ws = Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"])
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE)
    assert S.disclosure_has_content(ws) is False
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE + "\nThe invention is a phase-change cooling loop.\n")
    assert S.disclosure_has_content(ws) is True
