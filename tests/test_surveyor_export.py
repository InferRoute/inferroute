"""`ir surveyor export` — the one-file record the attorney can hand to a client: the disclosure, the
relevance marks with their exposure, every attested session with its confinement stamp, the enclave-signed
statements verbatim, and the note that this device assembled it from records it wrote itself. Built entirely
from host-held files under confidential/, never from anything the agent could reach.
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


def _write_session(sid, record, statements=None):
    rdir = S.records_dir("AcmeCorp", "battery-cooling")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{sid}.json").write_text(json.dumps(record))
    if statements:
        (rdir / f"{sid}.statements.jsonl").write_text("".join(json.dumps(s) + "\n" for s in statements))


def _write_state(marks):
    S.state_path("AcmeCorp", "battery-cooling").write_text(json.dumps({"approved": [], "marks": marks, "surfaced": {}}))


def test_export_renders_the_full_record(matter, monkeypatch):
    _write_session("sess-1", {
        "started_at": "2026-09-14T10:00:00Z",
        "confinement": "require (address-level egress enforced or the session does not start)",
        "model_lane": {"verified": True, "checks": "15/15 passed"},
        "search_lane": {"searches": [{"at": "2026-09-14T10:05:00Z", "hits": 3, "measurement": "a" * 40,
                                      "policy": "b" * 40, "index": "us-2026-09"}]},
        "which_surface_saw_what": {"model_enclave": "saw the conversation, inside a verified enclave",
                                   "network": "confined to the two local verifying proxies"},
        "contract": {"modified": False},
    }, statements=[{"at": "2026-09-14T10:05:01Z", "signer_pub": "ed25519-pub-hex",
                    "statement": {"hits_n": 3, "cutoff_date": 20200115, "request": "r1", "sig": "SIGNATUREHEX"}}])
    _write_state({"US-7000-B2": {"latest": {"value": "relevant", "actor": "human", "at": "2026-09-14T10:06:00Z",
                                            "surfaced": "this_session", "rank": 1},
                                 "history": [{"value": "relevant", "at": "2026-09-14T10:06:00Z"}]}})

    out = matter / "out.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    # matter + date bound
    assert "AcmeCorp" in h and "battery-cooling" in h and "2020-01-15" in h
    # disclosure content
    assert "COOLANT-MARKER" in h
    # the mark with its host-computed exposure and human actor
    assert "US-7000-B2" in h and "relevant" in h and "surfaced by this session" in h and "human" in h
    # the session's confinement stamp and model verification
    assert "require (address-level egress enforced" in h and "15/15 passed" in h
    # the signed statement verbatim, including the signature and signer key
    assert "SIGNATUREHEX" in h and "ed25519-pub-hex" in h and "20200115" in h
    # this device's record framing
    assert "this device" in h.lower() and "not by the model" in h
    # self-contained: no external resource references
    assert "http://" not in h and "https://" not in h and "<script" not in h


def test_export_flags_a_dev_unconfined_session(matter):
    _write_session("sess-dev", {
        "started_at": "2026-09-14T11:00:00Z",
        "confinement": "unconfined (developer override)",
        "model_lane": {"verified": True, "checks": "15/15"},
        "search_lane": {"searches": []},
    })
    out = matter / "dev.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    assert "unconfined (developer override)" in h
    # it is rendered as a warning class, not silently normal
    assert 'class=bad>unconfined (developer override)' in h


def test_export_of_a_matter_with_no_sessions_still_renders(matter):
    out = matter / "empty.html"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = out.read_text()
    assert "No attested sessions" in h and "No relevance marks" in h


def test_export_of_unknown_matter_refuses(matter):
    assert S.main(["export", "Nobody/none"]) == 2


def test_disclosure_content_gates_prewarm(matter):
    # L3: a fresh matter has only the template → do not prewarm; once the attorney writes a disclosure → prewarm.
    ws = Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"])
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE)
    assert S.disclosure_has_content(ws) is False
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE + "\nThe invention is a phase-change cooling loop.\n")
    assert S.disclosure_has_content(ws) is True
