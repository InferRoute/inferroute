"""start_search_proxy builds the verifier command line. Two things must hold that the probant relies on:
the disclosure record goes to a fresh per-session file (Q2), and approvals are trusted from the state file
ONLY when the launch is confined in require mode (Q1). These are checked by capturing the argv without
starting a real verifier.
"""
import json
import os
from pathlib import Path

import pytest

from inferroute_cli import pi_attested as PA


class _FakeStdout:
    def readline(self):
        return json.dumps({"listening": 44444}) + "\n"


class _FakeProc:
    def __init__(self, argv):
        self.args = argv
        self.stdout = _FakeStdout()

    def terminate(self):
        pass


@pytest.fixture
def rig(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    cfg_dir = tmp_path / "ir" / "confidential"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "search.json").write_text(json.dumps({
        "python": "/usr/bin/python3", "enclave": "http://enclave.invalid",
        "expect_host_data": "aa" * 32, "cwd": str(tmp_path)}))
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR", "IR_ATTESTED_CONFINE",
              "IR_PROBANT_DEV_UNCONFINED", "IR_REPORT_MATTER", "IR_REPORT_FIRM"):
        monkeypatch.delenv(k, raising=False)
    captured = {}

    def fake_popen(argv, **kw):
        captured["argv"] = argv
        return _FakeProc(argv)

    # start_search_proxy does `import subprocess` / `import select` inside the function; patch the modules.
    import select
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(select, "select", lambda r, w, x, t: (r, [], []))
    monkeypatch.setattr(PA, "_SEARCH_PROXIES", [])
    return captured


def test_trust_state_only_in_require_mode(rig, tmp_path, monkeypatch):
    monkeypatch.setenv("IR_MATTER_STATE_FILE", str(tmp_path / "ir" / "confidential" / "matters" / "s.json"))
    monkeypatch.setenv("IR_MATTER_CUTOFF", "20210101")
    monkeypatch.setenv("IR_MATTER_RECORD_DIR", str(tmp_path / "ir" / "confidential" / "attested-records" / "C" / "m"))
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    addr = PA.start_search_proxy()
    assert addr == "http://127.0.0.1:44444"
    argv = rig["argv"]
    assert "--trust-state" in argv
    assert "--cutoff" in argv and "20210101" in argv
    i = argv.index("--record-file")
    rec = Path(argv[i + 1])
    assert rec.suffix == ".json" and rec.parent.name == "m" and "attested-records" in str(rec)


def test_no_trust_state_when_not_required(rig, tmp_path, monkeypatch):
    monkeypatch.setenv("IR_MATTER_STATE_FILE", str(tmp_path / "ir" / "confidential" / "matters" / "s.json"))
    # confine not required (unset) → memory-only approvals, no --trust-state
    addr = PA.start_search_proxy()
    assert "--trust-state" not in rig["argv"]


def test_no_trust_state_when_confine_off(rig, tmp_path, monkeypatch):
    monkeypatch.setenv("IR_MATTER_STATE_FILE", str(tmp_path / "ir" / "confidential" / "matters" / "s.json"))
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "off")
    PA.start_search_proxy()
    assert "--trust-state" not in rig["argv"]


def test_confinement_label_is_passed_and_reflects_the_mode(rig, tmp_path, monkeypatch):
    # require mode
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    PA.start_search_proxy()
    argv = rig["argv"]
    assert "--confinement" in argv
    assert "require" in argv[argv.index("--confinement") + 1]
    # dev-unconfined override wins over anything else
    monkeypatch.setattr(PA, "_SEARCH_PROXIES", [])
    monkeypatch.setenv("IR_PROBANT_DEV_UNCONFINED", "1")
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "off")
    PA.start_search_proxy()
    argv = rig["argv"]
    assert argv[argv.index("--confinement") + 1] == "unconfined (developer override)"


def test_record_file_is_unique_per_session(rig, tmp_path, monkeypatch):
    monkeypatch.setenv("IR_MATTER_RECORD_DIR", str(tmp_path / "recs"))
    PA.start_search_proxy()
    first = rig["argv"][rig["argv"].index("--record-file") + 1]
    monkeypatch.setattr(PA, "_SEARCH_PROXIES", [])
    PA.start_search_proxy()
    second = rig["argv"][rig["argv"].index("--record-file") + 1]
    assert first != second and Path(first).parent == Path(second).parent
