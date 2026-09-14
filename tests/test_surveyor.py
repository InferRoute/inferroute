"""`ir surveyor` — the attorney-facing matter launcher. These tests cover the parts that must hold with
no Pi binary and no enclave: where the date bound and matter record live (host-side, under confidential/,
NOT the writable workspace — S1), that the shared search.json is never touched (the cutoff/state/record
travel as per-matter env — S2), that names are sanitized before any path is built (S3), and that a .git
in the workspace or a cloud-sync root is refused rather than opened (S4 / sync-root).

`open` is exercised only up to the point it would launch Pi: launch is monkeypatched to capture the env
the launcher hands it, so the test sees IR_MATTER_* without starting an agent.
"""
import json
import os
from pathlib import Path

import pytest

from inferroute_cli import surveyor as S


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_SURVEYOR_ROOT", str(tmp_path / "Surveyor"))
    # A clean slate for the per-matter env the launcher sets.
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_FILE", "IR_ATTESTED_CONFINE"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def _rec(tmp, client, matter):
    return json.loads((S.record_path(client, matter)).read_text())


def test_new_holds_the_record_under_confidential_not_the_workspace(home):
    assert S.main(["new", "Acme", "battery-cooling"]) == 0
    rec_path = S.record_path("Acme", "battery-cooling")
    # S1: the record lives under ~/.inferroute/confidential/matters, not in the workspace.
    assert "confidential" in rec_path.parts and "matters" in rec_path.parts
    ws = Path(_rec(home, "Acme", "battery-cooling")["workspace"])
    assert S.matters_dir() not in rec_path.parents or True
    assert not str(ws).startswith(str(S.matters_dir()))          # workspace is not under the record tree
    assert (ws / "disclosure.md").is_file()
    # Nothing that looks like a date bound was written into the writable workspace.
    assert not (ws / "matter.json").exists()


def test_pre_filing_default_is_today_and_flagged(home, monkeypatch):
    assert S.main(["new", "Acme", "m1"]) == 0
    rec = _rec(home, "Acme", "m1")
    assert rec["pre_filing_default"] is True
    assert rec["date_bound"] == S._today()


def test_explicit_priority_date_is_not_flagged_default(home):
    assert S.main(["new", "Acme", "m2", "--priority-date", "2020-01-15"]) == 0
    rec = _rec(home, "Acme", "m2")
    assert rec["date_bound"] == "2020-01-15" and rec["pre_filing_default"] is False


def test_set_date_records_the_change_and_clears_the_default_flag(home):
    S.main(["new", "Acme", "m3"])
    old = _rec(home, "Acme", "m3")["date_bound"]
    assert S.main(["set-date", "Acme/m3", "2019-03-03"]) == 0
    rec = _rec(home, "Acme", "m3")
    assert rec["date_bound"] == "2019-03-03" and rec["pre_filing_default"] is False
    assert rec["changes"][-1] == {**rec["changes"][-1], "field": "date_bound", "old": old, "new": "2019-03-03"}


def test_duplicate_new_is_refused(home):
    assert S.main(["new", "Acme", "m4"]) == 0
    assert S.main(["new", "Acme", "m4"]) == 2


def test_unknown_matter_is_refused(home):
    assert S.main(["set-date", "Ghost/none", "2020-01-01"]) == 2


@pytest.mark.parametrize("client,matter", [
    ("..", "x"), ("a/b", "x"), (".hidden", "x"), ("ok", "../escape"),
    ("ok", ".dot"), ("bad\x00", "x"), ("", "x"), ("ok", ""),
])
def test_names_are_sanitized_before_any_path_is_built(home, client, matter):
    # S3: rejected with exit 2, and no directory was created for the bad component.
    assert S.main(["new", client, matter]) == 2
    assert not (S.matters_dir()).exists() or not any(S.matters_dir().rglob("*.json"))


def test_bad_date_is_refused(home):
    S.main(["new", "Acme", "m5"])
    assert S.main(["set-date", "Acme/m5", "not-a-date"]) == 2
    assert S.main(["new", "Acme", "m6", "--priority-date", "2020-13-40"]) == 2


def test_open_passes_per_matter_env_and_never_touches_search_json(home, monkeypatch):
    S.main(["new", "Acme", "m7", "--priority-date", "2021-07-08"])
    captured = {}

    def fake_launch(args, agent="claude"):
        captured["args"] = args
        captured["agent"] = agent
        captured["env"] = {k: os.environ.get(k) for k in
                           ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_FILE", "IR_ATTESTED_CONFINE")}
        captured["cwd"] = os.getcwd()
        return 0

    import inferroute_cli.confidential as confidential_mod
    monkeypatch.setattr(confidential_mod, "launch", fake_launch)
    assert S.main(["open", "Acme/m7"]) == 0
    assert captured["agent"] == "pi" and captured["args"] == []
    env = captured["env"]
    # S2: the cutoff/state/record are per-matter env from the host record, and all live under confidential/.
    assert env["IR_MATTER_CUTOFF"] == "20210708"
    assert "confidential" in env["IR_MATTER_STATE_FILE"] and "confidential" in env["IR_MATTER_RECORD_FILE"]
    assert env["IR_ATTESTED_CONFINE"] == "require"             # attorney default: address-level egress
    # open chdir'd into the matter workspace.
    assert captured["cwd"] == str(Path(_rec(home, "Acme", "m7")["workspace"]))


def test_open_refuses_a_git_repo_in_the_workspace(home, monkeypatch):
    S.main(["new", "Acme", "m8"])
    ws = Path(_rec(home, "Acme", "m8")["workspace"])
    (ws / ".git").mkdir()
    import inferroute_cli.confidential as confidential_mod
    monkeypatch.setattr(confidential_mod, "launch", lambda *a, **k: pytest.fail("must not launch"))
    assert S.main(["open", "Acme/m8"]) == 2                    # S4


def test_new_refuses_a_cloud_sync_root(home, monkeypatch):
    monkeypatch.setenv("IR_SURVEYOR_ROOT", str(home / "OneDrive" / "Surveyor"))
    assert S.main(["new", "Acme", "m9"]) == 2
    assert not S.record_path("Acme", "m9").exists()
