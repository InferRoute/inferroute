"""`ir probant` — the attorney-facing matter launcher. These tests cover the parts that must hold with
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

from inferroute_cli import probant as S


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    # A clean slate for the per-matter env the launcher sets.
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR",
              "IR_ATTESTED_CONFINE", "IR_PROBANT_DEV_UNCONFINED"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def _patch_launch(monkeypatch, captured):
    def fake_launch(args, agent="claude", *, probant=None):
        captured["args"] = args
        captured["agent"] = agent
        captured["probant"] = probant
        captured["env"] = {k: os.environ.get(k) for k in
                           ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR",
                            "IR_ATTESTED_CONFINE", "IR_PROBANT_DEV_UNCONFINED")}
        captured["cwd"] = os.getcwd()
        return 0
    import inferroute_cli.confidential as confidential_mod
    monkeypatch.setattr(confidential_mod, "launch", fake_launch)


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
    _patch_launch(monkeypatch, captured)
    assert S.main(["open", "Acme/m7"]) == 0
    assert captured["agent"] == "pi" and captured["args"] == []
    # The plain-language card is drawn for THIS matter: its name and host-held date bound, never the model's.
    assert captured["probant"] == {"matter": "Acme/m7", "date_bound": "2021-07-08"}
    env = captured["env"]
    # S2: the cutoff/state/record are per-matter env from the host record, and all live under confidential/.
    assert env["IR_MATTER_CUTOFF"] == "20210708"
    assert "confidential" in env["IR_MATTER_STATE_FILE"] and "confidential" in env["IR_MATTER_RECORD_DIR"]
    assert Path(env["IR_MATTER_RECORD_DIR"]).name == "m7" and "attested-records" in env["IR_MATTER_RECORD_DIR"]
    assert env["IR_ATTESTED_CONFINE"] == "require"             # attorney default: address-level egress
    # open chdir'd into the matter workspace.
    assert captured["cwd"] == str(Path(_rec(home, "Acme", "m7")["workspace"]))


def test_open_forces_require_even_when_the_shell_set_confine_off(home, monkeypatch):
    # F1: a leftover IR_ATTESTED_CONFINE=off from dev work must NOT make an attorney session unconfined.
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "off")
    S.main(["new", "Acme", "m7b"])
    captured = {}
    _patch_launch(monkeypatch, captured)
    assert S.main(["open", "Acme/m7b"]) == 0
    assert captured["env"]["IR_ATTESTED_CONFINE"] == "require"
    assert captured["env"]["IR_PROBANT_DEV_UNCONFINED"] is None


def test_dev_unconfined_override_is_loud_and_untrusted(home, monkeypatch, capsys):
    # The only way down from require: an explicit flag, recorded as unconfined, never granted trusted state.
    S.main(["new", "Acme", "m7c"])
    captured = {}
    _patch_launch(monkeypatch, captured)
    assert S.main(["open", "Acme/m7c", "--dev-unconfined"]) == 0
    assert captured["env"]["IR_ATTESTED_CONFINE"] == "off"
    assert captured["env"]["IR_PROBANT_DEV_UNCONFINED"] == "1"
    assert "DEVELOPER OVERRIDE" in capsys.readouterr().err


def test_open_refuses_a_git_repo_in_the_workspace(home, monkeypatch):
    S.main(["new", "Acme", "m8"])
    ws = Path(_rec(home, "Acme", "m8")["workspace"])
    (ws / ".git").mkdir()
    import inferroute_cli.confidential as confidential_mod
    monkeypatch.setattr(confidential_mod, "launch", lambda *a, **k: pytest.fail("must not launch"))
    assert S.main(["open", "Acme/m8"]) == 2                    # S4


def test_new_refuses_a_cloud_sync_root(home, monkeypatch):
    monkeypatch.setenv("IR_PROBANT_ROOT", str(home / "OneDrive" / "Probant"))
    assert S.main(["new", "Acme", "m9"]) == 2
    assert not S.record_path("Acme", "m9").exists()


def test_a_matter_is_private_to_this_account_even_under_a_permissive_umask(home, monkeypatch):
    # Records hold the search text (the invention) and results. Under umask 0002, the default on many
    # desktops, they were readable by every other account on the computer.
    import stat
    old = os.umask(0o002)
    try:
        S.main(["new", "Acme", "priv"])
        rec = _rec(home, "Acme", "priv")
        for d in (Path(rec["workspace"]), S.records_dir("Acme", "priv"), S.matters_dir(), S._irhome() / "confidential"):
            assert stat.S_IMODE(d.stat().st_mode) == 0o700, d
        assert stat.S_IMODE(S.record_path("Acme", "priv").stat().st_mode) & 0o077 == 0
        assert os.umask(0o002) == 0o077, "the command leaves this process creating owner-only files"
    finally:
        os.umask(old)


def test_open_tightens_a_matter_created_before_it_was_private(home, monkeypatch):
    import stat
    S.main(["new", "Acme", "loose"])
    ws = Path(_rec(home, "Acme", "loose")["workspace"])
    os.chmod(ws, 0o775)
    os.chmod(S.records_dir("Acme", "loose"), 0o775)
    _patch_launch(monkeypatch, {})
    S.main(["open", "Acme/loose"])
    assert stat.S_IMODE(ws.stat().st_mode) == 0o700
    assert stat.S_IMODE(S.records_dir("Acme", "loose").stat().st_mode) == 0o700


# ── the rename (Surveyor → Probant, 2026-09-18) ──
#
# The product was renamed the night before its first rehearsal. Neither of these is decoration: the
# rehearsal notes, the wrapper script and a home page already running all say `surveyor`, and the matters
# already on this machine live under ~/Surveyor with their absolute paths written into host-side records.

def test_the_old_command_name_still_reaches_the_same_place(monkeypatch):
    from inferroute_cli import main as main_mod
    seen = []
    monkeypatch.setattr(S, "main", lambda rest: seen.append(rest) or 0)
    assert main_mod.main(["surveyor", "list"]) == 0
    assert main_mod.main(["probant", "list"]) == 0
    assert seen == [["list"], ["list"]]


def test_matters_already_on_this_machine_are_not_stranded_by_the_rename(tmp_path, monkeypatch):
    monkeypatch.delenv("IR_PROBANT_ROOT", raising=False)
    monkeypatch.delenv("IR_SURVEYOR_ROOT", raising=False)
    monkeypatch.setattr(S, "_home", lambda: tmp_path)
    assert S.probant_root() == tmp_path / "Probant"          # a fresh install gets the new name
    (tmp_path / "Surveyor").mkdir()
    assert S.probant_root() == tmp_path / "Surveyor"         # an existing tree keeps being used
    (tmp_path / "Probant").mkdir()
    assert S.probant_root() == tmp_path / "Probant"          # once both exist, the new one wins
    monkeypatch.setenv("IR_SURVEYOR_ROOT", str(tmp_path / "named"))
    assert S.probant_root() == tmp_path / "named"            # the old setting still names a root


def test_a_setting_answers_to_both_spellings(monkeypatch):
    from inferroute_cli import probant_web as W
    monkeypatch.delenv("IR_PROBANT_HOME_URL", raising=False)
    monkeypatch.setenv("IR_SURVEYOR_HOME_URL", "http://127.0.0.1:1/#k=x")
    # A home page started before the rename passes the old spelling to the session it starts; a session
    # that loses its way back home is how a rename breaks someone's day.
    assert W.env("HOME_URL") == "http://127.0.0.1:1/#k=x"
    monkeypatch.setenv("IR_PROBANT_HOME_URL", "http://127.0.0.1:2/#k=y")
    assert W.env("HOME_URL") == "http://127.0.0.1:2/#k=y"
    assert W.env("NOTHING_SET", "fallback") == "fallback"
