"""Deleting a matter (Henry, 19 Sep: "we need a way to delete matters").

Everything of the matter moves, nothing else does, and it comes back exactly as it was. Refused while a
session is working on it; erased for good after the retention period or on request.
"""
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_delete as D


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    for name in ("cooling", "other"):
        assert S.main(["new", "Acme", name, "--priority-date", "2020-01-15"]) == 0
        (S.workspace_path("Acme", name) / "disclosure.md").write_text(f"# {name} SECRET-{name}\n")
        S.state_path("Acme", name).write_text(json.dumps({"marks": {"US-1": {"latest": {"value": "relevant"}}}}))
        rd = S.records_dir("Acme", name)
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "s1.json").write_text("{}")
        ex = S.probant_root() / "Acme" / "exports" / f"{name}-prior-art-record-20260919T100000Z"
        ex.mkdir(parents=True)
        (ex / "MANIFEST.json").write_text(json.dumps({"n": name}))
        (ex / "record.html").write_text(f"record {name}")
        pack = S.probant_root() / "Acme" / "exports" / f"audit-pack-{name}"
        pack.mkdir()
        (pack / "MANIFEST.json").write_text(json.dumps({"derived_from_manifest_sha256": D._sha256(ex / "MANIFEST.json")}))
    return tmp_path


def _snapshot(root: Path):
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_delete_moves_all_of_the_matter_and_nothing_else_and_restore_puts_it_back(home):
    before = _snapshot(home)
    out = D.delete("Acme", "cooling")
    assert not S.record_path("Acme", "cooling").exists() and not S.state_path("Acme", "cooling").exists()
    assert not S.records_dir("Acme", "cooling").exists() and not S.workspace_path("Acme", "cooling").exists()
    exports = S.probant_root() / "Acme" / "exports"
    assert sorted(p.name for p in exports.iterdir()) == ["audit-pack-other", "other-prior-art-record-20260919T100000Z"]
    # The other matter is untouched, byte for byte.
    now = _snapshot(home)
    assert {k: v for k, v in before.items() if "other" in k} == {k: v for k, v in now.items() if "other" in k and "deleted-matters" not in k}
    assert [d["matter"] for d in D.list_deleted()] == ["Acme/cooling"]
    trash = D.trash_root() / out["id"]
    assert (trash.stat().st_mode & 0o777) == 0o700
    assert b"SECRET-cooling" in (trash / "workspace" / "disclosure.md").read_bytes()
    assert D.restore(out["id"]) == "Acme/cooling"
    assert _snapshot(home) == before                     # everything back where it was, byte for byte
    assert D.list_deleted() == []


def test_erase_now_and_after_the_retention_period(home):
    a = D.delete("Acme", "cooling")["id"]
    b = D.delete("Acme", "other")["id"]
    D.erase(a)
    assert not (D.trash_root() / a).exists()
    assert D.erase_expired(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=D.RETENTION_DAYS - 1)) == []
    assert D.erase_expired(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=D.RETENTION_DAYS + 1)) == [b]
    assert not any(b"SECRET" in v for v in _snapshot(home).values())


def test_refused_while_a_session_is_working_on_the_matter(home):
    env = dict(os.environ, IR_MATTER_STATE_FILE=str(S.state_path("Acme", "cooling")))
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], env=env)
    try:
        with pytest.raises(S.ProbantError, match="still open"):
            D.delete("Acme", "cooling")
        assert S.record_path("Acme", "cooling").exists()
        D.delete("Acme", "other")                         # a session on ANOTHER matter blocks nothing
    finally:
        proc.kill()
        proc.wait()


def test_only_the_matters_own_folder_is_ever_moved(home, monkeypatch, tmp_path):
    rec = S.load_record("Acme", "cooling")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for pointed in (str(elsewhere), ""):
        rec["workspace"] = pointed
        S._write_record("Acme", "cooling", rec)
        monkeypatch.chdir(S.probant_root() / "Acme")      # an empty field must not become "the current folder"
        out = D.delete("Acme", "cooling")
        assert elsewhere.is_dir() and (S.probant_root() / "Acme").is_dir()
        assert out["left_in_place"] == ([str(elsewhere)] if pointed else [])
        D.restore(out["id"])


def test_restore_refuses_over_a_new_matter_of_the_same_name(home):
    out = D.delete("Acme", "cooling")
    assert S.main(["new", "Acme", "cooling"]) == 0
    with pytest.raises(S.ProbantError, match="same name"):
        D.restore(out["id"])
    assert (D.trash_root() / out["id"]).is_dir()          # nothing lost by the refusal


def test_a_tampered_list_cannot_move_files_anywhere(home):
    out = D.delete("Acme", "cooling")
    m = D.trash_root() / out["id"] / D.MANIFEST
    info = json.loads(m.read_text())
    info["moved"][0]["from"] = "/tmp/outside-probant.json"
    m.write_text(json.dumps(info))
    with pytest.raises(S.ProbantError, match="not valid"):
        D.restore(out["id"])
    assert not Path("/tmp/outside-probant.json").exists()
    with pytest.raises(S.ProbantError):
        D.erase("../../etc")


def test_the_home_page_deletes_only_when_the_name_is_typed(home):
    from fastapi.testclient import TestClient
    from inferroute_cli import probant_home as H
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    r = c.post("/api/matter/delete", json={"id": "Acme/cooling", "confirm": "Acme/cooling"})
    assert r.status_code == 400 and S.record_path("Acme", "cooling").exists()
    r = c.post("/api/matter/delete", json={"id": "Acme/cooling", "confirm": "cooling"})
    assert r.status_code == 200 and not S.record_path("Acme", "cooling").exists()
    listed = c.get("/api/deleted").json()["deleted"]
    assert [d["matter"] for d in listed] == ["Acme/cooling"]
    assert c.post("/api/deleted/restore", json={"id": listed[0]["id"]}).json()["id"] == "Acme/cooling"
    assert S.record_path("Acme", "cooling").exists()
