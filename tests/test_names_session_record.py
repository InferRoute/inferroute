"""A name check's session is recorded under its matter, however it ends (Mac, 0.9.122, 22 Oct).

A founder ended a name check with "End this session" on the matter page. Its receipts and its trademark search
log were written; its session record (attested-records/<client>/<matter>/<session>.json) was not, so the matter
page said "No sessions yet" beside the session's own report.

The cause was not the stop. A matter session's record is written by the search verifier, when the extension
POSTs it. A name session starts no search verifier, so the extension wrote its record into Pi's config dir
(IR_ATTESTED_RECORD_DIR), which nothing that lists sessions reads. No name session was ever recorded, on Linux
or on a Mac, ended or finished. The launcher now writes the record itself, before the agent starts, so a
session ended from the home page (SIGTERM, a bounded wait, SIGKILL) keeps it.

These tests drive the real `confidential.launch` with the sealed model, the sandbox and the screen stubbed out,
and an agent that is a small Python script, then end it with the home page's own `Launches.stop_running`.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_cli import pi_attested as PA
from inferroute_cli import probant as S
from inferroute_cli import probant_home as H

CLIENT, MATTER = "Acme", "kwench"
HERE = Path(__file__).resolve().parent

# The agent stand-in: notes whether the session's record already exists while it runs, then exits, or (with
# "wait") stays until the launcher that started it is gone.
AGENT = r'''
import json, os, sys, time
rdir, marker, how = sys.argv[1], sys.argv[2], sys.argv[3]
names = sorted(n for n in os.listdir(rdir) if n.endswith(".json")) if os.path.isdir(rdir) else []
open(marker, "w").write(json.dumps(names))
if how == "wait":
    parent = os.getppid()
    while os.getppid() == parent:
        time.sleep(0.05)
'''


def _receipt():
    return SimpleNamespace(is_confidential=True, verdict="confidential", path="/r/receipt.json",
                           model_short="kimi-k2.6", instance={"id": "inst-1"},
                           checks={"tdx": {"ok": True, "label": "TDX quote", "why": "fresh"},
                                   "gpu": {"ok": True, "label": "GPU report", "why": "ok"}})


def patch_launch(setattr_, agent_script: str, marker: str, how: str) -> None:
    """Stub out everything around the session that needs a sealed machine, a sandbox or a terminal. What stays
    real: confidential.launch's own sequence, the record writing, the trademark route's install."""
    from fastapi import FastAPI
    from inferroute_cli import agents, confidential as C, launch as L, probant_trust
    from inferroute_local import macos_vm
    from inferroute_local.confidential import display, server

    receipt = _receipt()
    session = SimpleNamespace(receipt=receipt, close=lambda: None, shown_model="")

    async def open_session(*a, **k):
        return session, receipt

    setattr_(C, "_need_extra", lambda: None)
    setattr_(C, "_resolve_model", lambda *a: SimpleNamespace(short="kimi-k2.6", model_id="kimi-k2.6"))
    setattr_(C, "_open_session", open_session)
    setattr_(C, "_interactive", lambda *a: False)
    setattr_(macos_vm, "required_for", lambda *a: False)
    setattr_(server, "create_app", lambda *a, **k: FastAPI())
    setattr_(agents, "binary_for", lambda *a: sys.executable)
    setattr_(agents, "put_agent_on_path", lambda *a, **k: None)
    setattr_(L, "_record_launch", lambda *a, **k: None)
    setattr_(probant_trust, "build", lambda *a, **k: {})
    setattr_(probant_trust, "render_card", lambda *a, **k: None)
    setattr_(probant_trust, "render_howto", lambda *a, **k: None)
    setattr_(display, "render_summary", lambda *a, **k: None)
    setattr_(PA, "check_workspace", lambda *a: "")
    setattr_(PA, "workspace_extras", lambda *a: ([], []))
    setattr_(PA, "plan_netns_bind", lambda: False)
    setattr_(PA, "netns_bind_intended", lambda: False)
    setattr_(PA, "confine_precheck", lambda: (True, ""))
    setattr_(PA, "confine_write_paths", lambda *a, **k: [])
    setattr_(PA, "preexec_confine", lambda *a, **k: None)
    setattr_(PA, "confinement_label", lambda **k: "require (test)")
    rdir = str(S.records_dir(CLIENT, MATTER))
    def env_argv(binary, env, *a, **k):
        env["PI_CODING_AGENT_DIR"] = str(Path(rdir).parent / "pi-config")
        return [binary, agent_script, rdir, marker, how]

    setattr_(PA, "env_argv", env_argv)


def _env(tmp: Path) -> dict:
    return {"INFERROUTE_HOME": str(tmp / "ir"), "IR_PROBANT_ROOT": str(tmp / "Anteriora"),
            "IR_MATTER_RECORD_DIR": str(tmp / "ir" / "confidential" / "attested-records" / CLIENT / MATTER),
            "IR_ATTESTED_CONFINE": "require"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    for k, v in _env(tmp_path).items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    (tmp_path / "ws").mkdir()
    monkeypatch.chdir(tmp_path / "ws")
    script = tmp_path / "agent.py"
    script.write_text(AGENT)
    return tmp_path, script


def _records(tmp: Path) -> list:
    rdir = Path(_env(tmp)["IR_MATTER_RECORD_DIR"])
    return sorted(p for p in rdir.glob("*.json")) if rdir.is_dir() else []


def test_the_extension_alone_cannot_record_a_name_session(home):
    """The cause, stated: with no search verifier, the extension's record goes to Pi's config dir."""
    tmp, _ = home
    env = {"IR_TM_SEARCH": "1", "IR_MATTER_RECORD_DIR": _env(tmp)["IR_MATTER_RECORD_DIR"]}
    alias = SimpleNamespace(short="kimi-k2.6", model_id="kimi-k2.6", ref_key="fixture/Model-TEE")
    PA.env_argv("pi", env, [], base_url="http://127.0.0.1:9", api_key="k", alias=alias, upstream_name="u",
                search_endpoint="http://127.0.0.1:7")
    assert "IR_SEARCH_ENDPOINT" not in env
    assert Path(env["IR_ATTESTED_RECORD_DIR"]) != Path(env["IR_MATTER_RECORD_DIR"])


def test_a_name_session_that_finishes_is_listed_on_its_matter(home, monkeypatch):
    from inferroute_cli import confidential as C
    tmp, script = home
    marker = tmp / "seen.json"
    patch_launch(monkeypatch.setattr, str(script), str(marker), "exit")
    assert C.launch([], agent="pi", probant={"matter": f"{CLIENT}/{MATTER}", "mode": "names"}) == 0
    # Written before the agent ran, so no way of ending the agent can lose it.
    assert len(json.loads(marker.read_text())) == 1
    (rec_file,) = _records(tmp)
    rec = json.loads(rec_file.read_text())
    assert H.SESSION_ID_RE.match(rec_file.stem) and rec["session_id"] == rec_file.stem
    assert rec["mode"] == "names" and rec["surface"] == "terminal" and rec["confinement"] == "require (test)"
    assert rec["model_lane"]["verified"] is True and rec["model_lane"]["checks"] == "2/2"
    assert rec["ended_at"] and rec["exit_code"] == 0
    (listed,) = H.list_sessions(CLIENT, MATTER)
    assert listed["id"] == rec_file.stem and listed["ai_verified"]
    assert H.session_detail(CLIENT, MATTER, rec_file.stem)["model"]["verified"]


def test_a_matter_session_is_still_recorded_by_its_verifier_not_the_launcher(home, monkeypatch):
    from inferroute_cli import confidential as C
    tmp, script = home
    patch_launch(monkeypatch.setattr, str(script), str(tmp / "seen.json"), "exit")
    monkeypatch.setattr(PA, "start_search_proxy", lambda **k: None)
    C.launch([], agent="pi", probant={"matter": f"{CLIENT}/{MATTER}", "date_bound": "2024-01-01"})
    assert _records(tmp) == []


CHILD = r'''
import os, sys
sys.path[:0] = [{tests!r}, {root!r}]
os.chdir({ws!r})
import test_names_session_record as T
T.patch_launch(setattr, {script!r}, {marker!r}, "wait")
from inferroute_cli import confidential as C
print("https://127.0.0.1:1/session-ready", flush=True)
sys.exit(C.launch([], agent="pi", probant={{"matter": "{client}/{matter}", "mode": "names"}}))
'''


def test_a_name_session_ended_from_the_home_page_keeps_its_record(home):
    """The reported path: the home page ends the running session with stop_running (SIGTERM, a bounded
    wait, SIGKILL). The record must be there afterwards, and the session must have ended."""
    tmp, script = home
    marker = tmp / "seen.json"
    code = CHILD.format(tests=str(HERE), root=str(HERE.parent), ws=str(tmp / "ws"), script=str(script), marker=str(marker),
                        client=CLIENT, matter=MATTER)
    env = dict(os.environ, **_env(tmp))
    env.pop("CLAUDECODE", None)
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.DEVNULL,
                            stderr=open(tmp / "launcher.err", "w"), start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while not marker.exists():                       # the agent is running: the session is live
            assert proc.poll() is None, (tmp / "launcher.err").read_text()[-3000:]
            assert time.monotonic() < deadline, "the agent never started"
            time.sleep(0.05)
        launches = H.Launches()
        launches.items["x"] = {"id": "x", "matter": f"{CLIENT}/{MATTER}", "state": "ready", "proc": proc}
        t0 = time.monotonic()
        assert launches.stop_running(f"{CLIENT}/{MATTER}") is True
        assert proc.poll() is not None and time.monotonic() - t0 < H.session_stop_wait() + 5
    finally:
        if proc.poll() is None:
            proc.kill()
    (rec_file,) = _records(tmp)
    assert [listed["id"] for listed in H.list_sessions(CLIENT, MATTER)] == [rec_file.stem]
    assert json.loads(rec_file.read_text())["mode"] == "names"


def test_the_record_is_never_written_over(tmp_path):
    rec = {"session_id": "s"}
    PA.begin_host_session_record(tmp_path, "20261022T200000Z-0a0b0c0d", rec)
    with pytest.raises(FileExistsError):
        PA.begin_host_session_record(tmp_path, "20261022T200000Z-0a0b0c0d", {"session_id": "other"})
    PA.end_host_session_record(tmp_path / "20261022T200000Z-0a0b0c0d.json", exit_code=0)
    doc = json.loads((tmp_path / "20261022T200000Z-0a0b0c0d.json").read_text())
    assert doc["session_id"] == "s" and doc["ended_at"] and doc["exit_code"] == 0
    PA.end_host_session_record(tmp_path / "missing.json", exit_code=0)        # never raises
