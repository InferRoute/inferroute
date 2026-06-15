"""Tests for the 2026-06 recorder redesign: transcript ingest, cost estimation,
the SessionEnd hook merge, wire mining, and doctor's unit validation."""
from __future__ import annotations

import json
import os

from inferroute_local import pricing, wire
from inferroute_local.ingest import ingest_transcript
from inferroute_local.recorder import Recorder


# ----- helpers ---------------------------------------------------------------

def _assistant(req, sid="s1", model="claude-opus-4-7", tin=100, tout=20):
    return {
        "type": "assistant",
        "sessionId": sid,
        "requestId": req,
        "uuid": req + "-u",
        "timestamp": "2026-06-01T00:00:00.000Z",
        "cwd": "/tmp",
        "gitBranch": "main",
        "version": "2.1.177",
        "message": {
            "id": "msg_" + req,
            "model": model,
            "stop_reason": "end_turn",
            "content": [{"type": "tool_use", "name": "Read", "id": "t1", "input": {}}],
            "usage": {"input_tokens": tin, "output_tokens": tout,
                      "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
        },
    }


def _write_transcript(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")


# ----- ingest ----------------------------------------------------------------

def test_ingest_extracts_turns_no_blobs(tmp_path):
    t = tmp_path / "s1.jsonl"
    _write_transcript(t, [
        {"type": "user", "message": {"role": "user", "content": "hi"}},
        _assistant("req_a"),
        _assistant("req_b"),
    ])
    rec = Recorder(tmp_path / "corpus", level="metadata")
    summary = ingest_transcript(t, rec)
    assert summary["ok"] and summary["turns"] == 2
    # No blob store written — content stays in the transcript.
    assert not (tmp_path / "corpus" / "blobs").exists()
    events = (tmp_path / "corpus" / "events").glob("events-*.jsonl")
    turns = [json.loads(l) for f in events for l in f.read_text().splitlines()]
    assert all(e["kind"] == "turn" for e in turns)
    assert {e["request_id"] for e in turns} == {"req_a", "req_b"}
    # Spine only — no prompt/response text leaked into the event.
    assert all(not any(k in e for k in ("content", "text", "messages", "system")) for e in turns)


def test_ingest_idempotent_and_resume(tmp_path):
    t = tmp_path / "s1.jsonl"
    _write_transcript(t, [_assistant("req_a")])
    rec = Recorder(tmp_path / "corpus", level="metadata")
    assert ingest_transcript(t, rec)["turns"] == 1
    # Re-ingest unchanged → nothing new.
    assert ingest_transcript(t, rec)["turns"] == 0
    # Append a turn (session resumed) → only the new one is ingested.
    _write_transcript(t, [_assistant("req_a"), _assistant("req_b")])
    assert ingest_transcript(t, rec)["turns"] == 1


def test_ingest_off_records_nothing(tmp_path):
    t = tmp_path / "s1.jsonl"
    _write_transcript(t, [_assistant("req_a")])
    rec = Recorder(tmp_path / "corpus", level="off")
    summary = ingest_transcript(t, rec)
    assert summary["turns"] == 0
    assert not (tmp_path / "corpus" / "events").exists()


# ----- pricing (read-time estimate, never stored) ----------------------------

def test_pricing_math_native_model():
    est = pricing.estimate_cost({
        "served_model": "claude-opus-4-7", "iso": "2026-06-01T00:00:00Z",
        "tokens_in": 10000, "tokens_out": 2000,
        "cache_read_tokens": 50000, "cache_creation_tokens": 1000,
    })
    assert est["is_estimate"] is True
    assert est["cost_usd"] == round((10000*15 + 2000*75 + 50000*1.5 + 1000*18.75)/1e6, 6)


def test_pricing_unknown_model_returns_none():
    # Routed open-weights models get real server cost, not an estimate.
    assert pricing.estimate_cost({"served_model": "moonshotai/Kimi-K2.6-TEE",
                                  "tokens_in": 100, "tokens_out": 10}) is None


# ----- wire mining (mine then delete) ----------------------------------------

def test_wire_mine_and_consume_deletes(tmp_path):
    sid = "sess-1"
    wdir = wire.session_dir(tmp_path, sid)
    wdir.mkdir(parents=True)
    (wdir / "b.json").write_text(json.dumps({
        "request_id": "req_x",
        "body": {"system": [{"type": "text", "text": "sys"}],
                 "tools": [{"name": "Bash"}, {"name": "Read"}]},
    }))
    out = wire.mine_and_consume(tmp_path, f"/x/{sid}.jsonl")
    assert out["req_x"]["tool_names"] == ["Bash", "Read"]
    assert out["_session"]["system_hash"]
    assert not wdir.exists()  # nothing left behind


def test_wire_absent_returns_none(tmp_path):
    assert wire.mine_and_consume(tmp_path, "/x/nope.jsonl") is None


# ----- SessionEnd hook merge -------------------------------------------------

def test_cc_hook_install_remove_preserves_others(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / ".claude"))
    (tmp_path / ".claude").mkdir()
    settings = tmp_path / ".claude" / "settings.json"
    settings.write_text(json.dumps({
        "theme": "dark",
        "hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": "echo other"}]}]},
    }))
    from inferroute_cli import cc_hook
    assert cc_hook.install() == "installed"
    assert cc_hook.install() == "exists"  # idempotent
    d = json.loads(settings.read_text())
    assert d["theme"] == "dark"
    cmds = [h["command"] for g in d["hooks"]["SessionEnd"] for h in g["hooks"]]
    assert any("ingest --stdin" in c for c in cmds)
    assert any("echo other" in c for c in cmds)
    assert cc_hook.remove() == "removed"
    d2 = json.loads(settings.read_text())
    cmds2 = [h["command"] for g in d2["hooks"].get("SessionEnd", []) for h in g["hooks"]]
    assert any("echo other" in c for c in cmds2)
    assert not any("ingest --stdin" in c for c in cmds2)


def test_cc_hook_skips_invalid_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / ".claude"))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{not valid json")
    from inferroute_cli import cc_hook
    assert cc_hook.install().startswith("skipped")


# ----- doctor unit validation ------------------------------------------------

def test_doctor_catches_serve_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    unit = tmp_path / ".config" / "systemd" / "user" / "inferroute-local.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=/x/inferroute-daemon serve --port 5005\n")
    from inferroute_local.cli import _check_systemd_unit
    problems, _ = _check_systemd_unit()
    assert any("serve" in p for p in problems)
