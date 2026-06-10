"""Real-cost wiring: daemon captures server-reported `usage.cost` and keeps a
per-session running total the ir status line reads.

Cost path (see shared-docs/inferroute/goose-real-cost-display-spec.md):
  cc-proxy-prod emits usage.cost (USD) → daemon proxy parses it (float, not just
  ints) → recorder accumulates per session into <base>/sessions/<sid>.cost →
  ir status line reads that file. CC's own cost.total_cost_usd is NOT used (it
  mis-prices our routed models).
"""
import json

from inferroute_local.proxy import _merge_usage, _apply_obj, _extract_json
from inferroute_local.recorder import Recorder


# --- proxy: usage.cost (a float) survives parsing, ints still kept, bools dropped ---

def test_merge_usage_keeps_cost_float_and_int_tokens():
    dst = {}
    _merge_usage(dst, {
        "input_tokens": 3156, "output_tokens": 312,
        "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
        "cost": 0.000287, "cost_currency": "USD",
        "some_bool": True,  # bool is an int subclass — must be skipped
    })
    assert dst["input_tokens"] == 3156
    assert dst["output_tokens"] == 312
    assert dst["cost"] == 0.000287
    assert dst["cost_currency"] == "USD"
    assert "some_bool" not in dst


def test_merge_usage_ignores_non_dict():
    dst = {"x": 1}
    _merge_usage(dst, None)
    _merge_usage(dst, "nope")
    assert dst == {"x": 1}


def test_streaming_message_delta_carries_cost():
    usage = {}
    # message_start: tokens, no cost yet
    _apply_obj({"type": "message_start", "message": {"model": "kimi",
               "usage": {"input_tokens": 100}}}, usage)
    # message_delta: final output_tokens + cost (where inferroute emits it)
    stop, _ = _apply_obj({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                          "usage": {"output_tokens": 50, "cost": 0.0012}}, usage)
    assert stop == "end_turn"
    assert usage["input_tokens"] == 100
    assert usage["output_tokens"] == 50
    assert usage["cost"] == 0.0012


def test_nonstreaming_extract_json_carries_cost():
    raw = json.dumps({"stop_reason": "end_turn", "model": "kimi",
                      "usage": {"input_tokens": 10, "output_tokens": 5, "cost": 0.0009}}).encode()
    usage, stop, served = _extract_json(raw)
    assert stop == "end_turn" and served == "kimi"
    assert usage["cost"] == 0.0009


# --- recorder: per-session .cost file accumulates, seeds from disk, fail-soft ---

def _rec(tmp_path):
    return Recorder(tmp_path, level="metadata")


def test_session_cost_file_accumulates_across_turns(tmp_path):
    r = _rec(tmp_path)
    sid = "a" * 32
    r.record_outcome(turn_id="t1", session_id=sid, status=200, ttft_ms=10, total_ms=20,
                     usage={"input_tokens": 1, "cost": 0.10}, stop_reason="end_turn", served_model="kimi")
    r.record_outcome(turn_id="t2", session_id=sid, status=200, ttft_ms=10, total_ms=20,
                     usage={"input_tokens": 1, "cost": 0.05}, stop_reason="end_turn", served_model="kimi")
    cost_file = tmp_path / "sessions" / f"{sid}.cost"
    assert cost_file.is_file()
    assert abs(float(cost_file.read_text()) - 0.15) < 1e-9


def test_session_cost_seeds_from_disk_on_fresh_recorder(tmp_path):
    sid = "b" * 32
    (tmp_path / "sessions").mkdir(parents=True)
    (tmp_path / "sessions" / f"{sid}.cost").write_text("1.000000")  # prior daemon run
    r = _rec(tmp_path)  # fresh process, empty in-memory total
    r.record_outcome(turn_id="t", session_id=sid, status=200, ttft_ms=1, total_ms=1,
                     usage={"cost": 0.25}, stop_reason="end_turn", served_model="kimi")
    assert abs(float((tmp_path / "sessions" / f"{sid}.cost").read_text()) - 1.25) < 1e-9


def test_no_cost_file_when_cost_absent_or_zero(tmp_path):
    r = _rec(tmp_path)
    r.record_outcome(turn_id="t1", session_id="c" * 8, status=200, ttft_ms=1, total_ms=1,
                     usage={"input_tokens": 5}, stop_reason="end_turn", served_model="kimi")  # no cost
    r.record_outcome(turn_id="t2", session_id="d" * 8, status=200, ttft_ms=1, total_ms=1,
                     usage={"cost": 0.0}, stop_reason="end_turn", served_model="kimi")  # zero
    assert not (tmp_path / "sessions" / ("c" * 8 + ".cost")).exists()
    assert not (tmp_path / "sessions" / ("d" * 8 + ".cost")).exists()


def test_cost_usd_recorded_in_outcome_event(tmp_path):
    r = _rec(tmp_path)
    r.record_outcome(turn_id="t", session_id="e" * 8, status=200, ttft_ms=1, total_ms=1,
                     usage={"cost": 0.0033}, stop_reason="end_turn", served_model="kimi")
    r.flush()
    events = list((tmp_path / "events").glob("events-*.jsonl"))
    assert events
    rows = [json.loads(l) for l in events[0].read_text().splitlines()]
    outcome = [e for e in rows if e["kind"] == "outcome"][0]
    assert outcome["cost_usd"] == 0.0033


def test_unsafe_session_id_does_not_escape_sessions_dir(tmp_path):
    r = _rec(tmp_path)
    # a path-traversal-y id must be refused (no file written), never raise
    r.record_outcome(turn_id="t", session_id="../../etc/pwned", status=200, ttft_ms=1, total_ms=1,
                     usage={"cost": 0.5}, stop_reason="end_turn", served_model="kimi")
    assert not (tmp_path.parent / "etc" / "pwned.cost").exists()
    assert list((tmp_path / "sessions").glob("*.cost")) == []
