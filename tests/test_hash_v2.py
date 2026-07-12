"""hash_v2 (HMAC turn-chain) — fixture-pinned vectors + daemon integration.

Fixture discipline mirrors test_visibility.py: tests/fixtures/hash_vectors_v2.json
is dual-pinned here and in cc-proxy-prod (byte-identical copy), and doubles as
the cross-language reference for the Phase-3 verifiers. Requires rfc8785 (the
[local] extra): run with `uv run --with rfc8785 python -m pytest`.
"""
import hashlib
import json
import stat
from pathlib import Path

import pytest

from inferroute_local import hash_v2 as h2
from inferroute_local.config import Config
from inferroute_local.hash_v2 import HashV2, load_or_create_record_key
from inferroute_local.proxy import InferrouteProxy

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "hash_vectors_v2.json"

# MUST equal the pin in cc-proxy-prod/tests/unit/test_recording_visibility.py.
FIXTURE_V2_SHA256 = "fddf3ee4514070a543c80cd534ee48444807c6d7b967d789bc513ba4a243dee4"

_FIXTURE = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
TEST_KEY_HEX = _FIXTURE["record_key_hex"]

pytestmark = pytest.mark.skipif(
    not h2._JCS_AVAILABLE, reason="rfc8785 not installed (inferroute[local] extra)"
)


def _hash2(tmp_path) -> HashV2:
    """HashV2 seeded with the fixture's fixed test key."""
    (tmp_path / "record_key").write_text(TEST_KEY_HEX + "\n")
    return HashV2(tmp_path)


def test_fixture_file_is_pinned():
    data = _FIXTURE_PATH.read_text(encoding="utf-8")
    assert hashlib.sha256(data.encode("utf-8")).hexdigest() == FIXTURE_V2_SHA256, (
        "hash_vectors_v2.json changed — if deliberate, regenerate via "
        "scripts/gen_hash_vectors_v2.py, re-pin FIXTURE_V2_SHA256 in BOTH repos, "
        "and copy the file to cc-proxy-prod/tests/fixtures/"
    )


def test_fp_vectors_match(tmp_path):
    hv = _hash2(tmp_path)
    for v in _FIXTURE["fp_vectors"]:
        assert hv.fp(v["body"]) == v["fp_v2"], v["name"]


def test_string_and_list_forms_now_equal(tmp_path):
    # THE v2 normalization fix: the two wire forms of the same text fingerprint
    # identically (they hashed differently under v1 — fixture v1 documents that).
    hv = _hash2(tmp_path)
    s, l = _FIXTURE["fp_vectors"][0], _FIXTURE["fp_vectors"][1]
    assert hv.fp(s["body"]) == hv.fp(l["body"]) is not None


def test_chain_vectors_match(tmp_path):
    hv = _hash2(tmp_path)
    sid = _FIXTURE["chain_vectors"][0]["session_id"]
    for c in _FIXTURE["chain_vectors"]:
        out = hv.turn(sid, c["body"])
        assert out["turn_seq"] == c["turn_seq"]
        assert out["fp_v2"] == c["fp_v2"]
        assert out["turn_hash"] == c["turn_hash"]


def test_same_text_different_position_differs(tmp_path):
    # Boilerplate turns ("yes") no longer collide — the v1 undercount bug.
    c1, c2 = _FIXTURE["chain_vectors"][1], _FIXTURE["chain_vectors"][2]
    assert c1["body"] == c2["body"]
    assert c1["turn_hash"] != c2["turn_hash"]


def test_chain_persists_across_daemon_restart(tmp_path):
    body = {"messages": [{"role": "user", "content": "turn"}]}
    a = _hash2(tmp_path)
    assert a.turn("sess_x", body)["turn_seq"] == 0
    assert a.turn("sess_x", body)["turn_seq"] == 1
    # New instance over the same base_dir = daemon restart: chain continues.
    b = HashV2(tmp_path)
    assert b.turn("sess_x", body)["turn_seq"] == 2


def test_no_session_emits_fp_only(tmp_path):
    hv = _hash2(tmp_path)
    out = hv.turn("", {"messages": [{"role": "user", "content": "x"}]})
    assert out["turn_seq"] is None
    assert out["turn_hash"] == out["fp_v2"]


def test_no_user_block_returns_none(tmp_path):
    hv = _hash2(tmp_path)
    assert hv.turn("sess", {"messages": [{"role": "assistant", "content": "x"}]}) is None


def test_record_key_created_0600_and_stable(tmp_path):
    k1 = load_or_create_record_key(tmp_path)
    k2 = load_or_create_record_key(tmp_path)
    assert k1 == k2 and len(k1) == 32
    mode = stat.S_IMODE((tmp_path / "record_key").stat().st_mode)
    assert mode == 0o600
    hv = HashV2(tmp_path)
    assert len(hv.key_fingerprint()) == 8


def test_malformed_record_key_disables_never_rotates(tmp_path):
    # A truncated/corrupted key file must FAIL-DISABLE v2, not silently mint a
    # new key — rotation would orphan every previously-recorded HMAC while the
    # user might still restore the file from backup.
    for bad in ("1f" * 10, "z" * 64, ""):
        (tmp_path / "record_key").write_text(bad)
        assert load_or_create_record_key(tmp_path) is None
        # The malformed file is left in place for the user to restore/inspect.
        assert (tmp_path / "record_key").read_text() == bad


def test_corrupted_chain_state_never_raises_into_request_path(tmp_path):
    # Type-corrupted state entries (not just unparseable JSON) must drop and
    # restart their chain — never raise out of turn() (fail-soft invariant).
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "session_chains.json").write_text(
        json.dumps({"sessions": {
            "bad_seq": {"seq": "abc", "prev": "0" * 64},
            "null_seq": {"seq": None, "prev": "0" * 64},
            "bad_prev": {"seq": 3, "prev": 12345},
            "good": {"seq": 7, "prev": "a" * 64, "t": 1.0},
        }})
    )
    hv = _hash2(tmp_path)
    body = {"messages": [{"role": "user", "content": "x"}]}
    # Corrupted entries restart at 0; the intact entry continues at 8.
    assert hv.turn("bad_seq", body)["turn_seq"] == 0
    assert hv.turn("null_seq", body)["turn_seq"] == 0
    assert hv.turn("bad_prev", body)["turn_seq"] == 0
    assert hv.turn("good", body)["turn_seq"] == 8


# ── daemon integration ─────────────────────────────────────────────────────────

def _proxy(tmp_path, level):
    p = InferrouteProxy(Config(record_dir=str(tmp_path), record_level=level))
    (tmp_path / "record_key").write_text(TEST_KEY_HEX + "\n")
    p.hash2 = HashV2(tmp_path)
    return p


def test_visibility_headers_dual_emit(tmp_path):
    p = _proxy(tmp_path, "metadata")
    body = _FIXTURE["chain_vectors"][0]["body"]
    v2 = p.hash2.turn(_FIXTURE["chain_vectors"][0]["session_id"], body)
    h = p._visibility_headers(body, v2)
    # v1 stays (transition window) …
    assert len(h["x-inferroute-content-hash"]) == 64
    # … and v2 rides alongside, matching the fixture chain.
    assert h["x-inferroute-hash-v"] == "2"
    assert h["x-inferroute-content-hash-v2"] == _FIXTURE["chain_vectors"][0]["turn_hash"]
    assert h["x-inferroute-turn-seq"] == "0"


def test_visibility_headers_off_emits_no_hashes(tmp_path):
    p = _proxy(tmp_path, "off")
    h = p._visibility_headers({"messages": [{"role": "user", "content": "x"}]}, None)
    assert h == {"x-inferroute-recording": "off"}


def test_record_choice_event_carries_v2(tmp_path):
    p = _proxy(tmp_path, "metadata")
    body = {"messages": [{"role": "user", "content": "hello"}]}
    v2 = p.hash2.turn("sess_ev", body)
    p.recorder.record_choice(body=body, headers={"x-inferroute-session": "sess_ev"}, v2=v2)
    p.recorder.flush()
    events = list((tmp_path / "events").glob("events-*.jsonl"))
    choice = [json.loads(l) for l in events[0].read_text().splitlines() if '"choice"' in l][0]
    # The local corpus carries the SAME values the upstream headers carried —
    # the identity `ir verify` (Phase 3) checks against the server + anchors.
    assert choice["hash_v"] == 2
    assert choice["turn_hash"] == v2["turn_hash"]
    assert choice["fp_v2"] == v2["fp_v2"]
    assert choice["turn_seq"] == 0
    # v1 fields still present (dual identity during the transition).
    assert len(choice["new_user_block_hash"]) == 64


def test_missing_rfc8785_degrades_to_v1_only(tmp_path, monkeypatch):
    monkeypatch.setattr(h2, "_JCS_AVAILABLE", False)
    hv = _hash2(tmp_path)
    assert not hv.available
    assert hv.turn("sess", {"messages": [{"role": "user", "content": "x"}]}) is None
    p = _proxy(tmp_path, "metadata")
    body = {"messages": [{"role": "user", "content": "x"}]}
    h = p._visibility_headers(body, None)
    assert "x-inferroute-content-hash" in h  # v1 keeps flowing
    assert "x-inferroute-content-hash-v2" not in h
