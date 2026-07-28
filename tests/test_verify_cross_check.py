"""Unit tests for the ir verify local cross-check categorizer (spine §4.5).

The crypto (leaf/Merkle/commitment parity with the TS side) is covered by
test_anchor_verify.py; this covers the join/categorization logic: matched vs
tamper (hash-differs / metadata-relabeled) vs not-on-this-machine vs awaiting.
"""
from inferroute_cli.verify import _cross_check, _ns_hash

UID = "user_test"


def _local(entries):
    """Build the _local_corpus_index shape from (raw, sid, seq, v) tuples."""
    idx, turns_v2 = {}, {}
    for raw, sid, seq, v in entries:
        n = _ns_hash(UID, raw)
        idx[n] = {"sid": sid, "seq": seq, "v": v}
        if v == 2 and sid is not None and seq is not None:
            turns_v2[(sid, seq)] = n
    return {"idx": idx, "turns_v2": turns_v2, "turns": len(entries), "base": "/tmp/x"}


def _leaf(raw, sid, seq, hash_v=2):
    return {"content_hash": _ns_hash(UID, raw), "session_id": sid,
            "turn_seq": seq, "hash_v": hash_v}


def test_match_and_awaiting():
    local = _local([("aa" * 32, "s1", 0, 2), ("bb" * 32, "s1", 1, 2)])
    out = _cross_check([_leaf("aa" * 32, "s1", 0)], local)
    assert out["matched"] == 1 and not out["tamper"] and out["not_local"] == 0
    assert out["awaiting"] == 1  # bb turn not anchored yet


def test_hash_differs_is_tamper():
    # Local recorded turn (s1,0) with hash aa; the anchored leaf claims a
    # DIFFERENT hash for the same turn → hard tamper signal.
    local = _local([("aa" * 32, "s1", 0, 2)])
    out = _cross_check([_leaf("cc" * 32, "s1", 0)], local)
    assert out["matched"] == 0
    assert len(out["tamper"]) == 1 and out["tamper"][0]["reason"] == "hash-differs"


def test_metadata_relabeled_is_tamper():
    # Hash matches a local v2 turn, but the leaf carries different session/seq
    # → the server relabeled the turn's identity.
    local = _local([("aa" * 32, "s1", 0, 2)])
    out = _cross_check([_leaf("aa" * 32, "s9", 4)], local)
    assert out["matched"] == 0
    assert len(out["tamper"]) == 1 and out["tamper"][0]["reason"] == "metadata-relabeled"


def test_unknown_turn_is_not_local_not_tamper():
    # Anchored fingerprint for a turn this machine never recorded (another
    # machine / wiped corpus) → informational, NOT a tamper alarm.
    local = _local([("aa" * 32, "s1", 0, 2)])
    out = _cross_check([_leaf("dd" * 32, "s7", 3)], local)
    assert out["matched"] == 0 and not out["tamper"] and out["not_local"] == 1


def test_v1_lenient_match_no_metadata_compare():
    # v1 hashes carry no session binding — a match counts, metadata is not
    # compared (same content re-sent across sessions collides by design in v1).
    local = _local([("ee" * 32, "sX", None, 1)])
    out = _cross_check([_leaf("ee" * 32, "sOther", 9, hash_v=1)], local)
    assert out["matched"] == 1 and not out["tamper"]
