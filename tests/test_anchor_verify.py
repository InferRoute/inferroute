"""Cross-language parity: the Python `ir verify` crypto must reproduce EXACTLY
what the server (TypeScript) anchored. Pins tests/fixtures/anchor_vectors.json
(emitted by inferroute-site/src/lib/anchor/anchor.test.ts). If either side's
canonicalization/Merkle drifts, this breaks — which is the whole point: the
user's independent recomputation has to match the anchored roots byte-for-byte.
"""
import json
import pytest
from pathlib import Path

from inferroute_local import anchor_verify as av
from inferroute_local.anchor_verify import (
    leaf_hash, verify_record, verify_commitment, verify_merkle_path, node_hash,
)

_VEC = json.loads((Path(__file__).parent / "fixtures" / "anchor_vectors.json").read_text())


def test_python_reproduces_ts_leaf_hashes():
    for rec in _VEC["records"]:
        assert leaf_hash(rec["leaf_fields"]) == rec["leaf_hash"], rec["record_id"]


def test_every_record_proof_verifies_against_the_batch_root():
    for rec in _VEC["records"]:
        assert verify_record(rec, _VEC["batch_root"]), rec["record_id"]


def test_commitment_chains():
    assert verify_commitment(_VEC["prev_commitment"], _VEC["batch_root"], _VEC["commitment"])


def test_tampered_leaf_field_fails():
    rec = dict(_VEC["records"][0])
    rec = {**rec, "leaf_fields": {**rec["leaf_fields"], "cost_millicents": rec["leaf_fields"]["cost_millicents"] + 1}}
    # leaf hash changes → recorded leaf_hash no longer matches → verify fails
    assert leaf_hash(rec["leaf_fields"]) != _VEC["records"][0]["leaf_hash"]
    rec["leaf_hash"] = leaf_hash(rec["leaf_fields"])
    assert verify_record(rec, _VEC["batch_root"]) is False


def test_node_hash_is_domain_separated():
    # A node hash must differ from a plain concat hash (0x01 prefix present).
    import hashlib
    a, b = "aa" * 32, "bb" * 32
    plain = hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
    assert node_hash(a, b) != plain


# ---------------------------------------------------------------------------
# v3 leaf schema is enforced FAIL-CLOSED.
#
# Regression guard for a defect measured 2026-08-18: a leaf carrying NO cost
# field verified True against its own anchored root, and `ir verify` totalled
# that record as 0 millicents without a word. Inclusion proofs establish that
# what was committed is unaltered; they say nothing about whether the fields
# that SHOULD have been committed were. These cases must fail on incomplete
# leaves and stay quiet on complete ones — including legacy v2, which must not
# be retroactively invalidated.
def _v2_fields(ub):
    return {"v": 2, "kind": "usage", "record_id": "r", "user_bucket": ub,
            "session_id": None, "turn_seq": 0, "content_hash": None,
            "hash_v": None, "recording": None, "model": "kimi",
            "economy": False, "input_tokens": 100, "output_tokens": 50,
            "cache_read_tokens": 0, "cost_millicents": 42, "created_at_ms": 1}


def _v3_fields(ub):
    return _v2_fields(ub) | {"v": 3, "credits_cost_millicents": 16,
                             "requested_model": "kimi",
                             "cache_creation_tokens": 0,
                             "rate_input_mc": 44000, "rate_cached_mc": 8900,
                             "rate_output_mc": 240000}


def _single_leaf_tree(fields):
    lh = av.leaf_hash(fields)
    ub = fields["user_bucket"]
    rec = {"leaf_fields": fields, "leaf_hash": lh, "user_bucket": ub,
           "user_root": lh, "user_path": [], "epoch_path": []}
    return rec, av.epoch_leaf(ub, lh)


def test_complete_v3_leaf_verifies():
    rec, root = _single_leaf_tree(_v3_fields(av.user_bucket("u1")))
    assert av.verify_record(rec, root) is True


def test_legacy_v2_leaf_still_verifies():
    """v3 must not retroactively invalidate already-anchored epochs."""
    rec, root = _single_leaf_tree(_v2_fields(av.user_bucket("u1")))
    assert av.verify_record(rec, root) is True


@pytest.mark.parametrize("dropped", [
    "credits_cost_millicents",   # what the user was actually charged
    "requested_model",           # without it, model substitution is unprovable
    "cache_creation_tokens",     # a billed input class v2 committed nowhere
    "cost_millicents",           # the exact 2026-08-18 repro
    "rate_input_mc",             # without rates the charge cannot be recomputed
    "rate_output_mc",
])
def test_incomplete_v3_leaf_is_refused(dropped):
    f = {k: v for k, v in _v3_fields(av.user_bucket("u1")).items() if k != dropped}
    rec, root = _single_leaf_tree(f)
    assert av.verify_record(rec, root) is False
    assert dropped in av.missing_usage_fields(f)


def test_unversioned_leaf_is_refused():
    """An absent `v` would otherwise let an operator opt out of every
    requirement simply by omitting the version."""
    f = {k: v for k, v in _v3_fields(av.user_bucket("u1")).items() if k != "v"}
    rec, root = _single_leaf_tree(f)
    assert av.verify_record(rec, root) is False


def test_non_usage_kinds_are_unaffected():
    f = {"kind": "founding_capsule", "v": 2, "x": 1}
    assert av.missing_usage_fields(f) == set()


def test_committed_charge_must_match_its_own_rates():
    """A leaf whose credits_cost disagrees with the rates it commits is not a
    valid leaf -- this is the check that turns the rate fields from decoration
    into verification."""
    f = _v3_fields(av.user_bucket("u1"))
    f["credits_cost_millicents"] = 999          # rates say 16
    rec, root = _single_leaf_tree(f)
    assert av.verify_record(rec, root) is False


def test_recompute_matches_producer_arithmetic():
    f = _v3_fields(av.user_bucket("u1"))
    assert av.recompute_credits(f) == 16


def test_null_rates_are_unverifiable_not_invalid():
    """Rows predating rate capture must still verify structurally, but the
    charge is NOT verified -- recompute_credits returns None so callers can
    report them distinctly instead of counting them as checked."""
    f = _v3_fields(av.user_bucket("u1"))
    f["rate_input_mc"] = f["rate_cached_mc"] = f["rate_output_mc"] = None
    f["credits_cost_millicents"] = 12345        # arbitrary: nothing to check it against
    rec, root = _single_leaf_tree(f)
    assert av.verify_record(rec, root) is True
    assert av.recompute_credits(f) is None
