"""Cross-language parity: the Python `ir verify` crypto must reproduce EXACTLY
what the server (TypeScript) anchored. Pins tests/fixtures/anchor_vectors.json
(emitted by inferroute-site/src/lib/anchor/anchor.test.ts). If either side's
canonicalization/Merkle drifts, this breaks — which is the whole point: the
user's independent recomputation has to match the anchored roots byte-for-byte.
"""
import json
from pathlib import Path

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
