"""Client-side anchor verification crypto (the core of `ir verify`).

Reproduces, in Python, the EXACT leaf/Merkle/commitment computation the server
does in TypeScript (inferroute-site/src/lib/anchor/*), so a user can independently
recompute their anchored proofs and check them against the roots read from Base —
trusting no InferRoute-served value. docs/verifiable-recording-spine.md §4.5.

Canonical form is byte-identical to the TS side (JSON.stringify over
recursively key-sorted values) because leaf values are integer/string/bool/null
only:  json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).
Domain separation: leaf = sha256(0x00 ‖ canonical), node = sha256(0x01 ‖ l ‖ r).
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def leaf_hash(fields: dict) -> str:
    return hashlib.sha256(b"\x00" + canonical_bytes(fields)).hexdigest()


def node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def sha256_hex(*parts_hex: str) -> str:
    h = hashlib.sha256()
    for p in parts_hex:
        h.update(bytes.fromhex(p))
    return h.hexdigest()


def verify_merkle_path(leaf_hex: str, path: list[dict], root_hex: str) -> bool:
    """path steps: {"sibling": hex, "right": bool} — right=True ⇒ sibling on the
    RIGHT (we are the left child). Matches the TS merkleProof / promote-odd rule."""
    acc = leaf_hex
    for step in path:
        sib = step["sibling"]
        acc = node_hash(acc, sib) if step["right"] else node_hash(sib, acc)
    return acc == root_hex


def user_bucket(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()


def epoch_leaf(user_bucket_hex: str, user_root_hex: str) -> str:
    # SHA256(0x01 ‖ sha256(user_bucket_bytes) ‖ user_root) — matches tree-builder.ts
    ub = hashlib.sha256(bytes.fromhex(user_bucket_hex)).hexdigest()
    return node_hash(ub, user_root_hex)


def verify_record(rec: dict, batch_root_hex: str) -> bool:
    """Full per-record check: recompute leaf from fields, prove to user_root, then
    the epoch-leaf to the batch_root. `rec` = one entry from a proof bundle
    (leaf_fields, leaf_hash, user_bucket, user_root, user_path, epoch_path)."""
    if leaf_hash(rec["leaf_fields"]) != rec["leaf_hash"]:
        return False
    if not verify_merkle_path(rec["leaf_hash"], rec["user_path"], rec["user_root"]):
        return False
    el = epoch_leaf(rec["user_bucket"], rec["user_root"])
    return verify_merkle_path(el, rec["epoch_path"], batch_root_hex)


def verify_commitment(prev_commitment_hex: str, batch_root_hex: str, commitment_hex: str) -> bool:
    """C_t == sha256(C_{t-1} ‖ batch_root_t)."""
    return sha256_hex(prev_commitment_hex, batch_root_hex) == commitment_hex
