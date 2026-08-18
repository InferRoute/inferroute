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


# ---------------------------------------------------------------------------
# LEAF SCHEMA REQUIREMENTS (fail-closed).
#
# WHY THIS EXISTS. The Merkle machinery proves the integrity of WHAT WAS
# COMMITTED — it cannot prove that the right things were committed. Measured
# 2026-08-18: a leaf with NO cost field at all verifies True against its own
# anchored root, and the CLI totalled that record as 0 millicents. Nothing
# anywhere required a field to be present. That is the "blind != quiet" class:
# a verifier that never checks for a field prints exactly what a verifier that
# checked and found it correct prints.
#
# So the v3 billing fields are only worth committing if verification REFUSES a
# leaf that omits them. Enforced per declared version, so already-anchored v2
# epochs keep verifying instead of being retroactively invalidated.
_USAGE_V2 = {
    "v", "kind", "record_id", "user_bucket", "session_id", "turn_seq",
    "content_hash", "hash_v", "recording", "model", "economy",
    "input_tokens", "output_tokens", "cache_read_tokens",
    "cost_millicents", "created_at_ms",
}
# v3 adds: what was ACTUALLY debited (credits_cost), what the caller ASKED for
# (requested_model — without it a silent model substitution is unprovable), and
# cache-creation tokens (a billed input class that v2 committed nowhere).
_USAGE_V3 = _USAGE_V2 | {
    "credits_cost_millicents", "requested_model", "cache_creation_tokens",
    # The rates that PRODUCED credits_cost. Required to be PRESENT (they may be
    # null) so they can never be quietly dropped -- absence would restore the
    # exact hole this file exists to close.
    "rate_input_mc", "rate_cached_mc", "rate_output_mc",
}
USAGE_REQUIRED = {2: _USAGE_V2, 3: _USAGE_V3}


def recompute_credits(fields: dict):
    """Recompute credits_cost from the committed rates, or None if the leaf
    carries no rate snapshot (then the charge is UNVERIFIABLE -- callers must
    report that distinctly and never as "verified").

    This reproduces the producer's expression EXACTLY, floats and truncation
    included (cc_proxy_prod/user_db.py compute_cost). Exact integer arithmetic
    was measured against it over 400k synthetic turns and disagreed on 0.0085%
    by one millicent -- enough to brand ~7 honest rows in 82k as fraudulent, so
    the float form is deliberate, not an oversight. Python and JS both evaluate
    it in IEEE-754 binary64 and were checked to agree on the disagreeing cases.
    """
    ri, rc, ro = (fields.get("rate_input_mc"), fields.get("rate_cached_mc"),
                  fields.get("rate_output_mc"))
    if ri is None or rc is None or ro is None:
        return None
    i = fields.get("input_tokens") or 0
    o = fields.get("output_tokens") or 0
    cr = fields.get("cache_read_tokens") or 0
    cc = fields.get("cache_creation_tokens") or 0
    d = ((i / 1_000_000) * (ri / 100_000)
         + (cr / 1_000_000) * (rc / 100_000)
         + (cc / 1_000_000) * (ri / 100_000)      # no create bucket -> input rate
         + (o / 1_000_000) * (ro / 100_000))
    return int(d * 100_000)


def missing_usage_fields(fields: dict) -> set:
    """Fields a usage leaf of its declared version must carry but does not.

    An absent/unknown `v` is itself a failure: an unversioned leaf would let an
    operator opt out of every requirement simply by omitting the version."""
    if fields.get("kind") != "usage":
        return set()                      # other kinds carry their own shapes
    req = USAGE_REQUIRED.get(fields.get("v"))
    if req is None:
        return {"v(unknown-or-absent)"}
    return req - set(fields)


def verify_record(rec: dict, batch_root_hex: str) -> bool:
    """Full per-record check: recompute leaf from fields, prove to user_root, then
    the epoch-leaf to the batch_root. `rec` = one entry from a proof bundle
    (leaf_fields, leaf_hash, user_bucket, user_root, user_path, epoch_path)."""
    if leaf_hash(rec["leaf_fields"]) != rec["leaf_hash"]:
        return False
    if missing_usage_fields(rec["leaf_fields"]):
        return False          # fail-closed: an incomplete leaf is not a valid one
    _exp = recompute_credits(rec["leaf_fields"])
    if _exp is not None and _exp != rec["leaf_fields"].get("credits_cost_millicents"):
        return False          # the committed charge is not what its own rates produce
    if not verify_merkle_path(rec["leaf_hash"], rec["user_path"], rec["user_root"]):
        return False
    el = epoch_leaf(rec["user_bucket"], rec["user_root"])
    return verify_merkle_path(el, rec["epoch_path"], batch_root_hex)


def verify_commitment(prev_commitment_hex: str, batch_root_hex: str, commitment_hex: str) -> bool:
    """C_t == sha256(C_{t-1} ‖ batch_root_t)."""
    return sha256_hex(prev_commitment_hex, batch_root_hex) == commitment_hex
