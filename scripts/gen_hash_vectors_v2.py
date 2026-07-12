"""Generate tests/fixtures/hash_vectors_v2.json — hash_v2 (HMAC turn-chain) vectors.

Same dual-pin discipline as v1 (see gen_hash_vectors.py): byte-identical copy in
cc-proxy-prod/tests/fixtures/, both suites pin sha256(fixture_file). These vectors
also become the cross-language reference for the Phase-3 verifier implementations
(`ir verify` in Python, the site's proof/tree code in TS).

Vectors use a FIXED test record key (never a real one). Run with the [local]
extra (rfc8785):

    uv run --with rfc8785 python scripts/gen_hash_vectors_v2.py
    cp tests/fixtures/hash_vectors_v2.json \
       ../cc-proxy-prod/tests/fixtures/hash_vectors_v2.json
"""
import hashlib
import hmac
import json
from pathlib import Path

from inferroute_local.hash_v2 import _ZERO_PREV, canonical_v2_bytes, _last_user_block

TEST_RECORD_KEY_HEX = "1f" * 32
USER_ID = "user_test_123"

FP_CASES = [
    {
        "name": "string_form",
        "note": "String content — must equal the list form below (v2 normalizes).",
        "body": {"messages": [{"role": "user", "content": "same text"}]},
    },
    {
        "name": "list_form",
        "note": "List form of the same text — must equal string_form.",
        "body": {"messages": [{"role": "user", "content": [{"type": "text", "text": "same text"}]}]},
    },
    {
        "name": "unicode_strict",
        "note": "Astral + combining + CJK through JCS, UTF-8 strict.",
        "body": {"messages": [{"role": "user", "content": "café vs café — \U0001f680 你好"}]},
    },
    {
        "name": "nested_tool_result",
        "note": "Nested structures + numbers through JCS (the number path is why we use a library).",
        "body": {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": [{"type": "text", "text": "exit 0"}],
                        }
                    ],
                }
            ]
        },
    },
    {
        "name": "no_user_block",
        "note": "No user message → no fingerprint.",
        "body": {"messages": [{"role": "assistant", "content": "x"}]},
    },
]

# A 3-turn session chained under a fixed session id.
CHAIN_SESSION = "sess_fixture_01"
CHAIN_BODIES = [
    {"messages": [{"role": "user", "content": "first turn"}]},
    {"messages": [{"role": "user", "content": "yes"}]},
    {"messages": [{"role": "user", "content": "yes"}]},  # same text as turn 1 — MUST differ via chain
]


def _fp(key: bytes, body: dict):
    block = _last_user_block(body.get("messages") or [])
    if block is None:
        return None
    data = canonical_v2_bytes(block)
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def main() -> None:
    key = bytes.fromhex(TEST_RECORD_KEY_HEX)

    fp_vectors = []
    for case in FP_CASES:
        fp = _fp(key, case["body"])
        stored = hashlib.sha256(f"{USER_ID}:{fp}".encode()).hexdigest() if fp else None
        fp_vectors.append({**case, "fp_v2": fp, "stored_hash": stored})

    chain_vectors = []
    prev = _ZERO_PREV
    for seq, body in enumerate(CHAIN_BODIES):
        fp = _fp(key, body)
        msg = f"{CHAIN_SESSION}:{seq}:{prev}:{fp}".encode("utf-8")
        turn_hash = hmac.new(key, msg, hashlib.sha256).hexdigest()
        chain_vectors.append(
            {
                "body": body,
                "session_id": CHAIN_SESSION,
                "turn_seq": seq,
                "prev": prev,
                "fp_v2": fp,
                "turn_hash": turn_hash,
                "stored_hash": hashlib.sha256(f"{USER_ID}:{turn_hash}".encode()).hexdigest(),
            }
        )
        prev = turn_hash

    fixture = {
        "version": 2,
        "description": (
            "hash_v2 vectors: fp_v2 = HMAC-SHA256(record_key, "
            "rfc8785(normalize(last_user_block))); turn_hash_n = HMAC(key, "
            "'{session}:{n}:{prev}:{fp}'), prev_0 = 64*'0'; stored_hash = "
            "sha256(user_id + ':' + emitted_hash). Dual-pinned in inferroute and "
            "cc-proxy-prod; reference for the Phase-3 Python/TS verifiers."
        ),
        "record_key_hex": TEST_RECORD_KEY_HEX,
        "user_id": USER_ID,
        "namespace_formula": "sha256(user_id + ':' + emitted_hash)",
        "fp_vectors": fp_vectors,
        "chain_vectors": chain_vectors,
    }

    out = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "hash_vectors_v2.json"
    data = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    out.write_text(data, encoding="utf-8")
    print(f"wrote {out}")
    print(f"FIXTURE_V2_SHA256 = {hashlib.sha256(data.encode('utf-8')).hexdigest()}")


if __name__ == "__main__":
    main()
