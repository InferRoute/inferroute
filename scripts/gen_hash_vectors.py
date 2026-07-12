"""Generate tests/fixtures/hash_vectors_v1.json — the cross-repo canonicalization fixture.

The fixture is the single source of truth for the v1 content-hash canonicalization
(recorder._block_bytes → sha256) AND the server-side per-account namespacing
(sha256("<user_id>:" + raw)). A byte-identical copy lives in
cc-proxy-prod/tests/fixtures/; both repos pin sha256(fixture_file) so drift in
either copy fails one of the two CI suites. This replaces the hand-copied
canonicalization replica that used to live in cc-proxy-prod's tests.

Regenerate (from the inferroute repo root) after any deliberate canonicalization
change, then re-pin FIXTURE_SHA256 in BOTH repos' tests and copy the file over:

    python scripts/gen_hash_vectors.py
    cp tests/fixtures/hash_vectors_v1.json \
       ../cc-proxy-prod/tests/fixtures/hash_vectors_v1.json
"""
import hashlib
import json
from pathlib import Path

from inferroute_local.recorder import new_user_block_hash

USER_ID = "user_test_123"

# NOTE(v1 semantics, documented deliberately):
# - `content: "s"` and `content: [{"type":"text","text":"s"}]` hash DIFFERENTLY
#   (no normalization in v1; hash_v2 will normalize).
# - The whole last-user message dict is hashed, so incidental fields like
#   cache_control change the hash.
CASES = [
    {
        "name": "pinned_join_vector",
        "note": "Original cross-repo pinned vector (fa027481…); kept as case 0 forever.",
        "body": {
            "model": "kimi",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
                {"role": "user", "content": [{"type": "text", "text": "do the thing"}]},
            ],
        },
    },
    {
        "name": "string_content",
        "note": "Plain string content.",
        "body": {"messages": [{"role": "user", "content": "fix the bug in auth.py"}]},
    },
    {
        "name": "unicode_astral_and_combining",
        "note": "Astral emoji, combining accents, CJK — ensure_ascii=False path.",
        "body": {
            "messages": [
                {"role": "user", "content": "café vs café — \U0001f680 你好"}
            ]
        },
    },
    {
        "name": "string_vs_list_string_form",
        "note": "Pair with the next case: same text, string form. v1 hashes these DIFFERENTLY.",
        "body": {"messages": [{"role": "user", "content": "same text"}]},
    },
    {
        "name": "string_vs_list_list_form",
        "note": "Pair with the previous case: same text, list form. v1 hashes these DIFFERENTLY.",
        "body": {"messages": [{"role": "user", "content": [{"type": "text", "text": "same text"}]}]},
    },
    {
        "name": "cache_control_included",
        "note": "Incidental provider fields on the block are part of the v1 hash.",
        "body": {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "do the thing",
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                }
            ]
        },
    },
    {
        "name": "nested_tool_result",
        "note": "Deeply nested tool_result content; key order must not matter (sort_keys).",
        "body": {
            "messages": [
                {"role": "assistant", "content": [{"type": "text", "text": "running"}]},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": [
                                {"type": "text", "text": "exit 0"},
                                {"type": "text", "text": "{\"rows\": [1, 2, 3]}"},
                            ],
                        }
                    ],
                },
            ]
        },
    },
    {
        "name": "last_user_block_selected",
        "note": "Multiple user messages — only the LAST user block is hashed.",
        "body": {
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "second"},
            ]
        },
    },
    {
        "name": "no_user_block",
        "note": "No user message → no hash (header omitted; server stores NULL).",
        "body": {"messages": [{"role": "assistant", "content": "x"}]},
    },
]


def main() -> None:
    vectors = []
    for case in CASES:
        raw = new_user_block_hash(case["body"])
        stored = (
            hashlib.sha256(f"{USER_ID}:{raw}".encode("utf-8")).hexdigest() if raw else None
        )
        vectors.append({**case, "raw_hash": raw, "stored_hash": stored})

    fixture = {
        "version": 1,
        "description": (
            "v1 content-hash canonicalization vectors: raw_hash = "
            "sha256(json.dumps(last_user_block, sort_keys=True, ensure_ascii=False, "
            "separators=(',',':')).encode('utf-8','ignore')); stored_hash = "
            "sha256(user_id + ':' + raw_hash). Dual-pinned in inferroute and "
            "cc-proxy-prod test suites."
        ),
        "namespace_formula": "sha256(user_id + ':' + raw_hash)",
        "user_id": USER_ID,
        "vectors": vectors,
    }

    out = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "hash_vectors_v1.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    out.write_text(data, encoding="utf-8")
    print(f"wrote {out}")
    print(f"FIXTURE_SHA256 = {hashlib.sha256(data.encode('utf-8')).hexdigest()}")


if __name__ == "__main__":
    main()
