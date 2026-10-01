"""A reflection turn: what the enclave accepts, how it talks to the model, what it returns.

Stdlib only, and deliberately no network import: this module runs inside the sealed namespace and is
also shipped in the open-source client for payload construction, so it must be readable and small.

A turn is a sealed job. The client holds the transcript; each turn carries the whole conversation so
the enclave is stateless between turns and a spot eviction loses nothing. Validation refuses with a
CATEGORY (never the content), because the refusal reaches a signed statement and a log.

The system prompt is a thinking partner and nothing else. It contains no rule about the product, no
mention of coverage, refusal, or admissibility — there is nothing here for a model to verbalise.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, List

MAX_PLAINTEXT = 262_144
MAX_MESSAGES = 200
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SYSTEM_PROMPT = (
    "You are a rigorous, candid thinking partner for someone developing an idea. Engage with the "
    "specific idea in front of you, not the general topic. Name the assumptions it rests on and the "
    "weakest of them. Say plainly when you are unsure or when a claim would need checking. Prefer "
    "concrete, actionable observations to encouragement. Keep the thread: build on what was said "
    "earlier in this conversation and do not restate it."
)


class RefusedPayload(ValueError):
    """The category is the whole message. Content never appears here."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def transcript_hash(transcript: List[Dict[str, str]]) -> str:
    return hashlib.sha256(canonical(transcript)).hexdigest()


def validate(raw: bytes) -> Dict[str, Any]:
    if len(raw) > MAX_PLAINTEXT:
        raise RefusedPayload("oversize")
    try:
        p = json.loads(raw)
    except ValueError:
        raise RefusedPayload("not-json") from None
    if not isinstance(p, dict) or p.get("kind") != "reflect":
        raise RefusedPayload("bad-kind")
    sid = p.get("session_id")
    if not isinstance(sid, str) or not SESSION_RE.match(sid):
        raise RefusedPayload("no-session-id")
    t = p.get("transcript")
    if not isinstance(t, list) or len(t) > MAX_MESSAGES:
        raise RefusedPayload("bad-transcript")
    for i, m in enumerate(t):
        if (not isinstance(m, dict) or m.get("role") not in ("user", "assistant")
                or not isinstance(m.get("content"), str) or not m["content"].strip()):
            raise RefusedPayload("bad-transcript")
        if m["role"] != ("user" if i % 2 == 0 else "assistant"):
            raise RefusedPayload("bad-role-order")
    msg = p.get("message")
    if not isinstance(msg, str) or not msg.strip():
        raise RefusedPayload("no-message")
    n_user = sum(1 for m in t if m["role"] == "user")
    if not isinstance(p.get("turn"), int) or p["turn"] != n_user + 1:
        raise RefusedPayload("bad-turn")
    meta = p.get("meta", {})
    if not isinstance(meta, dict):
        raise RefusedPayload("bad-meta")
    sf = meta.get("seeded_from")
    if sf is not None and not (isinstance(sf, str) and re.fullmatch(r"[0-9a-f]{64}", sf)):
        raise RefusedPayload("bad-seeded-from")
    return p


def messages(turn: Dict[str, Any]) -> List[Dict[str, str]]:
    return ([{"role": "system", "content": SYSTEM_PROMPT}] + list(turn["transcript"])
            + [{"role": "user", "content": turn["message"]}])


def answer(turn: Dict[str, Any], chat: Callable[[List[Dict[str, str]]], str], model: str) -> Dict[str, Any]:
    """`chat` is injected: the enclave passes engine.chat; tests pass a stub. Nothing here knows how
    the model is reached, which is what keeps this module free of network code."""
    reply = chat(messages(turn)).strip()
    if not reply:
        raise RefusedPayload("model-silent")
    out = list(turn["transcript"]) + [{"role": "user", "content": turn["message"]},
                                      {"role": "assistant", "content": reply}]
    return {"answer": reply, "transcript": out, "model": model,
            "session_id": turn["session_id"], "turn": turn["turn"]}
