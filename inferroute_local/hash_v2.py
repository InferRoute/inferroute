"""hash_v2: HMAC turn-chain content fingerprints (verifiable-recording-spine, Phase 1).

Fixes the v1 fingerprint's audit findings (docs/verifiable-recording-spine.md §2):

- F1 dictionary attacks: fp = HMAC-SHA256(record_key, canonical_bytes) with a
  user-held key generated on this machine and NEVER uploaded. Even with full
  server-DB access, a stored hash cannot confirm guessed content.
- F4 canonicalization: RFC 8785 (JCS) via the `rfc8785` library (never
  hand-rolled — number serialization is the trap), UTF-8 strict, NO repr
  fallback (serialization failure → None + a counted drop). String content is
  normalized to the text-block list form first, so `content: "hi"` and
  `content: [{"type":"text","text":"hi"}]` fingerprint identically.
- F5 per-turn collisions: the emitted value is a per-session chain
      turn_hash_n = HMAC(key, session_id:n:prev:fp_n),   prev_0 = 64*"0"
  so boilerplate turns ("yes", "continue") no longer collide across
  conversations, and within-session deletion/reorder breaks the chain a user
  can verify (`ir verify`, Phase 3).

The v1 hash stays dual-emitted for one release window; the server prefers v2
(x-inferroute-content-hash-v2 + x-inferroute-turn-seq + x-inferroute-hash-v).
Chain state is persisted so a daemon restart does not restart chains; if state
IS lost, chains restart at seq 0 — harmless, because turn_seq/turn_hash are only
recorded metadata for the future anchor leaf, never a server-side billing or
dedup key (that would be a client-controlled bypass). Duplicate turns are
resolved at epoch-build time (anchoring), not at the usage INSERT.
"""
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inferroute_local.hash_v2")

try:  # pure-python, but only in the [local] extra — degrade to v1-only without it
    import rfc8785

    _JCS_AVAILABLE = True
except Exception:  # pragma: no cover - environment-dependent
    rfc8785 = None
    _JCS_AVAILABLE = False

HASH_V = 2
_ZERO_PREV = "0" * 64
_MAX_TRACKED_SESSIONS = 500


def load_or_create_record_key(base_dir: Path) -> Optional[bytes]:
    """The user's record key: 32 random bytes, hex on disk at <base>/record_key,
    0600, generated once (atomically). Never leaves the machine — `ir verify`
    uses it to recompute fingerprints; losing it makes old turns unverifiable
    (not lost).

    A key is generated ONLY when the file is absent. An existing-but-malformed
    file FAIL-DISABLES v2 (loud error, v1 keeps flowing) — never silently
    rotates: rotating would orphan every previously-recorded HMAC, and the user
    may be able to restore the file from backup. Returns None when disabled.
    """
    path = Path(base_dir) / "record_key"
    try:
        if path.exists():
            raw = path.read_text(encoding="utf-8").strip()
            if len(raw) == 64:
                return bytes.fromhex(raw)  # non-hex → ValueError → disabled below
            logger.error(
                f"record_key at {path} is malformed — hash_v2 DISABLED (not rotated: "
                "a new key would orphan previously-recorded fingerprints). Restore "
                "the file from backup, or delete it to mint a fresh key."
            )
            return None
        key = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic create: a crash mid-write must never leave a truncated key file
        # (which would then fail-disable v2 on every subsequent start).
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key.hex() + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return key
    except Exception as e:
        logger.error(f"record_key unavailable ({e}) — hash_v2 disabled")
        return None


def _normalize_block(block: dict) -> dict:
    """Canonical shape for hashing: string content becomes the equivalent
    text-block list, so the two wire forms of the same text hash identically."""
    content = block.get("content")
    if isinstance(content, str):
        block = dict(block)
        block["content"] = [{"type": "text", "text": content}]
    return block


def canonical_v2_bytes(block: dict) -> Optional[bytes]:
    """RFC 8785 canonical bytes of the normalized block. None on any failure —
    deliberately NO fallback (v1's repr()/errors='ignore' fallbacks made hashes
    non-reproducible and collision-prone)."""
    if not _JCS_AVAILABLE:
        return None
    try:
        return rfc8785.dumps(_normalize_block(block))
    except Exception:
        return None


def _last_user_block(messages: list):
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == "user":
            return m
    return None


class HashV2:
    """Per-daemon v2 fingerprinting + persisted per-session turn chains."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self._key = load_or_create_record_key(self.base_dir)
        self._state_path = self.base_dir / "state" / "session_chains.json"
        self._chains: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._dropped = 0
        self._loaded = False
        if not _JCS_AVAILABLE:
            logger.warning(
                "rfc8785 not installed — hash_v2 disabled, emitting v1 fingerprints only "
                "(pip install 'inferroute[local]')"
            )

    @property
    def available(self) -> bool:
        return _JCS_AVAILABLE and self._key is not None

    @property
    def dropped(self) -> int:
        return self._dropped

    def key_fingerprint(self) -> Optional[str]:
        """First 8 hex of sha256(record_key) — safe to display, never the key."""
        if self._key is None:
            return None
        return hashlib.sha256(self._key).hexdigest()[:8]

    # ----- fingerprints ------------------------------------------------------

    def fp(self, body: dict) -> Optional[str]:
        """HMAC fingerprint of the latest user block (v2 analogue of
        recorder.new_user_block_hash). None when unavailable / no user block /
        canonicalization failure (counted)."""
        if not self.available:
            return None
        block = _last_user_block((body or {}).get("messages") or [])
        if block is None:
            return None
        data = canonical_v2_bytes(block)
        if data is None:
            self._dropped += 1
            return None
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def turn(self, session_id: str, body: dict) -> Optional[dict]:
        """Compute this turn's v2 emission. Returns
        {"hash_v": 2, "fp_v2": …, "turn_hash": …, "turn_seq": …} — turn_hash
        equals fp_v2 (and turn_seq is None) when there is no session id to
        chain under. None when v2 is unavailable or the block can't be hashed.

        Fail-soft like everything in the recording path: NEVER raises into the
        request path — any internal error returns None (counted).

        NOTE for the Phase-3 verifier: the chain advances on every inbound
        request, including turns that later FAIL to reach the server — so
        server-side seqs legitimately have gaps. `ir verify` must join by
        turn_hash and treat local-only turns with failed outcomes as benign,
        never expect dense server sequences. (Rolling back on failure would be
        worse: it would reuse (seq, prev) for different content.)
        """
        try:
            fp = self.fp(body)
            if fp is None:
                return None
            if not session_id:
                return {"hash_v": HASH_V, "fp_v2": fp, "turn_hash": fp, "turn_seq": None}
            with self._lock:
                self._load_state_locked()
                chain = self._chains.get(session_id) or {"seq": -1, "prev": _ZERO_PREV}
                seq = int(chain["seq"]) + 1
                msg = f"{session_id}:{seq}:{chain['prev']}:{fp}".encode("utf-8")
                turn_hash = hmac.new(self._key, msg, hashlib.sha256).hexdigest()
                self._chains[session_id] = {"seq": seq, "prev": turn_hash, "t": time.time()}
                self._save_state_locked()
            return {"hash_v": HASH_V, "fp_v2": fp, "turn_hash": turn_hash, "turn_seq": seq}
        except Exception as e:
            self._dropped += 1
            logger.warning(f"hash_v2 turn skipped ({e})")
            return None

    # ----- chain-state persistence (survives daemon restarts) ----------------

    def _load_state_locked(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            chains = data.get("sessions")
            if isinstance(chains, dict):
                # Type-validate, not just presence: a corrupted entry must be
                # dropped (its chain restarts — harmless, seq is only anchor-leaf
                # metadata), never raise in the request path.
                self._chains = {
                    k: v
                    for k, v in chains.items()
                    if isinstance(v, dict)
                    and isinstance(v.get("seq"), int)
                    and not isinstance(v.get("seq"), bool)
                    and isinstance(v.get("prev"), str)
                    and len(v.get("prev", "")) == 64
                }
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"session chain state unreadable ({e}) — chains restart")

    def _save_state_locked(self) -> None:
        try:
            if len(self._chains) > _MAX_TRACKED_SESSIONS:
                keep = sorted(
                    self._chains.items(),
                    key=lambda kv: kv[1].get("t", 0),
                    reverse=True,
                )[:_MAX_TRACKED_SESSIONS]
                self._chains = dict(keep)
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"sessions": self._chains}, f)
            os.replace(tmp, self._state_path)
        except Exception as e:
            self._dropped += 1
            logger.debug(f"session chain state not persisted ({e})")
