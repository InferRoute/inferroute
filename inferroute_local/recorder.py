"""Local decision recorder — the privacy-local corpus of the user's model
choices and how they turned out.

Design: shared-docs/inferroute/local-decision-recorder-spec.md

Three append-only, daily-rotated JSONL event kinds:
  - choice  : a model was selected for a turn (the spine / the label)
  - outcome : what happened when that turn ran (joined by `ref` = choice id)
  - signal  : an explicit human satisfaction signal (switch / redo / rating)

Difficulty, episodes, regret, convergence are NOT recorded — they are views
computed offline over this log. We record raw signals, never verdicts.

Privacy
-------
Everything stays under `base_dir` on the user's machine. Level:
  - off      : no events, no blobs
  - metadata : events only — hashes, counts, model ids; NO prompt text, NO blobs
  - full     : also a content-addressed blob store of raw payloads (prompt text,
               responses) so the corpus can train richer models later

Exception: per-session COST (`sessions/<sid>.cost`, a single USD number — the
price the user paid, no content) is captured at EVERY level including "off",
because it's the product's headline number and isn't corpus data. See note_cost.

What leaves the machine: the corpus (events/blobs) never does. Separately, when a
corpus IS being recorded (metadata/full), the daemon emits a one-way hash of each
turn upstream for fleet aggregates — a fingerprint, never content (see
new_user_block_hash + proxy._visibility_headers; recording-visibility-spec.md).

Storage layout
--------------
  <base>/events/events-YYYY-MM-DD.jsonl     append-only event stream
  <base>/blobs/<aa>/<sha256>.gz             content-addressed, store-once (full)
  <base>/derived/                           offline-computed features (later)

Because Claude Code re-sends the whole conversation every turn, consecutive
turns share almost all message blocks — content addressing dedups them, so the
marginal cost of a turn is ~the novel block, not the whole context.

Fail-soft
---------
NEVER raises into the request path. All writes are best-effort and buffered;
on any error we drop the record and bump a counter.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inferroute_local.recorder")

_VALID_LEVELS = ("off", "metadata", "full")


def _now() -> tuple[float, str]:
    t = time.time()
    return t, datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="milliseconds")


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _block_bytes(block) -> bytes:
    """Deterministic serialization of a message/content block for hashing."""
    try:
        return json.dumps(block, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8", "ignore"
        )
    except Exception:
        return repr(block).encode("utf-8", "ignore")


def _context_chars(messages: list) -> int:
    total = 0
    for m in messages:
        content = m.get("content") if isinstance(m, dict) else None
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for b in content:
                if not isinstance(b, dict):
                    continue
                for k in ("text", "content", "input"):
                    v = b.get(k)
                    if isinstance(v, str):
                        total += len(v)
                    elif isinstance(v, (dict, list)):
                        try:
                            total += len(json.dumps(v))
                        except Exception:
                            pass
    return total


def _last_user_block(messages: list):
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == "user":
            return m
    return None


def new_user_block_hash(body: dict) -> Optional[str]:
    """SHA-256 of the latest user message block of a request.

    Uses the SAME canonicalization as the local corpus (`_block_bytes` →
    `_sha256`, identical to what `record_choice` stores as `new_user_block_hash`),
    so a value emitted upstream by the daemon EQUALS the one stored on disk. That
    identity is what lets the server-side content index line up with the local
    corpus (dedup counts, export verification) — and it holds across the TEE
    transition, since the daemon computes it locally either way. Returns None when
    there's no user block.
    """
    messages = (body or {}).get("messages") or []
    block = _last_user_block(messages)
    return _sha256(_block_bytes(block)) if block is not None else None


class Recorder:
    """Append-only event recorder + content-addressed blob store. One per daemon."""

    def __init__(
        self,
        base_dir: Path,
        *,
        level: str = "metadata",
        ttl_days: int = 90,
        blob_cap_bytes: int = 65536,
        flush_every_n: int = 16,
        flush_every_s: float = 30.0,
    ):
        self.base_dir = Path(base_dir)
        self.level = level if level in _VALID_LEVELS else "metadata"
        self.ttl_days = ttl_days
        self.blob_cap_bytes = max(1024, blob_cap_bytes)
        self.flush_every_n = flush_every_n
        self.flush_every_s = flush_every_s

        self.events_dir = self.base_dir / "events"
        self.blobs_dir = self.base_dir / "blobs"
        # Per-session cumulative-cost files (`<sid>.cost`, full-precision USD)
        # that the `ir` status line reads to show the REAL session cost — no
        # network. See inferroute_cli.launch._strip_command.
        self.sessions_dir = self.base_dir / "sessions"

        self._buf: list[str] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._dropped = 0
        # Per-session last chosen model → lets us label provenance cheaply
        # (first sight = explicit, same = sticky, changed = switch).
        self._session_model: dict[str, str] = {}
        # Per-session running cost total (USD), authoritative in-process; seeded
        # from disk on first touch so it survives a daemon restart mid-session.
        self._session_cost: dict[str, float] = {}
        # Per-session cumulative (fresh_input, cache_read) token totals → the status
        # line shows the cache-hit % climbing through a session (explains the cost
        # curve). In-process; not seeded from disk (a restart just resumes counting).
        self._session_cache: dict[str, tuple[int, int]] = {}
        # Lazily-built secret scrubber, reused across all blob writes so its
        # reverse map + detectors are compiled once. Only ever instantiated on
        # the `full` (blob-storing) level. See _get_scrubber / _scrub_blob_bytes.
        self._scrubber_inst = None
        self._scrubber_failed = False

        if self.enabled:
            try:
                self.events_dir.mkdir(parents=True, exist_ok=True)
                self.sessions_dir.mkdir(parents=True, exist_ok=True)
                if self.level == "full":
                    self.blobs_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"recorder dir unwritable ({e}); disabling")
                self.level = "off"

    @property
    def enabled(self) -> bool:
        return self.level != "off"

    @property
    def store_blobs(self) -> bool:
        return self.level == "full"

    @property
    def dropped(self) -> int:
        return self._dropped

    # ----- public API ------------------------------------------------------

    def record_choice(self, *, body: dict, headers: dict, v2: Optional[dict] = None) -> Optional[str]:
        """Record a model selection. Returns the turn id (to join the outcome),
        or None if disabled / on error.

        v2: this turn's hash_v2 emission (from HashV2.turn — hash_v / fp_v2 /
        turn_hash / turn_seq), stored on the event so the local corpus carries
        the SAME values the upstream headers carried (`ir verify` joins on them).
        """
        if not self.enabled:
            return None
        try:
            turn_id = uuid.uuid4().hex
            ts, iso = _now()
            session_id = self._session_id(body, headers)
            messages = body.get("messages") or []
            chosen = str(body.get("model") or "")
            provenance = self._provenance(session_id, chosen)

            block_hashes = [self._block(m) for m in messages]
            last_user = _last_user_block(messages)
            new_user_hash = self._block(last_user) if last_user is not None else None
            cmd_hash, has_cmd = self._claude_md(body.get("system"))
            tools = [
                t.get("name")
                for t in (body.get("tools") or [])
                if isinstance(t, dict) and t.get("name")
            ]

            self._emit(
                {
                    "schema_version": 1,
                    "kind": "choice",
                    "id": turn_id,
                    "session_id": session_id,
                    "ts": ts,
                    "iso": iso,
                    "chosen_model": chosen,
                    "provenance": provenance,
                    "message_count": len(messages),
                    "context_chars": _context_chars(messages),
                    "has_claude_md": has_cmd,
                    "claude_md_hash": cmd_hash,
                    "tool_names": tools,
                    "turn_block_hashes": block_hashes,
                    "new_user_block_hash": new_user_hash,
                    "stream": bool(body.get("stream")),
                    **(
                        {
                            "hash_v": v2["hash_v"],
                            "fp_v2": v2["fp_v2"],
                            "turn_hash": v2["turn_hash"],
                            "turn_seq": v2["turn_seq"],
                        }
                        if v2
                        else {}
                    ),
                }
            )
            return turn_id
        except Exception as e:
            self._dropped += 1
            logger.debug(f"record_choice skipped ({e})")
            return None

    def record_outcome(
        self,
        *,
        turn_id: Optional[str],
        session_id: str,
        status: int,
        ttft_ms: Optional[float],
        total_ms: float,
        usage: dict,
        stop_reason: Optional[str],
        served_model: str,
        error_kind: Optional[str] = None,
        response_bytes: Optional[bytes] = None,
        request_id: Optional[str] = None,
    ) -> None:
        """Record what happened when a choice's turn ran. Best-effort.

        `request_id` is the Anthropic response request-id, which equals the
        transcript's `requestId` — so the real (server-billed) cost on this
        outcome can be joined to the exact ingested transcript turn, not just the
        session."""
        if not self.enabled or turn_id is None:
            return
        try:
            ts, iso = _now()
            resp_hash = None
            if response_bytes is not None and self.store_blobs:
                resp_hash = self._store(response_bytes)
            usage = usage or {}
            self._emit(
                {
                    "schema_version": 1,
                    "kind": "outcome",
                    "id": uuid.uuid4().hex,
                    "ref": turn_id,
                    "request_id": request_id,
                    "session_id": session_id,
                    "ts": ts,
                    "iso": iso,
                    "served_model": served_model,
                    "http_status": status,
                    "ttft_ms": round(ttft_ms, 1) if ttft_ms is not None else None,
                    "total_ms": round(total_ms, 1),
                    "tokens_in": usage.get("input_tokens"),
                    "tokens_out": usage.get("output_tokens"),
                    "cache_read_tokens": usage.get("cache_read_input_tokens"),
                    "cache_creation_tokens": usage.get("cache_creation_input_tokens"),
                    # Server-computed real cost for this turn (USD), passed through
                    # by the proxy from usage.cost. Same number the dashboard bills.
                    # (The per-session running total is maintained by note_cost,
                    # which the proxy calls independently of record_level.)
                    "cost_usd": usage.get("cost"),
                    "stop_reason": stop_reason,
                    "error_kind": error_kind,
                    "response_block_hash": resp_hash,
                }
            )
        except Exception as e:
            self._dropped += 1
            logger.debug(f"record_outcome skipped ({e})")

    def record_signal(
        self,
        *,
        session_id: str,
        type: str,
        from_model: Optional[str] = None,
        to_model: Optional[str] = None,
        ref: Optional[str] = None,
        rating=None,
    ) -> None:
        """Record an explicit human satisfaction signal (switch/redo/rating)."""
        if not self.enabled:
            return
        try:
            ts, iso = _now()
            self._emit(
                {
                    "schema_version": 1,
                    "kind": "signal",
                    "id": uuid.uuid4().hex,
                    "session_id": session_id,
                    "ts": ts,
                    "iso": iso,
                    "type": type,
                    "from_model": from_model,
                    "to_model": to_model,
                    "ref": ref,
                    "rating": rating,
                }
            )
        except Exception as e:
            self._dropped += 1
            logger.debug(f"record_signal skipped ({e})")

    def record_turn(self, fields: dict) -> None:
        """Record one native-transcript turn — the metadata DELTA over the CC
        transcript spine (see ingest.py). NEVER stores a blob: the content
        already lives in ~/.claude/projects, so even at level "full" this path
        writes no payload, only the joinable metadata. `fields` carries the
        turn's own timestamp (ts/iso) from the transcript, not ingest time.
        Best-effort; never raises."""
        if not self.enabled:
            return
        try:
            _, ingested_iso = _now()
            event = {
                "schema_version": 1,
                "kind": "turn",
                "id": uuid.uuid4().hex,
                "ingested_iso": ingested_iso,
                **fields,
            }
            self._emit(event)
        except Exception as e:
            self._dropped += 1
            logger.debug(f"record_turn skipped ({e})")

    def flush(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._flush_locked()

    def gc(self) -> None:
        """Delete raw blobs older than ttl_days. Events are kept indefinitely
        (tiny). Best-effort; safe to call at startup."""
        if self.ttl_days <= 0 or not self.blobs_dir.exists():
            return
        cutoff = time.time() - self.ttl_days * 86400
        try:
            for shard in self.blobs_dir.iterdir():
                if not shard.is_dir():
                    continue
                for blob in shard.iterdir():
                    try:
                        if blob.stat().st_mtime < cutoff:
                            blob.unlink()
                    except OSError:
                        pass
        except OSError:
            pass

    # ----- internals -------------------------------------------------------

    def _session_id(self, body: dict, headers: dict) -> str:
        sid = (headers or {}).get("x-inferroute-session") or (headers or {}).get(
            "x-inferroute-session-id"
        )
        if sid:
            return sid.strip()
        # Fallback: content-derived id (older clients without the header). Marked
        # by a prefix so offline analysis can tell them apart.
        messages = body.get("messages") or []
        first = messages[0] if messages else {}
        basis = _block_bytes(first)[:500]
        return "ch_" + _sha256(basis)[:16]

    def note_cost(self, session_id: str, cost_usd) -> None:
        """Add this turn's USD cost to the session's running total and write it to
        `<sessions>/<sid>.cost` (full-precision plain text) for the status line.

        Independent of `record_level` ON PURPOSE: the cost is a single content-free
        number — the price the user paid — not part of the prompt/response corpus.
        So it's captured whenever the daemon proxies a turn, even at level "off"
        ("store nothing, but still show the price"). The rich corpus (events,
        blobs) stays gated by `record_level`; only this one number doesn't. The
        daemon merely has to be running — see inferroute_cli.launch._strip_command
        for why the daemon is the only place this can be captured.

        Authoritative in-process (`_session_cost`); seeded once from disk so a
        mid-session daemon restart resumes the total instead of resetting it.
        Best-effort and fail-soft — never raises into the request path. Only acts
        on a real, positive float cost and a filename-safe session id.
        """
        if not session_id:
            return
        if not isinstance(cost_usd, (int, float)) or isinstance(cost_usd, bool):
            return
        if cost_usd <= 0:
            return
        # session ids from ir are uuid hex; guard anyway so a weird header can't
        # escape the sessions dir.
        if not all(c.isalnum() or c in "_.-" for c in session_id):
            return
        try:
            path = self.sessions_dir / f"{session_id}.cost"
            with self._lock:
                cur = self._session_cost.get(session_id)
                if cur is None:
                    try:
                        cur = float(path.read_text().strip())
                    except (OSError, ValueError):
                        cur = 0.0
                cur += float(cost_usd)
                self._session_cost[session_id] = cur
                self.sessions_dir.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".cost.tmp")
                tmp.write_text(f"{cur:.6f}")
                tmp.replace(path)
        except Exception as e:
            logger.debug(f"session cost bump skipped ({e})")

    def note_cache(self, session_id: str, input_tokens, cache_read_tokens) -> None:
        """Accumulate this session's fresh-input vs cache-read tokens and write the
        running cache-hit % to `<sessions>/<sid>.cache` (integer percent) for the
        status line. Same always-on rationale as note_cost (content-free number,
        independent of record_level) and tracked separately from cost because a
        fully-cached turn can cost ~$0 yet still move the ratio. Fail-soft."""
        if not session_id or not all(c.isalnum() or c in "_.-" for c in session_id):
            return
        try:
            fin = int(input_tokens or 0)
            cr = int(cache_read_tokens or 0)
        except (TypeError, ValueError):
            return
        if fin <= 0 and cr <= 0:
            return
        try:
            with self._lock:
                pin, pcr = self._session_cache.get(session_id, (0, 0))
                pin += fin
                pcr += cr
                self._session_cache[session_id] = (pin, pcr)
                total = pin + pcr
                pct = round(100 * pcr / total) if total else 0
                self.sessions_dir.mkdir(parents=True, exist_ok=True)
                path = self.sessions_dir / f"{session_id}.cache"
                tmp = path.with_suffix(".cache.tmp")
                tmp.write_text(str(pct))
                tmp.replace(path)
        except Exception as e:
            logger.debug(f"session cache bump skipped ({e})")

    def _provenance(self, session_id: str, chosen: str) -> str:
        last = self._session_model.get(session_id)
        self._session_model[session_id] = chosen
        if last is None:
            return "human_explicit"
        if last != chosen:
            return "human_switch"
        return "human_sticky"

    def _block(self, block) -> str:
        """Hash a message block; store it (full mode). Returns the hash."""
        data = _block_bytes(block)
        h = _sha256(data)
        if self.store_blobs:
            self._store_at(h, data)
        return h

    def _claude_md(self, system) -> tuple[Optional[str], bool]:
        if not system:
            return None, False
        if isinstance(system, list):
            text = " ".join(b.get("text", "") for b in system if isinstance(b, dict))
        else:
            text = str(system)
        # CLAUDE.md is injected into the system prompt; CC marks project context.
        has = "CLAUDE.md" in text or "[PROJECT]" in text[:400]
        h = _sha256(text.encode("utf-8", "ignore")) if text else None
        if self.store_blobs and text:
            self._store_at(h, text.encode("utf-8", "ignore"))
        return h, has

    def _store(self, data: bytes) -> str:
        h = _sha256(data)
        self._store_at(h, data)
        return h

    def _get_scrubber(self):
        """Lazily build the shared, deterministic secret scrubber.

        One instance per Recorder — its detectors are compiled once and its
        reverse map accumulates so tokenization stays stable across blobs.
        Returns None if the scrubber can't be constructed (then callers treat
        the blob as un-scrubbable and refuse to write it raw — see
        _scrub_blob_bytes). Best-effort: never raises out of here.
        """
        if self._scrubber_inst is not None:
            return self._scrubber_inst
        if self._scrubber_failed:
            return None
        try:
            from .scrubber import Scrubber
            # Default per-user config dir (scrubber.default_config_dir():
            # $INFERROUTE_SCRUBBER_DIR or ~/.config/inferroute/scrubber) — the
            # same salt + reverse map the inferroute-scrub CLI uses, so a
            # redacted blob can be locally rehydrated with the existing tooling.
            self._scrubber_inst = Scrubber()
            return self._scrubber_inst
        except Exception as e:
            self._scrubber_failed = True
            logger.warning(f"scrubber unavailable; blobs will be redaction-placeholdered ({e})")
            return None

    def _scrub_blob_bytes(self, data: bytes) -> bytes:
        """Redact secrets from a blob payload BEFORE it is written to disk.

        Security-critical: this runs over EVERY blob the recorder persists, so
        on-disk blobs never contain raw secrets (sk-/cpk-/inf_/PEM keys/DB URLs)
        even at the `full` recording level. The blob's content-address HASH is
        computed by the caller from the ORIGINAL bytes and is unchanged — only
        the bytes written here are redacted — so dedup, event references, and
        the upstream new_user_block_hash identity all still hold; downstream
        readers fetch by hash and get the scrubbed payload.

        Fail-soft but NEVER leak: if the scrubber can't run, we return a
        redaction-failed placeholder rather than the raw bytes, so a scrubber
        error degrades to "no content" instead of "unscrubbed content". The
        gzip format/structure is preserved either way (still UTF-8 bytes).
        """
        scrubber = self._get_scrubber()
        if scrubber is None:
            return b"<inferroute: redaction unavailable; blob omitted>"
        try:
            text = data.decode("utf-8", "replace")
            scrubbed = scrubber.scrub(text, persist=False).scrubbed_text
            return scrubbed.encode("utf-8", "ignore")
        except Exception as e:
            logger.debug(f"blob scrub failed; omitting content ({e})")
            return b"<inferroute: redaction failed; blob omitted>"

    def _store_at(self, h: str, data: bytes) -> None:
        """Write one content-addressed blob (gzip), store-once. Oversize blobs
        are truncated head+tail so a single huge tool-result can't bloat the
        store — the hash still reflects the full content for dedup/reference.

        The content is SCRUBBED of secrets before it touches disk (see
        _scrub_blob_bytes); the hash `h` is the caller's hash of the ORIGINAL
        bytes, so content-addressing/dedup is unaffected. Truncation runs on the
        original bytes first (keeping the byte cap meaningful), then the kept
        head+tail are scrubbed — so a secret straddling the cut is still in one
        of the two retained pieces and gets redacted."""
        try:
            shard = self.blobs_dir / h[:2]
            path = shard / f"{h}.gz"
            if path.exists():  # dedup — already stored
                return
            shard.mkdir(parents=True, exist_ok=True)
            if len(data) > self.blob_cap_bytes:
                half = self.blob_cap_bytes // 2
                data = (
                    data[:half]
                    + f"...<truncated {len(data)} bytes>...".encode()
                    + data[-half:]
                )
            data = self._scrub_blob_bytes(data)
            tmp = path.with_suffix(".gz.tmp")
            with gzip.open(tmp, "wb") as f:
                f.write(data)
            tmp.replace(path)
        except Exception:
            pass  # blob store is best-effort; the event still records the hash

    def _emit(self, event: dict) -> None:
        try:
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        except Exception as e:
            self._dropped += 1
            logger.debug(f"event serialize failed ({e})")
            return
        with self._lock:
            self._buf.append(line)
            if (
                len(self._buf) >= self.flush_every_n
                or time.monotonic() - self._last_flush >= self.flush_every_s
            ):
                self._flush_locked()

    def _current_path(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.events_dir / f"events-{today}.jsonl"

    def _flush_locked(self) -> None:
        if not self._buf:
            return
        chunk = "\n".join(self._buf) + "\n"
        self._buf.clear()
        self._last_flush = time.monotonic()
        try:
            with self._current_path().open("a", encoding="utf-8") as f:
                f.write(chunk)
        except Exception as e:
            self._dropped += chunk.count("\n")
            if self._dropped <= 5 or self._dropped % 100 == 0:
                logger.warning(f"event write failed ({e}); dropped={self._dropped}")
