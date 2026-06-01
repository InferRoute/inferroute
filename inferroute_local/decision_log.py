"""Per-turn routing decision log — the feedstock for v1 classifier retraining.

Why this exists
---------------
v0 routing thresholds and label distributions came from offline-labelled
session captures. To improve the classifier we need PRODUCTION OUTCOMES:
which routing decisions led to satisfied users (session continued, no
abandonment, no immediate re-issue at a higher tier), and which didn't.
We can't compute that signal online — but we CAN log enough at decision
time to compute it offline, post-hoc, by grouping per `session_key` and
looking at turn cadence.

What gets logged
----------------
One JSONL record per routed turn. Fields are flat (no nested dicts that
require unpacking in pandas/duckdb later). See `DecisionRecord` for the
exact schema. Records are append-only; rotation by date (one file per
UTC day).

Privacy model
-------------
DEFAULT: metadata only — no prompt text, no message bodies. We log
`context_chars`, `assembled_text_sha256` (for dedup), `argmax`, probs,
tier, reason, etc. — everything an outside observer would need to RANK
the routing decision, but nothing they'd need to RECONSTRUCT the request.

OPT-IN (`INFERROUTE_LOG_TRAINING=1`): also records the assembled classifier
input verbatim. This is what v1 retraining needs. Users opt in knowing
that their prompts will land on disk in plain text in their own
`~/.inferroute/logs/` directory. The data never leaves their machine
unless they explicitly upload it.

Failure mode
------------
Always fail-soft. The logger NEVER raises into the request path. If we
can't write a record, we drop it and increment a counter.

Performance
-----------
Records are buffered in memory and flushed every `flush_every_n` writes
or `flush_every_s` seconds, whichever comes first. fsync is left to the
OS — we'd rather lose 30 seconds of logs on a crash than pay fsync cost
on every routing decision.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inferroute_local.decision_log")


@dataclass
class DecisionRecord:
    """Flat JSON-friendly per-turn record. New fields go at the end (additive
    schema) so older log files keep parsing in offline analysis."""

    # When
    ts: float                                  # unix seconds, UTC
    iso: str                                   # ISO-8601 for human inspection

    # Who (session continuity — the join key for outcome inference)
    session_key: Optional[str]                 # 16-hex from router.compute_session_key
    message_count: int                         # number of messages in the request body

    # Request shape (no content)
    context_chars: int                         # sum of all message-content lengths
    has_claude_md: bool                        # CLAUDE.md detected in system prompt
    model_in: str                              # model the user ASKED for (claude-sonnet-4-6 etc.)

    # Optional content fingerprint — sha256 of the assembled_text, used to
    # detect duplicate routing decisions on the same input without needing
    # the text itself. Always written (cheap).
    assembled_text_sha256: str

    # Classifier output (null if classifier unavailable / hard-rule path)
    clf_argmax: Optional[str]
    clf_max_prob: Optional[float]
    clf_p_minimax: Optional[float]
    clf_p_middle: Optional[float]
    clf_p_frontier: Optional[float]
    clf_inference_ms: Optional[float]

    # Router decision
    tier: str                                  # final tier
    reason: str                                # short rule label
    previous_tier: Optional[str]               # null on first turn / fresh session
    is_upgrade: bool                           # tier went up this turn
    committed: bool                            # session state persisted

    # Proxy execution
    backend: str                               # "anthropic" / "minimax" / "anthropic_fast"
    fast_path: bool                            # bypassed router (compaction / high context)
    compacted: bool                            # compaction-on-upgrade applied

    # Optional training-grade fields (only present when INFERROUTE_LOG_TRAINING=1)
    assembled_text: Optional[str] = None       # the EXACT input the classifier saw


class DecisionLogger:
    """Append-only JSONL writer with date-stamped files and best-effort buffering.

    Single instance per daemon. Thread-safe via a lock on the buffer (we may
    write from different asyncio tasks; the lock is uncontended in practice).
    """

    def __init__(
        self,
        log_dir: Path,
        *,
        enabled: bool = True,
        include_text: bool = False,
        flush_every_n: int = 16,
        flush_every_s: float = 30.0,
    ):
        self.log_dir = Path(log_dir)
        self.enabled = enabled
        self.include_text = include_text
        self.flush_every_n = flush_every_n
        self.flush_every_s = flush_every_s

        self._buf: list[str] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._dropped = 0

        if self.enabled:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"decision log dir unwritable ({e}); disabling logger")
                self.enabled = False

    # ----- public ----------------------------------------------------------

    def emit(self, record: DecisionRecord) -> None:
        """Buffer one record. NEVER raises into the caller's request path."""
        if not self.enabled:
            return
        try:
            if not self.include_text:
                record.assembled_text = None  # belt-and-suspenders
            line = json.dumps(asdict(record), ensure_ascii=False, separators=(",", ":"))
        except Exception as e:
            self._dropped += 1
            if self._dropped <= 5 or self._dropped % 100 == 0:
                logger.warning(f"decision log serialize failed ({e}); dropped={self._dropped}")
            return

        with self._lock:
            self._buf.append(line)
            if (
                len(self._buf) >= self.flush_every_n
                or time.monotonic() - self._last_flush >= self.flush_every_s
            ):
                self._flush_locked()

    def flush(self) -> None:
        """Manual flush (used at daemon shutdown)."""
        if not self.enabled:
            return
        with self._lock:
            self._flush_locked()

    @property
    def dropped(self) -> int:
        return self._dropped

    # ----- internals -------------------------------------------------------

    def _current_path(self) -> Path:
        # Rotate daily so files stay small and `wc -l` per day is a one-liner.
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"decisions-{today}.jsonl"

    def _flush_locked(self) -> None:
        """Write the buffer to disk. Lock must be held by caller."""
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
                logger.warning(f"decision log write failed ({e}); dropped={self._dropped}")


# ──────────────────────────────────────────────────────────────────────────
# Record construction helpers
# ──────────────────────────────────────────────────────────────────────────

def build_record(
    *,
    body: dict,
    assembled_text: str,
    session_key: Optional[str],
    classifier_result,                          # Optional[ClassifierResult]
    decision,                                   # Optional[RouterDecision]
    tier: str,
    reason: str,
    backend: str,
    fast_path: bool,
    compacted: bool,
    include_text: bool,
) -> DecisionRecord:
    """Build a DecisionRecord from the proxy's per-turn state.

    `body` is the (possibly compressed/compacted) request body. We snapshot
    counts off it, not content (unless include_text is True for the
    assembled_text field only — never the raw body).

    `classifier_result` and `decision` can be None on the fast-path or legacy
    server-route fallback. We log "None" rather than skipping the record so
    every routed turn shows up.
    """
    now = time.time()
    iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="milliseconds")

    messages = body.get("messages") or []
    context_chars = _context_chars(messages)
    has_claude_md = "[PROJECT]" in assembled_text[:200]

    probs = (classifier_result.probs if classifier_result else None) or {}
    record = DecisionRecord(
        ts=now,
        iso=iso,
        session_key=session_key,
        message_count=len(messages),
        context_chars=context_chars,
        has_claude_md=has_claude_md,
        model_in=str(body.get("model") or ""),
        assembled_text_sha256=hashlib.sha256(
            assembled_text.encode("utf-8", errors="ignore")
        ).hexdigest(),
        clf_argmax=classifier_result.argmax_label if classifier_result else None,
        clf_max_prob=classifier_result.max_prob if classifier_result else None,
        clf_p_minimax=probs.get("minimax_ok"),
        clf_p_middle=probs.get("middle_tier"),
        clf_p_frontier=probs.get("frontier"),
        clf_inference_ms=classifier_result.inference_ms if classifier_result else None,
        tier=tier,
        reason=reason,
        previous_tier=(decision.previous_tier if decision else None),
        is_upgrade=(decision.is_upgrade if decision else False),
        committed=(decision.committed if decision else True),
        backend=backend,
        fast_path=fast_path,
        compacted=compacted,
        assembled_text=assembled_text if include_text else None,
    )
    return record


def _context_chars(messages: list) -> int:
    total = 0
    for m in messages:
        content = m.get("content")
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
