"""Tool-output compression via Headroom (https://github.com/chopratejas/headroom).

Compresses the request body in-flight before it is forwarded to either
destination (Anthropic-direct or our hosted MiniMax). Headroom is deterministic
and cache-aware — it never touches a block carrying ``cache_control`` and
protects the most recent messages, so Anthropic prefix-cache locality is
preserved. See shared-docs/inferroute/inferroute-local-strategy.md v2, Phase 2.

Safety (this mutates live Claude Code traffic, so it is strictly fail-open):
  - kill-switch: Config.compress_enabled (env INFERROUTE_COMPRESS=0).
  - integrity check: the compressed body must keep exactly the same tool_use /
    tool_result ids and message structure. Any mismatch, or any exception, and
    we forward the ORIGINAL body unchanged. Compression must never break CC.

Why we re-configure the pipeline router:
  Headroom's bare ``compress()`` defaults protect *all* Read/Bash/Grep/... output
  (DEFAULT_EXCLUDE_TOOLS + protect_recent_reads_fraction≈1.0), so it would be a
  no-op on Claude Code traffic. Headroom's own proxy sets
  ``protect_recent_reads_fraction=0.3`` so that *stale* reads (outside the recent
  window) compress while fresh reads stay verbatim. We replicate that here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import Config

logger = logging.getLogger("inferroute_local")

# Match Headroom's proxy "token mode": compress excluded-tool output once it
# falls outside the most-recent fraction of the conversation.
_PROTECT_RECENT_READS_FRACTION = 0.3


@dataclass
class Savings:
    """Token accounting for one compression attempt."""

    tokens_before: int = 0
    tokens_after: int = 0
    tokens_saved: int = 0
    ratio: float = 0.0  # fraction removed, 0.0–1.0
    applied: bool = False  # True only when the compressed body was actually used

    @classmethod
    def none(cls) -> "Savings":
        return cls()


class Compressor:
    """Wraps Headroom's ``compress()`` with config, safety, and accounting."""

    def __init__(self, config: Config):
        self.config = config
        self._compress = None  # headroom.compress, imported lazily
        self._compress_config = None  # headroom.CompressConfig instance
        self._router_tuned = False
        if config.compress_enabled:
            self._init_headroom()

    def _init_headroom(self) -> None:
        """Import Headroom and pin the pipeline to the CC-effective config.

        Defensive: if anything about Headroom's internals has shifted, we log and
        disable compression rather than risk forwarding a broken body.
        """
        try:
            from headroom import CompressConfig, compress

            self._compress = compress
            self._compress_config = CompressConfig(
                min_tokens_to_compress=self.config.compress_min_tokens,
                # Heuristic base by default (~2% real-traffic reduction). Set
                # INFERROUTE_COMPRESS_KOMPRESS_MODEL to unlock 60-95% ratios
                # (requires headroom-ai[ml] + model download).
                kompress_model=self.config.compress_kompress_model or None,
            )
            self._tune_router()
        except Exception as e:  # pragma: no cover - exercised only on import/ABI drift
            logger.warning(
                "Headroom unavailable (%s); tool-output compression disabled", e
            )
            self._compress = None

    def _tune_router(self) -> None:
        """Set protect_recent_reads_fraction=0.3 on the shared pipeline's router.

        This is the one internal touchpoint Headroom does not yet expose as a
        public ``compress()`` kwarg. Isolated here so a future headroom release
        that surfaces it is a one-line swap. Failure here is non-fatal —
        compression still runs, just with fewer savings.
        """
        try:
            from headroom.compress import _get_pipeline
            from headroom.transforms.content_router import ContentRouter

            pipeline = _get_pipeline()
            transforms = getattr(pipeline, "transforms", None) or getattr(
                pipeline, "_transforms", []
            )
            tuned = 0
            for t in transforms:
                if isinstance(t, ContentRouter):
                    t.config.protect_recent_reads_fraction = _PROTECT_RECENT_READS_FRACTION
                    tuned += 1
            self._router_tuned = tuned > 0
            if not self._router_tuned:
                logger.warning(
                    "Headroom ContentRouter not found; compression will run with "
                    "default (conservative) read protection and may save little."
                )
        except Exception as e:
            logger.warning("Could not tune Headroom router (%s); using defaults", e)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def compress_body(self, body: dict) -> tuple[dict, Savings]:
        """Compress ``body["messages"]`` in place-safe fashion.

        Returns ``(body_to_forward, savings)``. On the kill-switch, any failure,
        or a failed integrity check, returns the original body and unapplied
        savings — never raises.
        """
        if self._compress is None:
            return body, Savings.none()

        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return body, Savings.none()

        try:
            result = self._compress(
                messages,
                model=body.get("model") or "claude-sonnet-4-5-20250929",
                model_limit=_model_limit(body.get("model", "")),
                config=self._compress_config,
            )
        except Exception as e:
            logger.warning("Headroom compress() raised (%s); forwarding original", e)
            return body, Savings.none()

        compressed = result.messages
        if not _structure_preserved(messages, compressed):
            logger.warning(
                "Compression altered message structure (tool_use/tool_result or "
                "cache_control); forwarding original body"
            )
            return body, Savings.none()

        saved = int(getattr(result, "tokens_saved", 0) or 0)
        if saved <= 0:
            # Nothing meaningful removed — forward original to keep things simple.
            return body, Savings(
                tokens_before=int(getattr(result, "tokens_before", 0) or 0),
                tokens_after=int(getattr(result, "tokens_after", 0) or 0),
                tokens_saved=0,
                ratio=0.0,
                applied=False,
            )

        new_body = dict(body)
        new_body["messages"] = compressed
        before = int(getattr(result, "tokens_before", 0) or 0)
        after = int(getattr(result, "tokens_after", 0) or 0)
        return new_body, Savings(
            tokens_before=before,
            tokens_after=after,
            tokens_saved=saved,
            ratio=(saved / before) if before else 0.0,
            applied=True,
        )


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

_CONTEXT_LIMITS = {
    "claude-opus": 200_000,
    "claude-sonnet": 200_000,
    "claude-haiku": 200_000,
    "claude-3": 200_000,
}
_DEFAULT_LIMIT = 200_000


def _model_limit(model: str) -> int:
    for prefix, limit in _CONTEXT_LIMITS.items():
        if model.startswith(prefix):
            return limit
    return _DEFAULT_LIMIT


def _collect_block_ids(messages: list) -> tuple[set, set, int]:
    """Return (tool_use_ids, tool_result_ids, cache_control_block_count).

    The Anthropic API requires every tool_use to be answered by a tool_result
    with the same id; compression must preserve that pairing exactly. We also
    count cache_control markers — Headroom must never drop one (it would bust the
    client's prefix-cache breakpoint).
    """
    tool_use_ids: set = set()
    tool_result_ids: set = set()
    cache_markers = 0
    for m in messages:
        content = m.get("content") if isinstance(m, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if "cache_control" in block:
                cache_markers += 1
            btype = block.get("type")
            if btype == "tool_use":
                tool_use_ids.add(block.get("id"))
            elif btype == "tool_result":
                tool_result_ids.add(block.get("tool_use_id"))
    return tool_use_ids, tool_result_ids, cache_markers


def _structure_preserved(original: list, compressed: list) -> bool:
    """True iff compression preserved message count, tool pairing, cache markers."""
    if not isinstance(compressed, list) or len(compressed) != len(original):
        return False
    o_use, o_res, o_cache = _collect_block_ids(original)
    c_use, c_res, c_cache = _collect_block_ids(compressed)
    return o_use == c_use and o_res == c_res and c_cache >= o_cache
