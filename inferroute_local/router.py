"""Session-aware tier router: stickiness + asymmetric thresholds + deferred commitment.

This is Phase 2 of the local-routing rollout. It sits on top of `classifier_v2.py`
(stateless per-turn predictor) and adds the three pieces that turn raw classifier
output into a cache-friendly, quality-aware routing decision:

  1. STICKINESS. Once a session lands on a tier, stay there unless the classifier's
     evidence for switching crosses an asymmetric threshold. Why: switching tiers
     mid-conversation kills KV-cache hits at the backend and breaks the assistant's
     working context.

  2. ASYMMETRIC THRESHOLDS (quality-first). Upgrades (toward frontier) are CHEAP;
     downgrades (toward minimax_ok) are EXPENSIVE. A momentary signal that the
     task got harder should immediately upgrade; a momentary signal that it got
     easier needs strong corroboration. Numerical values come from the design doc.

  3. DEFERRED COMMITMENT. On the very first turn of a session, if the classifier
     isn't confident (max_prob < commit_threshold), we provisionally route to
     minimax_ok but DON'T persist the session state. The next turn re-evaluates
     from scratch. This avoids locking a fresh session into a wrong tier on a
     single ambiguous greeting like "hi" or "ok continue".

Hard rules (`ultrathink` keyword, explicit `x-inferroute-tier` header override)
short-circuit the classifier entirely. Compaction signals are already caught
upstream in the fast-path layer, so they don't appear here.

State eviction: each session entry is ~200 bytes. We cap at 10K live sessions
and lazily drop entries older than `session_ttl_seconds`. Total memory bound ≈ 2MB.

See `shared-docs/inferroute/stability-and-routing.md` for the full design.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .classifier_v2 import ClassifierResult, RoutingClassifier

logger = logging.getLogger("inferroute_local.router")

# ──────────────────────────────────────────────────────────────────────────
# Tier model
# ──────────────────────────────────────────────────────────────────────────

TIER_MINIMAX = "minimax_ok"
TIER_MIDDLE = "middle_tier"
TIER_FRONTIER = "frontier"
TIER_ORDER = {TIER_MINIMAX: 0, TIER_MIDDLE: 1, TIER_FRONTIER: 2}

# Asymmetric switch thresholds — (current_tier, target_tier) → required P(target).
# UPGRADES (left→right in tier order) are cheap (0.25-0.35).
# DOWNGRADES are expensive (0.45-0.55).
# Tune via Phase B production data; for v0 these are informed guesses from
# the design discussions, not learned values.
SWITCH_THRESHOLDS: dict[tuple[str, str], float] = {
    (TIER_MINIMAX, TIER_MIDDLE):    0.25,
    (TIER_MINIMAX, TIER_FRONTIER):  0.35,
    (TIER_MIDDLE, TIER_FRONTIER):   0.25,
    (TIER_MIDDLE, TIER_MINIMAX):    0.45,
    (TIER_FRONTIER, TIER_MIDDLE):   0.45,
    (TIER_FRONTIER, TIER_MINIMAX):  0.55,
}

# ──────────────────────────────────────────────────────────────────────────
# Hard rules — keyword/header overrides that bypass the classifier
# ──────────────────────────────────────────────────────────────────────────

# `ultrathink` is CC's explicit signal that the user wants deep reasoning; we
# always send these to frontier regardless of classifier output. Case-insensitive,
# word-boundary match so "ultrathinking" / "preultrathink" don't false-trigger.
_ULTRATHINK_RE = re.compile(r"\bultrathink\b", re.IGNORECASE)

# Header values map directly to tier names; anything else is ignored.
_VALID_TIER_OVERRIDES = {TIER_MINIMAX, TIER_MIDDLE, TIER_FRONTIER}


def detect_hard_rule(body: dict, request_headers: dict[str, str]) -> Optional[tuple[str, str]]:
    """Return (tier, reason) if a hard rule fires, else None.

    Order matters: explicit header > ultrathink keyword. The header is a debugging
    / power-user escape hatch and must always win.
    """
    hdr_tier = (request_headers.get("x-inferroute-tier") or "").strip().lower()
    if hdr_tier in _VALID_TIER_OVERRIDES:
        return hdr_tier, f"hdr_override:{hdr_tier}"

    # Walk only the latest user message — earlier turns might mention the keyword
    # in passing without intending to switch the current turn.
    last_user_text = _last_user_text(body)
    if last_user_text and _ULTRATHINK_RE.search(last_user_text):
        return TIER_FRONTIER, "kw_ultrathink"

    return None


def _last_user_text(body: dict) -> str:
    for msg in reversed(body.get("messages") or []):
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = [
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            ]
            if parts:
                return "\n".join(parts)
    return ""


# ──────────────────────────────────────────────────────────────────────────
# Session identification
# ──────────────────────────────────────────────────────────────────────────

def compute_session_key(body: dict) -> Optional[str]:
    """Identify the conversation. None if the request has no messages.

    We hash the first user message's text (first 500 chars). Rationale:
    - CC sessions always start with a stable first user turn
    - Truncating to 500 chars makes the key insensitive to later edits to that
      message that CC sometimes performs (e.g., appended tool result blocks)
    - SHA-256 collisions are not a concern at this scale
    """
    messages = body.get("messages") or []
    if not messages:
        return None
    first = messages[0]
    content = first.get("content")
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            b.get("text", "") for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        )
    else:
        return None
    if not text:
        return None
    digest = hashlib.sha256(text[:500].encode("utf-8", errors="ignore")).hexdigest()
    return digest[:16]  # 64 bits is plenty


# ──────────────────────────────────────────────────────────────────────────
# Session state
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class SessionState:
    tier: str
    committed: bool                 # False = first-turn provisional
    last_seen: float                # monotonic seconds
    turn_count: int = 0
    # Most recent classifier probs — useful for debugging and Phase B logging.
    last_probs: dict[str, float] = field(default_factory=dict)


@dataclass
class RouterDecision:
    """The router's output. Maps to a backend at the proxy edge."""
    tier: str                       # canonical 3-class label
    reason: str                     # compact rule label for stats / logs
    committed: bool                 # was the session state persisted this turn?
    classifier_result: Optional[ClassifierResult] = None  # None on hard-rule path
    previous_tier: Optional[str] = None  # session's tier before this turn (None if new session)
    is_upgrade: bool = False        # tier went UP relative to previous_tier — triggers compaction


# ──────────────────────────────────────────────────────────────────────────
# TierRouter — orchestrates the four-layer routing algorithm
# ──────────────────────────────────────────────────────────────────────────

class TierRouter:
    """Session-aware classifier wrapper.

    The proxy holds one instance per daemon. It's NOT thread-safe in the strict
    sense, but the daemon's asyncio model means there's effectively one writer
    at a time on the session map — the brief race on dict updates is benign.
    """

    def __init__(
        self,
        classifier: RoutingClassifier,
        commit_threshold: float = 0.6,
        session_ttl_seconds: float = 2 * 3600,
        max_sessions: int = 10_000,
        evict_every_n_calls: int = 500,
    ):
        self._clf = classifier
        self._commit_threshold = commit_threshold
        self._ttl = session_ttl_seconds
        self._max_sessions = max_sessions
        self._evict_every = evict_every_n_calls

        self._sessions: dict[str, SessionState] = {}
        self._calls_since_evict = 0

    # ----- public interface -------------------------------------------------

    def route(
        self, body: dict, request_headers: Optional[dict[str, str]] = None
    ) -> Optional[RouterDecision]:
        """Return a routing decision for this turn, or None if classifier unavailable.

        None signals the proxy to fall back to the legacy server route. We
        return None ONLY when the classifier failed to load — hard rules still
        produce a decision even with no classifier.
        """
        headers = request_headers or {}

        # Layer A: hard rules — bypass classifier entirely.
        hard = detect_hard_rule(body, headers)
        if hard is not None:
            tier, reason = hard
            self._update_session(body, tier, committed=True, probs={})
            return RouterDecision(tier=tier, reason=reason, committed=True)

        # Layer B: classifier inference. If it fails, give the proxy a chance
        # to fall back; we don't pretend to know the answer.
        result = self._clf.classify_body(body)
        if result is None:
            return None

        # Layer C: stickiness + asymmetric switch + deferred commitment.
        session_key = compute_session_key(body)
        state = self._get_session(session_key) if session_key else None

        if state is None:
            # First observed turn for this session.
            if result.max_prob < self._commit_threshold:
                # Defer: route provisionally to the safe default, don't persist.
                return RouterDecision(
                    tier=TIER_MINIMAX,
                    reason=(
                        f"deferred_p{int(result.max_prob*100)}"
                        f"_{result.argmax_label}"
                    ),
                    committed=False,
                    classifier_result=result,
                )
            # Confident first call: commit to argmax.
            tier = result.argmax_label
            if session_key:
                self._put_session(session_key, tier, committed=True, probs=result.probs)
            return RouterDecision(
                tier=tier,
                reason=f"commit_p{int(result.max_prob*100)}_{tier}",
                committed=True,
                classifier_result=result,
            )

        # Sticky session: apply asymmetric thresholds against current tier.
        new_tier = apply_asymmetric_thresholds(state.tier, result.probs)
        if new_tier == state.tier:
            self._touch_session(session_key, result.probs)
            return RouterDecision(
                tier=state.tier,
                reason=f"sticky_{state.tier}_t{state.turn_count}",
                committed=True,
                classifier_result=result,
                previous_tier=state.tier,
                is_upgrade=False,
            )

        # Switch crossed the threshold.
        is_upgrade = TIER_ORDER[new_tier] > TIER_ORDER[state.tier]
        self._put_session(session_key, new_tier, committed=True, probs=result.probs)
        return RouterDecision(
            tier=new_tier,
            reason=f"switch_{state.tier}→{new_tier}_p{int(result.probs[new_tier]*100)}",
            committed=True,
            classifier_result=result,
            previous_tier=state.tier,
            is_upgrade=is_upgrade,
        )

    def session_count(self) -> int:
        return len(self._sessions)

    # ----- session map plumbing --------------------------------------------

    def _get_session(self, key: str) -> Optional[SessionState]:
        state = self._sessions.get(key)
        if state is None:
            return None
        if time.monotonic() - state.last_seen > self._ttl:
            # Expired — drop and treat as new session.
            self._sessions.pop(key, None)
            return None
        return state

    def _put_session(
        self, key: str, tier: str, committed: bool, probs: dict[str, float]
    ) -> None:
        existing = self._sessions.get(key)
        turn_count = (existing.turn_count + 1) if existing else 1
        self._sessions[key] = SessionState(
            tier=tier,
            committed=committed,
            last_seen=time.monotonic(),
            turn_count=turn_count,
            last_probs=probs,
        )
        self._maybe_evict()

    def _touch_session(self, key: Optional[str], probs: dict[str, float]) -> None:
        if not key:
            return
        state = self._sessions.get(key)
        if state is None:
            return
        state.last_seen = time.monotonic()
        state.turn_count += 1
        state.last_probs = probs

    def _update_session(
        self, body: dict, tier: str, committed: bool, probs: dict[str, float]
    ) -> None:
        key = compute_session_key(body)
        if key:
            self._put_session(key, tier, committed, probs)

    def _maybe_evict(self) -> None:
        self._calls_since_evict += 1
        # Full sweep periodically OR when we exceed the cap.
        if (
            self._calls_since_evict < self._evict_every
            and len(self._sessions) <= self._max_sessions
        ):
            return
        self._calls_since_evict = 0
        cutoff = time.monotonic() - self._ttl
        before = len(self._sessions)
        self._sessions = {
            k: v for k, v in self._sessions.items() if v.last_seen > cutoff
        }
        # Still over cap after TTL sweep? Drop oldest by last_seen.
        if len(self._sessions) > self._max_sessions:
            sorted_items = sorted(
                self._sessions.items(), key=lambda kv: kv[1].last_seen, reverse=True
            )
            self._sessions = dict(sorted_items[: self._max_sessions])
        dropped = before - len(self._sessions)
        if dropped > 0:
            logger.debug(f"router session eviction: dropped {dropped}, kept {len(self._sessions)}")


# ──────────────────────────────────────────────────────────────────────────
# Asymmetric threshold logic (pure function, exposed for tests)
# ──────────────────────────────────────────────────────────────────────────

def apply_asymmetric_thresholds(current_tier: str, probs: dict[str, float]) -> str:
    """Decide whether to switch `current_tier` given calibrated probs.

    Rule: a target tier wins iff P(target) >= SWITCH_THRESHOLDS[(current, target)].
    If multiple targets cross, pick the HIGHEST tier (quality-first tiebreak).
    If none cross, stay on `current_tier`.
    """
    winners: list[str] = []
    for target in (TIER_FRONTIER, TIER_MIDDLE, TIER_MINIMAX):
        if target == current_tier:
            continue
        threshold = SWITCH_THRESHOLDS.get((current_tier, target))
        if threshold is None:
            continue
        if probs.get(target, 0.0) >= threshold:
            winners.append(target)
    if not winners:
        return current_tier
    return max(winners, key=lambda t: TIER_ORDER[t])


def tier_to_backend(tier: str) -> str:
    """Phase 2 mapping: 3-class tier → 2 backends (no middle-tier wiring yet).

    middle_tier currently routes through the same MiniMax backend as minimax_ok
    because we haven't provisioned a middle-tier model yet. The full 3-class
    probabilities still get logged in the stats reason field for Phase B,
    so when middle-tier backend lands the labels are already there to A/B test
    against.
    """
    if tier == TIER_FRONTIER:
        return "anthropic"
    return "minimax"
