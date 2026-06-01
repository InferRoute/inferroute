"""In-process routing-decision + compression-savings stats.

Lightweight, thread-safe-enough for the daemon's needs: every handled request
increments a counter for (route, reason) and, when tool-output compression is
applied, accumulates token savings. Exposed at GET /stats on the daemon.

Routing counters are ephemeral (reset on restart) — good enough for dogfooding
visibility. Compression-savings aggregates are persisted to a small JSON
(~/.config/inferroute/compression_stats.json) so the "tokens saved" number
survives daemon restarts, which is the headline metric users want to track.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock


def _stats_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "inferroute" / "compression_stats.json"


@dataclass
class _Stats:
    started_at: float = field(default_factory=time.time)
    total: int = 0
    # (route, reason) -> count.  Route ∈ {anthropic_fast,anthropic_server,minimax,kimi,glm,error}
    # (kimi/glm kept for backwards-compat with pre-2026-05-28 deployments; new traffic uses minimax)
    by_route: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # Last 50 decisions (route, reason, ts, model_in, files, ratio)
    recent: list[dict] = field(default_factory=list)

    # --- Compression savings (persisted across restarts) ---
    comp_requests: int = 0          # requests where compression was applied (saved>0)
    comp_tokens_before: int = 0     # cumulative pre-compression tokens (applied reqs)
    comp_tokens_after: int = 0      # cumulative post-compression tokens (applied reqs)
    comp_tokens_saved: int = 0      # cumulative tokens removed
    comp_saved_by_route: dict[str, int] = field(default_factory=lambda: defaultdict(int))


_LOCK = Lock()
_STATS = _Stats()
_RECENT_MAX = 50


def record(
    route: str,
    reason: str,
    *,
    model_in: str = "",
    file_count: int = 0,
    context_ratio: float = 0.0,
    tokens_before: int = 0,
    tokens_after: int = 0,
    tokens_saved: int = 0,
) -> None:
    """Record one routing decision and any tool-output compression savings.

    Compression savings are counted only when ``tokens_saved > 0`` (i.e. the
    compressed body was actually forwarded). Aggregates are persisted on each
    request that yields savings.
    """
    with _LOCK:
        _STATS.total += 1
        _STATS.by_route[(route, reason)] += 1
        _STATS.recent.append({
            "ts": time.time(),
            "route": route,
            "reason": reason,
            "model_in": model_in,
            "files": file_count,
            "context_ratio": round(context_ratio, 3),
            "tokens_saved": tokens_saved,
        })
        if len(_STATS.recent) > _RECENT_MAX:
            del _STATS.recent[: len(_STATS.recent) - _RECENT_MAX]

        if tokens_saved > 0:
            _STATS.comp_requests += 1
            _STATS.comp_tokens_before += tokens_before
            _STATS.comp_tokens_after += tokens_after
            _STATS.comp_tokens_saved += tokens_saved
            _STATS.comp_saved_by_route[route] += tokens_saved
            _persist_compression_locked()


def _compression_snapshot_locked() -> dict:
    before = _STATS.comp_tokens_before
    return {
        "requests_compressed": _STATS.comp_requests,
        "tokens_before": before,
        "tokens_after": _STATS.comp_tokens_after,
        "tokens_saved": _STATS.comp_tokens_saved,
        "reduction_ratio": round(_STATS.comp_tokens_saved / before, 4) if before else 0.0,
        "saved_by_route": dict(_STATS.comp_saved_by_route),
    }


def snapshot() -> dict:
    """Return current stats as a JSON-serializable dict."""
    with _LOCK:
        rollup: dict[str, dict] = {}
        for (route, reason), n in _STATS.by_route.items():
            rollup.setdefault(route, {"total": 0, "by_reason": {}})
            rollup[route]["total"] += n
            rollup[route]["by_reason"][reason] = n

        uptime = time.time() - _STATS.started_at
        return {
            "uptime_seconds": round(uptime, 1),
            "total_requests": _STATS.total,
            "rate_per_min": round(60 * _STATS.total / uptime, 2) if uptime else 0.0,
            "by_route": rollup,
            "compression": _compression_snapshot_locked(),
            "recent": list(_STATS.recent[-20:]),
        }


# -----------------------------------------------------------------------------
# Persistence (compression aggregates only — routing counters stay ephemeral)
# -----------------------------------------------------------------------------

def _persist_compression_locked() -> None:
    """Atomically write compression aggregates to disk. Best-effort; never raises."""
    try:
        path = _stats_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "comp_requests": _STATS.comp_requests,
            "comp_tokens_before": _STATS.comp_tokens_before,
            "comp_tokens_after": _STATS.comp_tokens_after,
            "comp_tokens_saved": _STATS.comp_tokens_saved,
            "comp_saved_by_route": dict(_STATS.comp_saved_by_route),
        }
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".compstats-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except Exception:
        pass  # persistence is best-effort; in-memory counters remain authoritative


def load_persisted() -> None:
    """Load persisted compression aggregates at daemon startup. Best-effort."""
    try:
        path = _stats_path()
        if not path.exists():
            return
        data = json.loads(path.read_text())
        with _LOCK:
            _STATS.comp_requests = int(data.get("comp_requests", 0))
            _STATS.comp_tokens_before = int(data.get("comp_tokens_before", 0))
            _STATS.comp_tokens_after = int(data.get("comp_tokens_after", 0))
            _STATS.comp_tokens_saved = int(data.get("comp_tokens_saved", 0))
            _STATS.comp_saved_by_route = defaultdict(
                int, {str(k): int(v) for k, v in (data.get("comp_saved_by_route") or {}).items()}
            )
    except Exception:
        pass


def reset() -> None:
    """Wipe all counters (used by tests; can be called by /stats?reset=1).

    Also clears persisted compression aggregates so a reset is durable.
    """
    with _LOCK:
        _STATS.started_at = time.time()
        _STATS.total = 0
        _STATS.by_route.clear()
        _STATS.recent.clear()
        _STATS.comp_requests = 0
        _STATS.comp_tokens_before = 0
        _STATS.comp_tokens_after = 0
        _STATS.comp_tokens_saved = 0
        _STATS.comp_saved_by_route.clear()
        _persist_compression_locked()
