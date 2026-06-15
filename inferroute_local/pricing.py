"""Read-time cost ESTIMATION over the recorded token spine.

We never persist a self-computed cost into the corpus — that would solidify a
false-precision number that drifts as prices change. Instead cost is derived ON
DEMAND (`ir data cost`) from the stored token counts against a DATED price table
selected by the turn's timestamp, and every derived figure is flagged
``is_estimate=True``. Correct a rate and re-run; there is no historical data to
migrate. Real (non-estimated) cost for ROUTED turns comes from the daemon's
server ``usage.cost`` — this module is the fallback for NATIVE Claude turns.

Rates are USD per 1,000,000 tokens. Tables are DATED: a turn is priced with the
table whose ``effective_date`` is the latest one on or before the turn's date.

  ⚠ These rates are PLACEHOLDERS / estimates — verify against
    https://www.anthropic.com/pricing. When prices change, APPEND a new dated
    table; never edit an old one (that would silently restate history).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# Each model entry (USD / 1M tokens):
#   input, output, cache_read (~0.1× input), cache_write_5m (~1.25×),
#   cache_write_1h (~2×). Matched by PREFIX against the served model id.
_TABLES = [
    {
        "version": "anthropic-claude4 (PLACEHOLDER 2026-06 — verify)",
        "effective_date": "2025-01-01",
        "currency": "USD",
        "models": {
            "claude-opus":   {"input": 15.0, "output": 75.0, "cache_read": 1.50, "cache_write_5m": 18.75, "cache_write_1h": 30.0},
            "claude-sonnet": {"input": 3.0,  "output": 15.0, "cache_read": 0.30, "cache_write_5m": 3.75,  "cache_write_1h": 6.0},
            "claude-haiku":  {"input": 0.80, "output": 4.0,  "cache_read": 0.08, "cache_write_5m": 1.00,  "cache_write_1h": 1.6},
        },
    },
]


def _turn_date(turn: dict) -> str:
    iso = turn.get("iso")
    if isinstance(iso, str) and len(iso) >= 10:
        return iso[:10]
    ts = turn.get("ts")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    return "9999-12-31"  # unknown date → newest table


def _table_for(turn: dict) -> dict:
    d = _turn_date(turn)
    eligible = [t for t in _TABLES if t["effective_date"] <= d]
    return max(eligible or _TABLES, key=lambda t: t["effective_date"])


def _match_rates(model: str, models: dict) -> Optional[dict]:
    m = (model or "").lower()
    for prefix, rates in models.items():
        if m.startswith(prefix):
            return rates
    return None


def estimate_cost(turn: dict) -> Optional[dict]:
    """Estimate one turn's cost from its recorded token counts. Returns
    {cost_usd, is_estimate, price_table, currency} or None when the served model
    isn't in the table (e.g. a routed open-weights model — those get real cost
    from the server, not this estimator)."""
    table = _table_for(turn)
    rates = _match_rates(turn.get("served_model", ""), table["models"])
    if not rates:
        return None

    ti = turn.get("tokens_in") or 0
    to = turn.get("tokens_out") or 0
    cr = turn.get("cache_read_tokens") or 0
    e1 = turn.get("cache_ephemeral_1h") or 0
    e5 = turn.get("cache_ephemeral_5m") or 0
    cc = turn.get("cache_creation_tokens") or 0
    if not (e1 or e5) and cc:  # no ephemeral split recorded → treat as 5m writes
        e5 = cc

    usd = (
        ti * rates["input"]
        + to * rates["output"]
        + cr * rates["cache_read"]
        + e5 * rates["cache_write_5m"]
        + e1 * rates["cache_write_1h"]
    ) / 1_000_000.0
    return {
        "cost_usd": round(usd, 6),
        "is_estimate": True,
        "price_table": table["version"],
        "currency": table["currency"],
    }
