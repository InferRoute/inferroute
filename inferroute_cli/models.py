"""Friendly name → canonical inferroute model ID.

Used by `ir --model NAME` (and by the interactive `ir choose` picker) to let
users type `minimax` instead of `MiniMax-M2.7`. The short name is the user-
facing contract; the canonical model_id can change without breaking muscle
memory.

These are NOT subcommands. The supported forms are:
    ir                              # interactive picker (ir choose)
    ir --model minimax              # short name → translated
    ir --model MiniMax-M2.7         # canonical id passes through
    ir --model claude-opus-4-8      # any other model id passes through too

There is no auto-route. The user picks a model per session; the local daemon
never decides. (Cloud-side fallbacks still apply upstream.)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    """Published USD price per 1,000,000 tokens.

    Three buckets, matching what the dashboard/pricing page surface:
      * input      — fresh prompt tokens
      * cache_read — tokens served from a prior prompt cache (much cheaper)
      * output     — generated tokens

    These are display values for the `ir choose` picker; the authoritative
    billing rates live server-side. Keep them in sync with
    inferroute-site/src/lib/constants.ts (CURRENT_RATE).
    """
    input: float
    cache_read: float
    output: float


@dataclass(frozen=True)
class ModelAlias:
    short: str           # what the user types as the --model value
    model_id: str        # what we pass to claude --model on the wire
    label: str           # one-line description shown by `ir help` / `ir choose`
    tier: str            # "fast" | "balanced" | "smart"
    price: Price | None = None  # $/1M tokens; None = priced on your own plan

    @property
    def help_line(self) -> str:
        # Kept for `ir choose` button labels; `ir help` formats its own table.
        return f"  ir --model {self.short:<8} {self.label}"


# Order matters — `ir choose` shows them top-to-bottom.
#
# Prices are USD per 1M tokens (input / cache_read / output). The MiniMax M2.7,
# Kimi K2.6 and GLM-5.1 rows mirror inferroute-site CURRENT_RATE exactly. The
# newer/alternate models (M3, Kimi K2.5, DeepSeek V3.2) aren't on the public
# pricing page yet — their numbers below are provisional placeholders and should
# be reconciled once published.
# BUNDLED FALLBACK ONLY. The live list + prices come from the backend catalog
# (catalog.py → GET /pricing), refreshed at launch. These are used when the backend
# is unreachable and there's no cache yet (first run / offline). Order = picker order.
# Versioned shorts only (no bare kimi/glm/minimax — those are hidden back-compat
# aliases, see _HIDDEN_ALIASES). model_id is the CLEAN user-facing id (no -TEE /
# provider prefix); the proxy normalizes it to the Chutes "…-TEE" id for routing.
_BUNDLED: list[ModelAlias] = [
    ModelAlias(short="minimax-m2.7", model_id="MiniMax-M2.7",
               label="MiniMax M2.7 — cheaper/smaller direct-sub model", tier="fast",
               price=Price(input=0.18, cache_read=0.036, output=0.90)),
    ModelAlias(short="minimax-m3", model_id="MiniMax-M3",
               label="MiniMax M3 — newer/stronger flagship", tier="balanced",
               price=Price(input=0.30, cache_read=0.060, output=1.50)),
    ModelAlias(short="kimi-k2.6", model_id="Kimi-K2.6",
               label="Kimi K2.6 — strong reasoning, thinks before acting", tier="balanced",
               price=Price(input=0.49, cache_read=0.099, output=2.40)),
    ModelAlias(short="glm-5.1", model_id="GLM-5.1",
               label="GLM-5.1 — solid general-purpose alternative", tier="balanced",
               price=Price(input=0.69, cache_read=0.139, output=1.80)),
    ModelAlias(short="kimi-k2.5", model_id="Kimi-K2.5",
               label="Kimi K2.5 — prior-gen Kimi, alternate when K2.6 is busy", tier="balanced",
               price=Price(input=0.29, cache_read=0.059, output=1.40)),
    ModelAlias(short="deepseek-v3.2", model_id="DeepSeek-V3.2",
               label="DeepSeek V3.2 — strong coding/reasoning, separate capacity", tier="balanced",
               price=Price(input=0.69, cache_read=0.139, output=0.69)),
]

# Bare versionless shorts → versioned canonical. Kept ONLY so existing muscle memory
# and scripts (`ir --model kimi`) keep working; never displayed in the picker/help
# (those show only the versioned shorts). Resolved silently in get().
_HIDDEN_ALIASES = {
    "minimax": "minimax-m2.7",
    "kimi": "kimi-k2.6",
    "glm": "glm-5.1",
    "deepseek": "deepseek-v3.2",
    "kimi-2.5": "kimi-k2.5",  # prior short form
}


_RESOLVED: list[ModelAlias] | None = None  # memoized per process


def _from_catalog() -> list[ModelAlias] | None:
    """ModelAliases built from the backend catalog cache (catalog.py), or None.

    The picker's display Price uses the STANDARD (on-demand) lane — the default a
    manual `ir` session is billed at. (The economy lane is the discounted deferred
    price; we don't want to understate the headline number.)
    """
    from . import catalog
    rows = catalog.load()
    if not rows:
        return None
    out: list[ModelAlias] = []
    for m in rows:
        try:
            std = m.get("standard") or {}
            price = (Price(input=std["input"], cache_read=std["cached"], output=std["output"])
                     if std else None)
            out.append(ModelAlias(short=m["short"], model_id=m["model_id"],
                                   label=m["label"], tier=m.get("tier", "balanced"),
                                   price=price))
        except (KeyError, TypeError):
            continue
    return out or None


def all_aliases() -> list[ModelAlias]:
    """The offered models — from the backend catalog when available, else bundled."""
    global _RESOLVED
    if _RESOLVED is None:
        _RESOLVED = _from_catalog() or list(_BUNDLED)
    return list(_RESOLVED)


def get(short: str) -> ModelAlias | None:
    short = short.lower().strip()
    short = _HIDDEN_ALIASES.get(short, short)  # bare kimi/glm/minimax → versioned
    for a in all_aliases():
        if a.short == short:
            return a
    return None


def short_for_model_id(model_id: str) -> str | None:
    """Reverse of `_resolve_model_name`: canonical model_id → friendly short.

    Returns the FIRST alias whose model_id matches (catalog/bundled order), so
    `MiniMax-M2.7` maps back to bare `minimax`. None for ids we don't alias
    (callers fall back to the id verbatim — a valid `ir --model <id>` value).
    """
    if not model_id:
        return None
    for a in all_aliases():
        if a.model_id == model_id:
            return a.short
    return None


def by_tier(tier: str) -> list[ModelAlias]:
    return [a for a in all_aliases() if a.tier == tier]


# Bundled `ir choose` picker subset (offline / no cache). Mirrors the catalog rows
# that carry a `picker` block. choose.py maps `accent` → its rich color and appends
# the native-Anthropic escape hatch locally.
_BUNDLED_PICKER = [
    {"short": "minimax-m2.7", "name": "MiniMax M2.7", "desc": "get something usable — cheap, fast iteration", "badge": "FAST",     "accent": "amber"},
    {"short": "minimax-m3",   "name": "MiniMax M3",   "desc": "newer MiniMax — multimodal, 1M context, fast", "badge": "FLAGSHIP", "accent": "blue"},
    {"short": "kimi-k2.6",    "name": "Kimi K2.6",    "desc": "strong reasoning, thinks before acting",       "badge": "BALANCED", "accent": "green"},
    {"short": "glm-5.1",      "name": "GLM-5.1",      "desc": "solid general-purpose alternative",            "badge": "BALANCED", "accent": "green"},
]


def picker_options() -> list[dict]:
    """The `ir choose` options — from the backend catalog (rows carrying a `picker`
    block, in catalog order) when available, else the bundled subset. Each dict:
    {short, name, desc, badge, accent}. Excludes the native escape hatch, which
    choose.py appends locally."""
    from . import catalog
    rows = catalog.load()
    if rows:
        out = [
            {"short": m["short"], "name": p.get("name", m["short"]),
             "desc": p.get("desc", ""), "badge": p.get("badge", ""),
             "accent": p.get("accent", "green")}
            for m in rows if (p := m.get("picker"))
        ]
        if out:
            return out
    return [dict(o) for o in _BUNDLED_PICKER]
