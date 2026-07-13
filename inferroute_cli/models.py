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
from pathlib import Path


@dataclass(frozen=True)
class Price:
    """USD price per 1,000,000 tokens (input / cache_read / output), as surfaced by
    the picker. These are the authoritative rates from the backend catalog — this
    module no longer carries its own price table."""
    input: float
    cache_read: float
    output: float


@dataclass(frozen=True)
class ModelAlias:
    short: str           # CANONICAL id — what the CLI sends + /v1/models advertises
    model_id: str        # Title-case display spelling (back-compat, still resolves)
    label: str           # one-line description shown by `ir help` / `ir choose`
    tier: str            # "fast" | "balanced" | "smart"
    price: Price | None = None  # $/1M tokens; None = priced on your own plan
    aliases: tuple = ()  # bare/family shorts that also resolve here (e.g. "kimi")
    ref_key: str = ""    # backend key (e.g. moonshotai/Kimi-K2.6-TEE) — internal,
                         # used only to reverse-map a served/persisted backend id
                         # back to the canonical short for display.

    @property
    def help_line(self) -> str:
        # Kept for `ir choose` button labels; `ir help` formats its own table.
        return f"  ir --model {self.short:<14} {self.label}"


# This module holds NO model data of its own — list, prices, picker metadata and
# bare-name aliases ALL come from the backend catalog (catalog.py → GET /pricing),
# cached locally and refreshed at launch. The only offline fallback is a GENERATED
# snapshot of that same catalog, committed as catalog_bundled.json (written by the
# proxy's gen_pricing_card.py), so nothing here drifts from the backend.

_RESOLVED: list[ModelAlias] | None = None  # memoized per process


def _bundled_rows() -> list[dict] | None:
    """The generated offline catalog snapshot shipped in the package, or None."""
    import json
    try:
        rows = json.loads((Path(__file__).parent / "catalog_bundled.json").read_text()).get("models")
        return rows if isinstance(rows, list) and rows else None
    except Exception:
        return None


def _rows() -> list[dict]:
    """Catalog rows: the user's fresh cache (backend) if present, else the bundled
    snapshot. Empty only if both are missing (shouldn't happen — snapshot ships)."""
    from . import catalog
    return catalog.load() or _bundled_rows() or []


def _to_alias(m: dict) -> ModelAlias:
    """Build a ModelAlias from a catalog row. Display Price = STANDARD (on-demand)
    lane — what a manual `ir` session bills at (economy is the deferred discount)."""
    std = m.get("standard") or {}
    price = (Price(input=std["input"], cache_read=std["cached"], output=std["output"])
             if std else None)
    return ModelAlias(short=m["short"], model_id=m["model_id"],
                      label=m.get("label", m["short"]), tier=m.get("tier", "balanced"),
                      price=price, aliases=tuple(m.get("aliases") or ()),
                      ref_key=m.get("_ref_key", "") or "")


def all_aliases() -> list[ModelAlias]:
    """The offered models (versioned shorts), sourced from the catalog/snapshot."""
    global _RESOLVED
    if _RESOLVED is None:
        out: list[ModelAlias] = []
        for m in _rows():
            try:
                out.append(_to_alias(m))
            except (KeyError, TypeError):
                continue
        _RESOLVED = out
    return list(_RESOLVED)


def get(short: str) -> ModelAlias | None:
    """Resolve a short — or any of its catalog-declared aliases (e.g. bare `kimi`
    → kimi-k2.6) — to its ModelAlias."""
    short = short.lower().strip()
    for a in all_aliases():
        if a.short == short or short in a.aliases:
            return a
    return None


def short_for_model_id(model_id: str) -> str | None:
    """Any known spelling — canonical short, Title-case model_id, or family alias,
    case-insensitively — → the canonical friendly short. Used for status-line /
    resume DISPLAY, so it must recognise whatever form was persisted (new clients
    persist the short; older ones the model_id). None for ids we don't alias
    (callers fall back to the id verbatim)."""
    if not model_id:
        return None
    a = get(model_id)  # matches short + family aliases, case-insensitive
    if a is not None:
        return a.short
    ml = model_id.strip().lower()
    for a in all_aliases():
        # Title-case model_id OR the internal backend key → canonical short, so a
        # served/persisted backend id (e.g. moonshotai/Kimi-K2.6-TEE) never leaks
        # into the status line (naming-standard invariant: backend keys not user-facing).
        if a.model_id.lower() == ml or a.ref_key.lower() == ml:
            return a.short
    return None


def by_tier(tier: str) -> list[ModelAlias]:
    return [a for a in all_aliases() if a.tier == tier]


def picker_options() -> list[dict]:
    """The `ir choose` options — catalog rows carrying a `picker` block, sorted
    cheapest-first by standard input price. Each: {short, name, desc, badge, accent}.
    Excludes the native escape hatch (choose.py appends it locally)."""
    out = []
    for m in _rows():
        p = m.get("picker")
        if p:
            out.append({"short": m["short"], "name": p.get("name", m["short"]),
                        "desc": p.get("desc", ""), "badge": p.get("badge", ""),
                        "accent": p.get("accent", "green"),
                        "_input": m.get("standard", {}).get("input", 0)})
    out.sort(key=lambda x: x["_input"])
    for row in out:
        row.pop("_input")
    return out
