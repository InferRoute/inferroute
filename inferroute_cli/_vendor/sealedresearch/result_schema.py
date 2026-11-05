"""The shape of what the engine may hand the front (v14, published, stdlib only).

WHY. search.run forwarded hits as the engine produced them, checking only that each had a "key". The engine is
closed code in its own process; a result is the one thing it writes that reaches a client. An extra field on a hit
("note": <someone else's query>) would have been sealed to the client and signed into result_sha256 like any other.
Every result now passes through these specs before anything is sealed or signed: known keys only, known types,
bounded lengths and counts. An unknown key is DROPPED; a known key of the wrong type or over its bound refuses the
whole result (search.RefusedPayload "searcher_failed"): a wrong shape is an engine defect to surface, not to coerce.

WHAT THIS DOES NOT DO. A field that is legitimately a string (a title, a held abstract) can carry any string of
that length. The schema bounds WHERE content can sit and HOW MUCH; the per-request engine process (engine_link)
is what leaves nothing from another request to put there.

SPEC FORMS (a spec is a tuple; the first element names the form):
    ("str", max_len)                a str of at most max_len characters
    ("hex", n)                      a lowercase hex str of exactly n characters
    ("int",) ("num",) ("bool",)     int (bool excluded), int or float (finite), bool
    ("opt", spec)                   None or spec
    ("list", spec, max_items)       a list of at most max_items, each spec
    ("dict", {key: spec, ...})      a dict with ALLOWLISTED keys: unknown keys dropped, present keys checked
    ("map", key_max_len, spec, max_items)   a dict with free str keys (bounded), values spec
    ("any_scalar", max_len)         None, bool, int, finite float, or a str of at most max_len (tunables)
    ("tunable", max_len, max_items) an any_scalar, or ONE level of {str key: any_scalar} (e.g. survey_legs.KIND_CAPS)
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict

# Bounds. Hits: MAX_K is 200 (search.py); a hit's text is the held title+abstract (<= 1500 chars in the index).
MAX_HITS = 200
MAX_KEY = 64
MAX_SHORT = 64
MAX_TITLE = 400
MAX_HIT_TEXT = 4096
MAX_DOC_TEXT = 65_536           # abstract + claim 1, or abstract + a truncated (14 000 char) description
MAX_UNION = 100                 # survey_run.UNION_TOP
MAX_FAMILY_KEYS = 64
MAX_SURVEY_LEGS = 16            # survey_legs.MAX_LEGS is 8; retries do not add entries, the bound is slack
MAX_LEG_TEXT = 200_000          # a leg's text is a slice of the disclosure (search.MAX_DISCLOSURE)
MAX_SCORES = 16
MAX_CPC = 64
MAX_OFFICES = 20
MAX_MARKS = 50
MAX_SOURCES = 16
MAX_STAGES = 16
MAX_TUNABLES = 32

_HEX = re.compile(r"^[0-9a-f]+$")


class SchemaError(ValueError):
    """The engine's result is not of the published shape (the message names the path, never the value)."""


def shape(value: Any, spec: tuple, path: str = "result") -> Any:
    """`value` reduced to `spec`: unknown dict keys dropped, everything else checked. Raises SchemaError."""
    form = spec[0]
    if form == "opt":
        return None if value is None else shape(value, spec[1], path)
    if form == "str":
        if not isinstance(value, str) or len(value) > spec[1]:
            raise SchemaError(f"{path}: not a str of at most {spec[1]} chars")
        return value
    if form == "hex":
        if not isinstance(value, str) or len(value) != spec[1] or not _HEX.match(value):
            raise SchemaError(f"{path}: not {spec[1]} lowercase hex chars")
        return value
    if form == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            raise SchemaError(f"{path}: not an int")
        return value
    if form == "num":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise SchemaError(f"{path}: not a finite number")
        return value
    if form == "bool":
        if not isinstance(value, bool):
            raise SchemaError(f"{path}: not a bool")
        return value
    if form == "list":
        if not isinstance(value, list) or len(value) > spec[2]:
            raise SchemaError(f"{path}: not a list of at most {spec[2]} items")
        return [shape(v, spec[1], f"{path}[{i}]") for i, v in enumerate(value)]
    if form == "dict":
        if not isinstance(value, dict):
            raise SchemaError(f"{path}: not an object")
        return {k: shape(value[k], s, f"{path}.{k}") for k, s in spec[1].items() if k in value}
    if form == "map":
        if not isinstance(value, dict) or len(value) > spec[3]:
            raise SchemaError(f"{path}: not an object of at most {spec[3]} entries")
        out = {}
        for k, v in value.items():
            ks = str(k) if isinstance(k, int) and not isinstance(k, bool) else k   # JSON turns int keys into str
            if not isinstance(ks, str) or len(ks) > spec[1]:
                raise SchemaError(f"{path}: a key is not a str of at most {spec[1]} chars")
            out[ks] = shape(v, spec[2], f"{path}.{ks}")
        return out
    if form == "any_scalar":
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if isinstance(value, float) and not math.isfinite(value):
                raise SchemaError(f"{path}: not finite")
            return value
        if isinstance(value, str) and len(value) <= spec[1]:
            return value
        raise SchemaError(f"{path}: not a scalar of at most {spec[1]} chars")
    if form == "tunable":
        # v14 rc7 (4 Nov 2026): survey_legs.TUNABLES carries KIND_CAPS, a small dict of per-kind caps; a scalar-only
        # spec refused EVERY real survey as searcher_failed on the box. One level of scalars, bounded; no deeper nesting.
        if isinstance(value, dict):
            return shape(value, ("map", spec[1], ("any_scalar", spec[1]), spec[2]), path)
        return shape(value, ("any_scalar", spec[1]), path)
    raise SchemaError(f"{path}: unknown spec form {form!r}")


# ── the specs ────────────────────────────────────────────────────────────────────────────────────────────────────

HIT = ("dict", {
    "key": ("str", MAX_KEY), "score": ("num",),
    "scores": ("map", MAX_SHORT, ("num",), MAX_SCORES),
    "legs": ("list", ("str", MAX_SHORT), 8), "source": ("str", MAX_SHORT),
    "year": ("opt", ("int",)), "date_known": ("bool",),
    "title": ("str", MAX_TITLE), "text": ("str", MAX_HIT_TEXT),
})

_FILTER_INTS = {"candidates_considered": ("int",)}
SEARCH = ("dict", {
    "hits": ("list", HIT, MAX_HITS),
    "legs": ("map", MAX_SHORT, ("int",), 8),
    "candidates": ("int",),
    "cpc": ("list", ("str", MAX_SHORT), MAX_CPC),
    "calibration": ("opt", ("map", MAX_SHORT, ("any_scalar", MAX_SHORT), 32)),
    "paper_coverage": ("opt", ("map", MAX_SHORT, ("any_scalar", MAX_SHORT), 32)),
    "cutoff_applied": ("opt", ("dict", {"cutoff_date": ("int",), "removed_by_cutoff": ("int",), **_FILTER_INTS})),
    "from_date_applied": ("opt", ("dict", {"from_date": ("int",), "removed_by_from_date": ("int",), **_FILTER_INTS})),
    "offices_applied": ("opt", ("dict", {"offices": ("list", ("str", MAX_SHORT), MAX_OFFICES),
                                         "removed_by_offices": ("int",), **_FILTER_INTS})),
    "hits_by_source": ("opt", ("map", MAX_SHORT, ("int",), MAX_SOURCES)),
    "text_coverage": ("opt", ("dict", {"retrieval_text": ("str", MAX_SHORT), "hits_n": ("int",), "claim_1_held": ("int",),
                                       "claim_1_missing": ("int",), "description": ("str", MAX_SHORT)})),
    "stages_applied": ("opt", ("map", MAX_SHORT, ("map", MAX_SHORT, ("int",), MAX_STAGES), MAX_STAGES)),
    "marks_applied": ("opt", ("map", MAX_SHORT, ("int",), MAX_STAGES)),
    "marks_unresolved": ("opt", ("list", ("str", MAX_KEY), MAX_MARKS)),
})

DOCUMENT = ("dict", {
    "key": ("str", MAX_KEY),
    "text": ("str", MAX_DOC_TEXT),
    "coverage": ("opt", ("map", MAX_SHORT, ("str", MAX_SHORT), 8)),
    "publication_date": ("opt", ("int",)),
    "country": ("opt", ("str", MAX_SHORT)),
})

_LEG_FIELDS = {
    "kind": ("str", MAX_SHORT), "sha256": ("hex", 64), "anchor_level": ("int",), "retried": ("bool",),
    "overlap": ("opt", ("num",)), "status": ("str", MAX_SHORT), "error": ("opt", ("str", MAX_SHORT)),
    "n_hits": ("int",), "n_families": ("int",),
}
SURVEY_LEG = ("dict", {**_LEG_FIELDS, "text": ("str", MAX_LEG_TEXT)})
MANIFEST_LEG = ("dict", _LEG_FIELDS)
UNION_FAMILY = ("dict", {
    "family": ("str", MAX_KEY), "keys": ("list", ("str", MAX_KEY), MAX_FAMILY_KEYS), "score": ("num",),
    "found_by": ("int",), "best_rank": ("int",), "per_leg": ("map", 8, ("int",), MAX_SURVEY_LEGS),
})
MANIFEST = ("dict", {
    "plan_sha256": ("hex", 64), "planned_legs": ("int",), "effective_legs": ("int",),
    "legs": ("list", MANIFEST_LEG, MAX_SURVEY_LEGS),
    "rrf_k0": ("int",), "leg_k": ("int",), "union_top": ("int",), "union_families": ("int",),
    "family_collapse": ("str", MAX_SHORT), "tau_gated": ("bool",), "tau": ("opt", ("num",)), "press_retries": ("int",),
    "scope": ("dict", {"cutoff_date": ("opt", ("int",)), "from_date": ("opt", ("int",)),
                       "offices": ("opt", ("list", ("str", MAX_SHORT), MAX_OFFICES))}),
    "tunables": ("map", MAX_SHORT, ("tunable", MAX_SHORT, MAX_TUNABLES), MAX_TUNABLES),
})
SURVEY = ("dict", {
    "union": ("list", UNION_FAMILY, MAX_UNION),
    "legs": ("list", SURVEY_LEG, MAX_SURVEY_LEGS),
    "manifest": MANIFEST,
})


def clean_search(res: Any) -> Dict[str, Any]:
    return shape(res, SEARCH)


def clean_document(res: Any) -> Dict[str, Any]:
    return shape(res, DOCUMENT)


def clean_survey(res: Any) -> Dict[str, Any]:
    return shape(res, SURVEY)
