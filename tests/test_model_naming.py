"""Enforces the client half of the Model Naming Standard (docs/model-naming-standard.md).

The CLI must emit the CANONICAL lowercase `short` — the same string /v1/models
advertises as a model's `id` — for every known spelling, and reverse-map any
served/persisted spelling (incl. the internal backend key) back to that short
for display. These tests keep it that way.
"""
from inferroute_cli import models
from inferroute_cli.main import _resolve_model_name


def _rows():
    rows = models._rows()
    assert rows, "bundled catalog must ship"
    return rows


def test_resolve_emits_canonical_short_for_every_spelling():
    for m in _rows():
        short = m["short"]
        # canonical short, Title-case model_id, and each family alias all → short.
        for spelling in [short, m.get("model_id"), *(m.get("aliases") or [])]:
            if not spelling:
                continue
            assert _resolve_model_name(spelling) == short, f"{spelling} → should be {short}"


def test_resolve_is_case_insensitive():
    for m in _rows():
        short = m["short"]
        for variant in [short.upper(), short.title(), (m.get("model_id") or "").upper()]:
            if variant:
                assert _resolve_model_name(variant) == short, variant


def test_unknown_model_passes_through_verbatim():
    assert _resolve_model_name("claude-opus-4-8") == "claude-opus-4-8"
    assert _resolve_model_name("auto") == "auto"  # router alias, cloud resolves


def test_backend_key_reverse_maps_to_canonical_short():
    # A served/persisted backend key must never leak into display — it maps back
    # to the canonical short (naming-standard invariant #1).
    for m in _rows():
        ref = m.get("_ref_key")
        if ref and "/" in ref:  # only the true backend keys (provider-prefixed)
            assert models.short_for_model_id(ref) == m["short"], ref


def test_shorts_are_lowercase_family_version():
    for m in _rows():
        assert m["short"] == m["short"].lower(), m["short"]
        assert "/" not in m["short"] and "-TEE" not in m["short"], m["short"]
