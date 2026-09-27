"""A firmware floor the operator can actually pin, and one that cannot be decoration.

The verifier's blocker text tells an operator to put min_tcb in the published reference. Until this,
`reference build` gave them no way to do it. These pin the parsing and, more importantly, the refusal:
a floor of all zeros passes whatever it is shown while reading like a check that held.
"""
import pytest

from inferroute_cli.reference import ReferenceError, build, parse_min_tcb

GOOD = {"policy_sha256": "a" * 64, "index_manifest_sha256": "b" * 64, "model_manifest_sha256": "c" * 64}


def test_parses_one_product():
    assert parse_min_tcb(["Genoa=snpSPL:23,ucodeSPL:84"]) == {"Genoa": {"snpSPL": 23, "ucodeSPL": 84}}


def test_parses_several_products():
    got = parse_min_tcb(["Genoa=snpSPL:23", "Milan=snpSPL:8"])
    assert got == {"Genoa": {"snpSPL": 23}, "Milan": {"snpSPL": 8}}


@pytest.mark.parametrize("spec", ["Genoa", "=snpSPL:23", "Genoa=", "Genoa=snpSPL", "Genoa=snpSPL:x"])
def test_malformed_specs_refuse(spec):
    with pytest.raises(ReferenceError):
        parse_min_tcb([spec])


def test_negative_level_refuses():
    with pytest.raises(ReferenceError):
        parse_min_tcb(["Genoa=snpSPL:-1"])


def test_all_zero_floor_refuses():
    """INVERSION: the decoration case must fail, or the guard is itself decoration."""
    with pytest.raises(ReferenceError) as exc:
        parse_min_tcb(["Genoa=snpSPL:0,ucodeSPL:0"])
    assert "zero" in str(exc.value).lower()


def test_a_floor_with_one_real_level_is_accepted():
    """Not every level must be non-zero -- teeSPL is legitimately 0 on Genoa today."""
    assert parse_min_tcb(["Genoa=snpSPL:23,teeSPL:0"]) == {"Genoa": {"snpSPL": 23, "teeSPL": 0}}


def test_build_emits_the_floor_and_source():
    ref = build(dict(GOOD), min_tcb={"Genoa": {"snpSPL": 23}}, image_source="https://example.invalid/src")
    assert ref["min_tcb"] == {"Genoa": {"snpSPL": 23}}
    assert ref["image_source"] == "https://example.invalid/src"


def test_extending_for_one_product_keeps_another_products_floor():
    first = build(dict(GOOD), min_tcb={"Genoa": {"snpSPL": 23}})
    second = build(dict(GOOD), merge=first, min_tcb={"Milan": {"snpSPL": 8}})
    assert second["min_tcb"] == {"Genoa": {"snpSPL": 23}, "Milan": {"snpSPL": 8}}


def test_build_without_the_flags_adds_neither_field():
    ref = build(dict(GOOD))
    assert "min_tcb" not in ref and "image_source" not in ref
