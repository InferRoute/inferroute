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


# build() refuses a reference missing the identity hashes, correctly — so supply them.
_VALUES = {"policy_sha256": "a" * 64, "index_manifest_sha256": "b" * 64, "model_manifest_sha256": "c" * 64}


def _build(**kw):
    from inferroute_cli import reference as R
    return R.build(dict(_VALUES), **kw)


def test_a_windowed_floor_is_emitted_when_a_window_is_given():
    """Schema agreed with the sealed-research session: valid_from required and inclusive, valid_to
    absent/null for an open window, retired distinct from supersession."""
    floor = {"Genoa": {"snpSPL": 23, "ucodeSPL": 84, "blSPL": 10}}
    ref = _build(min_tcb=floor, valid_from="2026-09-28T00:00:28Z")
    assert isinstance(ref["min_tcb"], list), "a windowed floor must be a list, not a flat mapping"
    e = ref["min_tcb"][0]
    assert e["value"] == floor and e["valid_from"] == "2026-09-28T00:00:28Z"
    assert e["retired"] is False, "supersession is not revocation; retired must not default true"


def test_back_dating_a_floor_is_REFUSED_without_a_stated_reason():
    """The whole temptation in one test. Back-dating valid_from is the ONLY way to turn an
    already-delivered record's firmware row from SKIP to PASS, and it would assert a threshold that
    did not exist when the search ran. Measured 2026-09-28: all 70 searches in the delivered pack
    predate the signing moment, so this is not hypothetical."""
    import pytest
    floor = {"Genoa": {"snpSPL": 23}}
    with pytest.raises(ValueError) as e:
        _build(merge={"published_at": "2026-09-28T00:00:28Z"},
               min_tcb=floor, valid_from="2026-09-20T00:00:00Z")
    assert "back-date" in str(e.value).lower()


def test_back_dating_is_allowed_when_stated_and_the_reason_is_SIGNED_IN():
    """The escape hatch must leave a trace in the document the client verifies, not only in a shell
    history. A reason that is not in the signed reference is not a reason anyone can audit."""
    floor = {"Genoa": {"snpSPL": 23}}
    ref = _build(merge={"published_at": "2026-09-28T00:00:28Z"}, min_tcb=floor,
                 valid_from="2026-09-20T00:00:00Z",
                 backdate_reason="floor took effect at the 09-20 host rollout")
    assert ref["min_tcb"][0]["backdated_because"] == "floor took effect at the 09-20 host rollout"


def test_a_legacy_flat_floor_is_not_handed_a_window_retroactively():
    """A flat floor's applicability was never established — which is exactly why the verifier SKIPs
    it. Inventing a start date for it now would assert what this signature cannot support."""
    ref = _build(merge={"min_tcb": {"Genoa": {"snpSPL": 1}}, "published_at": "2026-09-01T00:00:00Z"},
                 min_tcb={"Genoa": {"snpSPL": 23}}, valid_from="2026-09-28T00:00:28Z")
    assert len(ref["min_tcb"]) == 1, "the legacy flat floor must be dropped, not silently windowed"
    assert ref["min_tcb"][0]["value"] == {"Genoa": {"snpSPL": 23}}
