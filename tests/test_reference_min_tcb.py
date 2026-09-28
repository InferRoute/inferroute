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


# ── a later floor must never be applied retroactively ─────────────────────────────────────────────
# Found by the sealed-research session reviewing my port (b144c32): I ported the time-scoped
# resolver but left two call sites using the FLATTENED all-window maximum. Proven before fixing:
# with windows of snpSPL 20 (closed) and 25 (current), a record from the old window reporting 20 was
# checked against 25 and refused. Valid old records rejected; the opposite of what windowing is for.

_TWO_WINDOWS = {"min_tcb": [
    {"value": {"Milan": {"snpSPL": 20}}, "valid_from": "2026-01-01T00:00:00Z",
     "valid_to": "2026-06-01T00:00:00Z", "retired": False},
    {"value": {"Milan": {"snpSPL": 25}}, "valid_from": "2026-06-01T00:00:00Z",
     "valid_to": None, "retired": False},
]}


def _vr():
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[1] / "inferroute_cli" / "pi_attested" / "verify_record.py"
    s = importlib.util.spec_from_file_location("vr_floors", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def test_the_floor_active_at_an_OLD_search_is_the_old_one():
    m = _vr()
    floor, skip = m.reference_firmware_floor_at(_TWO_WINDOWS, "2026-03-01T00:00:00Z")
    assert skip is None
    assert floor == {"Milan": {"snpSPL": 20}}, (
        "a search inside the first window must be judged by the floor that was in force then, not by "
        "a later, stricter one")


def test_the_flattened_floor_is_STRICTER_than_any_single_window():
    """Why flattening is not a safe default: the combined view is the maximum across every window,
    including windows that had not opened when the search ran."""
    m = _vr()
    flattened = m.reference_firmware_floors(_TWO_WINDOWS)
    active_then = m.reference_firmware_floor_at(_TWO_WINDOWS, "2026-03-01T00:00:00Z")[0]
    assert flattened["Milan"]["snpSPL"] == 25
    assert active_then["Milan"]["snpSPL"] == 20
    assert flattened["Milan"]["snpSPL"] > active_then["Milan"]["snpSPL"]


def test_main_does_not_seed_the_cli_floor_from_the_reference():
    """The actual defect, pinned at its source. main() used to default min_tcb to the flattened
    reference floor; the per-statement path then merged that in as though the operator had typed it,
    so the later window won. The CLI floor must carry only what was typed."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "inferroute_cli" / "pi_attested" / "verify_record.py").read_text()
    assert "min_tcb = reference_floors or {}" not in src, (
        "main() is seeding the CLI floor from the reference again; that applies a later reference "
        "threshold retroactively to older searches")


def test_sealing_resolves_the_floor_at_offer_time():
    """The second call site: sealing to a LIVE enclave must use the floor in force now, not the
    flattened maximum, which could refuse a current offer over a window that has not opened."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "inferroute_cli" / "pi_attested" / "verify_record.py").read_text()
    seal = src[src.index("def check_reference_firmware_before_sealing"):]
    seal = seal[:seal.index("\ndef ", 10)]
    assert "reference_firmware_floor_at(" in seal, "sealing must resolve the floor at offer time"
    assert "floors = reference_firmware_floors(reference)" not in seal, "sealing still flattens"


def test_a_bare_min_tcb_writes_a_flat_floor_and_SAYS_it_enforces_nothing(capsys):
    """A bare --min-tcb still composes per-product, which is deliberate -- but the result is a flat
    floor, and a flat floor is never enforced. The composition is left alone; the SILENCE is not."""
    ref = build(dict(GOOD), min_tcb={"Genoa": {"snpSPL": 23}})
    assert isinstance(ref["min_tcb"], dict), "per-product composition semantics are unchanged"
    warned = capsys.readouterr().out
    assert "enforces nothing" in warned, f"got: {warned!r}"
    assert "--valid-from" in warned, "the warning must name what fixes it"


def test_a_build_that_inherits_a_FLAT_floor_says_it_enforces_nothing(capsys):
    """How the live reference came to enforce nothing (measured 2026-09-29): the changeover build
    windowed policy_sha256, index_manifest_sha256 and model_manifest_sha256, but did not re-supply
    --min-tcb, so a pre-existing flat floor passed through untouched and silently. It reads as
    protection and protects nothing, on every record past and future."""
    legacy = build(dict(GOOD))
    legacy["min_tcb"] = {"Genoa": {"snpSPL": 23}}          # the legacy flat shape
    capsys.readouterr()
    out = build(dict(GOOD), merge=legacy, valid_from="2026-09-28T00:00:28Z")
    assert isinstance(out["min_tcb"], dict), "this test is about the flat floor SURVIVING the build"
    warned = capsys.readouterr().out
    assert "enforces nothing" in warned, f"a surviving flat floor must be called out, got: {warned!r}"
    assert "--valid-from" in warned, "the warning must name what fixes it"


def test_a_WINDOWED_floor_draws_no_warning(capsys):
    """The inversion: the warning must distinguish. A windowed floor IS enforced, so warning about it
    would train the operator to ignore the line that matters."""
    ref = build(dict(GOOD), min_tcb={"Genoa": {"snpSPL": 23}}, valid_from="2026-09-28T00:00:28Z")
    assert isinstance(ref["min_tcb"], list)
    assert "enforces nothing" not in capsys.readouterr().out
