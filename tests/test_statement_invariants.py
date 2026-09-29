"""Properties that must hold for EVERY reachable rendering of the plain statement.

Eleven review rounds found defects in this statement. Every one had one of two shapes:

  (a) a sentence whose triggering predicate is true for MORE reasons than the sentence describes
      -- e.g. the platform census printed whenever a policy was not self-contained, asserting
      Microsoft-specific facts about a dependency the run could not identify;
  (b) a sentence referring to something ABSENT from that particular rendering -- "the settings
      above" with no settings printed, "These are gaps" with no bullets, "what was enforced for
      these saved operations" immediately after refusing to license any operation.

Both are COMPOSITION defects: the sentences are individually careful and assembled conditionally,
and until now nothing checked the assembled product. Six of nine rounds found a defect introduced
by the previous round's FIX, because each fix repaired the one composition a reviewer happened to
render and broke another nobody had.

So this file does not test sentences. It enumerates the reachable state space -- posture crossed
with gate outcomes, with reach and blockers taken from confidentiality_reach ITSELF rather than
invented -- renders each one, and asserts invariants over the text. A reviewer finds one bad
composition; this finds all of them, every run.
"""
import io
import contextlib
import importlib.util
import itertools
import os
import pytest

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "inferroute_cli", "pi_attested", "verify_record.py")


@pytest.fixture(scope="module")
def V():
    spec = importlib.util.spec_from_file_location("vr_invariants", _SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _render(V, reach, blockers, closed):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        V.report_plain(reach, blockers, closed=closed)
    return buf.getvalue()


def _reachable(V):
    """Every (reach, blockers, closed) the gate can actually produce, plus the bare refusal path."""
    keys = [k for k, *_ in V.CONFIDENTIALITY_POSTURE] + ["self_contained", "dependencies_identified"]
    gate_args = ("floor_pinned", "revocation_checked", "image_published", "authenticated")
    for bits in itertools.product((True, False), repeat=len(keys)):
        posture = dict(zip(keys, bits))
        posture["image_pinned"] = posture.get("self_contained", False)
        posture["no_exec"] = posture.get("dependencies_identified", False)
        for gbits in itertools.product((True, False), repeat=len(gate_args)):
            kw = dict(zip(gate_args, gbits))
            reach, blockers = V.confidentiality_reach(
                posture, record_ok=True, policy_committed=True, **kw)
            yield reach, blockers, posture
    for bad in ({"record_ok": False, "policy_committed": True},
                {"record_ok": True, "policy_committed": False}):
        reach, blockers = V.confidentiality_reach(
            {k: True for k in keys} | {"image_pinned": True, "no_exec": True},
            floor_pinned=True, revocation_checked=True, image_published=True,
            authenticated=True, **bad)
        yield reach, blockers, None
    yield -1, None, None


# (needle, what must also be present for the needle to have a referent, why)
_BACK_REFERENCES = (
    ("settings above", "records this:", "cites a settings list that was not printed"),
    ("these settings", "records this:", "cites a settings list that was not printed"),
    ("These are gaps", "      - ", "cites gaps when no gap bullets follow"),
    ("those containers", "further containers", "cites containers never introduced"),
)


def test_no_rendering_refers_to_something_it_did_not_print(V):
    """Shape (b), mechanically, over the whole reachable space."""
    bad = []
    for reach, blockers, closed in _reachable(V):
        text = _render(V, reach, blockers, closed)
        for needle, antecedent, why in _BACK_REFERENCES:
            if needle in text and antecedent not in text:
                bad.append(f"reach={reach} closed={closed} :: {why} ({needle!r})")
    assert not bad, "renderings citing absent text:\n  " + "\n  ".join(sorted(set(bad))[:6])


def test_the_platform_census_is_only_asserted_when_the_dependency_was_identified(V):
    """Shape (a). 'permits most of them to run with raised powers' comes from the
    PLATFORM_DEPENDENCIES census of Microsoft's fragment, so it may only be said when the run
    actually identified the dependency -- never merely because the policy was not self-contained."""
    bad = []
    for reach, blockers, closed in _reachable(V):
        text = _render(V, reach, blockers, closed)
        if "permits most of them" in text and (closed or {}).get("dependencies_identified") is not True:
            bad.append(f"reach={reach} dependencies_identified={(closed or {}).get('dependencies_identified')}")
        if "could not fully verify" in text and (closed or {}).get("dependencies_identified") is True:
            bad.append(f"reach={reach} says unverified about an IDENTIFIED dependency")
    assert not bad, "census asserted without identification:\n  " + "\n  ".join(sorted(set(bad))[:6])


def test_every_alarming_clause_carries_its_neutraliser(V):
    """This file's own doctrine: the correction must sit AGAINST the alarming clause, because a
    reader who stops midway never reaches a correction that trails the paragraph."""
    bad = []
    for reach, blockers, closed in _reachable(V):
        text = _render(V, reach, blockers, closed)
        if "raised powers" in text and "not a record of what happened" not in text:
            bad.append(f"reach={reach}: alarming clause with no neutraliser")
    assert not bad, "\n  ".join(sorted(set(bad))[:6])


def test_a_refusal_never_presupposes_what_it_refused(V):
    """At reach -1 the verifier has established nothing about the operations."""
    bad = []
    for reach, blockers, closed in _reachable(V):
        if reach != -1:
            continue
        text = _render(V, reach, blockers, closed)
        for claim in ("what was enforced for these saved operations",
                      "passed the checks", "the containers we control"):
            if claim in text:
                bad.append(f"refusal presupposes {claim!r}")
    assert not bad, "\n  ".join(sorted(set(bad))[:6])


def test_no_rendering_contains_a_forbidden_phrase(V):
    bad = []
    for reach, blockers, closed in _reachable(V):
        text = _render(V, reach, blockers, closed).lower()
        for phrase in V.PLAIN_FORBIDDEN:
            if phrase.lower() in text:
                bad.append(f"reach={reach}: {phrase!r}")
    assert not bad, "\n  ".join(sorted(set(bad))[:6])


def test_the_statement_keeps_one_voice_everywhere(V):
    """'we control' and 'your provider controls' named the same containers; the reader runs this
    verifier, so 'we' can read as the reader and misattribute control of the enclave to them."""
    bad = [f"reach={reach}" for reach, blockers, closed in _reachable(V)
           if "we control" in _render(V, reach, blockers, closed)]
    assert not bad, "mixed voice in: " + ", ".join(sorted(set(bad))[:6])


def test_the_invariants_can_actually_fail(V, monkeypatch):
    """A guard that cannot fail grades nothing. Re-introduce a historical defect and prove the
    property catches it -- the back-reference check against the round-6 regression."""
    original = V.PLAIN_BY_REACH
    hurt = dict(original)
    hurt[0] = ("Nothing here. It means the settings above describe one part of the machine.",
               original[0][1])
    monkeypatch.setattr(V, "PLAIN_BY_REACH", hurt)
    with pytest.raises(AssertionError) as exc:
        test_no_rendering_refers_to_something_it_did_not_print(V)
    assert "settings above" in str(exc.value)


def test_the_state_space_is_real_and_the_needles_are_mostly_live(V):
    """A property test that silently iterates nothing passes vacuously, and a needle that never
    occurs is coverage it does not provide. Both stated here as numbers so a future reader can see
    what this file actually exercises."""
    states = list(_reachable(V))
    assert len(states) > 1000, f"state space collapsed to {len(states)}"
    texts = [_render(V, r, b, c) for r, b, c in states]
    assert len(set(texts)) > 1000, "renderings are not distinct; the enumeration is degenerate"
    assert {r for r, _, _ in states} == {-1, 0, 1}, "every reach level must be exercised"
    live = {needle for needle, _, _ in _BACK_REFERENCES if any(needle in t for t in texts)}
    assert len(live) >= 3, f"only {len(live)} back-reference needles occur at all: {live}"
    # "these settings" is currently absent from every rendering: it is kept as a REGRESSION guard
    # for the round-9 wording, not as live coverage. If it ever starts appearing, this reminds
    # whoever added it that its antecedent is checked.
    assert "these settings" not in live, (
        "'these settings' is now live; that is fine, but move it out of the regression-only note")


def test_no_rendering_evaluates_what_it_only_recorded(V):
    """'at their protective values' judges the values rather than reporting them. The verifier checked
    that the document RECORDS certain control values; it did not check, and cannot check, that those
    values protect this reader's text. Found by the independent round on 2026-09-29 -- in wording an
    earlier fix of mine introduced."""
    bad = []
    for reach, blockers, closed in _reachable(V):
        text = _render(V, reach, blockers, closed)
        for evaluative in ("protective values", "protective value"):
            if evaluative in text:
                bad.append(f"reach={reach}: {evaluative!r} evaluates rather than reports")
    assert not bad, "\n  ".join(sorted(set(bad))[:6])


def test_a_self_contained_policy_says_so_rather_than_falling_silent(V):
    """Where the policy declares no external dependencies the platform paragraph is correctly absent --
    but ABSENCE is not a statement. This file's own doctrine: a reader told us 'if the setting was
    fixed, tell me that; it is the only good news the report could carry.' An absence also leaves a
    reader comparing two records with no way to tell why the paragraph vanished."""
    seen = 0
    for reach, blockers, closed in _reachable(V):
        if not closed or closed.get("self_contained") is not True:
            continue
        text = _render(V, reach, blockers, closed)
        if "records this:" not in text:      # only where a controls list was printed
            continue
        seen += 1
        assert "declares no dependencies outside itself" in text, (
            "a self-contained policy must SAY so, not merely omit the platform paragraph: " + text[:400])
    assert seen > 0, "fixture found no self-contained rendering with a controls list"


def test_the_ask_does_not_imply_one_setting_is_the_whole_fix(V):
    """The singular 'one setting switched off' frames stdio as the sole privacy-relevant lever, in a
    rendering that carries several other blockers. A reader who acts on it may believe the resulting
    record will be authoritative on privacy."""
    for _trigger, ask in V.PLAIN_ASKS:
        assert "one setting switched off" not in ask, ask
    joined = " ".join(a for _t, a in V.PLAIN_ASKS)
    assert "will not by itself" in joined or "other gaps" in joined, \
        "the ask must say that closing it does not remove the other gaps: " + joined
