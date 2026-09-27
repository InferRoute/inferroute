"""The plain-language line is a rendering of confidentiality_reach, not a second opinion.

Simplification is where an overclaim comes back: "your search was private" reads as fine and is
false. These pin that the plain line can only ever say what the computed level licenses, and that
the guard against overclaim vocabulary actually refuses rather than decorating.
"""
import io
import re
from contextlib import redirect_stdout

import pytest

from tests.test_verify_record import _load, _policy, _report_claims


def _mod():
    return _load()


ALL_LEVELS = (-1, 0, 1)


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_every_reachable_level_has_a_sentence(level):
    """A level with no sentence must not silently fall back to a stronger one."""
    assert _mod().plain_statement(level) is not None, f"no plain sentence for reach {level}"


def test_unwritten_level_prints_nothing_rather_than_the_nearest_sentence():
    m = _mod()
    assert m.plain_statement(2) is None
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(2)
    text = out.getvalue()
    assert "No plain statement is written" in text
    # the level-1 headline must not leak into a level the ladder never licensed
    assert "sealed computer" not in text.lower()


def test_refusal_level_makes_no_positive_claim():
    headline, caveat = _mod().plain_statement(-1)
    joined = (headline + " " + caveat).lower()
    for phrase in ("sealed computer", "in a position to read", "signed by that machine"):
        assert phrase not in joined, f"refusal text claims something: {phrase!r}"


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_no_level_uses_overclaim_vocabulary(level):
    headline, caveat = _mod().plain_statement(level)
    joined = (headline + " " + caveat).lower()
    for phrase in _mod().PLAIN_FORBIDDEN:
        assert phrase not in joined


def test_the_overclaim_guard_actually_refuses():
    """INVERSION: a guard never seen failing is decoration. Put an overclaim in and it must raise."""
    m = _mod()
    original = m.PLAIN_BY_REACH
    m.PLAIN_BY_REACH = dict(original)
    m.PLAIN_BY_REACH[1] = ("Your search was private and could not have been read.", "No caveat.")
    try:
        with pytest.raises(AssertionError) as exc:
            m.plain_statement(1)
    finally:
        m.PLAIN_BY_REACH = original
    assert "overclaim" in str(exc.value)


def test_higher_level_says_strictly_more_than_lower():
    m = _mod()
    zero = m.plain_statement(0)[0]
    one = m.plain_statement(1)[0]
    assert one != zero
    # level 1 is the one that earned the controls clause; level 0 must not carry it
    assert "listed protection checks" in one
    assert "listed protection checks" not in zero


@pytest.mark.parametrize("level", (0, 1))
def test_every_positive_level_keeps_the_caveat(level):
    """The unreachable level 2 is what the caveat exists for; it must survive every simplification."""
    caveat = _mod().plain_statement(level)[1]
    assert "does not show" in caveat.lower()
    assert "own computer" in caveat.lower()


@pytest.mark.parametrize("image_source", [None, {"url": "not-a-verified-publication"}])
def test_plain_level_zero_with_stdio_allowed_makes_no_host_secrecy_claim(capsys, image_source):
    """The real record permits host stdio: valid hardware evidence cannot license host exclusion."""
    m = _mod()
    _report_claims(m, _policy(stdio=True), reference={"image_source": image_source})
    out = capsys.readouterr().out
    plain = out.split("In plain words, for a reader")[1]
    assert m.plain_statement(0)[0] in plain
    assert "in a position to read" not in plain
    assert "every time it answers" not in plain
    assert "The program is published" not in plain
    assert "does not show who could read your text" in plain
    assert "AI conversation" in plain
    assert "publication and behavior were not verified" in plain


def test_all_controls_passing_does_not_restore_plain_disclosure_guarantee(capsys):
    m = _mod()
    _report_claims(m)
    out = capsys.readouterr().out
    plain = out.split("In plain words, for a reader")[1]
    assert m.plain_statement(1)[0] in plain
    assert "listed protection checks" in plain
    assert "does not show who could read your text" in plain
    assert "could not attach" not in plain


@pytest.mark.parametrize("phrase", ["No one hosting it was in a position to read your text.",
                                     "The program is published.",
                                     "It proves what it is every time it answers."])
def test_lint_rejects_the_specific_0958_overclaims(phrase):
    m = _mod()
    m.PLAIN_BY_REACH = {0: (phrase, "")}
    with pytest.raises(AssertionError, match="overclaim"):
        m.plain_statement(0)


def test_unestablished_coverage_does_not_call_an_intact_record_corrupt(capsys):
    m = _mod()
    _report_claims(m, committed=None)
    out = capsys.readouterr().out
    assert "REFUSED" in out and m.plain_statement(-1)[0] in out
    assert "record did not check out" not in out


# --- the reasons, in plain words ----------------------------------------------------------------------


def test_each_known_blocker_becomes_plain_words():
    m = _mod()
    known = [
        "policy 80c5424d: the policy does not satisfy: policy denies host access to the enclave's stdio",
        "policy 80c5424d: the policy has unresolved external fragments/imports, so the permission rows may omit effective rules",
    ]
    out = m.plain_blockers(known)
    assert any("attach to the program" in r for r in out)
    assert any("kept elsewhere" in r for r in out)
    assert not any("policy 80c5424d" in r for r in out), "technical prefix leaked into plain words"


def test_an_unrecognised_blocker_is_kept_not_dropped():
    """INVERSION: silence and nothing-to-say must not look alike, and silence is the stronger claim."""
    m = _mod()
    out = m.plain_blockers(["policy abc: some future blocker nobody has worded yet"])
    assert len(out) == 1
    assert "some future blocker nobody has worded yet" in out[0]
    assert "could not establish" in out[0]


def test_no_blockers_prints_no_reasons_section():
    m = _mod()
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(1, [])
    assert "In this record, specifically" not in out.getvalue()


def test_reasons_are_printed_under_a_positive_level():
    m = _mod()
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(0, ["policy x: the policy does not satisfy: policy denies host access to the enclave's stdio"])
    text = out.getvalue()
    assert "In this record, specifically" in text
    assert "attach to the program" in text


def test_duplicate_blockers_across_policies_are_said_once():
    m = _mod()
    dupes = ["policy a: ... policy denies host access to the enclave's stdio",
             "policy b: ... policy denies host access to the enclave's stdio"]
    assert len(m.plain_blockers(dupes)) == 1
