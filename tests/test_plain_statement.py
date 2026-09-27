"""The plain-language line is a rendering of confidentiality_reach, not a second opinion.

Simplification is where an overclaim comes back: "your search was private" reads as fine and is
false. These pin that the plain line can only ever say what the computed level licenses, and that
the guard against overclaim vocabulary actually refuses rather than decorating.
"""
import io
import re
from contextlib import redirect_stdout

import pytest

from tests.test_verify_record import _load


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
    assert "could not attach to it" in one
    assert "could not attach to it" not in zero


@pytest.mark.parametrize("level", (0, 1))
def test_every_positive_level_keeps_the_caveat(level):
    """The unreachable level 2 is what the caveat exists for; it must survive every simplification."""
    caveat = _mod().plain_statement(level)[1]
    assert "does not show" in caveat.lower()
    assert "own computer" in caveat.lower()
