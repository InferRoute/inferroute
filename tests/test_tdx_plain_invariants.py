"""The plain statement's composition invariants, over every rendering an Intel TDX record can produce.

test_statement_invariants.py enumerates the AMD state space (posture x gates). A TDX record has no container
policy, so it reaches report_plain by a different door (tee="intel-tdx") with blockers from
tdx_confidentiality_reach. The same doctrine applies there, and nothing enumerated it.
"""
import contextlib
import importlib.util
import io
import os

import pytest

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "inferroute_cli", "pi_attested", "verify_record.py")


@pytest.fixture(scope="module")
def V():
    spec = importlib.util.spec_from_file_location("vr_tdx_invariants", _SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _renderings(V):
    for record_ok in (True, False):
        for authenticated in (True, False):
            reach, blockers = V.tdx_confidentiality_reach(record_ok=record_ok, authenticated=authenticated)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                V.report_plain(reach, blockers, None, tee="intel-tdx")
            yield reach, buf.getvalue()


# Back-references the AMD file checks, plus the ones only a TDX rendering could get wrong: there is no
# policy document, no settings list, and nothing on this ladder is graded as enforced.
_ABSENT_IN_TDX = ("settings above", "these settings", "listed settings", "records this:", "The same document",
                  "further containers", "records what was permitted", "was enforced for these saved operations",
                  "the containers your provider controls", "we control",
                  # a TDX record fetches nothing; "ask" must be a change, since the follow-on calls it one
                  "chip maker", "ask your provider to show", "Intel program image", "cannot send data out")


def test_every_tdx_rendering_is_exercised(V):
    assert {r for r, _ in _renderings(V)} == {-1, 0}


def test_no_tdx_rendering_cites_a_policy_it_does_not_have(V):
    bad = [(r, n) for r, text in _renderings(V) for n in _ABSENT_IN_TDX if n in text]
    assert not bad, bad


def test_no_tdx_rendering_contains_a_forbidden_phrase(V):
    bad = [(r, p) for r, text in _renderings(V) for p in V.PLAIN_FORBIDDEN if p.lower() in text.lower()]
    assert not bad, bad


def test_every_tdx_gap_is_in_plain_words(V):
    """An untranslated blocker prints 'in its original words', which is the auditor's frame, not the reader's.
    The one exception is shared with the AMD ladder: an unauthenticated reference has no plain words yet."""
    for r, text in _renderings(V):
        if r != 0:
            continue
        gaps = text.split("Gaps identified in this record:", 1)[1].split("Any such list", 1)[0]
        raw = [line for line in gaps.splitlines() if "in its original words" in line]
        assert all("reference signature was not verified" in line for line in raw), raw


def test_the_tdx_image_gap_carries_its_neutraliser(V):
    for r, text in _renderings(V):
        if "console" in text:
            gap = next(line for line in text.splitlines() if "console" in line and "-" in line[:8])
            assert "cannot tell whether anyone looked or anything was sent" in gap, gap


def test_the_tdx_answer_states_both_bounds_and_leaves_a_next_step(V):
    for r, text in _renderings(V):
        if r == 0:
            assert "cannot tell you whether your text stayed private" in text
            assert "What you can do:" in text
            assert "For future searches:" in text and "cannot change this record" in text
