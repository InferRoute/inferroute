"""A portfolio clustered round after round (Henry, 20 Sep: "recursive analysis ... by clustering mentality
until convergence").

The agent does the reading and the grouping. Everything a reader could not check by eye is checked here: that
a quote is really in the document it names, that a round accounts for every candidate, and that convergence
is measured from the partitions rather than taken from the agent's word.
"""
import json
import stat

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_portfolio as P

A = "A jacket with COOLANT-MARKER channels moulded between the cells of a pack.\n" * 3
B = "Predicting swelling from SWELL-MARKER impedance drift over fifty cycles.\n" * 3


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    src = tmp_path / "portfolio"
    (src / "sub").mkdir(parents=True)
    (src / "one.md").write_text(A)
    (src / "sub" / "one.md").write_text(B)        # same basename, different document
    return tmp_path, src


def _stage(src):
    return P.stage(sorted(src.rglob("*.md")), "test portfolio")


def _propose(ident, rows):
    with (P.path_of(ident) / P.CANDIDATES).open("a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _cluster(ident, round_no, rows):
    with (P.path_of(ident) / (P.CLUSTERS % round_no)).open("a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_documents_are_copied_read_only_and_two_files_of_one_name_stay_two(home):
    tmp, src = home
    meta = _stage(src)
    names = [d["name"] for d in meta["documents"]]
    assert len(names) == 2 and len(set(names)) == 2, names      # one.md and one-2.md, never merged
    d = P.path_of(meta["id"])
    assert all(stat.S_IMODE((d / P.DOCS / n).stat().st_mode) == 0o400 for n in names)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    with pytest.raises(S.ProbantError, match="no readable documents"):
        P.stage([tmp / "nothing.md"])


def test_a_quote_counts_only_against_the_document_it_names(home):
    _, src = home
    meta = _stage(src)
    ident = meta["id"]
    first, second = [d["name"] for d in meta["documents"]]
    _propose(ident, [
        {"title": "Cooling jacket", "summary": "channels between cells", "quote": "COOLANT-MARKER channels moulded between", "source": first},
        # The quote exists in the PORTFOLIO, but not in the document this row names:
        {"title": "Swelling, misattributed", "summary": "drift", "quote": "SWELL-MARKER impedance drift over fifty", "source": first},
        {"title": "Swelling", "summary": "drift over fifty cycles", "quote": "SWELL-MARKER impedance drift over fifty", "source": second},
        {"title": "Invented", "summary": "not in any document", "quote": "a superconducting flywheel bonded to the chassis", "source": second},
        {"title": "No such document", "summary": "x", "quote": "COOLANT-MARKER channels moulded between", "source": "ghost.md"},
    ])
    got = P.candidates(ident)
    assert [c["title"] for c in got] == ["Cooling jacket", "Swelling"]
    assert [c["id"] for c in got] == ["c1", "c2"]
    assert P.dropped(ident) == 3


def test_a_round_accounts_for_every_candidate_and_says_what_it_did_not(home):
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [
        {"title": "Cooling jacket", "summary": "s", "quote": "COOLANT-MARKER channels moulded between", "source": first},
        {"title": "Swelling", "summary": "s", "quote": "SWELL-MARKER impedance drift over fifty", "source": second},
    ])
    _cluster(ident, 1, [
        {"label": "Thermal", "thesis": "heat out of the pack", "members": ["c1", "c1", "c99"], "why": "w"},
        {"label": "Empty after checking", "thesis": "t", "members": ["c99"], "why": "w"},
    ])
    r = P.clusters(ident, 1)
    assert [c["label"] for c in r["clusters"]] == ["Thermal"]     # a cluster of only unknown ids is not one
    assert r["clusters"][0]["members"] == ["c1"]                  # claimed twice, counted once
    assert r["twice"] == ["c1"] and r["missing"] == ["c2"] and r["unknown"] == ["c99"]


def test_convergence_is_measured_from_the_partitions_not_asserted(home):
    p1 = [frozenset({"c1", "c2"}), frozenset({"c3"})]
    p2 = [frozenset({"c1", "c2"}), frozenset({"c3"})]            # same membership, different labels upstream
    p3 = [frozenset({"c1"}), frozenset({"c2", "c3"})]
    assert P.movement(p1, p2) == 0.0
    assert P.movement(p1, p3) > 0.3
    assert P.converged([p1]) == (False, "one round so far; convergence needs two to compare")
    ok, why = P.converged([p1, p2])
    assert ok and "did not move" in why
    ok2, why2 = P.converged([p1, p3])
    assert not ok2 and "moved" in why2
    # A round that moves one member of ten is within the threshold; the default does not call that motion.
    ten = [frozenset({f"c{i}" for i in range(10)})]
    nine = [frozenset({f"c{i}" for i in range(9)}), frozenset({"c9"})]
    assert P.converged([ten, nine], threshold=0.2)[0] is True
    assert P.converged([ten, nine])[0] is False


def test_the_signals_are_counted_and_a_theme_spanning_documents_outranks_a_repeated_one(home):
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [
        {"title": "Cooling jacket", "summary": "s", "quote": "COOLANT-MARKER channels moulded between", "source": first},
        {"title": "Jacket, again", "summary": "s", "quote": "channels moulded between the cells of a pack", "source": first},
        {"title": "Swelling", "summary": "s", "quote": "SWELL-MARKER impedance drift over fifty", "source": second},
    ])
    _cluster(ident, 2, [
        {"label": "Thermal", "thesis": "t", "members": ["c1", "c2"], "why": "w"},
        {"label": "Across the portfolio", "thesis": "t", "members": ["c3"], "why": "w"},
    ])
    sig = P.signals(ident, P.clusters(ident, 2))
    assert [s["label"] for s in sig] == ["Thermal", "Across the portfolio"]
    assert sig[0]["candidates"] == 2 and sig[0]["documents"] == 1
    assert sig[1]["candidates"] == 1 and sig[1]["documents"] == 1
