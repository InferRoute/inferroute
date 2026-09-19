"""Reading a portfolio: what the host checks, and what it refuses to claim.

The clustering loop this started as is gone (docs/portfolio-analysis-proposal.md): a partition that agrees
with itself measures the model, not the corpus. What survives is what a reader cannot check by eye — that a
quote is really in the document it NAMES, and how much of a document any quote evidences at all. The
movement metric stays as a diagnostic for comparing two groupings, never as a stopping rule.
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




def test_a_quote_stripped_of_markdown_still_verifies_but_a_paraphrase_does_not(home):
    """Measured 20 Sep on a real filing: 17 of 31 findings failed verbatim matching, and EVERY one failed on
    markdown — the model quotes the sentence, not the `**` and `#` around it. Unicode punctuation and case
    accounted for none, so neither is touched. This stays an exact match on a form both sides agree about."""
    _, src = home
    (src / "formatted.md").write_text(
        "## A heading\n\n**The jacket** has `COOLANT-MARKER` channels moulded *between* the cells.\n")
    ident = P.stage([src / "formatted.md"], "formatted")["id"]
    name = P.meta_of(ident)["documents"][0]["name"]
    _propose(ident, [
        # As the model writes it: the sentence, without the formatting.
        {"title": "Jacket", "summary": "s", "source": name,
         "quote": "The jacket has COOLANT-MARKER channels moulded between the cells."},
        # A paraphrase of the same sentence: still dropped, which is the point of the check.
        {"title": "Paraphrase", "summary": "s", "source": name,
         "quote": "The jacket contains marked coolant channels formed between the cells."},
    ])
    assert [c["title"] for c in P.candidates(ident)] == ["Jacket"]
    assert P.dropped(ident) == 1
    assert P.canonical("**bold** and `code` and # head") == "bold and code and head"
