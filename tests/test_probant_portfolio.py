"""Reading a portfolio: what the host checks, and what it refuses to claim.

The clustering loop this started as is gone (docs/portfolio-analysis-proposal.md): a partition that agrees
with itself measures the model, not the corpus. What survives is what a reader cannot check by eye — that a
quote is really in the document it NAMES, and how much of a document any quote evidences at all. The
movement metric stays as a diagnostic for comparing two groupings, never as a stopping rule.
"""
import json
import stat
from pathlib import Path

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


def test_the_synthesis_sees_every_finding_and_its_themes_are_checked_back_to_them(home):
    """The corpus does not fit any context on this lane (2.46 M tokens against a 1 M ceiling); what it
    ASSERTS does. So the synthesis step reads every finding at once, and every theme it draws must name the
    findings it rests on — ids assigned here, so a theme traces back to a quote in a named document."""
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [
        {"title": "Cooling jacket", "summary": "s", "quote": "COOLANT-MARKER channels moulded between", "source": first},
        {"title": "Swelling", "summary": "s", "quote": "SWELL-MARKER impedance drift over fifty", "source": second},
    ])
    shape = P.write_findings(ident)
    assert shape == {"n": 2, "documents": 2, "tokens_roughly": shape["tokens_roughly"]}
    rows = json.loads((P.path_of(ident) / "findings.json").read_text())
    assert [r["id"] for r in rows] == ["f1", "f2"]
    with (P.path_of(ident) / P.THEMES).open("a") as fh:
        fh.write(json.dumps({"label": "Thermal", "thesis": "heat leaves through the jacket",
                             "members": ["f1", "f404"], "why": "w"}) + "\n")
        fh.write(json.dumps({"label": "Nothing real", "members": ["f404"]}) + "\n")
    got = P.themes(ident)
    assert [t["label"] for t in got["themes"]] == ["Thermal"]          # a theme of only invented ids is none
    assert got["themes"][0]["members"] == ["f1"] and got["themes"][0]["documents"] == 1
    assert got["uncited"] == ["f2"]                                    # said out loud, not quietly dropped
    assert got["unknown"] == ["f404"]


def test_the_same_document_filed_twice_is_read_once(home):
    """Measured on the real portfolio: 459 files, 385 distinct — 74 exact copies (bundle-preview beside
    audit-trail). A copy costs a session AND invents a "two documents agree" signal, which is worse."""
    _, src = home
    (src / "copy.md").write_text((src / "one.md").read_text())        # byte-identical to one.md
    meta = P.stage(sorted(src.rglob("*.md")), "with a duplicate")
    assert meta["given"] == 3 and len(meta["documents"]) == 2
    assert len(meta["duplicates"]) == 1 and meta["duplicates"][0]["same_as"] in [d["name"] for d in meta["documents"]]
    assert meta["bytes"] < meta["bytes_given"]                        # what is read, and what was handed over


def test_recall_is_measured_against_the_register_because_nothing_else_can_measure_it(home, tmp_path):
    """Henry, 20 Sep: "are you sure we can trust the results and will not need to run it again?" Precision is
    checkable by construction — every finding carries a verified quote. Recall is not: no reading pass can
    say what the model chose not to record. But this portfolio keeps a register of its own filings and
    candidates, and that is an answer key: a run that misses a third of it did not read the portfolio,
    whatever its totals say."""
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [
        {"title": "Cooling jacket with coolant channels between cells", "summary": "moulded jacket",
         "quote": "COOLANT-MARKER channels moulded between", "source": first},
    ])
    register = tmp_path / "corpus.json"
    register.write_text(json.dumps({
        "filed": [{"id": "P1", "title": "Cooling jacket with coolant channels between cells",
                   "concepts": [["C1", "coolant channels moulded between the cells of a pack"]]}],
        "surplus": [{"id": "TA-L3", "mechanism": "sealed lane resale commitment on a sealed transport"}],
    }))
    rows = P.register_rows(register)
    assert sorted(r["id"] for r in rows) == ["P1", "P1:C1", "TA-L3"]     # filings, their concepts, candidates
    got = P.recall_against_register(ident, register, floor=0.8)
    assert got["known"] == 3 and got["found"] == 2 and got["missed"] == 1
    assert got["misses"][0]["register"] == "TA-L3"                      # named, not counted away
    assert got["recall"] == 0.667 and got["accepted"] is False          # two of three: below an 0.8 floor
    assert P.recall_against_register(ident, register, floor=0.6)["accepted"] is True
    assert "cannot speak for anything the register does not list" in got["note"]


def test_every_module_function_the_runner_calls_exists():
    """It did not. brief(), record_job(), provenance() and unchanged_since() were wiped by a later edit to
    a neighbouring block, the full suite stayed green because no test drives the orchestration, and the run
    died on an AttributeError after staging — 20 Sep. A missing function must not need a live run to find."""
    import ast
    import inspect
    from inferroute_cli import probant as S_mod
    tree = ast.parse(Path(inspect.getfile(S_mod)).read_text())
    called = {node.attr for node in ast.walk(tree)
              if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "PF"}
    missing = sorted(name for name in called if not hasattr(P, name))
    assert not missing, f"probant.py calls probant_portfolio.{missing}, which does not exist"
    assert {"brief", "record_job", "provenance", "candidates", "plan"} <= called   # the runner really uses them


def test_the_brief_is_rewritten_before_every_job(home):
    """It was not: brief.json was left 0400 for the session to read, so the SECOND job of a run died with
    PermissionError writing the file the run had itself written (20 Sep, pilot killed after job 1 of 7).
    Anything regenerated per job must be rewritable by the host and read-only to the session."""
    import stat as st
    _, src = home
    ident = _stage(src)["id"]
    first = P.brief(ident)
    assert first["documents"] == 2 and first["documents_read_so_far"] == 0
    _propose(ident, [{"title": "Cooling jacket", "summary": "s", "source": P.meta_of(ident)["documents"][0]["name"],
                      "quote": "COOLANT-MARKER channels moulded between"}])
    again = P.brief(ident)                      # the failing call
    assert [r["title"] for r in again["recorded_so_far"]] == ["Cooling jacket"]
    assert st.S_IMODE((P.path_of(ident) / P.BRIEF).stat().st_mode) == 0o400
    P.write_findings(ident)
    P.write_findings(ident)                     # same fault, same fix
