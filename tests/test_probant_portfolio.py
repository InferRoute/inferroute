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


def _job(ident, *documents, found=1, worked=True):
    """Record that a session was GIVEN these documents, as a real run does after every round. Reading is
    what the job log says happened; it is not inferred from whether findings came back, because a document
    can be read honestly and hold nothing."""
    P.record_job(ident, {"documents": list(documents), "whole": True}, first=0, last=found, model="m",
                 prompt="p", seconds=1.0, exit_code=0, worked=worked)


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


def test_the_instruction_forbids_translating_a_quote(home):
    """Measured on the pilot: 4 of 5 quote failures came from the one FRENCH document, at 0.38-0.69
    similarity to the nearest passage — not an encoding artefact (that would score ~0.95) but the model
    rewriting or translating as it quoted. The host check caught all of them; the instruction now says it."""
    job = {"documents": ["a.md"], "whole": True}
    text = P.instruction_for(job)
    assert "IN THE DOCUMENT'S OWN LANGUAGE" in text and "Do not translate a quote" in text
    assert "Write the title and summary in English" in text          # the finding is still readable
    ranged = P.instruction_for({"document": "a.md", "start": 0, "end": 100})
    assert "own language, never translated" in ranged


def test_a_partial_run_reports_recall_but_gives_no_verdict(home, tmp_path):
    """A run that staged 8 documents of 385 reported 13% and "NOT ACCEPTED" — true, useless, and the kind
    of control that fires every time and so stops being read. The verdict belongs to a run that read
    everything it staged; otherwise the register is the wrong denominator and only the number is shown."""
    _, src = home
    ident = _stage(src)["id"]
    first = P.meta_of(ident)["documents"][0]["name"]
    _propose(ident, [{"title": "Cooling jacket", "summary": "channels", "source": first,
                      "quote": "COOLANT-MARKER channels moulded between"}])
    _job(ident, first)
    register = tmp_path / "corpus.json"
    register.write_text(json.dumps({"filed": [{"id": "P1", "title": "Cooling jacket with coolant channels"},
                                              {"id": "P2", "title": "Predicting swelling from impedance drift"}]}))
    assert P.unread(ident) == [P.meta_of(ident)["documents"][1]["name"]]      # one document still unread
    partial = P.recall_against_register(ident, register, complete=False)
    assert partial["accepted"] is None and partial["complete"] is False
    assert "wrong denominator" in partial["note"]
    whole = P.recall_against_register(ident, register, complete=True)
    assert whole["accepted"] is False                                        # 1 of 2, below the 0.6 floor


def test_resuming_reads_only_what_produced_nothing(home):
    """A re-run is a delta: findings already held are kept, and the corpus staged stays the same, so recall
    is judged against the same denominator as the original run."""
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [{"title": "Cooling jacket", "summary": "s", "source": first,
                      "quote": "COOLANT-MARKER channels moulded between"}])
    _job(ident, first)
    jobs = P.plan_unread(ident)
    assert len(jobs) == 1 and jobs[0]["documents"] == [second]
    _propose(ident, [{"title": "Swelling", "summary": "s", "source": second,
                      "quote": "SWELL-MARKER impedance drift over fifty"}])
    _job(ident, second)
    assert P.plan_unread(ident) == [] and P.unread(ident) == []


def test_parallel_workers_keep_their_findings_apart_and_the_reader_puts_them_together(home):
    """One findings file shared by several sessions is a write race, and a lost line is a finding nobody
    knows was found. Each worker appends to its own; candidates() reads them all."""
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    d = P.path_of(ident)
    for worker, (title, source, quote) in enumerate((
            ("Cooling jacket", first, "COOLANT-MARKER channels moulded between"),
            ("Swelling", second, "SWELL-MARKER impedance drift over fifty"))):
        with (d / f"candidates-{worker}-2.jsonl").open("a") as fh:
            fh.write(json.dumps({"title": title, "summary": "s", "source": source, "quote": quote}) + "\n")
    got = P.candidates(ident)
    assert sorted(c["title"] for c in got) == ["Cooling jacket", "Swelling"]
    _job(ident, first, second)
    assert P.unread(ident) == [] and P.dropped(ident) == 0


def test_a_subset_run_gets_no_verdict_even_when_every_document_was_read(home, tmp_path):
    """The gate judged a 15-document subset of prior art and specs against the whole register and said 20%
    — but P2-P4 live in the filings folder that run never staged. Read-everything-staged is not
    staged-everything-the-register-describes."""
    _, src = home
    meta = P.stage(sorted(src.rglob("*.md")), "subset", selection="first 15")
    assert meta["selection"] == "first 15"
    assert P.stage([src / "one.md"], "all")["selection"] == "whole corpus"


def test_a_quota_refusal_stops_the_run_instead_of_being_retried(home):
    """The first full-corpus run hit "upstream 402: Quota exceeded and account balance is $0.0" partway
    through, and every later round came back as two silent turns — which the pipeline read as documents
    asserting nothing, and would have retried 88 jobs into the same refusal."""
    _, src = home
    ident = _stage(src)["id"]
    log = P.path_of(ident) / "rounds.jsonl"
    log.write_text(json.dumps({"ended": "x", "recorded": 0, "turns": 2, "tools": {}, "worked": False,
                               "error": 'error: 402 upstream: {"detail":"Subscription usage cap exceeded."}'}) + "\n")
    assert "402" in P.last_round_blocked(ident)
    assert P.last_round_worked(ident) is False
    # A round that failed for another reason is retried, not treated as the account refusing.
    log.write_text(json.dumps({"ended": "x", "recorded": 0, "turns": 2, "tools": {}, "worked": False,
                               "error": "aborted: Request aborted"}) + "\n")
    assert P.last_round_blocked(ident) == ""


def test_a_document_that_honestly_holds_nothing_is_not_read_forever(home):
    """The bug this fixes, found on the 20 Sep corpus run. "Unread" meant "no finding names it", so a
    document that was read and honestly holds nothing quotable — a checksums file, a transcript manifest —
    stayed unread for ever: every resume planned it again, and the completeness gate (`not unread()`) could
    never be satisfied by any corpus containing one. That run reported 207 documents unread when 439 of 453
    had been read, and was reading a 712 KB manifest for the eleventh time.

    Reading is now what the job log says happened. An empty document is retried, because an empty result is
    often a failed call rather than an empty document — but only MAX_ATTEMPTS times, so a resume terminates.
    """
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [{"title": "Cooling jacket", "summary": "s", "source": first,
                      "quote": "COOLANT-MARKER channels moulded between"}])
    _job(ident, first)
    _job(ident, second, found=0)                      # read, and nothing came back

    assert P.unread(ident) == []                      # both have been read: neither is UNread
    empty = P.barren(ident)
    assert [r["document"] for r in empty] == [second] and empty[0]["attempts"] == 1
    assert empty[0]["give_up"] is False               # one go is not enough to call a document empty

    # It is retried — up to the cap, and then the planner stops offering it.
    for n in range(2, P.MAX_ATTEMPTS + 1):
        assert [j.get("documents") or [j["document"]] for j in P.plan_unread(ident)] == [[second]]
        _job(ident, second, found=0)
        assert P.barren(ident)[0]["attempts"] == n
    assert P.barren(ident)[0]["give_up"] is True
    assert P.plan_unread(ident) == []                 # TERMINATES: this is the whole point

    # And a document nobody has opened yet is still unread, which is a different thing entirely.
    other = _stage(src)["id"]
    assert sorted(P.unread(other)) == sorted([first, second]) and P.barren(other) == []


def _docx(path, paragraphs):
    """A minimal real .docx: the zip members Word needs, and one w:p per paragraph."""
    import zipfile
    NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("word/document.xml", f'<?xml version="1.0"?><w:document {NS}><w:body>{body}</w:body></w:document>')
    return path


def test_a_filing_as_deposited_is_staged_as_its_text_not_its_markup(home, tmp_path):
    """Henry, 20 Sep: run this over the self-contained bundle — where the filings are .docx as deposited at
    INPI. Handing those bytes to a session gives it a zip of XML, so the text is extracted here, and BOTH
    hashes are kept: the staged text is what a quote is checked against, the original is the document of
    record that the bundle's manifest lists."""
    import hashlib
    src = tmp_path / "bundle"
    src.mkdir()
    _docx(src / "FR2609630-P1.docx", ["A jacket with COOLANT-MARKER channels moulded between the cells.",
                                      "Claim 1. A pack, characterised in that the channels are moulded."])
    meta = P.stage([src / "FR2609630-P1.docx"], "bundle")
    doc = meta["documents"][0]
    assert doc["name"] == "FR2609630-P1.txt"          # staged as text, under a name a session can read
    assert doc["converted_from"] == "docx" and doc["original_name"] == "FR2609630-P1.docx"
    staged = (P.path_of(meta["id"]) / P.DOCS / doc["name"]).read_bytes()
    assert b"<w:t>" not in staged and b"<?xml" not in staged        # no markup reached the session
    assert b"COOLANT-MARKER channels moulded between" in staged
    assert b"Claim 1." in staged                                     # paragraphs stay separate lines
    # The two hashes answer different questions and must not be confused for one another.
    assert doc["sha256"] == hashlib.sha256(staged).hexdigest()
    assert doc["original_sha256"] == hashlib.sha256((src / "FR2609630-P1.docx").read_bytes()).hexdigest()
    assert doc["sha256"] != doc["original_sha256"]
    # A quote from the extracted text verifies against it — which is the only agreement that matters.
    _propose(meta["id"], [{"title": "Cooling jacket", "summary": "s", "source": doc["name"],
                           "quote": "COOLANT-MARKER channels moulded between the cells"}])
    assert [c["title"] for c in P.candidates(meta["id"])] == ["Cooling jacket"]
    with pytest.raises(S.ProbantError, match="could not be opened"):
        P.docx_text(b"not a zip at all")


def test_the_matter_list_says_which_register_entries_no_matter_claims(home, tmp_path):
    """The synthesis is the step nothing can verify — no computation says a matter is the right matter. What
    IS computable is whether it accounted for the index the portfolio already keeps. Today's themes run cited
    285 of 4,420 findings and read like an answer; a list that silently drops register entries must not."""
    _, src = home
    ident = _stage(src)["id"]
    first, second = [d["name"] for d in P.meta_of(ident)["documents"]]
    _propose(ident, [{"title": "Cooling jacket", "summary": "s", "source": first,
                      "quote": "COOLANT-MARKER channels moulded between"},
                     {"title": "Swelling", "summary": "s", "source": second,
                      "quote": "SWELL-MARKER impedance drift over fifty"}])
    _job(ident, first, second)
    P.write_findings(ident)
    reg = P.path_of(ident) / "register.json"
    P._write_readonly(reg, json.dumps({
        "filed": [{"id": "P1", "title": "Cooling jacket"}, {"id": "P2", "title": "Swelling prediction"}],
        "surplus": [{"id": "TA-L3", "mechanism": "sealed-lane resale commitment", "ep_urgent": True,
                     "status": "held", "risk": "high"}]}))
    with (P.path_of(ident) / P.THEMES).open("a") as fh:
        fh.write(json.dumps({"label": "Cooling", "thesis": "coolant between cells", "members": ["f1"],
                             "register": ["P1", "NOT-A-REAL-ID"], "aspects": ["moulded channels", "per cell"],
                             "detail": "does not cover air cooling"}) + "\n")
    m = P.matter_list(ident)
    assert m["known"] == 3 and m["covered"] == 1
    assert [k["id"] for k in m["missing"]] == ["P2", "TA-L3"]     # named, not merely counted
    assert m["invented"] == ["NOT-A-REAL-ID"]                     # a register id that does not exist
    assert m["matters"][0]["aspects"] == ["moulded channels", "per cell"]
    assert m["matters"][0]["detail"] == "does not cover air cooling"
    text = P.render_matters(ident)
    assert "1/3 register entries accounted for" in text
    assert "TA-L3" in text and "EP-URGENT" in text                # the urgent one is not buried
    assert "P2 (filed)" in text and "NOT covered" in text
    assert "1 of 2 findings are in no matter" in text
    assert "it does not rule" in text


def test_the_register_is_never_staged_as_one_of_the_documents(home, tmp_path, monkeypatch, capsys):
    """A self-contained bundle keeps its index beside its filings. Staging corpus.json as a document would
    make the recall gate circular: a session that reads the answer key can report its entries as findings and
    score full recall having learnt nothing from the filings it was supposed to read."""
    from inferroute_cli import probant as CLI
    src = tmp_path / "bundle"
    (src / "filings").mkdir(parents=True)
    _docx(src / "filings" / "FR2609630-P1.docx", ["COOLANT-MARKER channels moulded between the cells."])
    (src / "P10-TEMP-surplus.md").write_text("TA-L3 is the sealed-lane resale commitment.\n")
    (src / "corpus.json").write_text(json.dumps({"filed": [{"id": "P1", "title": "Cooling jacket"}],
                                                 "surplus": [{"id": "TA-L3", "mechanism": "resale"}]}))
    staged = {}
    monkeypatch.setattr(CLI, "_portfolio_round", lambda *a, **k: 0)
    real_stage = P.stage
    monkeypatch.setattr(P, "stage", lambda files, *a, **k: staged.setdefault("m", real_stage(files, *a, **k)))
    CLI.cmd_portfolio(str(src))
    names = [d["name"] for d in staged["m"]["documents"]]
    assert "corpus.json" not in names, names
    assert sorted(names) == ["FR2609630-P1.txt", "P10-TEMP-surplus.md"]
    # …and it IS kept as the register, beside the run, where the gate reads it.
    assert (P.path_of(staged["m"]["id"]) / "register.json").is_file()
    assert {k["id"] for k in P.matter_list(staged["m"]["id"])["register"]} == {"P1", "TA-L3"}
