"""`Check this record` — the exported record checked from the home page, in words a professional can use.

The point of these is that the page never invents a verdict. The verifier's exit code decides; this layer
only says what that code means for the person holding the record, and which part of it a failure touches.
"""
import json

import pytest

from inferroute_cli import probant_check as C

# A shortened but faithful sample of what verify_record.py prints. Kept verbatim in shape (two leading
# spaces, "STATUS name: detail") so that a change to the verifier's own wording fails a test here rather
# than silently emptying the page.
PASSING = """Verifying record in /home/henry/Probant/Acme/exports/cooling-prior-art-record-20260918T010203Z

  PASS MANIFEST.json: 14 files listed, all present
  PASS bundle integrity (MANIFEST is an index, not a seal): every listed file matches its sha256
  PASS hardware report: version 3, signature present
  PASS debug disabled: guest policy forbids debugging
  PASS AMD root pinned: ARK-Genoa matches the pinned SPKI
  PASS report signature: ECDSA P-384 over the report verifies under the VCEK
  PASS UVM root is Microsoft's: fingerprint matches
  PASS enclave identity (InferRoute's policy, index, encoders): policy_sha256 caf68014… current at search time
  PASS reference signature: verifies under the publication key 748e4c8e4ca334c5… you recorded at first use
  PASS sealed to one recipient: the reply was sealed to the key this client generated
  PASS query text is the one searched: sha256 of the query matches the signed statement
  PASS completeness (per-session sequence): 3 searches, seq 1..3, no gap

RESULT: every check PASSED under production roots
"""

FAILING = PASSING.replace(
    "  PASS completeness (per-session sequence): 3 searches, seq 1..3, no gap",
    "  FAIL completeness (per-session sequence): sequence starts at seq 4; searches 1..3 are not in this record")


def test_the_verdict_is_the_verifiers_exit_code_not_a_reading_of_its_lines():
    # Every line says PASS; the exit code says otherwise. The code wins — a page that reported "passed"
    # here would be a second opinion, and the one that disagrees with the real verifier.
    out = C.parse(PASSING, 1)
    assert out["verdict"] == "failed" and out["headline"] == "Something did not check out."
    assert C.parse(PASSING, 0)["verdict"] == "passed"


@pytest.mark.parametrize("code,verdict", [(0, "passed"), (1, "failed"), (2, "refused"), (3, "test"), (4, "unauthenticated")])
def test_every_exit_code_the_verifier_can_return_has_words(code, verdict):
    out = C.parse(PASSING, code)
    assert out["verdict"] == verdict
    assert out["headline"] and out["explainer"]


def test_a_failure_says_what_it_costs_and_what_to_do():
    out = C.parse(FAILING, 1)
    done = next(g for g in out["groups"] if g["key"] == "complete")
    assert done["status"] == "fail"
    # The wording Henry was given before ("FAIL completeness") said nothing about whether the record was
    # still usable. This one has to.
    assert "could have been removed" in done["answer"]
    assert "not as evidence that these were all of them" in done["todo"]
    assert done["failed"] == ["completeness (per-session sequence)"]


def test_every_check_lands_in_a_question_a_professional_would_ask():
    out = C.parse(PASSING, 0)
    assert out["checks"] == 12
    assert sum(len(g["rows"]) for g in out["groups"]) == 12          # nothing dropped on the floor
    keys = [g["key"] for g in out["groups"]]
    assert keys == ["intact", "machine", "identity", "truthful", "complete"]
    assert "other" not in keys


def test_a_check_this_summary_has_no_name_for_is_shown_not_hidden():
    out = C.parse(PASSING + "  FAIL something entirely new: a check from a later build\n", 1)
    other = next(g for g in out["groups"] if g["key"] == "other")
    assert other["rows"][0]["name"] == "something entirely new" and other["todo"]


def test_a_skipped_check_is_reported_as_not_checked_never_as_passed():
    text = PASSING.replace("  PASS reference signature: verifies under the publication key 748e4c8e4ca334c5… you recorded at first use",
                           "  SKIP reference signature: reference carries a signature but no --reference-key was given")
    out = C.parse(text, 4)
    ident = next(g for g in out["groups"] if g["key"] == "identity")
    assert ident["status"] == "pass"                                  # other identity checks did pass
    assert any("no --reference-key" in s for s in ident["not_checked"])


def test_the_record_is_checked_against_the_reference_this_computer_searches_under(tmp_path, monkeypatch):
    # Not a reference chosen here: the same two files the session pins, so a record is checked against what
    # it was made under. If they are absent the check still runs, and says identity could not be settled.
    cfg = tmp_path / "search.json"
    ref = tmp_path / "current.json"
    ref.write_text("{}")
    cfg.write_text(json.dumps({"reference": str(ref), "reference_key": "ab" * 32}))
    from inferroute_cli import pi_attested
    monkeypatch.setattr(pi_attested, "search_config_path", lambda: cfg)
    assert C.published_reference() == (str(ref), "ab" * 32)
    cfg.write_text(json.dumps({"reference": str(tmp_path / "gone.json")}))
    assert C.published_reference() == (None, None)


def test_without_a_published_reference_the_page_is_told_why_identity_could_not_be_settled(tmp_path, monkeypatch):
    bundle = tmp_path / "record"
    bundle.mkdir()
    (bundle / "verify_record.py").write_text("import sys\nprint('  FAIL enclave identity (InferRoute\\'s policy, index, encoders): no reference given')\n"
                                             "print('RESULT: FAILED — 1 check(s) did not pass')\nsys.exit(1)\n")
    from inferroute_cli import pi_attested
    monkeypatch.setattr(pi_attested, "search_config_path", lambda: tmp_path / "absent.json")
    out = C.check(bundle)
    assert out["verdict"] == "failed" and out["reference_used"] is False
    assert "no published reference configured" in out["note"]
    ident = next(g for g in out["groups"] if g["key"] == "identity")
    assert "could have been a confidential machine belonging to anyone" in ident["answer"]


def test_the_check_runs_the_bundles_own_verifier_not_a_copy_of_the_verdict(tmp_path, monkeypatch):
    bundle = tmp_path / "record"
    bundle.mkdir()
    (bundle / "verify_record.py").write_text("import sys\nprint('  PASS MANIFEST.json: 1 file')\n"
                                             "print('RESULT: every check PASSED under production roots')\nsys.exit(0)\n")
    from inferroute_cli import pi_attested
    monkeypatch.setattr(pi_attested, "search_config_path", lambda: tmp_path / "absent.json")
    out = C.check(bundle)
    assert out["code"] == 0 and out["verdict"] == "passed"
    assert out["result_line"] == "every check PASSED under production roots"
