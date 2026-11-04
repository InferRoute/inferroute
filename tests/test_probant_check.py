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
  PASS signed recipient matches recorded key: signed hash matches the public key recorded in this search row; this does not rule out another copy or disclosure channel
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
    # Other identity checks did pass, but one line was not checked: a neutral mark, never a plain tick (23 Oct).
    assert ident["status"] == "limited" and ident["answer"] == "Passed, with limits noted below."
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


def test_a_disclosure_line_under_a_passing_verdict_is_shown_as_a_disclosure_not_a_failure():
    """21 Oct audit: "Everything checked out" and, three lines lower, a red "Other checks: a check this summary
    has no name for did not pass". The verifier prints what the hardware check cannot cover (the cloud
    platform's policy fragment) as a FAIL line beside RESULT "no failing record checks", and exits 0."""
    from inferroute_cli import probant_check as C
    # As the verifier prints it: the disclosure rows sit under its confidentiality report, after RESULT.
    out = ("  PASS MANIFEST.json: all files match\n"
           "RESULT: no failing record checks under production roots; SKIP rows remain unverified\n"
           "\nWhat this evidence licenses you to say about confidentiality\n"
           "  policy 380e3707bca09f61…\n"
           "    FAIL policy is self-contained: external policy dependency INSIDE the trust boundary\n")
    r = C.parse(out, 0)
    assert r["verdict"] == "passed" and r["failed"] == []
    assert [g["key"] for g in r["groups"]] == ["intact", "disclosed"]
    assert r["groups"][1]["status"] == "info" and "Not a failure" in r["groups"][1]["answer"]
    # under a FAILING verdict the same line still counts as a failure
    assert "policy is self-contained" in C.parse(out, 1)["failed"]


# ── the headline is derived from every check the page shows, not from the exit code alone ──

DISCLOSURE_HEADING = "What this evidence licenses you to say about confidentiality"

# A record-check FAIL that has no group of its own, printed BEFORE the confidentiality report, beside an exit
# code of 0. The page shows it under "Other checks" with a red cross; the headline above it must not say that
# everything checked out (22 Oct report: "Everything checked out" over a failed "Other checks").
OTHER_FAIL = PASSING.replace(
    "\nRESULT:", "  FAIL archive timestamp: the proof does not match the record\n\nRESULT:")


@pytest.mark.parametrize("code", [0, 4])
def test_a_failed_check_on_the_page_never_sits_under_a_reassuring_headline(code):
    r = C.parse(OTHER_FAIL, code)
    other = next(g for g in r["groups"] if g["key"] == "other")
    assert other["status"] == "fail" and other["failed"] == ["archive timestamp"]
    assert r["headline"] == "One check did not pass; see below."
    assert "Everything" not in r["headline"] and "passed" not in r["headline"]
    assert r["verdict"] == "failed" and r["failed"] == ["archive timestamp"]
    assert r["code"] == code                          # the verifier's own code is kept, and the page says it differs
    assert "verifier" in r["explainer"]
    # The statement a record licenses is not offered over a failure shown beside it.
    assert r["plain"] == []


def test_the_failure_headline_counts_distinct_checks_not_rows():
    two = FAILING.replace("  PASS hardware report: version 3, signature present",
                          "  FAIL hardware report: signature does not verify")
    assert C.parse(FAILING, 1)["headline"] == "One check did not pass; see below."
    assert C.parse(two, 1)["headline"] == "2 checks did not pass; see below."
    # A search-per-row failure repeated in every search is still one check.
    again = FAILING + "  FAIL completeness (per-session sequence): sequence starts at seq 9\n"
    assert C.parse(again, 1)["headline"] == "One check did not pass; see below."


def test_only_the_confidentiality_report_is_read_as_a_disclosure():
    """The verifier prints its confidentiality report under its own heading and says those rows "do NOT affect
    the exit code". A FAIL there, under a pass, is a disclosure. A FAIL anywhere else is a failure, whatever
    the exit code, and is never relabelled "Not a failure"."""
    out = (OTHER_FAIL.replace("RESULT: every check PASSED under production roots",
                              "RESULT: no failing record checks under production roots")
           + f"\n{DISCLOSURE_HEADING}\n  policy 380e3707bca09f61…\n"
             "    FAIL policy is self-contained: external policy dependency INSIDE the trust boundary\n")
    r = C.parse(out, 0)
    keys = {g["key"]: g for g in r["groups"]}
    assert keys["disclosed"]["status"] == "info"
    assert [x["name"] for x in keys["disclosed"]["rows"]] == ["policy is self-contained"]
    assert keys["other"]["status"] == "fail"
    assert r["failed"] == ["archive timestamp"] and r["verdict"] == "failed"


def test_a_clean_pass_still_says_so():
    r = C.parse(PASSING, 0)
    assert r["verdict"] == "passed" and r["headline"] == "Everything checked out."


# ── an Intel TDX record (4 Nov): the rows below are the verifier's own, printed by verify_record.verify_offer on the
# real c3-standard-22 offer in sealed-research's tests/fixtures/tdx (details shortened), plus the record rows every
# record carries. The sealed-machine answer used to be one fixed sentence naming AMD's and Microsoft's roots, and
# most TDX hardware rows matched no question and fell to "Other checks".
TDX_PASSING = """Verifying record in /home/henry/Anteriora/Acme/exports/cooling-prior-art-record-20261104T010203Z

  PASS MANIFEST.json: 14 files listed, all present
  PASS bundle integrity (MANIFEST is an index, not a seal): every listed file matches its sha256
  PASS runtime data present: 4079 bytes of readable runtime data
  PASS sealing key committed in runtime data: the query would be sealed to ffc38677ba635ec3…
  PASS signer key committed in runtime data: answers would be signed by b2b2108b1628e6e5…
  PASS index manifest names real bytes: 4d9c239b596946c5… identifies the files this enclave serves
  PASS encoder manifest names real bytes: 7f31cb3ff91adaea… identifies the files this enclave serves
  PASS REPORTDATA binds runtime data: REPORTDATA == SHA-256(runtime data) ‖ zeros
  PASS TD debug disabled: TD attributes 0000001000000000: DEBUG bit clear
  PASS Intel PCK certificate chain: PCK ← Intel SGX PCK Platform CA ← Intel SGX Root CA
  PASS Quoting Enclave report signed by the PCK key: ECDSA P-256 over the 384-byte QE report verifies
  PASS attestation key bound by the Quoting Enclave: QE REPORTDATA == SHA-256(attestation key ‖ QE auth data) ‖ zeros
  PASS TD quote signature: ECDSA P-256 over the quote header and TD report verifies under the bound attestation key
  PASS Intel TCB info: signed by Intel SGX TCB Signing under the pinned root, TDX v3
  PASS Intel QE identity: signed by Intel SGX TCB Signing under the pinned root, TD_QE v2
  PASS Intel revocation lists: Intel's root and PCK CRLs verify
  PASS Intel TCB status (platform, TDX module): FMSPC 00806f050000, platform UpToDate, TDX module UpToDate
  PASS Intel Quoting Enclave identity and status: QE is Intel's (MRSIGNER, product, attributes), ISVSVN 6: UpToDate
  PASS Google launch endorsement: RSA-PSS signature by GCE-uefi-signer, issued by the pinned GCE-cc-tcb-root
  PASS firmware (MRTD) is a build Google endorsed: MRTD f21e6b48743fe14c… is listed, firmware SVN 2
  PASS boot event log replays to the quote: 22 events replay to RTMR0-3 exactly
  PASS nothing measured after the image: RTMR2 and RTMR3 are empty
  PASS firmware boot entries pass no command line: Boot0001 'UEFI nvme_card-pd': no command line
  PASS boot application measured: first EFI application 07d49e2137bf87f4… (2 measured in total)
  PASS enclave identity (InferRoute's image, host configuration, index, encoders): image: current
  PASS reference signature: verifies under the publication key 748e4c8e4ca334c5… you recorded at first use
  PASS statement matches enclave commitments: index, encoders and keys are the ones the hardware report commits to
  PASS machine clock agrees with the client's: 0 s apart
  PASS signed recipient matches recorded key: signed hash matches the public key recorded in this search row
  PASS query text is the one searched: sha256 of the query matches the signed statement
  PASS completeness (per-session sequence): 3 searches, seq 1..3, no gap

RESULT: every check PASSED under production roots
"""


def test_a_tdx_record_is_answered_as_intel_hardware_and_every_row_has_a_question():
    out = C.parse(TDX_PASSING, 0)
    assert sum(len(g["rows"]) for g in out["groups"]) == out["checks"] == 31
    assert [g["key"] for g in out["groups"]] == ["intact", "machine", "identity", "truthful", "complete"]
    machine = next(g for g in out["groups"] if g["key"] == "machine")
    assert "Intel" in machine["answer"]
    names = {r["name"] for r in machine["rows"]}
    assert {"TD quote signature", "Intel PCK certificate chain", "Google launch endorsement",
            "boot event log replays to the quote", "TD debug disabled"} <= names
    identity = next(g for g in out["groups"] if g["key"] == "identity")
    assert "index manifest names real bytes" in {r["name"] for r in identity["rows"]}


def test_no_answer_names_a_vendor_the_record_does_not_show():
    tdx = C.parse(TDX_PASSING, 0)
    snp = C.parse(PASSING, 0)
    text = json.dumps([g["answer"] for g in tdx["groups"]])
    for word in ("AMD", "Microsoft", "Azure"):
        assert word not in text
    assert "Intel" not in json.dumps([g["answer"] for g in snp["groups"]])
    assert "Azure" not in json.dumps(C.VERDICTS)
