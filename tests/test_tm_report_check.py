"""tools/tm_report_check.py: a report's cited marks are checked against what the searches returned."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("tm_report_check", Path(__file__).parent.parent / "tools" / "tm_report_check.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

HITS = {("US", "86332176"): {"status": "registered", "classes": ["9"]},
        ("US", "98111403"): {"status": "registered", "classes": ["3"]},
        ("US", "99403047"): {"status": "pending", "classes": ["32"]}}


def test_a_faithful_report_passes_and_a_neighbour_s_words_are_not_read_as_its_own():
    got = C.check("**Searched:** US. Not searched: EU.\n## At a glance\n- QUENCH — US 86332176, registered, class 9.\n"
                  "KWENCH outside your classes (US 98111403, class 3; US 99403047, pending, class 32).\n"
                  "## What you can do next\n## Questions for a trademark professional\n", HITS)
    assert got["cited"] == 3 and not got["not_returned"] and not got["status_wrong"] and not got["classes_wrong"]
    assert got["sections_missing"] == [] and not got["forbidden"] and got["says_not_searched"]


def test_a_made_up_number_a_wrong_status_and_a_verdict_are_reported():
    got = C.check("QUENCH — US 86332176, pending, class 9. ZWENCH — FR 1234567, registered. Kwench looks safe.", HITS)
    assert got["not_returned"] == ["FR 1234567"] and got["status_wrong"] == ["US 86332176"]
    assert got["forbidden"] == ["safe"] and "At a glance" in got["sections_missing"]


def test_a_register_named_in_full_is_still_a_citation():
    # glm-5.2 wrote "USPTO 79150570" and the checker counted 0 citations although all were right.
    hits = {("US", "79150570"): {"status": "registered", "classes": ["9"]}, ("FR", "4774453"): {"status": "registered", "classes": ["1", "11"]}}
    got = C.check("AQUA — USPTO 79150570, registered, class 9. Aqualina — INPI 4774453, registered, classes 1, 11.", hits)
    assert got["cited"] == 2 and not got["not_returned"] and not got["classes_wrong"] and not got["classes_partial"]


def test_part_of_a_mark_s_classes_written_as_the_whole_is_flagged_unless_worded_as_an_overlap():
    hits = {("US", "72137309"): {"status": "registered", "classes": ["7", "9", "11", "21", "35"]}}
    assert C.check("GRINDEX — US 72137309, registered, classes 7/9/11.", hits)["classes_partial"] == ["US 72137309"]
    for ok in ("GRINDEX — US 72137309, registered, overlaps your classes 7, 21.",
               "GRINDEX — US 72137309, registered, in your class 21.",
               "GRINDEX — US 72137309, registered, classes 7, 9, 11, 21, 35."):
        got = C.check(ok, hits)
        assert not got["classes_partial"] and not got["classes_wrong"], ok


def test_an_eu_number_is_checked_however_it_is_written_and_eu_27_is_not_a_citation():
    # With EU marks searched, an EU number in a report went unchecked: invented or with a wrong status, it passed.
    # The index holds EU numbers without EUIPO's leading zeros, so 000275933 and 275933 are the same mark.
    hits = {("EU", "275933"): {"status": "registered", "classes": ["9"]}}
    got = C.check("FESTO — EUTM 000275933, registered, class 9. FESTA — EU 275933, pending. "
                  "FESTI — EUIPO 018999999, registered. The EU 27 member states.", hits)
    assert got["cited"] == 3 and got["not_returned"] == ["EU 18999999"] and got["status_wrong"] == ["EU 275933"]


def test_a_filing_grouped_under_a_name_is_a_returned_mark(tmp_path):
    # Since grouping, a name's other filings come back under "also"; citing one is citing what the search returned.
    log = tmp_path / "trademark-searches.jsonl"
    log.write_text(json.dumps({"hits": [{"register": "US", "number": "86332176", "status": "registered", "classes": ["9"],
                                         "also": [{"register": "EU", "number": "275933", "status": "pending",
                                                   "classes": ["7"]}]}]}) + "\n")
    got = C.check("QUENCH — EU 000275933, pending, class 7. QUENCH — US 86332176, registered.", C.logged_hits(log))
    assert got["cited"] == 2 and not got["not_returned"] and not got["status_wrong"] and not got["classes_wrong"]


def test_after_a_token_that_only_names_the_eu_register_a_short_number_is_still_checked():
    # A citation neither checked nor refused is how an invented number gets through: "EUTM 4321" is checked.
    hits = {("EU", "4321"): {"status": "registered", "classes": ["9"]}}
    got = C.check("A — EUTM 000004321, registered. B — EUIPO 4321, pending. C — EU trade mark 4322. D — EUTM 000004320. "
                  "The EU 27.", hits)
    assert got["cited"] == 4 and got["not_returned"] == ["EU 4322", "EU 4320"] and got["status_wrong"] == ["EU 4321"]


def test_an_international_registration_is_checked_and_a_patent_number_is_not_a_citation():
    # With IRs searched, an invented "WO 1234567" must not pass, nor "registered" for an IR: INPI's copy cannot show
    # protection in France or the EU. "WO 2020/123456" is a patent publication, not a mark.
    hits = {("WO", "855123"): {"status": "international registration", "classes": ["9"]}}
    got = C.check("FESTO — WO 0855123, international registration, class 9. FESTA — IR 855123, registered. "
                  "FESTI — WIPO 1999999. FESTU — international registration No. 4321. See WO 2020/123456.", hits)
    assert got["cited"] == 4
    assert got["not_returned"] == ["WO 1999999", "WO 4321"] and got["status_wrong"] == ["WO 855123"]


def test_an_australian_number_is_checked():
    hits = {("AU", "1672793"): {"status": "registered", "classes": ["42"]}}
    got = C.check("TRINITY OPS — AU 1672793, registered, class 42. TRINITY — IP Australia 1672794. The AU market.", hits)
    assert got["cited"] == 2 and got["not_returned"] == ["AU 1672794"] and not got["status_wrong"]


def test_an_italian_number_is_checked_and_a_short_it_number_is_not_a_citation():
    hits = {("IT", "302024000030610"): {"status": "registered (per UIBM)", "classes": []}}
    got = C.check("MASIFRAN — IT 302024000030610, registered (per UIBM). MASIFRA — UIBM 302024000030611. IT 2024 budget.", hits)
    assert got["cited"] == 2 and got["not_returned"] == ["IT 302024000030611"] and not got["status_wrong"]
