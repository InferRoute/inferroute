"""tools/tm_report_check.py: a report's cited marks are checked against what the searches returned."""
import importlib.util
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
