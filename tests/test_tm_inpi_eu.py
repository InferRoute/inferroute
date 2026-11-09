"""EU marks from INPI's open data into index rows (tools/tm_inpi_eu.py). What the index depends on: the newest
revision of a number wins and repeats collapse; dead marks and marks with no word element stay out; classes
and dates come out in the index's form; and every status the pull carries is classified."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tm_inpi_eu  # noqa: E402


def rec(number, text, status="Registered", classes="9,42", date="20180131", rev="202645"):
    return {"collection": "EU", "application_number": number, "mark_text": text, "status": status,
            "nice_classes": classes, "application_date": date, "designated_countries": "", "inpi_revision": rev}


def test_the_newest_revision_wins_and_repeats_collapse():
    state = tm_inpi_eu.merge([rec("1", "OLD", rev="202644"), rec("1", "NEW", rev="202645"),
                              rec("1", "STALE", rev="202644"), rec("2", "SAME"), rec("2", "SAME")])
    assert {n: r["mark_text"] for n, r in state.items()} == {"1": "NEW", "2": "SAME"}


def test_only_live_marks_with_words_become_rows_in_the_index_form():
    state = tm_inpi_eu.merge([rec("1", "PolyDigital", classes="42, 35"), rec("2", "Gone", status="Registration expired"),
                              rec("3", "", status="Registered"), rec("4", "Filed", status="Application filed", date="")])
    assert list(tm_inpi_eu.rows(state)) == [
        ("EU", "1", "PolyDigital", "registered", ["35", "42"], "2018-01-31"),
        ("EU", "4", "Filed", "pending", ["42", "9"], ""),
    ]


def test_every_status_is_either_live_or_dead():
    assert not tm_inpi_eu.LIVE & tm_inpi_eu.DEAD
    assert tm_inpi_eu.REGISTERED <= tm_inpi_eu.LIVE
