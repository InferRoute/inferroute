"""International registrations from INPI's open data into index rows (tools/tm_inpi_wo.py). INPI's copy has no
status, so what the index depends on is: an IR is held only while unexpired AND designating France or the EU, it
needs a word element, the newest revision wins, and numbers lose leading zeros as the citation check expects."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tm_inpi_wo  # noqa: E402


def rec(number, text, designated="FR,DE", expiry="20300101", classes="9,42", date="20200131", rev="202645"):
    return {"collection": "WO", "application_number": number, "mark_text": text, "status": "",
            "nice_classes": classes, "application_date": date, "designated_countries": designated,
            "inpi_revision": rev, "expiry_date": expiry}


def test_only_unexpired_irs_designating_france_or_the_eu_with_words_become_rows():
    state = tm_inpi_wo.merge([
        rec("0855123", "Festo"),                                  # FR, leading zero dropped
        rec("1500000", "Euro", designated="CN,EM"),               # EU designation
        rec("1500001", "Elsewhere", designated="CN,US"),          # neither France nor the EU
        rec("1500002", "Lapsed", expiry="20251231"),              # expired before the build date
        rec("1500003", "", designated="FR"),                      # figurative only
        rec("1500004", "Undated", expiry=""),                     # no expiry: cannot be shown to be in force
    ])
    assert list(tm_inpi_wo.rows(state, today="2026-11-11")) == [
        ("WO", "855123", "Festo", "international registration", ["42", "9"], "2020-01-31"),
        ("WO", "1500000", "Euro", "international registration", ["42", "9"], "2020-01-31"),
    ]


def test_the_newest_revision_wins():
    state = tm_inpi_wo.merge([rec("1", "OLD", rev="202644"), rec("1", "NEW", rev="202645")])
    assert [r[2] for r in tm_inpi_wo.rows(state, today="2026-11-11")] == ["NEW"]


def test_an_ir_expiring_on_the_build_date_is_still_held():
    state = tm_inpi_wo.merge([rec("7", "Today", expiry="20261111")])
    assert len(list(tm_inpi_wo.rows(state, today="2026-11-11"))) == 1
