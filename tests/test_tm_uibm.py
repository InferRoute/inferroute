"""Italian marks from the UIBM fetch into index rows (tools/tm_uibm.py): live statuses only, filed within ten and a
half years (UIBM shows no renewals), words from the title or a quoted phrase, never from a free description."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tm_uibm  # noqa: E402


def rec(n, title, status="Registrata", filed="31/01/2024", description=""):
    return {"app_number": n, "filing_date": filed, "status": status, "title": title, "description": description}


def test_live_recent_marks_with_words_become_rows():
    got = list(tm_uibm.rows([
        rec("1", "MASIFRAN"),
        rec("2", "", status="in esame", description='DIRTY Il marchio è costituito dalla parola "DIRTY", in caratteri.'),
        rec("3", "CON TE OGNI GIORNO fig."),
        rec("4", "", description="Il marchio consiste nella raffigurazione di sei quadrati"),   # no words given
        rec("5", "GONE", status="Rifiutata"),
        rec("6", "OLD", filed="31/01/2010"),                                                     # renewal unknown
        rec("1", "MASIFRAN"),                                                                    # repeated page
    ], today="2026-11-11"))
    assert got == [("IT", "1", "MASIFRAN", "registered (per UIBM)", [], "2024-01-31"),
                   ("IT", "2", "DIRTY", "pending (per UIBM)", [], "2024-01-31"),
                   ("IT", "3", "CON TE OGNI GIORNO", "registered (per UIBM)", [], "2024-01-31")]


def test_every_status_is_either_live_or_dead():
    assert not tm_uibm.LIVE & tm_uibm.DEAD


def test_the_cutoff_is_a_date_ten_and_a_half_years_back():
    assert tm_uibm.since("2026-11-11") == "2016-05-12"
