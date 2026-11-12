"""Australian marks from IP RAPID Parquet into index rows (tools/tm_ipau.py): live statuses only, a word mark's
phrase before the words read from a logo, current Nice classes only, and every status classified."""
import sys
from pathlib import Path

import pytest

pa = pytest.importorskip("pyarrow")
import pyarrow.parquet as pq  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tm_ipau  # noqa: E402


def write(folder, name, rows):
    (folder / name).mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), folder / name / "part-0.parquet")


def test_live_marks_with_words_become_rows(tmp_path):
    write(tmp_path, "tm_application", [
        {"application_number": 1, "status": "protected", "application_date": "2015-02-05T00:00:00.000Z"},
        {"application_number": 2, "status": "accepted", "application_date": "2026-10-01T00:00:00.000Z"},
        {"application_number": 3, "status": "lapsed", "application_date": "2001-01-01T00:00:00.000Z"},
        {"application_number": 4, "status": "protected", "application_date": "2010-01-01T00:00:00.000Z"},
    ])
    write(tmp_path, "tm_description", [
        {"application_number": "1", "description_type": "trade_mark_image_words", "description_value": "LOGO WORDS"},
        {"application_number": "1", "description_type": "trade_mark_word_mark_phrase", "description_value": "TRINITY OPS"},
        {"application_number": "2", "description_type": "trade_mark_image_words", "description_value": "GIDGEE"},
        {"application_number": "3", "description_type": "trade_mark_word_mark_phrase", "description_value": "GONE"},
        {"application_number": "4", "description_type": "trade_mark_figurative", "description_value": "figurative"},
    ])
    write(tmp_path, "tm_classification", [
        {"application_number": "1", "classification_system": "nice", "classification": "42", "is_current": "true"},
        {"application_number": "1", "classification_system": "nice", "classification": "09", "is_current": "true"},
        {"application_number": "1", "classification_system": "nice", "classification": "35", "is_current": "false"},
    ])
    assert sorted(tm_ipau.rows(tmp_path)) == [
        ("AU", "1", "TRINITY OPS", "registered", ["42", "9"], "2015-02-05"),
        ("AU", "2", "GIDGEE", "pending", [], "2026-10-01"),
    ]
    assert tm_ipau.data_date(tmp_path) == "2026-10-01"


def test_every_status_is_either_live_or_dead():
    assert not tm_ipau.LIVE & tm_ipau.DEAD
