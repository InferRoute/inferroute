"""The INPI French trademark feed into index rows (tools/tm_inpi.py). What the index silently depends on: a
malformed record in INPI's export loses only that record (the feed has records missing an opening tag);
updates replace older states in order and keep what they omit; weeks the backlog already holds are not
replayed over it; dead marks stay out; and a status nobody classified stops the build instead of guessing."""
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tm_inpi  # noqa: E402

GOOD = ('<TradeMark operationCode="Update"><ApplicationNumber>{n}</ApplicationNumber><ApplicationDate>2020-01-0{n}'
        '</ApplicationDate><MarkCurrentStatusCode>Marque enregistrée</MarkCurrentStatusCode><MarkFeature>Word</MarkFeature>'
        '<MarkVerbalElementText>NAME{n} &amp; CO</MarkVerbalElementText><ClassNumber>9</ClassNumber></TradeMark>')
# The shape seen in FR_FRUPDST66_2026-12: an identifier whose opening tag is missing, after the fields we use.
BROKEN = ('<TradeMark operationCode="Update"><ApplicationNumber>2</ApplicationNumber><MarkCurrentStatusCode>Demande publiée'
          '</MarkCurrentStatusCode><MarkVerbalElementText>SALVAGED</MarkVerbalElementText><ClassNumber>42</ClassNumber>'
          '<Claimant>353383821</ClaimantIdentifier></Claimant></TradeMark>')


def feed(tmp_path, backlog, weekly):
    (tmp_path / "backlog").mkdir()
    (tmp_path / "weekly").mkdir()
    for name, body in backlog.items():
        with zipfile.ZipFile(tmp_path / "backlog" / name, "w") as z:
            z.writestr("a.xml", f'<Transaction xmlns="http://www.inpi.fr/schemas/frst66/v1_00_13">{body}</Transaction>')
    for name, body in weekly.items():
        with zipfile.ZipFile(tmp_path / "weekly" / name, "w") as z:
            z.writestr("b.xml", f"<Transaction>{body}</Transaction>")
    tm_inpi.SKIPPED.clear()
    return tm_inpi.current(tmp_path)


def test_a_malformed_record_loses_nothing_the_index_uses(tmp_path):
    state = feed(tmp_path, {"BCK_ST66_FR_202448_000001_001.xml.zip": GOOD.format(n=1) + BROKEN + GOOD.format(n=3)}, {})
    assert set(state) == {"1", "2", "3"}
    assert state["2"]["text"] == "SALVAGED" and state["2"]["classes"] == {"42"}
    assert state["1"]["text"] == "NAME1 & CO"                       # entities decoded either way
    assert "1 read field by field, 0 unreadable" in tm_inpi.SKIPPED[0]


def test_updates_apply_in_order_keep_omitted_fields_and_skip_weeks_the_backlog_holds(tmp_path):
    expire = '<TradeMark operationCode="Update"><ApplicationNumber>{n}</ApplicationNumber><MarkCurrentStatusCode>Marque expirée</MarkCurrentStatusCode></TradeMark>'
    state = feed(tmp_path, {"BCK_ST66_FR_202448_000001_001.xml.zip": GOOD.format(n=1) + GOOD.format(n=3)},
                 {"FR_FRST66_2024-49.zip": expire.format(n=1),          # inside the backlog: not replayed
                  "FR_FRUPDST66_2026-01.zip": expire.format(n=3)})
    assert state["1"]["status"] == "Marque enregistrée"
    assert state["3"]["status"] == "Marque expirée" and state["3"]["text"] == "NAME3 & CO"
    rows = list(tm_inpi.rows(state))
    assert [r[1] for r in rows] == ["1"] and rows[0][3] == "registered"


def test_every_status_the_feed_carries_is_classified():
    assert not (tm_inpi.LIVE & tm_inpi.DEAD)
    for seen in ("Marque expirée", "Marque enregistrée", "Marque renouvelée", "Demande totalement rejetée",
                 "Marque ayant fait l'objet d'un retrait total", "Demande publiée",
                 "Marque ayant fait l'objet d'une renonciation totale", "Demande irrecevable après publication",
                 "Marque annulée", "Marque déchue"):
        assert seen in tm_inpi.LIVE or seen in tm_inpi.DEAD
