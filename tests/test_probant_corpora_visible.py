"""A corpus is an object; until now it had nowhere to be seen.

Henry, twice: "I didn't see the corpus integration in the client." Both times the mechanism was there —
`share --file/--corpus-name`, `open-share`, `new --from-corpus`, the records on disk — and both times the
answer was that nothing ever read those records back. A delivery could be made, sent, received and opened
without any command showing that it existed.
"""
import json

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_share as SH


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / ".inferroute"))
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))
    yield


def _corpus(cid="20260923T212443Z-e741a3", **kw):
    rec = {"schema": "inferroute.probant-corpus/1", "id": cid, "name": "InferRoute portfolio",
           "client": "Portfolio", "from": "cc5a-c1a2-4753-ed9e", "known_contact": False,
           "made_at": "2026-09-23T21:24:43Z", "files": ["MATTERS.txt"],
           "matters": ["InferRoute/portfolio-test"]}
    rec.update(kw)
    p = SH.corpora_record(cid)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec), encoding="utf-8")
    return rec


def test_a_corpus_that_exists_can_be_listed():
    _corpus()
    rows = SH.corpora()
    assert len(rows) == 1 and rows[0]["name"] == "InferRoute portfolio"


def test_corpora_come_back_newest_first():
    _corpus("a-old", made_at="2026-01-01T00:00:00Z", name="old")
    _corpus("b-new", made_at="2026-09-01T00:00:00Z", name="new")
    assert [c["name"] for c in SH.corpora()] == ["new", "old"]


def test_an_unreadable_record_is_skipped_rather_than_crashing_the_listing():
    """One bad file must not make `ir probant list` fail for every other delivery."""
    _corpus()
    bad = SH.corpora_record("broken")
    bad.write_text("{not json", encoding="utf-8")
    assert [c["id"] for c in SH.corpora()] == ["20260923T212443Z-e741a3"]


def _matter(client="Portfolio", matter="portfolio-test"):
    d = S.matters_dir() / client
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{matter}.json").write_text(json.dumps(
        {"client": client, "matter": matter, "date_bound": "2026-09-23", "workspace": "/tmp/ws"}),
        encoding="utf-8")


def test_listing_names_the_corpus_a_matter_arrived_in(capsys):
    _corpus()
    _matter()
    SH.note_corpus_origin("Portfolio", "portfolio-test", "20260923T212443Z-e741a3", how="arrived in this corpus")
    out = _list_output(capsys)
    assert "[20260923T212443Z-e741a3]" in out, "a matter must say which delivery it came from"


def test_the_listing_shows_the_delivery_its_documents_and_how_to_build_on_it(capsys):
    _corpus()
    out = _list_output(capsys)
    assert "Corpora" in out
    assert "InferRoute portfolio" in out and "20260923T212443Z-e741a3" in out
    assert "MATTERS.txt" in out, "the documents describing the delivery are the point of a corpus"
    assert "--from-corpus 20260923T212443Z-e741a3" in out, "it must say how to work from it"


def test_an_unknown_sender_is_flagged_in_the_listing(capsys):
    """A corpus seals to a key. Whether that key belongs to who you think is the human question, and the
    listing must not let it pass silently."""
    _corpus(known_contact=False)
    assert "not a known contact" in _list_output(capsys)
    _corpus(known_contact=True, from_name="betrancourt")
    assert "not a known contact" not in _list_output(capsys)


def test_no_corpora_prints_no_empty_heading(capsys):
    S.cmd_list()
    assert "Corpora" not in capsys.readouterr().out


def _list_output(capsys) -> str:
    capsys.readouterr()
    S.cmd_list()
    return capsys.readouterr().out
