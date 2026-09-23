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


# ── the sender's own record ──────────────────────────────────────────────────────────────────────

def _payload(cid="20260923T213234Z-3f5730"):
    return {"note": "",
            "corpus": {"id": cid, "name": "InferRoute portfolio", "made_at": "2026-09-23T21:32:34Z",
                       "files": [{"name": "MATTERS.txt"}, {"name": "READING-GUIDE.txt"}]},
            "matters": [{"matter": "InferRoute/attest-dynamics"},
                        {"matter": "InferRoute/disclosure-diode"}]}


def test_the_sender_records_what_they_sent(tmp_path):
    """`write_corpus` ran only on the RECEIVING side, so making a delivery left no trace of itself: not
    what went, not to whom, not when. For an attorney that is the audit trail of their own outbound
    disclosure."""
    dest = tmp_path / "corpus.probant-share"
    SH.record_sent(_payload(), "betrancourt", "7d94-4f0d-f72d-e695", dest)
    rows = SH.corpora()
    assert len(rows) == 1
    r = rows[0]
    assert r["direction"] == "sent" and r["to"] == "betrancourt"
    assert r["to_fingerprint"] == "7d94-4f0d-f72d-e695"
    assert r["sealed_to"] == str(dest)
    assert r["files"] == ["MATTERS.txt", "READING-GUIDE.txt"]


def test_a_sent_record_names_the_matters_without_doubling_the_client():
    """A payload entry's `matter` already reads "client/matter"; prefixing client again printed
    "None/InferRoute/attest-dynamics" the first time this reached a screen."""
    SH.record_sent(_payload(), "betrancourt", "ffff", Path_stub())
    assert SH.corpora()[0]["matters"] == ["InferRoute/attest-dynamics", "InferRoute/disclosure-diode"]
    assert not any(m.startswith("None/") for m in SH.corpora()[0]["matters"])


def Path_stub():
    from pathlib import Path
    return Path("/tmp/x.probant-share")


def test_a_payload_with_no_corpus_id_records_nothing():
    """Nothing to identify means nothing to record — a file with an empty id would be unaddressable."""
    SH.record_sent({"corpus": {}, "matters": []}, "x", "y", Path_stub())
    assert SH.corpora() == []


def test_the_listing_separates_what_was_sent_from_what_arrived(capsys):
    SH.record_sent(_payload(), "betrancourt", "7d94", Path_stub())
    out = _list_output(capsys)
    assert "[sent]" in out and "sent to betrancourt" in out
    assert "from " not in out.split("Corpora")[1], "a sent delivery has no sender to name"
    # the documents of a SENT corpus live in the sealed file, not in a local shared-corpus directory
    assert "shared-corpus" not in out and "None" not in out
    assert "--from-corpus" not in out, "that is advice for the recipient, not for the sender"


def test_the_web_page_renders_the_deliveries_it_is_given():
    """The API carrying them is half of it; a page that ignores the field shows the same blank Sharing
    tab as before."""
    js = (Path(__file__).resolve().parent.parent
          / "inferroute_cli" / "probant_web" / "home.js").read_text(encoding="utf-8")
    assert 'el("h2", "section", "Deliveries")' in js, "the heading, not the comment above it"
    assert "d.corpora" in js, "it must read the field the API added"
    assert "Nothing sent or received yet" in js, "an empty list needs a sentence, not a blank gap"
    assert 'c.direction === "sent"' in js
    assert "known_contact" in js, "an unknown sender must be marked on the page as on the command line"


from pathlib import Path  # noqa: E402


def test_the_share_COMMAND_records_the_delivery(tmp_path, monkeypatch):
    """The seam. Testing `record_sent` in isolation passes whether or not `share` ever calls it — and
    when that call was removed, every test still went green."""
    monkeypatch.chdir(tmp_path)
    assert S.main(["identity"]) == 0
    card = next(tmp_path.glob("probant-contact-*.json"))
    assert S.main(["identity", "--add", "them", "--card", str(card)]) == 0
    assert S.main(["new", "Acme", "battery"]) == 0
    doc = tmp_path / "MATTERS.txt"
    doc.write_text("what this delivery holds\n", encoding="utf-8")
    assert S.main(["share", "them", "--matter", "Acme/battery", "--file", str(doc),
                   "--corpus-name", "Acme portfolio"]) == 0
    rows = SH.corpora()
    assert len(rows) == 1, "sharing left no record of itself"
    assert rows[0]["direction"] == "sent" and rows[0]["to"] == "them"
    assert rows[0]["matters"] == ["Acme/battery"] and rows[0]["files"] == ["MATTERS.txt"]
