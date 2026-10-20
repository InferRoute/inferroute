"""Trademark name check (Anteriora, 19 Oct): what a founder relies on without being able to check it.

That a close mark is found whichever way it is spelled; that the reasons given are true of the pair; that a
long composite mark is not called close because of its length; that the same search returns the same list
every time; that the output never says a name is available or clear; and that nothing is sent anywhere.
"""
import json
import socket

import pytest

from inferroute_cli import probant as S
from inferroute_cli import tm_search as T

ROWS = [
    ("US", "1", "QUICK", "registered", ["29"], "2001-01-01"),
    ("US", "2", "KWIK'PAK", "registered", ["29"], "2002-01-01"),
    ("US", "3", "ANTERIOR", "registered", ["42"], "2024-01-01"),
    ("US", "4", "ANTERION", "registered", ["9", "42"], "2019-01-01"),
    ("US", "5", "Anteriora Labs", "pending", ["42"], "2026-01-01"),
    ("US", "6", "SOUNDPAIR " + "ROYALTY FREE MUSIC MEETS PARODY LYRICS " * 20, "pending", ["42"], "2026-01-01"),
    ("US", "7", "ZEBRA", "registered", ["9"], "2010-01-01"),
    ("FR", "8", "Antériora", "registered", ["45"], "2025-01-01"),
    ("US", "9", "ANTERIOR", "registered", ["35"], "2024-02-01"),
]


@pytest.fixture
def index(tmp_path):
    path = tmp_path / "tm.sqlite"
    T.build(iter(ROWS), path, "2026-09-30", ["test register"])
    return T.Index(path)


def test_spelling_and_accents_and_spacing_do_not_hide_a_mark(index):
    r = index.search("anteriora")
    by_number = {h["number"]: h for h in r["hits"]}
    assert by_number["8"]["reasons"][0] == "same spelling"                 # Antériora, accent folded
    assert "shares the word “anteriora”" in "; ".join(by_number["5"]["reasons"])
    assert "spelled closely" in by_number["3"]["reasons"] and "is contained in your name" in by_number["3"]["reasons"]
    assert "7" not in by_number                                             # ZEBRA is not close


def test_a_sound_alike_is_found_and_says_so(index):
    r = index.search("Kwik")
    by_number = {h["number"]: h for h in r["hits"]}
    assert "sounds alike" in by_number["1"]["reasons"]                      # QUICK
    assert any("kwik" in x for x in by_number["2"]["reasons"])              # KWIK'PAK shares the word


def test_a_long_composite_mark_is_not_close_because_it_is_long(index):
    assert "6" not in {h["number"] for h in index.search("Probant")["hits"]}
    assert "6" not in {h["number"] for h in index.search("Anteriora")["hits"]}
    assert T.similarity("anteriora", "x" * 900) == 0.0


def test_marks_in_the_classes_asked_about_come_first(index):
    r = index.search("Anteriora", ["9", "42"])
    order = [h["number"] for h in r["hits"]]
    overlapping = [h["number"] for h in r["hits"] if h["overlapping_classes"]]
    assert order[:len(overlapping)] == overlapping and set(overlapping) == {"3", "4", "5"}
    assert r["classes"] == ["9", "42"]


def test_the_same_search_returns_the_same_list(index):
    first = index.search("Anteriora", ["42"])
    assert all(index.search("Anteriora", ["42"]) == first for _ in range(5))


def test_the_report_states_coverage_and_never_gives_a_verdict(index):
    text = "\n".join(T.report_lines(index.search("Anteriora", ["42"])))
    assert "data as of 2026-09-30" in text and "was not sent anywhere" in text and "Not searched:" in text
    for word in ("available", "is clear", "cleared", "no risk", "likely to be confused", "safe to use"):
        assert word not in text.lower().replace("not an opinion on whether you can use", "")
    empty = "\n".join(T.report_lines(index.search("Xylophonique")))
    assert "No close registered word marks found in this data." in empty
    assert "does not mean the name is free to use" in empty                # an empty list is not a clearance


def test_every_register_not_in_the_data_is_named_as_not_searched():
    us_fr = T.coverage("USPTO (United States), live word marks; INPI (France), live word marks")
    assert len(us_fr["searched"]) == 2
    assert "EU trade marks (EUIPO)" in us_fr["not_searched"]
    assert any("WIPO Madrid" in x for x in us_fr["not_searched"])
    assert {"company and trading names", "domain names", "unregistered use of a name"} <= set(us_fr["not_searched"])
    with_eu = T.coverage("USPTO; INPI; EUIPO (European Union)")
    assert "EU trade marks (EUIPO)" in with_eu["searched"] and "EU trade marks (EUIPO)" not in with_eu["not_searched"]
    assert T.coverage("")["searched"] == []


def test_a_search_opens_no_network_connection(index, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a name check tried to open a network connection")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert index.search("Anteriora")["hits"]


def test_the_sound_key_groups_the_spellings_it_should_and_not_others():
    assert T.sound("Kwik") == T.sound("Quick") == T.sound("Kwick")
    assert T.sound("Fone") == T.sound("Phone")
    assert T.sound("Chick") != T.sound("Kwik")
    assert T.sound("Christal") == T.sound("Kristal")


def test_the_command_prints_the_report_and_refuses_without_an_index(index, tmp_path, monkeypatch, capsys):
    path = tmp_path / "tm.sqlite"
    assert S.main(["names", "Anteriora", "--class", "42", "--index", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ANTERIOR" in out and "[your classes: 42]" in out
    assert S.main(["names", "Anteriora", "--index", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["hits"]
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "nohome"))
    monkeypatch.delenv("IR_TM_INDEX", raising=False)
    rc = S.main(["names", "Anteriora"])
    assert rc != 0 and "no trademark index is installed" in capsys.readouterr().err


def test_a_name_made_of_common_fragments_is_still_found(tmp_path, monkeypatch):
    # On the 5.7M-mark index "ant", "ara" and friends are held by hundreds of thousands of marks. A version that
    # skipped such fragments, and still counted them in its threshold, returned nothing for "Anteriora".
    filler = [("US", str(100 + i), f"ANTARA{i:03d}X", "registered", ["1"], "") for i in range(60)]
    path = tmp_path / "busy.sqlite"
    T.build(iter(ROWS + filler), path, "2026-09-30", ["test"])
    monkeypatch.setattr(T, "MAX_CANDIDATES", 10)                 # the cap must keep the closest, not the first
    hits = {h["number"] for h in T.Index(path).search("Anteriora")["hits"]}
    assert {"3", "4"} <= hits                                        # ANTERIOR, ANTERION


def test_a_close_sound_key_alone_is_not_called_close():
    path_rows = [("FR", "1", "Annuaire EHRET", "registered", ["42"], "")]
    import tempfile, pathlib
    p = pathlib.Path(tempfile.mkdtemp()) / "x.sqlite"
    T.build(iter(path_rows), p, "d", ["t"])
    assert not T.Index(p).search("Antériorité")["hits"]


def test_the_fine_sound_key_hears_kw_and_keeps_vowels():
    # The index's key reads every vowel as "a" and "qu" as "k", so Kwik, Quick, Kick and Cake all read "kak";
    # on the real index KICK, KEEK and CAKE were reported as sounding like "Kwik".
    assert T.sound_fine("Kwik") == T.sound_fine("Quick") == T.sound_fine("Qwik") == T.sound_fine("Kwyk")
    assert T.sound_fine("Kick") != T.sound_fine("Kwik") != T.sound_fine("Cake")
    assert T.sound_fine("Zoum") == T.sound_fine("Zoom") and T.sound_fine("Konto") == T.sound_fine("Qonto")
    assert T.sound_fine("Danon") == T.sound_fine("Danone") and T.sound_fine("Stryp") == T.sound_fine("Stripe")


def _index_of(tmp_path, rows):
    path = tmp_path / "x.sqlite"
    T.build(iter(rows), path, "2026-09-30", ["test"])
    return T.Index(path)


def test_a_mark_that_sounds_the_same_ranks_above_one_that_only_contains_the_name(tmp_path):
    ix = _index_of(tmp_path, [("US", "1", "KWIK SEW", "registered", ["9"], ""),
                              ("US", "2", "QUICK", "registered", ["9"], ""),
                              ("US", "3", "KICK", "registered", ["9"], ""),
                              ("US", "4", "CAKE", "registered", ["9"], "")])
    hits = ix.search("Kwik", ["9"])["hits"]
    order = [h["number"] for h in hits]
    assert order.index("2") < order.index("1")                   # QUICK ranked 78th on the real index before
    reasons = {h["number"]: h["reasons"] for h in hits}
    assert reasons["2"] == ["sounds alike"]
    assert "sounds alike" not in reasons.get("3", []) and "4" not in reasons


def test_containing_the_name_means_containing_it_within_words(tmp_path):
    ix = _index_of(tmp_path, [("FR", "1", "Amplitude Anterior Approche", "registered", ["10"], ""),
                              ("US", "2", "AIR BNB", "registered", ["43"], ""),
                              ("US", "3", "ECHLORIAL", "registered", ["3"], ""),
                              ("US", "4", "L'OREAL", "registered", ["3"], "")])
    assert not ix.search("Anteriora")["hits"]                 # the letters only run on across a space
    assert ix.search("Airbnb")["hits"][0]["number"] == "2"
    order = [h["number"] for h in ix.search("Lorial", ["3"])["hits"]]
    assert order.index("4") < order.index("3")               # the name inside a longer word ranks low


EVAL_INDEX = __import__("os").environ.get("IR_TM_EVAL_INDEX") or str(__import__("pathlib").Path.home() / "anteriora-tmdata" / "index-us-fr.sqlite")


@pytest.mark.skipif(not __import__("os").path.isfile(EVAL_INDEX), reason="needs a built index (IR_TM_EVAL_INDEX)")
def test_the_evaluation_set_on_the_built_index(capsys):
    """tests/data/tm_eval.json against the real index (about a minute and a half). Measured 2026-10-20 on the
    US+FR index of 5,741,201 marks: before tuning 49/52 obvious conflicts in the top 20 (Kwik/QUICK 78th,
    Picaro/PICASSO and Karfour/CARREFOUR never scored) and 5 false same-sound claims for
    invented names (OSCAR ONO, TRUE VILLAINS); after, 52/52 and none. Median search 1.1 s before, 1.5 s after."""
    import importlib.util
    import pathlib
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("tm_eval", here.parent / "tools" / "tm_eval.py")
    tm_eval = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tm_eval)
    data = json.loads((here / "data" / "tm_eval.json").read_text())
    got = tm_eval.evaluate(T.Index(EVAL_INDEX), data)
    assert got["recall"] == got["of"], {k: v for k, v in got["ranks"].items() if not v or v > 20}
    assert not any(got["clean_strong"].values()), got["clean_strong"]


def test_searches_running_at_once_all_answer(index):
    # A name session searches its variants in parallel; one shared SQLite connection made most of them fail.
    from concurrent.futures import ThreadPoolExecutor
    names = ["Kwik", "Anteriora", "Quick", "Zebra", "Anterion", "Kwick", "Anteriore", "Zebras"] * 3
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda n: index.search(n, ["9", "42"]), names))
    assert all(r["name"] == n for r, n in zip(results, names))


def test_each_search_is_kept_where_the_matter_page_reads_it(index, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    T.install_route(app, index.path, tmp_path / "records")
    c = TestClient(app)
    assert c.post("/probant/tm/search", json={"name": "Kwik", "classes": ["29"]}).status_code == 200
    assert c.post("/probant/tm/search", json={"name": "Anteriora"}).status_code == 200
    assert c.post("/probant/tm/search", json={"name": "Kwik", "classes": ["29"]}).status_code == 200
    got = T.logged_searches(tmp_path / "records")
    assert [g["name"] for g in got] == ["Kwik", "Anteriora"]          # latest per name and classes, newest first
    kwik = got[0]
    assert kwik["classes"] == ["29"] and kwik["data_date"] == "2026-09-30"
    assert {h["number"] for h in kwik["hits"]} >= {"1", "2"}           # QUICK, KWIK'PAK as the search returned them
    assert T.logged_searches(tmp_path / "nothing") == []
