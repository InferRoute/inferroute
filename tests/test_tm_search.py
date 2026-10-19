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
