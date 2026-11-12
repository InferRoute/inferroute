"""The root's side lists (sealed-research d5a8fb7, open_rank/side_lists.py): `fr` first.

A root may carry `side_lists`: name -> one exact, dense-only list of a national office's families with no US/EP/WO
member. Every declared list runs on every search; when the request's scope left its offices out, `offices` is [] and
`hits` is empty (= not requested). These pin that the extension (terminal card, assistant, the page's `details`), the
page and the export show it by the Asian list's rules exactly: its own heading and "F1." numbering, never in the
ranking, the marks or the counts; only a name with words is shown, and any other name — or a block without
kind/exact/expanded/reranked/hits — gets the unlabelled sentence; an older result says nothing about France at all.
tests/asia_list_sim.ts and tests/asia_list_page_sim.js run the shipped blocks (fixtures `ext` / `page` below).
"""
import re

import pytest

from tests.test_asia_list import JS, PY, TS, UNLABELLED, ext, page  # noqa: F401  (fixtures)

FR_HEADING = "Separate list: French patent families"
FR_SEPARATE = "A separate list, not part of the ranking above, and never merged into it."
FR_CLASS = ("It holds French patent families that have no US, EP or WO member, matched on the English title + abstract "
            "of a French publication. Most were first published between 1970 and 2019.")
FR_RANK = "Ranked by dense similarity alone, with every family in the list scored: not citation-expanded and not reranked."
FR_NOT_REQUESTED = "French families were not requested in this search, so this list was not searched."
FR_EMPTY = ("This list is empty for this search: FR was searched and no family came back. That is not evidence that "
            "none exists.")
FR_NO_MARKS = "These rows cannot be marked or opened."
SEPARATE_NO_MAIN = "A separate list; no US, EP or WO ranking ran in this search."
FRENCH = re.compile(r"French|\bFR\b|France|F\d+\.")


@pytest.mark.parametrize("sentence", [FR_HEADING, FR_CLASS, FR_RANK, FR_NOT_REQUESTED])
def test_the_three_surfaces_use_one_set_of_fr_sentences(sentence):
    from inferroute_cli import probant_export as E
    assert sentence in TS.read_text(), "ir-attested.ts"
    assert sentence in JS.read_text(), "app.js"
    assert sentence in {E.FR_HEADING, E.FR_CLASS, E.FR_RANK, E.FR_NOT_REQUESTED}, "probant_export.py"


def test_the_shared_sentences_are_the_asian_lists_own():
    from inferroute_cli import probant_export as E
    assert E.FR_SEPARATE == E.ASIA_SEPARATE == FR_SEPARATE and E.FR_NO_MARKS == E.ASIA_NO_MARKS == FR_NO_MARKS
    for src in (TS.read_text(), JS.read_text()):
        assert "const FR_SEPARATE = ASIA_SEPARATE;" in src
    assert "const FR_NO_MARKS = ASIA_NO_MARKS;" in JS.read_text()


def test_only_fr_has_words():
    """Generic over side_lists, but only a name with words is ever shown."""
    from inferroute_cli import probant_export as E
    assert set(E.SIDE_WORDS) == {"fr"}
    for src in (TS.read_text(), JS.read_text()):
        a = src.index("SIDE_WORDS")
        block = src[a:src.index("};", a)]
        assert re.findall(r"^\s*(\w+): \{ heading", block, re.M) == ["fr"]


# ── the extension ───────────────────────────────────────────────────────────────────────────────────────────────

def test_ext_fr_with_hits_is_its_own_section_after_the_asian_one(ext):
    s = ext["fr_hits"]
    assert s["side"] == [{"notes": [FR_HEADING, FR_SEPARATE, FR_CLASS, FR_RANK, "Searched for this list: FR."],
                          "rows": ["F1. FR-2001-A1 (1994) Echangeur 1 [2 French publications in this family]",
                                   "F2. FR-2002-A1 (1994) Echangeur 2"]}]
    assert [x["name"] for x in s["spSide"]] == ["fr"]
    assert not any(k.startswith("FR-") for k in s["docKeys"]), "an FR row never enters the ranking's docs"
    m = s["model"]
    assert m.index("1. US-1-A") < m.index("A1. CN-101-A") < m.index(FR_HEADING) < m.index("F1. FR-2001-A1")
    ranked = [ln for ln in m.splitlines() if re.match(r"^\d+\. ", ln)]
    assert not any("FR-" in ln for ln in ranked)
    t = "\n".join(s["terminal"])
    assert t.index("A1. CN-101-A") < t.index(FR_HEADING) < t.index("F1. FR-2001-A1")
    assert t.count("(these rows cannot be marked)") == 2


def test_ext_fr_not_requested(ext):
    s = ext["fr_not_requested"]
    assert s["side"] == [{"notes": [FR_HEADING, FR_NOT_REQUESTED], "rows": []}]
    assert FR_NOT_REQUESTED in s["model"] and "empty" not in " ".join(s["side"][0]["notes"])


def test_ext_fr_empty_is_not_absence(ext):
    assert ext["fr_empty"]["side"] == [{"notes": [FR_HEADING, FR_EMPTY], "rows": []}]


def test_ext_fr_only_search_does_not_read_as_nothing_found(ext):
    s = ext["fr_only"]
    assert s["notes"][0] == ("No US, EP or WO ranking ran: this search asked only for FR. "
                             "Its results are in the separate list below.")
    assert s["side"][0]["notes"][1] == SEPARATE_NO_MAIN
    assert s["side"][0]["rows"] == ["F1. FR-2001-A1 (1994) Echangeur 1"]
    assert "Not in this index" not in s["model"], "FR is a side list's office, not unindexed"


def test_ext_fr_without_an_asian_layer(ext):
    s = ext["fr_no_asia"]
    assert s["notes"] == [] and s["side"][0]["notes"][0] == FR_HEADING
    assert not re.search(r"CN|JP|KR|TW", s["model"])
    assert FR_HEADING in "\n".join(s["terminal"])


@pytest.mark.parametrize("name", ["side_unknown", "fr_no_exact"])
def test_ext_an_unknown_or_unlabelled_side_list_is_not_shown(ext, name):
    s = ext[name]
    assert s["part"].get("sideUnlabelled") is True and "side" not in s["part"]
    assert s["side"] == [{"notes": [UNLABELLED], "rows": []}]
    assert FR_HEADING not in s["model"] and "FR-2001-A1" not in s["model"] and "DE-1-A" not in s["model"]
    assert "FR-2001-A1" not in "\n".join(s["terminal"])


def test_ext_the_unlabelled_sentence_is_said_once(ext):
    s = ext["both_unlabelled"]
    assert s["notes"] == [UNLABELLED] and s["side"] == []
    assert s["model"].count(UNLABELLED) == 1


def test_ext_an_older_result_says_nothing_about_france(ext):
    for name in ("old_root", "with_hits", "cn_only", "unlabelled"):
        s = ext[name]
        assert s["side"] == [] and s["spSide"] is None and "side" not in s["part"] and "sideUnlabelled" not in s["part"]
        assert not FRENCH.search(s["model"]), name
        assert not FRENCH.search("\n".join(s["terminal"])), name


def test_the_deep_press_carries_each_legs_side_lists_beside_its_docs_not_into_the_union():
    ts = TS.read_text()
    a = ts.index("for (const d of r.sp.docs) {\n\t\t\t\t\tif (!union.has(d.key))")
    leg = ts[a:ts.index("blocks.push(hitsText(", a)]
    assert "side: r.sp.side" in leg and "sideUnlabelled: r.sp.sideUnlabelled" in leg
    assert "r.sp.side" not in leg[:leg.index("const asiaOnly")]


def test_an_fr_key_is_refused_for_like_and_read_by_its_own_list():
    ts = TS.read_text()
    assert "for (const sl of sp.side ?? []) for (const d of sl.docs) sideKeys.set(" in ts
    for v in ("like", "key"):
        assert ts.count(f"if (sideKeys.has({v})) throw new Error(sideKeyRefusal({v}, String(sideKeys.get({v}))));") == 1
    assert "`${key} is in a search's separate list of ${list}, not in a ranking." in ts
    assert 'list: "French patent families"' in ts


def test_the_tool_description_says_french_only_conditionally():
    ts = TS.read_text()
    a = ts.index('name: "prior_art_search"')
    desc = ts[a:ts.index("promptSnippet", a)]
    assert "When the \" +\n\t\t\t\"answering index carries it, French national patent families" in desc


# ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_page_fr_with_hits(page):
    s = page["fr_hits"]["side"]
    assert len(s) == 1
    assert s[0]["section"].startswith(f"{FR_HEADING} {FR_SEPARATE} {FR_CLASS} {FR_RANK} Searched for this list: FR.")
    assert s[0]["section"].endswith(FR_NO_MARKS)
    assert s[0]["ranks"] == ["F1", "F2"] and s[0]["marks"] == 0 and s[0]["keyLinks"] == 0
    assert s[0]["families"] == [["4 French publications in this family", "FR-2001-A1, FR-2001-B1 and 2 more"]]
    assert page["fr_hits"]["ranks"] == ["A1"], "the Asian section keeps its own rows"


def test_page_fr_states(page):
    assert page["fr_not_requested"]["side"][0]["section"] == f"{FR_HEADING} {FR_NOT_REQUESTED}"
    assert page["fr_empty"]["side"][0]["section"] == f"{FR_HEADING} {FR_EMPTY}"
    s = page["fr_only"]
    assert s["note"] == "No US, EP or WO ranking ran: this search asked only for FR. Its results are in the separate list below."
    assert s["side"][0]["section"].startswith(f"{FR_HEADING} {SEPARATE_NO_MAIN}")


def test_page_unknown_and_unlabelled(page):
    for name in ("side_unknown", "side_unlabelled"):
        assert [x["section"] for x in page[name]["side"]] == [UNLABELLED], name
    assert page["both_unlabelled"]["side"] == [] and page["both_unlabelled"]["section"] == UNLABELLED


def test_page_older_search_draws_no_side_list(page):
    for name in ("old_root", "with_hits", "unlabelled"):
        assert page[name]["side"] == [], name


def test_page_appends_side_lists_after_the_asian_list():
    js = JS.read_text()
    card = js[js.index("    const docs = Array.isArray(d.docs) ? d.docs : [];"):js.index("entry.keys = docs.map(")]
    assert card.index("asiaSection(d)") < card.index("sideSections(d)")
    leg = js[js.index("const docs = leg.docs || [];"):js.index("e.body.append(block);")]
    assert leg.index("legBody.append(list);") < leg.index("asiaSection(leg)") < leg.index("sideSections(leg)")


# ── the export ───────────────────────────────────────────────────────────────────────────────────────────────────

def _side(offices, hits, **over):
    return {"kind": "dense_only", "exact": True, "expanded": False, "reranked": False, "offices": offices, "k": 20,
            "rows": 1000, "hits": hits, **over}


def _fr(i, **extra):
    return {"key": f"FR-200{i}-A1", "score": 0.7, "scores": {"dense": 0.7}, "legs": ["semantic"], "source": "patent",
            "year": 1994, "date_known": True, "title": f"Echangeur {i}", "text": f"Echangeur {i}. An abstract.", **extra}


ASIA = {"kind": "dense_only", "expanded": False, "reranked": False, "offices": ["CN"], "k": 20, "hits": []}
IFR = "patent1m-asia-2611-fr-2611+epwo+usall@89000000"


def _export(result, offices=None):
    from inferroute_cli import probant_export as E
    return E._asia_html(result, {"offices": offices, "index_snapshot": IFR}, IFR)


def test_export_fr_states():
    a = _export({"hits": [], "asia": ASIA, "side_lists": {"fr": _side(["FR"], [
        _fr(1, family_members=["FR-2001-A1", "FR-2001-B1"], family_members_total=3), _fr(2)])}})
    assert a.index("CN, JP, KR and TW") < a.index(FR_HEADING)
    assert FR_SEPARATE in a and FR_CLASS in a and FR_RANK in a and "Searched for this list: FR." in a
    assert "<td>F1</td>" in a and "<td>F2</td>" in a and "<td>A1</td>" not in a
    assert "3 French publications in this family" in a and a.count(FR_NO_MARKS) == 1
    b = _export({"hits": [], "asia": ASIA, "side_lists": {"fr": _side([], [])}}, ["US", "CN"])
    assert FR_NOT_REQUESTED in b and "empty" not in b.split(FR_HEADING)[1]
    c = _export({"hits": [], "asia": ASIA, "side_lists": {"fr": _side(["FR"], [])}})
    assert FR_EMPTY in c
    d = _export({"hits": [], "asia": dict(ASIA, offices=[]), "side_lists": {"fr": _side(["FR"], [_fr(1)])}}, ["FR"])
    assert ("No US, EP or WO ranking ran: this search asked only for FR. Its results are in the separate list below."
            in d) and SEPARATE_NO_MAIN in d.split(FR_HEADING)[1]
    # a root with the side list and no Asian layer
    e = _export({"hits": [], "side_lists": {"fr": _side(["FR"], [_fr(1)])}})
    assert FR_HEADING in e and "CN" not in e and "<td>F1</td>" in e


@pytest.mark.parametrize("side_lists", [
    {"de": _side(["DE"], [_fr(1)])},                         # a name with no words here
    {"fr": {k: v for k, v in _side(["FR"], [_fr(1)]).items() if k != "exact"}},   # missing exact: true
    {"fr": _side(["FR"], [_fr(1)], exact=False)},
    {"fr": _side(["FR"], [_fr(1)], reranked=True)},
    {"fr": dict(_side(["FR"], [_fr(1)]), hits=None)},
    ["fr"],
])
def test_export_unknown_or_unlabelled_side_list_is_not_shown(side_lists):
    a = _export({"hits": [], "asia": ASIA, "side_lists": side_lists})
    assert a.count(UNLABELLED) == 1 and FR_HEADING not in a and "FR-2001-A1" not in a


def test_export_unlabelled_sentence_once_when_both_are_unlabelled():
    a = _export({"hits": [], "asia": dict(ASIA, reranked=True), "side_lists": {"fr": _side(["FR"], [], exact=None)}})
    assert a.count(UNLABELLED) == 1


def test_export_older_result_says_nothing_about_france():
    assert _export({"hits": [{"key": "US-1-A"}]}) == ""
    a = _export({"hits": [], "asia": dict(ASIA, hits=[])})
    assert not FRENCH.search(a)


def test_export_escapes_side_list_text():
    a = _export({"hits": [], "side_lists": {"fr": _side(["FR"], [_fr(1, title="<script>x</script>")])}})
    assert "<script>" not in a and "&lt;script&gt;" in a
