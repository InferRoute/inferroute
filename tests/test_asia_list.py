"""The Asian layer's own list (sealed-research fbe365c, index asia-2611).

On a root carrying the layer, every search result carries `asia`: CN/JP/KR/TW DOCDB families with no US/EP/WO member,
ranked by dense similarity alone — not citation-expanded, not reranked — and NEVER merged into the main ranking, which
is scoped to US/EP/WO on that root. `offices_unindexed` names requested offices nothing indexes. On an older root
neither key is present and the reply is unchanged.

These pin, for the extension (what the terminal and the assistant get, and the page's `details`), the page and the
export, each state the reader can meet:
  (a) a list with hits;  (b) Asian offices searched, none back;  (c) no Asian office requested;
  (d) a CN-only search, where 0 main hits is not "nothing found";  (e) an office the index does not hold;
  (f) an older root: nothing about Asia at all;
and that an Asian hit never appears in the main ranking's rendering. The wording rules are checked over every
sentence the three files use for this list.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TS = ROOT / "inferroute_cli" / "pi_attested" / "ir-attested.ts"
JS = ROOT / "inferroute_cli" / "probant_web" / "app.js"
PY = ROOT / "inferroute_cli" / "probant_export.py"

HEADING = "Separate list: CN, JP, KR and TW patent families"
SEPARATE = "A separate list, not part of the ranking above, and never merged into it."
CLASS = ("It holds patent families from CN, JP, KR and TW that have no US, EP or WO member, matched on their "
         "English title + abstract (some have a title only).")
RANK = "Ranked by dense similarity alone: not citation-expanded and not reranked."
NOT_REQUESTED = "CN, JP, KR and TW families were not requested in this search, so this list was not searched."
UNLABELLED = "A separate list came back without the labels this page needs to describe it, so it is not shown."


def _node():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    return node


@pytest.fixture(scope="module")
def ext():
    r = subprocess.run([_node(), "--experimental-strip-types", str(ROOT / "tests" / "asia_list_sim.ts")],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "strip-types" in r.stderr:
        pytest.skip("this node cannot strip TypeScript")
    assert r.returncode == 0, r.stdout + r.stderr[-800:]
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def page():
    r = subprocess.run([_node(), str(ROOT / "tests" / "asia_list_page_sim.js")],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr[-800:]
    return json.loads(r.stdout)


def _asia(offices, hits):
    return {"kind": "dense_only", "expanded": False, "reranked": False, "offices": offices, "k": 20, "hits": hits}


def _hit(i, **extra):
    return {"key": f"CN-10{i}-A", "score": 0.8, "scores": {"dense": 0.8}, "legs": ["semantic"], "source": "patent",
            "year": 2018, "date_known": True, "title": f"Heat sink {i}", "text": f"Heat sink {i}. An abstract.", **extra}


# ── the same sentences everywhere ───────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sentence", [HEADING, SEPARATE, CLASS, RANK, NOT_REQUESTED, UNLABELLED])
def test_the_extension_the_page_and_the_export_use_one_set_of_sentences(sentence):
    js, ts = JS.read_text(), TS.read_text()
    py = PY.read_text()
    from inferroute_cli import probant_export as E
    assert sentence in ts, "ir-attested.ts"
    assert sentence in js, "app.js"
    assert sentence in {E.ASIA_HEADING, E.ASIA_SEPARATE, E.ASIA_CLASS, E.ASIA_RANK, E.ASIA_NOT_REQUESTED,
                        E.ASIA_UNLABELLED}, "probant_export.py"
    assert py  # read, so a moved constant fails above rather than here


def _asia_blocks():
    ts, js, py = TS.read_text(), JS.read_text(), PY.read_text()
    out = []
    for src, start, end in ((ts, "// ── the Asian list ──", "// ── end Asian list ──"),
                            (js, "  // ── the Asian list ──", "  // ── end Asian list ──"),
                            (py, "# ── the Asian list ──", "# ── end Asian list ──")):
        a = src.index(start)
        out.append(src[a:src.index(end, a)])
    # what the assistant is told after the list, in hitsText
    a = ts.index("// The Asian list (asia root only), AFTER the ranking")
    out.append(ts[a:ts.index("return lines.join", a)])
    return out


def _strings(block):
    """The string literals of a block (what a reader can be shown), not its comments."""
    lits = re.findall(r'"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`', block)
    return " ".join(a or b for a, b in lits)


@pytest.mark.parametrize("pattern", [
    r"full[- ]text", r"translat", r"machine[- ]", r"official", r"native", r"\bin (Chinese|Japanese|Korean)\b",
    r"searchable", r"complete", r"full coverage", r"all (Asian|CN)", r"Chutes", r"no Asian results",
    r"\b\d[\d.,]*\s*(M|million|bn|publications|families)\b",
])
def test_no_forbidden_claim_in_any_sentence_about_the_asian_list(pattern):
    """WORDING RULES (hard): English title + abstract, never full text; no native-language search; nothing about
    who produced the English text; never complete coverage; no numbers bound to one index; no vendor name."""
    for block in _asia_blocks():
        text = _strings(block)
        assert not re.search(pattern, text, re.I), (pattern, re.search(pattern, text, re.I))


def test_every_description_of_the_list_says_dense_only_not_expanded_not_reranked_not_merged():
    for block in _asia_blocks()[:3]:
        assert RANK in block or "ASIA_RANK" in block
        assert "never merged into it" in block


# ── the extension: what the terminal card and the assistant are told, and the page's details ────────────────────

def test_a_list_with_hits_is_its_own_section_numbered_apart(ext):            # state (a)
    s = ext["with_hits"]
    assert s["notes"] == [HEADING, SEPARATE, CLASS, RANK, "Searched for this list: CN, JP, KR and TW."]
    assert s["rows"][0] == "A1. CN-101-A (2018) Heat sink 1 [family of 2 publications]"
    # the true family size, not the capped member list's length
    assert s["rows"][1].endswith("[family of 90 publications]")
    assert s["rows"][2] == "A3. CN-103-A (2018) Heat sink 3"


def test_offices_searched_with_none_back_is_said_and_is_not_absence(ext):    # state (b)
    assert ext["empty"]["notes"] == [HEADING, "This list is empty for this search: CN and JP were searched and no "
                                              "family came back. That is not evidence that none exists."]
    assert ext["empty"]["rows"] == []


def test_no_asian_office_requested_says_not_requested_not_no_results(ext):  # state (c)
    s = ext["not_requested"]
    assert s["notes"] == [HEADING, NOT_REQUESTED]
    assert not any("empty" in n or "no family" in n for n in s["notes"])


def test_a_cn_only_search_does_not_read_as_nothing_found(ext):              # state (d)
    s = ext["cn_only"]
    assert s["docKeys"] == []
    assert s["notes"][0] == ("No US, EP or WO ranking ran: this search asked only for CN. "
                             "Its results are in the separate list below.")
    assert s["rows"] == ["A1. CN-101-A (2018) Heat sink 1"]
    assert "0 references above does not mean nothing was found" in s["model"]


def test_an_office_nothing_indexes_is_named_plainly(ext):                   # state (e)
    s = ext["unindexed"]
    assert "Not in this index: DE. Nothing from this office was searched." in s["notes"]
    assert s["notes"][0] == "No US, EP or WO ranking ran: this search asked only for DE."
    assert "separate list below" not in s["notes"][0]          # nothing Asian ran either


def test_an_older_root_says_nothing_about_asia(ext):                        # state (f)
    s = ext["old_root"]
    assert s["part"] == {} and s["notes"] == [] and s["rows"] == [] and s["spAsia"] is None
    assert not re.search(r"CN|JP|KR|TW|Asia|separate list", s["model"])


def test_a_list_without_its_labels_is_not_shown_under_them(ext):
    s = ext["unlabelled"]
    assert s["part"] == {"asiaUnlabelled": True}
    assert s["notes"] == [UNLABELLED] and s["rows"] == []
    assert "CN-101-A" not in s["model"]


def test_an_asian_hit_never_enters_the_main_ranking(ext):
    """`docs` is what the page's ranking, the marks, "also in", the results panel and the session's document count
    read; the assistant's numbered list is the ranking. An Asian key must be in neither."""
    for name, s in ext.items():
        assert not any(k.startswith("CN-") for k in s["docKeys"]), name
        ranked = [ln for ln in s["model"].splitlines() if re.match(r"^\d+\. ", ln)]
        assert not any("CN-10" in ln for ln in ranked), name
    model = ext["with_hits"]["model"]
    assert model.index("1. US-1-A") < model.index(HEADING) < model.index("A1. CN-101-A")


def test_the_deep_press_carries_each_legs_list_beside_its_docs_not_into_the_union():
    ts = TS.read_text()
    a = ts.index("for (const d of r.sp.docs) {\n\t\t\t\t\tif (!union.has(d.key))")
    leg = ts[a:ts.index("blocks.push(hitsText(", a)]
    assert "asia: r.sp.asia" in leg and "docs: r.sp.docs" in leg
    assert "r.sp.asia" not in leg[:leg.index("results.push")], "the union is built from the ranking only"


# ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_page_a_list_with_hits(page):                                        # state (a)
    s = page["with_hits"]
    assert s["section"].startswith(f"{HEADING} {SEPARATE} {CLASS} {RANK} Searched for this list: CN, JP, KR and TW.")
    assert s["ranks"] == ["A1", "A2", "A3"]
    assert s["marks"] == 0 and s["keyLinks"] == 0, "the ranking's controls are not on this list"
    assert s["families"] == [["family of 3 publications", "CN-101-A, JP-2001-A, KR-3-B"],
                             ["family of 70 publications", "TW-9-A and 69 more"]]
    assert all("separate list only" in t for t in s["barTitles"])
    assert s["note"] is None


def test_page_offices_searched_none_back(page):                              # state (b)
    assert page["empty"]["section"] == (f"{HEADING} This list is empty for this search: CN and JP were searched and "
                                        "no family came back. That is not evidence that none exists.")


def test_page_no_asian_office_requested(page):                               # state (c)
    assert page["not_requested"]["section"] == f"{HEADING} {NOT_REQUESTED}"


def test_page_cn_only(page):                                                 # state (d)
    s = page["cn_only"]
    assert s["note"] == "No US, EP or WO ranking ran: this search asked only for CN. Its results are in the separate list below."
    assert s["ranks"] == ["A1"]


def test_page_offices_unindexed(page):                                       # state (e)
    assert page["unindexed"]["section"].endswith("Not in this index: DE. Nothing from this office was searched.")
    assert page["unindexed"]["note"] == "No US, EP or WO ranking ran: this search asked only for DE."
    assert page["unindexed_two"]["section"].endswith("Not in this index: DE and FR. Nothing from these offices was searched.")


def test_page_older_root_draws_nothing(page):                                # state (f)
    assert page["old_root"] == {"section": None, "note": None, "ranks": [], "marks": 0, "keyLinks": 0,
                                "families": [], "barTitles": []}


def test_page_unlabelled(page):
    assert page["unlabelled"]["section"] == UNLABELLED


def test_page_builds_the_ranking_from_docs_and_the_list_from_asia_only():
    """The main rows are built from `d.docs` alone; the Asian section is appended AFTER the ranking and its footnote,
    in the search card and in each deep-search leg, and the family badge is on the Asian rows only."""
    js = JS.read_text()
    assert js.count("familyOf(doc), title") == 1, "the family badge is on the Asian rows only (main hits carry none)"
    card = js[js.index("    const docs = Array.isArray(d.docs) ? d.docs : [];"):js.index("entry.keys = docs.map(")]
    assert card.index('"card-foot", "Mark what matters') < card.index("asiaSection(d)")
    assert "asia" not in card[:card.index('"card-foot", "Mark what matters')]
    leg = js[js.index("const docs = leg.docs || [];"):js.index("e.body.append(block);")]
    assert leg.index("legBody.append(list);") < leg.index("asiaSection(leg)")


# ── the export ───────────────────────────────────────────────────────────────────────────────────────────────────

def _export(result):
    from inferroute_cli import probant_export as E
    return E._asia_html(result)


def test_export_states():
    a = _export({"hits": [], "offices": None, "offices_unindexed": [],
                 "asia": _asia(["CN", "JP", "KR", "TW"], [_hit(1, family_members=["CN-101-A", "JP-1-A"],
                                                                    family_members_total=5)])})
    assert HEADING in a and SEPARATE in a and RANK in a and "English title + abstract" in a
    assert "<td>A1</td>" in a and "family of 5 publications" in a                          # (a)
    b = _export({"hits": [], "offices": ["CN", "US"], "asia": _asia(["CN"], [])})
    assert "This list is empty for this search: CN was searched and no family came back." in b   # (b)
    c = _export({"hits": [], "offices": ["US"], "asia": _asia([], [])})
    assert NOT_REQUESTED in c and "empty" not in c                                           # (c)
    d = _export({"hits": [], "offices": ["CN"], "asia": _asia(["CN"], [_hit(1)])})
    assert "No US, EP or WO ranking ran: this search asked only for CN. Its results are in the separate list below." in d
    e = _export({"hits": [], "offices": ["DE"], "offices_unindexed": ["DE"], "asia": _asia([], [])})
    assert "Not in this index: DE. Nothing from this office was searched." in e             # (e)
    assert _export({"hits": [{"key": "US-1-A"}]}) == "" and _export(None) == ""             # (f)
    bad = _asia(["CN"], [_hit(1)])
    bad["reranked"] = True
    assert UNLABELLED in _export({"hits": [], "asia": bad}) and "CN-101-A" not in _export({"hits": [], "asia": bad})


def test_export_escapes_what_the_engine_sent():
    a = _export({"hits": [], "asia": _asia(["CN"], [_hit(1, title="<script>x</script>")])})
    assert "<script>" not in a and "&lt;script&gt;" in a


def test_the_per_search_report_shows_the_main_ranking_only():
    """The report rendered for each search (sealed-research's search_report) reads `hits`; an Asian hit in `asia`
    must not appear in it. The export then adds the Asian list after it, as its own section."""
    from inferroute_cli._vendor.sealedresearch import search_report
    import inspect
    src = inspect.getsource(search_report)
    assert '"asia"' not in src and "'asia'" not in src
    py = PY.read_text()
    a = py.index('A("<p class=note>No report was rendered for this search.</p>")')
    assert "_asia_html(x.get(\"result\"))" in py[a:a + 400]


def test_the_wording_scan_reads_the_sentences_it_claims_to_check():
    """Positive control for the forbidden-claim scan: it must actually see the list's sentences in every block, or a
    clean scan would mean nothing (an extractor that matched no literal would pass every pattern)."""
    blocks = _asia_blocks()
    assert len(blocks) == 4
    for block in blocks:
        assert "English title + abstract" in _strings(block)
    assert re.search(r"full[- ]text", _strings('"the full text"'))


def test_the_home_page_limits_no_longer_say_no_other_office_is_ever_shown():
    """Home's "Limits right now" said patent search covers US, EP and WO "not other national offices" — false beside a
    search card showing a CN/JP/KR/TW list. It now bounds the RANKED results and names the separate list without
    naming Asia, so it stays true on an index without the layer too."""
    home = (ROOT / "inferroute_cli" / "probant_web" / "home.js").read_text()
    assert "not other national offices" not in home
    assert ("its ranked results cover US, EP and WO publications to mid-April 2026. Documents from any other office "
            "appear only as a separate list under a search's ranked results, when that search shows one.") in home
