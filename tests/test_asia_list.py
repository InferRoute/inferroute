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
DATES = ("Families are dated by their earliest CN/JP/KR/TW publication; the list is dense to August 2026, and "
         "September and October 2026 are almost absent (about 3% and under 2% of a normal month), as of index 2611.")
I2611 = "patent1m-asia-2611+epwo+usall@88844190"
NO_MARKS = "These rows cannot be marked or opened."
COUNT_NOTE = ("The index identifier's row count includes this separate list's families; the ranking's pool is its "
              "US/EP/WO part only — do not quote that count as the size of the ranking.")
SEPARATE_NO_MAIN = "A separate list; no US, EP or WO ranking ran in this search."
HOME_LIMIT = ("Patent search reads each document's title and the start of its abstract, not the full text or the "
              "claims. Its ranked results cover US, EP and WO publications to late October 2026. Some search machines "
              "also return a short, separate list of patent families from a few further offices, shown under the "
              "ranking and labelled there with the offices it covers. Offices beyond US, EP and WO are searched only "
              "when that label names them; no other office is searched at all.")
ASIAN_KEY = re.compile(r"^(CN|JP|KR|TW)-")
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

@pytest.mark.parametrize("sentence", [HEADING, SEPARATE, SEPARATE_NO_MAIN, CLASS, DATES, RANK, NOT_REQUESTED, UNLABELLED])
def test_the_extension_the_page_and_the_export_use_one_set_of_sentences(sentence):
    js, ts = JS.read_text(), TS.read_text()
    py = PY.read_text()
    from inferroute_cli import probant_export as E
    assert sentence in ts, "ir-attested.ts"
    assert sentence in js, "app.js"
    assert sentence in {E.ASIA_HEADING, E.ASIA_SEPARATE, E.ASIA_SEPARATE_NO_MAIN, E.ASIA_CLASS, E.ASIA_DATES, E.ASIA_RANK,
                        E.ASIA_NOT_REQUESTED, E.ASIA_UNLABELLED}, "probant_export.py"
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
    # home's "Limits right now" line, which speaks about the separate list too
    home = (ROOT / "inferroute_cli" / "probant_web" / "home.js").read_text()
    a = home.index('list("Patent search reads each document')
    out.append(home[a:home.index("\n", a)])
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
        # Allowed text, removed before the scan: the dating sentence (its numbers are bound to "as of index 2611",
        # measured by sealed-research), and home's "not the full text" (a negation about the RANKED documents).
        text = _strings(block).replace(DATES, "").replace("not the full text or the claims", "")
        assert not re.search(pattern, text, re.I), (pattern, re.search(pattern, text, re.I))


def test_every_description_of_the_list_says_dense_only_not_expanded_not_reranked_not_merged():
    for block in _asia_blocks()[:3]:
        assert RANK in block or "ASIA_RANK" in block
        assert "never merged into it" in block


# ── the extension: what the terminal card and the assistant are told, and the page's details ────────────────────

def test_a_list_with_hits_is_its_own_section_numbered_apart(ext):            # state (a)
    s = ext["with_hits"]
    assert s["notes"] == [HEADING, SEPARATE, CLASS, DATES, RANK, "Searched for this list: CN, JP, KR and TW."]
    assert s["rows"][0] == "A1. CN-101-A (2018) Heat sink 1 [2 CN/JP/KR/TW publications in this family]"
    # the true family size, not the capped member list's length
    assert s["rows"][1].endswith("[90 CN/JP/KR/TW publications in this family]")
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
        assert not any(ASIAN_KEY.match(k) for k in s["docKeys"]), name
        ranked = [ln for ln in s["model"].splitlines() if re.match(r"^\d+\. ", ln)]
        assert not any(ASIAN_KEY.match(ln.split(" ", 2)[1]) for ln in ranked), name
    model = ext["with_hits"]["model"]
    assert model.index("1. US-1-A") < model.index(HEADING) < model.index("A1. CN-101-A")


def test_the_deep_press_carries_each_legs_list_beside_its_docs_not_into_the_union():
    ts = TS.read_text()
    a = ts.index("for (const d of r.sp.docs) {\n\t\t\t\t\tif (!union.has(d.key))")
    leg = ts[a:ts.index("blocks.push(hitsText(", a)]
    assert "asia: r.sp.asia" in leg and "docs: r.sp.docs" in leg
    union = leg[:leg.index("const asiaOnly")]
    assert "r.sp.asia" not in union and "union.set(d.key" in union, "the union is built from the ranking only"


# ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_page_a_list_with_hits(page):                                        # state (a)
    s = page["with_hits"]
    assert s["section"].startswith(f"{HEADING} {SEPARATE} {CLASS} {DATES} {RANK} Searched for this list: CN, JP, KR and TW.")
    assert s["ranks"] == ["A1", "A2", "A3"]
    assert s["marks"] == 0 and s["keyLinks"] == 0, "the ranking's controls are not on this list"
    assert s["families"] == [["3 CN/JP/KR/TW publications in this family", "CN-101-A, JP-2001-A, KR-3-B"],
                             ["70 CN/JP/KR/TW publications in this family", "TW-9-A and 69 more"]]
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

def _export(result, offices=None, index=I2611):
    """The export's Asian section; `offices` is the REQUEST's scope as the signed statement records it."""
    from inferroute_cli import probant_export as E
    return E._asia_html(result, {"offices": offices, "index_snapshot": index}, index)


def test_export_states():
    a = _export({"hits": [], "offices_unindexed": [],
                 "asia": _asia(["CN", "JP", "KR", "TW"], [_hit(1, family_members=["CN-101-A", "JP-1-A"],
                                                                    family_members_total=5)])})
    assert HEADING in a and SEPARATE in a and RANK in a and "English title + abstract" in a
    assert "<td>A1</td>" in a and "5 CN/JP/KR/TW publications in this family" in a and "CN/JP/KR/TW members" in a and DATES in a                         # (a)
    b = _export({"hits": [], "asia": _asia(["CN"], [])}, ["CN", "US"])
    assert "This list is empty for this search: CN was searched and no family came back." in b   # (b)
    c = _export({"hits": [], "asia": _asia([], [])}, ["US"])
    assert NOT_REQUESTED in c and "empty" not in c                                           # (c)
    d = _export({"hits": [], "asia": _asia(["CN"], [_hit(1)])}, ["CN"])
    assert "No US, EP or WO ranking ran: this search asked only for CN. Its results are in the separate list below." in d
    e = _export({"hits": [], "offices_unindexed": ["DE"], "asia": _asia([], [])}, ["DE"])
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
    assert '_asia_html(x.get("result"), stmt, x.get("index_snapshot"))' in py[a:a + 400]


def test_the_wording_scan_reads_the_sentences_it_claims_to_check():
    """Positive control for the forbidden-claim scan: it must actually see the list's sentences in every block, or a
    clean scan would mean nothing (an extractor that matched no literal would pass every pattern)."""
    blocks = _asia_blocks()
    assert len(blocks) == 5
    for block in blocks[:4]:
        assert "English title + abstract" in _strings(block)
    assert "separate list of patent families" in _strings(blocks[4])
    assert re.search(r"full[- ]text", _strings('"the full text"'))


def test_the_home_page_limits_name_only_what_the_label_shows():
    """Home's "Limits right now" first said US, EP and WO "not other national offices" (false beside a CN/JP/KR/TW
    list), then "documents from any other office appear only as a separate list" (false: DE, FR, GB… never appear).
    It now says some machines return a short separate list labelled with its offices, and that any office not on that
    label is not searched at all. The ranked pool reaches late October 2026 on every index the reference accepts."""
    home = (ROOT / "inferroute_cli" / "probant_web" / "home.js").read_text()
    assert "not other national offices" not in home and "Documents from any other office" not in home
    assert f'list("{HOME_LIMIT}",' in home


def test_no_shipped_text_still_dates_the_ranked_pool_to_mid_april():
    """Both the 2610 root and the asia root carry usall-2610/epwo-2610 (US to 2026-10-29, EP/WO to 2026-10-28, full
    monthly volume May–Oct); only the older roots, now closed in the reference, stopped at mid-April."""
    for p in (ROOT / "inferroute_cli").rglob("*"):
        if p.is_file() and "_vendor" not in p.parts and p.suffix in (".js", ".ts", ".py", ".html"):
            assert "mid-April" not in p.read_text(errors="ignore"), p
    home = (ROOT / "inferroute_cli" / "probant_web" / "home.js").read_text()
    assert "(titles and abstracts, to late October 2026)" in home


# ── review of e42b1d9 ────────────────────────────────────────────────────────────────────────────────────────────────

def test_state_d_does_not_point_at_a_ranking_that_did_not_run(ext, page):
    """With no US/EP/WO ranking, "not part of the ranking above" points at nothing; state (d) says what happened."""
    assert SEPARATE_NO_MAIN in ext["cn_only"]["notes"] and SEPARATE not in ext["cn_only"]["notes"]
    assert SEPARATE_NO_MAIN in page["cn_only"]["section"] and SEPARATE not in page["cn_only"]["section"]
    d = _export({"hits": [], "asia": _asia(["CN"], [_hit(1)])}, ["CN"])
    assert SEPARATE_NO_MAIN in d and SEPARATE not in d
    assert SEPARATE in ext["with_hits"]["notes"] and SEPARATE_NO_MAIN not in ext["with_hits"]["notes"]


def test_the_assistant_is_told_it_has_the_asian_rows_titles_only(ext):
    model = ext["with_hits"]["model"]
    assert ("You have been given these rows' titles only — not their abstracts — so say nothing about what any of "
            "them discloses beyond its title. What the index holds for each is an English title + abstract (some have "
            "a title only), matched in English; describe it as nothing more, and say nothing about where the English "
            "text came from.") in model
    tail = model[model.index("A1. CN-101-A"):]
    assert "An abstract." not in tail, "no Asian abstract is handed over"


def test_the_family_count_says_whose_members_it_counts(ext, page):
    """The engine counts the family's CN/JP/KR/TW members only (build_asia_increment.py), so "family of N
    publications" undercounted a family with US/EP members elsewhere. The true total is kept."""
    for src in (TS.read_text(), JS.read_text(), PY.read_text()):
        assert "family of ${" not in src and "family of {total}" not in src
    assert ext["long_title"]["rows"][0].endswith("[642 CN/JP/KR/TW publications in this family]")


def test_the_terminal_card_never_cuts_a_row_through_its_family_count(ext):
    """The terminal used to slice the composed row to 120 characters, which can end inside "[642 …" and show 64.
    The title is bounded to 96 first; the row is never cut."""
    rows = [ln for ln in ext["long_title"]["terminal"] if ln.lstrip().startswith("A1.")]
    assert len(rows) == 1
    assert rows[0].endswith("[642 CN/JP/KR/TW publications in this family]")
    assert ("A" * 96 + "…") in rows[0] and ("A" * 97) not in rows[0]
    assert "  (these rows cannot be marked)" in ext["long_title"]["terminal"]
    folded = ext["with_hits"]["terminalFolded"]
    assert folded.index("  Separate list: CN, JP, KR and TW patent families") > folded.index("   1. US-1-A Main")
    assert "  (these rows cannot be marked)" not in ext["empty"]["terminal"], "no rows, no note about rows"
    assert not any(re.search(r"CN|JP|KR|TW|separate list", ln) for ln in ext["old_root"]["terminal"])   # (f)


def test_a_read_or_like_on_an_asian_key_says_where_it_came_from():
    """read_patent and `like` refused an Asian-list key as "not returned by any search on this matter" — false. Keys
    from the separate list are remembered, and the refusal names the list, before the generic message, in both."""
    ts = TS.read_text()
    msg = ("`${key} is in a search's separate CN/JP/KR/TW list, not in a ranking. Those rows cannot be opened or used as "
           "a 'like' seed here; nothing was sent. Tell the professional so.`")
    assert msg in ts
    assert "for (const d of sp.asia?.docs ?? []) asiaKeys.add(String(d.key).toUpperCase());" in ts
    generic = ("was not returned by any search's ranking on this matter — or came back only in a search's separate "
               "CN/JP/KR/TW list, which cannot be opened here; nothing was sent`")
    assert ts.count(generic) == 2, "read_patent and like say the same thing"
    g = 0
    for _ in range(2):
        g = ts.index(generic, g + 1)
        line_start = ts.rindex("\n", 0, ts.rindex("\n", 0, g))
        assert "if (asiaKeys.has(" in ts[line_start:g], "the in-session message comes first"
    # runtime: the refusal itself, built by the same arrow function
    a = ts.index("const asiaKeyRefusal = ")
    fn = ts[a:ts.index(";\n", a) + 2]
    node = _node()
    r = subprocess.run([node, "--experimental-strip-types", "--input-type=module-typescript", "-e",
                        fn + "\nconsole.log(asiaKeyRefusal('JP-2019123456-A'));"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "input-type" in r.stderr:
        pytest.skip("this node cannot run TypeScript from -e")
    assert r.stdout.strip() == ("JP-2019123456-A is in a search's separate CN/JP/KR/TW list, not in a ranking. Those rows "
                                "cannot be opened or used as a 'like' seed here; nothing was sent. Tell the professional so.")


def test_a_deep_leg_with_only_an_asian_list_is_not_counted_as_finding_nothing():
    """A leg that ran no US/EP/WO ranking but whose separate list has rows is "asia_only": labelled so on the page and
    in the terminal, and in neither the "found nothing" count nor the next round's gaps."""
    ts, js = TS.read_text(), JS.read_text()
    assert ('const asiaOnly = !r.sp.docs.length && Boolean(r.sp.mainNotRun) && Boolean(r.sp.asia?.docs.length);'
            in ts)
    assert 'status: r.sp.docs.length ? "ok" : asiaOnly ? "asia_only" : "empty",' in ts
    assert 'const empty = results.filter((x) => x.status === "empty");' in ts      # asia_only is not in it
    assert '" — no US/EP/WO ranking ran; see its separate list"' in ts
    assert ': leg.status === "asia_only" ? "no US/EP/WO ranking ran; see its separate list"' in js
    # the page's own deepCoverage, run: an asia_only leg is not "found nothing"
    a = js.index("  function deepCoverage(d) {")
    body = js[a:js.index("  function seenIn(", a)]
    harness = ("const el=(t,c,...k)=>{const n={k:[],text:''};for(const x of k){if(x==null)continue;"
               "if(typeof x==='string')n.text+=x;else n.k.push(x)}n.append=(...m)=>{for(const x of m)if(x!=null)"
               "(typeof x==='string'?n.text+=x:n.k.push(x))};return n};const flat=n=>n==null?'':n.text+n.k.map(flat).join('|');"
               + "const fn=new Function('el',%s+'\\nreturn deepCoverage;')(el);" % json.dumps(body)
               + "console.log(JSON.stringify([flat(fn({legs:[{status:'asia_only',hits:0,feature:'cn leg'}]})),"
                 "flat(fn({legs:[{status:'asia_only',hits:0,feature:'cn leg'},{status:'empty',hits:0,feature:'x'}]}))]));")
    r = subprocess.run([_node(), "-e", harness], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-600:]
    only, mixed = json.loads(r.stdout)
    assert only == ""
    assert "1 query found nothing: x." in mixed and "cn leg" not in mixed


def test_the_searched_pool_is_stated_as_about_30_4_million():
    """The 2610 root (and the main part of the asia root) holds 30,398,469 US/EP/WO rows, measured and attested
    (88,844,190 = 30,398,469 + 58,445,721 Asian rows). "about 29.6 million" was the older root's count."""
    for p in (ROOT / "inferroute_cli").rglob("*"):
        if p.is_file() and "_vendor" not in p.parts and p.suffix in (".js", ".ts", ".py", ".html"):
            assert not re.search(r"29[.,]6 million", p.read_text(errors="ignore")), p
    home = (ROOT / "inferroute_cli" / "probant_web" / "home.js").read_text()
    assert home.count("about 30.4 million US, European and WIPO patent publications") == 2   # the hint, and the help
    # corpusName has no table: it derives the count from the signed identifier itself, so the 2610 root names itself
    ts = TS.read_text()
    fn = ts[ts.index("function corpusName("):ts.index("\n}\n", ts.index("function corpusName(")) + 3]
    r = subprocess.run([_node(), "--experimental-strip-types", "--input-type=module-typescript", "-e",
                        fn + "\nconsole.log(corpusName('patent1m-epwo+usall@30398469'));"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "input-type" in r.stderr:
        pytest.skip("this node cannot run TypeScript from -e")
    assert r.stdout.strip() == "30.4 million published patents from the United States, Europe and WIPO"


# ── second review of f347470 ─────────────────────────────────────────────────────────────────────────────────────────

def test_the_dating_sentence_is_said_only_under_index_asia_2611(ext, page):
    """It is a measurement of asia-2611. Under any other index carrying a layer it is omitted, on every surface."""
    assert DATES in ext["with_hits"]["notes"]
    assert DATES not in ext["index_2612"]["notes"] and DATES not in ext["index_2612"]["model"]
    assert not any(DATES in ln for ln in ext["index_2612"]["terminal"])
    assert HEADING in ext["index_2612"]["notes"] and RANK in ext["index_2612"]["notes"]      # the list itself is shown
    assert DATES in page["with_hits"]["section"] and DATES not in page["index_2612"]["section"]
    assert "A1" in page["index_2612"]["ranks"]
    res = {"hits": [], "asia": _asia(["CN"], [_hit(1)])}
    assert DATES in _export(res)
    assert DATES not in _export(res, index="patent1m-asia-2612+epwo+usall@90000000") and RANK in _export(res, index="x")
    for block in _asia_blocks()[:3]:
        assert "only partly" not in block and "~1% of a month" not in block


def test_state_d_comes_from_the_request_never_from_a_result_key(ext):
    """The engine's result schema drops a top-level `offices`, so a result carrying one is not engine-attested. A
    result with offices:["CN"] and no main hits, from a request that named no office, is state (a), not (d)."""
    s = ext["result_offices"]
    assert "mainNotRun" not in s["part"]
    assert s["notes"][:3] == [HEADING, SEPARATE, CLASS]
    assert not any("No US, EP or WO ranking ran" in n for n in s["notes"])
    assert "0 references above does not mean" not in s["model"]
    ts = TS.read_text()
    a = ts.index("function asiaOf(")
    body = ts[a:ts.index("\n}\n", a)]
    assert "officeCodes(requestOffices)" in body and "r.offices)" not in body
    assert '"/search", { text, k, expect_lifetime_id' in ts, "this client sends no office scope today"
    py = PY.read_text()
    body = py[py.index("def _asia_html("):py.index("# ── end Asian list ──")]
    assert 'stmt.get("offices")' in body and 'result.get("offices")' not in body
    # the export: the same result with no request scope is state (a)
    a_ = _export({"hits": [], "offices": ["CN"], "asia": _asia(["CN", "JP", "KR", "TW"], [_hit(1)])})
    assert "No US, EP or WO ranking ran" not in a_ and SEPARATE in a_


def _corpus_name(*ids):
    ts = TS.read_text()
    fn = ts[ts.index("function corpusName("):ts.index("\n}\n", ts.index("function corpusName(")) + 3]
    r = subprocess.run([_node(), "--experimental-strip-types", "--input-type=module-typescript", "-e",
                        fn + f"\nconsole.log(JSON.stringify({json.dumps(list(ids))}.map(corpusName)));"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "input-type" in r.stderr:
        pytest.skip("this node cannot run TypeScript from -e")
    assert r.returncode == 0, r.stderr[-600:]
    return json.loads(r.stdout)


def test_corpus_name_names_only_an_identifier_made_of_us_ep_wo_parts():
    assert _corpus_name("patent1m-asia-2611+epwo+usall@88844190", "patent1m-asia+epwo+usall@88844190",
                        "patent1m-epwo+usall@30398469", "patent1m-epwo+usall+kr@30398469") == [
        "", "", "30.4 million published patents from the United States, Europe and WIPO", ""]


def test_the_assistant_is_told_the_identifier_count_is_not_the_rankings_pool(ext):
    for name in ("with_hits", "empty", "not_requested", "index_2612"):
        assert COUNT_NOTE in ext[name]["model"], name
    assert COUNT_NOTE not in ext["old_root"]["model"] and COUNT_NOTE not in ext["unlabelled"]["model"]


def test_the_page_and_export_say_the_rows_cannot_be_marked_or_opened(page):
    assert page["with_hits"]["section"].endswith(f"Cooling plate 3 {NO_MARKS}")
    assert NO_MARKS not in (page["empty"]["section"] or "") and NO_MARKS not in (page["not_requested"]["section"] or "")
    assert NO_MARKS in _export({"hits": [], "asia": _asia(["CN"], [_hit(1)])})


def test_the_next_round_denominator_leaves_out_asia_only_legs():
    ts = TS.read_text()
    a = ts.index("const nextRound = (gaps.length")
    brief = ts[a:ts.index("reached nothing new", a)]
    assert 'results.filter((x) => x.status !== "asia_only").length} queries' in brief
    assert "${legs.length} queries reached" not in ts
