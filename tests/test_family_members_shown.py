"""A Chinese/Japanese/Korean/Taiwanese hit is a DOCDB family with no US/EP/WO member, and the engine lists its
member publications (sealed-research asia/ram-corpus, 1 Nov 2026). The extension must carry them to the page and
the page must say how many publications the row stands for: that is what makes '72.3M publications' true."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "inferroute_cli"


def test_the_extension_carries_family_members_into_the_search_card():
    ts = (ROOT / "pi_attested" / "ir-attested.ts").read_text()
    assert "family_members" in ts and "family?: string[]" in ts


def test_the_page_shows_the_family_size_from_text_nodes_only():
    js = (ROOT / "probant_web" / "app.js").read_text()
    assert "function familyOf(doc)" in js and "family of ${f.length} publications" in js
    assert js.count("familyOf(doc), title)") == 2, "both result lists (search card and deep-search leg) show it"
    body = js[js.index("function familyOf(doc)"):js.index("function familyOf(doc)") + 400]
    assert "innerHTML" not in body
