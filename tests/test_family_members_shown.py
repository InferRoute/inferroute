"""A CN/JP/KR/TW row is a DOCDB family with no US/EP/WO member, and the engine lists its member publications (capped,
with the true count beside them). Those rows are in the Asian layer's OWN list (sealed-research fbe365c), never in the
main ranking, so the family size is carried and shown on that list only — the main ranking's rows carry none.
tests/test_asia_list.py runs both halves; these pin where the family code lives."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "inferroute_cli"


def test_the_extension_carries_family_members_on_the_asian_list_not_on_the_ranking():
    ts = (ROOT / "pi_attested" / "ir-attested.ts").read_text()
    block = ts[ts.index("// ── the Asian list ──"):ts.index("// ── end Asian list ──")]
    assert "family_members" in block and "family_members_total" in block
    proof = ts[ts.index("function searchProofOf("):ts.index("// What the model is told a read returned")]
    assert "family_members" not in proof, "main hits carry no family: the schema's HIT has no such field"
    assert "family?: string[] }[];" not in ts


def test_the_page_shows_the_family_size_on_the_asian_list_only_from_text_nodes():
    js = (ROOT / "probant_web" / "app.js").read_text()
    assert "function familyOf(doc)" in js and "family of ${total} publications" in js
    assert js.count("familyOf(doc), title)") == 1, "the Asian rows only"
    block = js[js.index("  // ── the Asian list ──"):js.index("  // ── end Asian list ──")]
    assert "familyOf(doc), title)" in block
    assert "innerHTML" not in block
