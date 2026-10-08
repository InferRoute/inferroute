"""The shipped client names no enclave operator (Henry, 2026-10-08: "hide it as much as possible").

What this guards is TEXT the package carries: code, comments, the bundled catalog, briefs. What it cannot
guard, and the design says so, is the operator's own evidence: the enclave's certificate is issued by the
operator's CA and receipts keep it verbatim so a third party can re-verify. That lives in data written at
run time, never in the package.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = [ROOT / "inferroute_cli", ROOT / "inferroute_local"]
# Lower-cased fragments that identify the current operator or its naming. Assembled so this file does not
# itself trip a search for them.
FORBIDDEN = ["fle" + "et", "gue" + "stos", "-te" + "e\"", "-te" + "e`", "-te" + "e'", "/te" + "e-"]
SUFFIXES = {".py", ".json", ".js", ".ts", ".md", ".html", ".css", ".txt", ".toml", ".yaml", ".yml"}


def _files():
    for base in SHIPPED:
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in SUFFIXES and "__pycache__" not in p.parts:
                yield p


def test_no_shipped_file_names_the_operator():
    hits = []
    for p in _files():
        text = p.read_text(errors="replace").lower()
        for frag in FORBIDDEN:
            for m in re.finditer(re.escape(frag), text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{p.relative_to(ROOT)}:{line}: {frag!r}")
    assert not hits, "operator identifiers in the shipped client:\n" + "\n".join(hits[:40])


def test_the_guard_would_catch_a_planted_identifier(tmp_path):
    """A guard that never fires proves nothing: plant each fragment and see it caught."""
    for frag in FORBIDDEN:
        assert re.search(re.escape(frag), f"x = {frag} y".lower())
