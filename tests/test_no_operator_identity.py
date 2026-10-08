"""The shipped client names no enclave operator (Henry, 2026-10-08: "hide it as much as possible").

What this guards is TEXT the package carries: code, comments, the bundled catalog, briefs. What it cannot
guard, and the design says so, is the operator's own evidence: the enclave's certificate is issued by the
operator's CA and receipts keep it verbatim so a third party can re-verify. That lives in data written at
run time, never in the package.

The forbidden words are held only as SHA-256 hashes and found by hashing every 5-character window of each
file, so this test does not spell them, not even in pieces: a split literal such as "ab" + "cd" is still
the word to anyone reading the repository.
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = [ROOT / "inferroute_cli", ROOT / "inferroute_local"]
SUFFIXES = {".py", ".json", ".js", ".ts", ".md", ".html", ".css", ".txt", ".toml", ".yaml", ".yml"}
WIDTH = 5
FORBIDDEN_SHA256 = {
    "af751f13b6b2ed89e0ccd30729792daccaf69907d1fd9a4d6d9b01559f3a6bc8",
    "01fdf371c2a1581f3b3e399c06e0792d9a0251ebe8ec98758795b5076e3aab9c",
}


def _hits(text: str) -> list[int]:
    t = text.lower()
    out = []
    for i in range(len(t) - WIDTH + 1):
        if hashlib.sha256(t[i:i + WIDTH].encode("utf-8", "surrogatepass")).hexdigest() in FORBIDDEN_SHA256:
            out.append(i)
    return out


def _files():
    for base in SHIPPED:
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in SUFFIXES and "__pycache__" not in p.parts:
                yield p


def test_no_shipped_file_names_the_operator():
    found = []
    for p in _files():
        text = p.read_text(errors="replace")
        for i in _hits(text):
            found.append(f"{p.relative_to(ROOT)}:{text.count(chr(10), 0, i) + 1}")
    assert not found, "an operator identifier in the shipped client at:\n" + "\n".join(found[:40])


def test_the_guard_fires_on_a_planted_word(monkeypatch):
    """A guard that never fires proves nothing. Plant a harmless word, hold only its hash, and the window
    search must find it whatever its case and surroundings."""
    word = "qzxvw"
    import sys
    monkeypatch.setattr(sys.modules[__name__], "FORBIDDEN_SHA256", {hashlib.sha256(word.encode()).hexdigest()})
    assert _hits(f"x = '{word.upper()}' and {word}") == [5, 16]
    assert _hits("nothing to see here") == []
