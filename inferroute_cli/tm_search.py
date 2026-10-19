"""Trademark name check: registered word marks close to a name, searched on this computer.

The index is one SQLite file built from public registers (the USPTO first; INPI and EUIPO through the same
`build()` input once their feeds are in). A search reads that file and nothing else: no request leaves the
computer, so a name that has not been announced is not disclosed to anyone by checking it.

How a candidate is found, and why each step exists:

* **Normalised spelling.** Case, accents, punctuation and spacing are removed ("Ante-Riora", "anteriora" and
  "ANTÉRIORA" are one spelling). Each word of a mark is also kept on its own, so "Anteriora Labs" is found
  from "Anteriora".
* **A sound key.** A small rule set for English and French spellings ("qu"/"kw"/"ck" sound like "k", "ph" like
  "f", doubled letters are one, most vowels collapse), so "Kwik" and "Quick" share a key. It is deliberately
  crude: it finds candidates, it does not decide anything.
* **Shared fragments.** Three-letter fragments of the sound key retrieve marks that are spelled differently
  but close, which are then scored by edit distance on both spelling and sound.

The output is a list of marks with the REASONS each one resembles the name (same spelling, sounds alike,
spelled closely, contains the name, shares a word) and whether its classes overlap the ones asked about.
It never says a name is available, clear or likely to be confused: those are legal judgements, and the
register searched is only one of the rights that can apply (company names, unregistered use and other
registers are not in it).
"""
from __future__ import annotations

import array
import math
import datetime as dt
import re
import sqlite3
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA = "anteriora.tm-index/1"
GRAM = 3
MAX_CANDIDATES = 12000      # scored in full; ties are broken by id so a search always returns the same list

_DIGITS = {"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four", "5": "five", "6": "six",
           "7": "seven", "8": "eight", "9": "nine"}


def fold(text: str) -> str:
    """Lower case, accents removed, '&' as 'and', every other non-alphanumeric a space."""
    t = unicodedata.normalize("NFKD", text or "")
    t = "".join(c for c in t if not unicodedata.combining(c)).lower().replace("&", " and ")
    return re.sub(r"[^a-z0-9]+", " ", t).strip()


def words(text: str) -> List[str]:
    return fold(text).split()


def compact(text: str) -> str:
    return fold(text).replace(" ", "")


_RULES = [
    (r"^kn", "n"), (r"^wr", "r"), (r"^ps", "s"), (r"^x", "s"),
    (r"^chr", "kr"), (r"eau", "o"), (r"sch", "sh"), (r"ch", "sh"), (r"tch", "ch"), (r"dg", "j"), (r"ph", "f"), (r"gh", "g"),
    (r"qu", "k"), (r"q", "k"), (r"ck", "k"), (r"kw", "k"), (r"cw", "k"), (r"x", "ks"),
    (r"c(?=[eiy])", "s"), (r"c", "k"), (r"z", "s"), (r"y", "i"), (r"w(?=[aeiou])", "v"),
    (r"(?<=[aeiou])w", "u"), (r"ou|oo", "u"), (r"ee|ea|ie|ei", "i"), (r"ai|ay|ei", "e"), (r"au|aw", "o"),
    (r"oe", "e"), (r"(?<![cs])h", ""),
]
_RULES = [(re.compile(a), b) for a, b in _RULES]


def sound(text: str) -> str:
    """A crude sound key for English and French spellings. Same key = worth a look, nothing more."""
    s = compact(text)
    s = "".join(_DIGITS.get(c, c) for c in s)
    for pattern, repl in _RULES:
        s = pattern.sub(repl, s)
    s = re.sub(r"(.)\1+", r"\1", s)                        # doubled letters sound once
    if len(s) > 3 and s.endswith("e"):
        s = s[:-1]                                         # a silent final e
    head, tail = s[:1], s[1:]
    tail = re.sub(r"[aeiou]+", "a", tail)                  # vowel quality after the first letter is noisy
    return head + tail


def grams(key: str) -> List[str]:
    padded = f"^{key}$"
    return [padded[i:i + GRAM] for i in range(max(1, len(padded) - GRAM + 1))]


def distance(a: str, b: str, cap: int = 99) -> int:
    """Levenshtein distance, stopping early once it exceeds `cap`."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = i
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    """1 for the same string, falling to 0. Strings of very different lengths are not similar: the early
    exit in distance() must never be read as a small distance."""
    if not a or not b:
        return 0.0
    longest = max(len(a), len(b))
    if abs(len(a) - len(b)) > longest // 2:
        return 0.0
    return max(0.0, 1.0 - distance(a, b, cap=longest) / longest)


# ── building the index (our side; the result is the file a computer downloads) ──

def build(rows: Iterable[Tuple[str, str, str, str, Sequence[str], str]], out: Path,
          data_date: str, sources: Sequence[str]) -> Dict[str, Any]:
    """rows: (register, number, mark text, status, classes, filed YYYY-MM-DD). Writes `out` atomically."""
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.executescript("""
        PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
        CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE marks (id INTEGER PRIMARY KEY, register TEXT, number TEXT, text TEXT, status TEXT,
                            classes TEXT, filed TEXT);
        CREATE TABLE post (key TEXT PRIMARY KEY, ids BLOB) WITHOUT ROWID;
    """)
    postings: Dict[str, array.array] = {}
    n = 0
    batch = []
    for register, number, text, status, classes, filed in rows:
        key = sound(text)
        flat = compact(text)
        if not flat:
            continue
        n += 1
        batch.append((n, register, number, text, status, ",".join(sorted({c for c in classes if c})), filed))
        if len(batch) >= 50_000:
            db.executemany("INSERT INTO marks VALUES (?,?,?,?,?,?,?)", batch)
            batch.clear()
        keys = {"c:" + flat} | {"w:" + w for w in words(text) if len(w) >= 2} | {"g:" + g for g in grams(key)}
        for k in keys:
            a = postings.get(k)
            if a is None:
                a = postings[k] = array.array("I")
            a.append(n)
    if batch:
        db.executemany("INSERT INTO marks VALUES (?,?,?,?,?,?,?)", batch)
    db.executemany("INSERT INTO post VALUES (?,?)", ((k, v.tobytes()) for k, v in postings.items()))
    info = {"schema": SCHEMA, "marks": str(n), "data_date": data_date, "sources": "; ".join(sources),
            "built": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "byteorder": __import__("sys").byteorder}
    db.executemany("INSERT INTO meta VALUES (?,?)", info.items())
    db.commit()
    db.execute("VACUUM")
    db.close()
    tmp.replace(out)
    return info


# ── searching (on the founder's computer) ──

class Index:
    def __init__(self, path: Path):
        if not Path(path).is_file():
            raise FileNotFoundError(f"no trademark index at {path}")
        self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.meta = dict(self.db.execute("SELECT k, v FROM meta"))
        if self.meta.get("schema") != SCHEMA:
            raise ValueError(f"{path} is not a trademark index this version reads")

    def _ids(self, key: str) -> array.array:
        row = self.db.execute("SELECT ids FROM post WHERE key = ?", (key,)).fetchone()
        a = array.array("I")
        if row:
            a.frombytes(row[0])
            if self.meta.get("byteorder") != __import__("sys").byteorder:
                a.byteswap()
        return a

    def search(self, name: str, classes: Sequence[str] = (), limit: int = 50) -> Dict[str, Any]:
        flat, key, ws = compact(name), sound(name), [w for w in words(name) if len(w) >= 2]
        if not flat:
            raise ValueError("type a name with at least one letter or digit")
        votes: Counter = Counter()
        for i in self._ids("c:" + flat):
            votes[i] += 100
        for w in ws:
            for i in self._ids("w:" + w):
                votes[i] += 40
        if len(flat) >= 4:                                 # a name typed as one word may be a word inside a mark
            for i in self._ids("w:" + flat):
                votes[i] += 40
        # Every fragment votes, weighted by how rare it is (log of marks / marks holding it): a mark sharing the
        # rare fragments of the name ranks above one sharing only "ant" and "ara". (An earlier version skipped
        # common fragments outright and counted them in the threshold anyway, so on the 5.7M-mark index
        # "Anteriora" returned nothing; counting every list costs about 0.3 s.)
        total = max(1, int(self.meta.get("marks", 1)))
        weights = []
        for g in sorted(set(grams(key))):
            ids = self._ids("g:" + g)
            if not ids:
                continue
            w = math.log(1 + total / len(ids))
            weights.append(w)
            for i in ids:
                votes[i] += w
        need = 0.3 * sum(weights) if weights else 1.0       # a floor; the weighted ranking and the cap do the rest
        cand = [i for i, v in votes.items() if v >= need]
        cand.sort(key=lambda i: (-votes[i], i))
        cand = cand[:MAX_CANDIDATES]
        wanted = {str(int(c)) for c in classes if str(c).strip().isdigit()}
        hits = []
        for chunk in range(0, len(cand), 900):
            part = cand[chunk:chunk + 900]
            q = f"SELECT id, register, number, text, status, classes, filed FROM marks WHERE id IN ({','.join('?' * len(part))})"
            for row in self.db.execute(q, part):
                hit = self._score(row, flat, key, ws, wanted)
                if hit:
                    hits.append(hit)
        hits.sort(key=lambda h: (-h["class_overlap"], -h["score"], h["text"].lower()))
        return {"name": name, "classes": sorted(wanted, key=int), "data_date": self.meta.get("data_date", ""),
                "sources": self.meta.get("sources", ""), "marks_searched": int(self.meta.get("marks", 0)),
                "hits": hits[:limit], "more": max(0, len(hits) - limit)}

    @staticmethod
    def _score(row, flat: str, key: str, ws: List[str], wanted: set) -> Optional[Dict[str, Any]]:
        _, register, number, text, status, classes, filed = row
        mflat, mkey, mws = compact(text), sound(text), words(text)
        reasons = []
        spell = similarity(flat, mflat)
        hear = similarity(key, mkey)
        if mflat == flat:
            reasons.append("same spelling")
        elif mkey == key:
            reasons.append("sounds alike")
        elif spell >= 0.75 and len(flat) >= 4:
            reasons.append("spelled closely")
        elif hear >= 0.85 and spell >= 0.5 and len(key) >= 3:
            # Vowels are collapsed in the sound key, so a close key alone is weak evidence; the spelling has
            # to be at least half the same too ("Annuaire Ehret" is not close to "Antériorité").
            reasons.append("sounds close")
        if len(flat) >= 4 and flat != mflat and flat in mflat:
            reasons.append("contains your name")
        elif len(mflat) >= 4 and flat != mflat and mflat in flat:
            reasons.append("is contained in your name")
        shared = sorted({w for w in ws if w in mws and len(w) >= 3} - {flat if flat in mws and mflat == flat else ""})
        if shared and "same spelling" not in reasons:
            reasons.append("shares the word " + ", ".join(f"“{w}”" for w in shared))
        if not reasons:
            return None
        mclasses = [c for c in (classes or "").split(",") if c]
        overlap = sorted(set(mclasses) & wanted, key=int) if wanted else []
        # Closest first. A shared whole word outranks a loose sound-alike, and a sound key of three letters or
        # fewer is too short to carry much on its own. Spelling breaks ties between marks that sound the same.
        sounds = (0.9 if len(key) >= 4 else 0.75) if mkey == key else hear * 0.85
        score = round(max(spell, sounds, 1.0 if mflat == flat else 0, 0.95 if shared else 0) + 0.1 * spell, 3)
        return {"register": register, "number": number, "text": text, "status": status, "classes": mclasses,
                "filed": filed, "reasons": reasons, "score": score,
                "class_overlap": 1 if overlap else 0, "overlapping_classes": overlap}


def report_lines(result: Dict[str, Any]) -> List[str]:
    """The plain-text result: what was searched first, then each mark and why it resembles the name."""
    out = [f"Registered marks close to “{result['name']}”",
           f"Searched: {result['sources']} ({result['marks_searched']:,} live word marks), data as of "
           f"{result['data_date']}. Searched on this computer; the name was not sent anywhere.",
           "Not searched: other registers, company and domain names, unregistered use, figurative marks. "
           "This is a list of similar marks, not an opinion on whether you can use or register the name."]
    if result["classes"]:
        out.append(f"Classes you asked about: {', '.join(result['classes'])}.")
    if not result["hits"]:
        out.append("No close registered word marks found in this data.")
        return out
    out.append("")
    for h in result["hits"]:
        cls = ", ".join(h["classes"]) or "none recorded"
        flag = "  [your classes: " + ", ".join(h["overlapping_classes"]) + "]" if h["overlapping_classes"] else ""
        text = h["text"] if len(h["text"]) <= 90 else h["text"][:87] + "…"
        out.append(f"{text}  ({h['register']} {h['number']}, {h['status']}, classes {cls}){flag}")
        out.append(f"    {'; '.join(h['reasons'])}")
    if result["more"]:
        out.append(f"\n…and {result['more']} more, less close.")
    return out


def install_route(app, index_path: Path) -> None:
    """The trademark search as a host capability for a name session, behind the sealed proxy's per-session
    authentication. The index is opened on the host; the agent sends a name and classes and gets marks back.
    Nothing here makes a network request."""
    import asyncio
    from fastapi import Request
    from fastapi.responses import JSONResponse

    state: Dict[str, Any] = {}

    def run(body: Dict[str, Any]) -> Dict[str, Any]:
        if "index" not in state:
            state["index"] = Index(index_path)
        name = str(body.get("name") or "").strip()
        if not name or len(name) > 120:
            raise ValueError("give one name of 1 to 120 characters")
        classes = [str(c) for c in (body.get("classes") or [])][:45]
        limit = max(1, min(int(body.get("limit") or 25), 100))
        return state["index"].search(name, classes, limit=limit)

    async def tm_search(request):
        raw = await request.body()
        if len(raw) > 8_000:
            return JSONResponse({"error": "the request is too large"}, status_code=413)
        try:
            import json as _json
            result = await asyncio.to_thread(run, _json.loads(raw or b"{}"))
        except FileNotFoundError:
            return JSONResponse({"error": "no trademark index is installed on this computer"}, status_code=503)
        except (ValueError, TypeError) as error:
            return JSONResponse({"error": str(error)}, status_code=400)
        return result

    tm_search.__annotations__["request"] = Request
    app.add_api_route("/probant/tm/search", tm_search, methods=["POST"])
