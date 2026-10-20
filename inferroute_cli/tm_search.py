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
import threading
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA = "anteriora.tm-index/1"
GRAM = 3
MAX_CANDIDATES = 12000      # scored in full; ties are broken by id so a search always returns the same list
POOL = 8                    # how many times that many are gathered before the length-aware shortlist

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


_FINE = [
    (r"^kn", "n"), (r"^wr", "r"), (r"^ps", "s"), (r"^x", "s"),
    (r"^chr", "kr"), (r"eau", "o"), (r"sch", "sh"), (r"tch", "ch"), (r"ch", "sh"), (r"dg", "j"), (r"ph", "f"), (r"gh", "g"),
    (r"qu", "kw"), (r"q", "k"), (r"ck", "k"), (r"cw", "kw"), (r"x", "ks"),
    (r"c(?=[eiy])", "s"), (r"c", "k"), (r"z", "s"), (r"y", "i"),
    (r"ou|oo", "u"), (r"ee|ea|ie|ei", "i"), (r"ai|ay", "e"), (r"au|aw", "o"), (r"oe", "e"), (r"(?<![cs])h", ""),
]
_FINE = [(re.compile(a), b) for a, b in _FINE]


def sound_fine(text: str) -> str:
    """A finer sound key: sound()'s spelling rules with the vowels and the w of "qu" kept. sound() is what the
    index is built on and only gathers candidates; with every vowel read as "a" and "qu"/"kw" as "k", "Kwik",
    "Quick", "Kick" and "Cake" all read "kak". This key decides "sounds alike" (Kwik = Quick = Qwik, not Kick or
    Cake) and grades how close two sounds are. It is computed at search time, so it changes without a new index."""
    flat = compact(text)
    s = "".join(_DIGITS.get(c, c) for c in flat)
    for pattern, repl in _FINE:
        s = pattern.sub(repl, s)
    s = re.sub(r"(.)\1+", r"\1", s)
    if len(s) > 3 and re.search(r"[^aeiouy]e$", flat):
        s = s[:-1]                                         # a silent final e after a consonant
    return s


def _runs_of_words(flat: str, ws: Sequence[str]) -> bool:
    """True if `flat` is two or more consecutive whole words of `ws` run together ("airbnb" in "AIR BNB")."""
    for i in range(len(ws)):
        joined = ws[i]
        for j in range(i + 1, len(ws)):
            joined += ws[j]
            if joined == flat:
                return True
            if len(joined) >= len(flat):
                break
    return False


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


# ── what a search covers, said the same way on the page, in the report and to the assistant ──

# The registers a founder in France, the EU or the US would expect, in the order they are named. An index says
# which it holds in its "sources"; every one it does not hold is named as NOT searched, so a register is never
# left out of a sentence by being absent from the data.
REGISTERS = [
    ("USPTO", "the US register (USPTO), including international registrations designating the US"),
    ("INPI", "the French register (INPI), French national filings"),
    ("EUIPO", "EU trade marks (EUIPO)"),
    ("WIPO", "international registrations designating France or the EU (WIPO Madrid)"),
]
ALWAYS_UNCOVERED = ["registers of other countries", "company and trading names", "domain names",
                    "unregistered use of a name", "marks made only of a logo or picture"]


def coverage(sources: str) -> Dict[str, List[str]]:
    """{"searched": [...], "not_searched": [...]} for an index whose meta "sources" is `sources`."""
    held = [label for key, label in REGISTERS if key in (sources or "")]
    missing = [label for key, label in REGISTERS if key not in (sources or "")
]
    return {"searched": held, "not_searched": missing + ALWAYS_UNCOVERED}


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
        self.path = Path(path)
        # One read-only connection per thread. A name session searches several variants at once, and the host
        # route runs each in a worker thread: sharing one connection failed 6 of 8 concurrent searches with
        # "bad parameter or other API misuse" (a live session on 20 Oct saw 2 of 8 fail and retried them).
        self._local = threading.local()
        self.meta = dict(self.db.execute("SELECT k, v FROM meta"))
        if self.meta.get("schema") != SCHEMA:
            raise ValueError(f"{path} is not a trademark index this version reads")

    @property
    def db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "db", None)
        if conn is None:
            conn = self._local.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        return conn

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
        cand = self._shortlist(cand[:MAX_CANDIDATES * POOL], votes, sum(weights), len(grams(key)))
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
                **coverage(self.meta.get("sources", "")),
                "hits": hits[:limit], "more": max(0, len(hits) - limit)}

    def _shortlist(self, ids: List[int], votes: Counter, weight: float, n_grams: int) -> List[int]:
        """The candidates scored in full: those sharing the most of the name's sound fragments RELATIVE TO THEIR
        OWN LENGTH. Raw shared weight favours long marks, which share more fragments with anything; ranked that
        way, PICASSO (for "Picaro") and CARREFOUR (for "Karfour") sat past the 14,000th candidate and were never
        scored. A mark found by its whole spelling or a whole word (100 / 40 votes) is always kept."""
        if len(ids) <= MAX_CANDIDATES:
            return ids
        per_gram = weight / max(1, n_grams)
        size: Dict[int, int] = {}
        for chunk in range(0, len(ids), 900):
            part = ids[chunk:chunk + 900]
            for i, text in self.db.execute(f"SELECT id, text FROM marks WHERE id IN ({','.join('?' * len(part))})", part):
                size[i] = len(compact(text)) + 2 - GRAM + 1
        def dice(i: int) -> float:
            return 2 * votes[i] / (weight + per_gram * size.get(i, n_grams))
        kept = sorted(ids, key=lambda i: (-(votes[i] >= 40), -dice(i), i))
        return kept[:MAX_CANDIDATES]

    @staticmethod
    def _score(row, flat: str, key: str, ws: List[str], wanted: set) -> Optional[Dict[str, Any]]:
        _, register, number, text, status, classes, filed = row
        mflat, mws = compact(text), words(text)
        fine, mfine = sound_fine(flat), sound_fine(text)
        reasons = []
        spell = similarity(flat, mflat)
        hear = similarity(fine, mfine)
        if mflat == flat:
            reasons.append("same spelling")
        elif mfine == fine and len(fine) >= 2:
            reasons.append("sounds alike")
        elif spell >= 0.75 and len(flat) >= 4:
            reasons.append("spelled closely")
        elif hear >= 0.75 and spell >= 0.5 and len(fine) >= 4:
            # A close sound with at least half the spelling in common ("Annuaire Ehret" is not close to
            # "Antériorité"; "Karfour" is close to "Carrefour").
            reasons.append("sounds close")
        # Containment counts whole words only: "Anteriora" is not inside "Amplitude Anterior Approche" just
        # because the letters run on across a space.
        inside = flat != mflat and len(flat) >= 4 and (_runs_of_words(flat, mws) or any(flat in w for w in mws))
        holds = flat != mflat and len(mflat) >= 4 and (_runs_of_words(mflat, ws) or any(mflat in w for w in ws))
        if inside:
            reasons.append("contains your name")
        elif holds:
            reasons.append("is contained in your name")
        shared = sorted({w for w in ws if w in mws and len(w) >= 3} - {flat if flat in mws and mflat == flat else ""})
        if shared and "same spelling" not in reasons:
            reasons.append("shares the word " + ", ".join(f"“{w}”" for w in shared))
        if not reasons:
            return None
        mclasses = [c for c in (classes or "").split(",") if c]
        overlap = sorted(set(mclasses) & wanted, key=int) if wanted else []
        # Closest first, in tiers measured on tests/data/tm_eval.json: the same spelling; the same sound (QUICK
        # for "Kwik" ranked 78th when a mark merely containing the word scored higher); the name as a whole word
        # of a longer mark, fewer extra words first; then close spellings and sounds by how close; then a word
        # of the name inside the mark; the name inside a longer word; a shorter mark inside the name. Spelling
        # breaks ties.
        whole_word = flat in mws or bool(_runs_of_words(flat, mws))
        tiers = [1.0 if mflat == flat else 0, 0.95 if "sounds alike" in reasons else 0,
                 0.9 - 0.02 * min(5, len(mws) - len(ws)) if whole_word and mflat != flat else 0,
                 0.9 * max(spell, hear), 0.75 if shared else 0,
                 0.7 if inside else 0,          # inside a longer word ("ECHLORIAL") ranked above L'OREAL at 0.8
                 0.5 + 0.15 * len(mflat) / len(flat) if holds else 0]
        score = round(max(tiers) + 0.05 * spell, 3)
        return {"register": register, "number": number, "text": text, "status": status, "classes": mclasses,
                "filed": filed, "reasons": reasons, "score": score,
                "class_overlap": 1 if overlap else 0, "overlapping_classes": overlap}


def report_lines(result: Dict[str, Any]) -> List[str]:
    """The plain-text result: what was searched first, then each mark and why it resembles the name."""
    cov = coverage(result.get("sources", ""))
    out = [f"Registered marks close to “{result['name']}”",
           f"Searched: {'; '.join(cov['searched'])} ({result['marks_searched']:,} live word marks), data as of "
           f"{result['data_date']}. Searched on this computer; the name was not sent anywhere.",
           f"Not searched: {'; '.join(cov['not_searched'])}.",
           "This is a list of similar marks, not an opinion on whether you can use or register the name."]
    if result["classes"]:
        out.append(f"Classes you asked about: {', '.join(result['classes'])}.")
    if not result["hits"]:
        out.append("No close registered word marks found in this data. That does not mean the name is free to use: "
                   "the registers and rights listed as not searched can still hold it.")
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


SEARCH_LOG = "trademark-searches.jsonl"
LOGGED_HITS = 40


def log_search(log_dir: Path, result: Dict[str, Any]) -> None:
    """Keep what a search returned, as the host saw it, in the matter's records (write-denied to the agent).
    The matter page lists every search from this file, so the marks a founder reads come from the search, not
    from the assistant retyping them, and the assistant's report can stay short."""
    entry = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             **{k: result.get(k) for k in ("name", "classes", "data_date", "sources", "marks_searched")},
             "hits": result.get("hits", [])[:LOGGED_HITS],
             "more": result.get("more", 0) + max(0, len(result.get("hits", [])) - LOGGED_HITS)}
    log_dir.mkdir(parents=True, exist_ok=True)
    with (log_dir / SEARCH_LOG).open("a", encoding="utf-8") as fh:
        fh.write(__import__("json").dumps(entry, ensure_ascii=False) + "\n")


def logged_searches(log_dir: Path) -> List[Dict[str, Any]]:
    """The searches of a matter, the latest for each name and set of classes, in the order they were run."""
    import json as _json
    try:
        lines = (log_dir / SEARCH_LOG).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    latest: Dict[Tuple, Dict[str, Any]] = {}
    for line in lines:
        try:
            e = _json.loads(line)
        except ValueError:
            continue
        latest[(compact(str(e.get("name") or "")), tuple(e.get("classes") or []))] = e
    return list(latest.values())                       # file order is search order; a repeat keeps its first place


def install_route(app, index_path: Path, log_dir: Optional[Path] = None) -> None:
    """The trademark search as a host capability for a name session, behind the sealed proxy's per-session
    authentication. The index is opened on the host; the agent sends a name and classes and gets marks back.
    Each result is also kept in `log_dir` (see log_search). Nothing here makes a network request."""
    import asyncio
    from fastapi import Request
    from fastapi.responses import JSONResponse

    state: Dict[str, Any] = {}
    # One search at a time. Scoring is Python, so eight variants searched at once took 26.7 s for all of them
    # to answer, against 14.0 s one after another (measured 20 Oct, US+FR index).
    one_at_a_time = threading.Lock()

    def run(body: Dict[str, Any]) -> Dict[str, Any]:
        with one_at_a_time:
            return _run(body)

    def _run(body: Dict[str, Any]) -> Dict[str, Any]:
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
            if log_dir is not None:
                await asyncio.to_thread(log_search, Path(log_dir), result)
        except FileNotFoundError:
            return JSONResponse({"error": "no trademark index is installed on this computer"}, status_code=503)
        except (ValueError, TypeError) as error:
            return JSONResponse({"error": str(error)}, status_code=400)
        return result

    tm_search.__annotations__["request"] = Request
    app.add_api_route("/probant/tm/search", tm_search, methods=["POST"])
