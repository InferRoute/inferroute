"""Australian trade marks from IP Australia's IP RAPID bulk data (data.gov.au, CC BY 4.0), to index rows.

Our side, not shipped. The pull is the IP RAPID zip converted to Parquet folders: tm_application (number, status,
dates), tm_description (the mark's words: "trade_mark_word_mark_phrase" for a word mark, "trade_mark_image_words"
for the words in a logo) and tm_classification (Nice classes, "is_current"). International registrations
designating Australia are in the same tables under an Australian number (tm_madrid_links ties them to the IR).

As for the other registers, a mark is kept when its status is live and it has words: "protected" is registered;
"accepted" and "published" are pending. Every status the pull carries is classified, so a new one stops the build.
"""
import glob
from pathlib import Path
from typing import Dict, Iterator, Tuple

REGISTERED = {"protected"}
PENDING = {"accepted", "published"}
LIVE = REGISTERED | PENDING
DEAD = {"ceased", "lapsed", "withdrawn", "cancelled", "removed", "linked", "inter_partes_refused", "refused",
        "voided", "ex_parte_refused", "not_filed"}
TEXT_TYPES = ("trade_mark_word_mark_phrase", "trade_mark_image_words")   # in order of preference


def _tables(folder: Path, name: str, columns):
    import pyarrow.parquet as pq
    for f in sorted(glob.glob(str(Path(folder) / name / "*.parquet"))):
        yield pq.read_table(f, columns=columns)


def statuses(folder: Path) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for t in _tables(folder, "tm_application", ["status"]):
        for s in t.column(0).to_pylist():
            out[s or ""] = out.get(s or "", 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def data_date(folder: Path) -> str:
    newest = ""
    for t in _tables(folder, "tm_application", ["application_date"]):
        newest = max([newest] + [d for d in t.column(0).to_pylist() if d])
    return newest[:10] or "unknown"


def rows(folder: Path) -> Iterator[Tuple]:
    live: Dict[str, Tuple[str, str]] = {}
    for t in _tables(folder, "tm_application", ["application_number", "status", "application_date"]):
        for n, s, d in zip(*(t.column(i).to_pylist() for i in range(3))):
            if s in LIVE:
                live[str(n)] = ("registered" if s in REGISTERED else "pending", (d or "")[:10])
    text: Dict[str, Tuple[int, str]] = {}
    for t in _tables(folder, "tm_description", ["application_number", "description_type", "description_value"]):
        for n, ty, v in zip(*(t.column(i).to_pylist() for i in range(3))):
            if n in live and ty in TEXT_TYPES and (v or "").strip():
                rank = TEXT_TYPES.index(ty)
                if n not in text or rank < text[n][0]:
                    text[n] = (rank, v.strip())
    classes: Dict[str, set] = {}
    for t in _tables(folder, "tm_classification", ["application_number", "classification_system", "classification",
                                                      "is_current"]):
        for n, sy, c, cur in zip(*(t.column(i).to_pylist() for i in range(4))):
            if n in text and sy == "nice" and cur == "true" and (c or "").strip().isdigit() and 1 <= int(c) <= 45:
                classes.setdefault(n, set()).add(str(int(c)))
    for n, (_, words) in text.items():
        status, filed = live[n]
        yield ("AU", n, words, status, sorted(classes.get(n, ())), filed)
