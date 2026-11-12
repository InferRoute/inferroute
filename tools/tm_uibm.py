"""Italian national trade marks from the UIBM (Ufficio Italiano Brevetti e Marchi) database, to index rows.

Our side, not shipped. The fetch writes one Parquet per filing month (month_YYYY-MM.parquet) with app_number,
filing_date (DD/MM/YYYY), status (Italian), title (the mark's words, often empty), description (free text).
It holds Italian national filings only: international registrations designating Italy are not in it.

What is kept, and why:
* Live statuses only (STATUS below); an empty or unknown status stops the build until it is classified.
* Filed within the last ten and a half years: UIBM's data shows no renewals, so a mark filed earlier may have
  lapsed while still reading "Registrata" (a registration lasts ten years from filing, renewable, with six months'
  grace). Older renewed marks are therefore not searched, and are named as not searched.
* Words: the title; failing that, the first quoted phrase of the description ("costituito dalla parola "DIRTY"");
  failing that the mark is left out, since a description is not the mark's words.
"""
import datetime
import glob
import re
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

REGISTERED = {"Registrata", "Rinunciata parzialmente"}
PENDING = {"in esame", "In esame", "in attesa attestato", "in opposizione", "attesa scadenza periodo di opponibilità",
           "esame superato"}
LIVE = REGISTERED | PENDING
DEAD = {"Rifiutata", "Ritirata", "Rinunciata", "Irricevibile", "Archiviata", "Annullata", "Decaduta",
        "Annullata da sentenza", ""}     # "" (no status given) is not shown as live
YEARS = 10.5
QUOTED = re.compile(r'["“]([^"”]{2,80})["”]')
FIG = re.compile(r"\s*\bfig\.?\s*$", re.I)


def read(folder: Path) -> Iterator[Dict]:
    import pyarrow.parquet as pq
    for f in sorted(glob.glob(str(Path(folder) / "month_*.parquet"))):
        yield from pq.read_table(f, columns=["app_number", "filing_date", "status", "title", "description"]).to_pylist()


def _iso(d: str) -> str:
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", (d or "").strip())
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else ""


def words_of(r: Dict) -> str:
    title = FIG.sub("", (r.get("title") or "").strip())
    if title:
        return title
    m = QUOTED.search(r.get("description") or "")
    return m.group(1).strip() if m else ""


def statuses(records) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in records:
        s = r.get("status") or ""
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def since(today: Optional[str] = None) -> str:
    """The earliest filing date kept (YEARS before `today`), YYYY-MM-DD: said in the index's source line."""
    today_d = datetime.date.fromisoformat(today or datetime.date.today().isoformat())
    return (today_d - datetime.timedelta(days=round(YEARS * 365.25))).isoformat()


def data_date(records) -> str:
    return max((_iso(r.get("filing_date")) for r in records), default="") or "unknown"


def rows(records, today: Optional[str] = None) -> Iterator[Tuple]:
    cutoff = since(today)
    seen = set()
    for r in records:
        number, filed = (r.get("app_number") or "").strip(), _iso(r.get("filing_date"))
        if not number or number in seen or r.get("status") not in LIVE or not filed or filed < cutoff:
            continue
        text = words_of(r)
        if text:
            seen.add(number)
            yield ("IT", number, text, "registered (per UIBM)" if r["status"] in REGISTERED else "pending (per UIBM)",
                   [], filed)
