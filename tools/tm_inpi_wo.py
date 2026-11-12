"""International registrations (WIPO Madrid) as INPI's open data republishes them (collection WO, monthly
Parquet), to index rows.

Our side, not shipped. The pull writes one Parquet per filing month (WO_YYYYMM.parquet), with the same columns as
the EU pull plus expiry_date. A number can appear more than once; the record from the newest inpi_revision wins.

INPI's copy carries NO status for these marks, so "live" here means: not expired on the build date, and naming
France (FR) or the EU (EM) among its designated parties. A designation refused in France or the EU still looks live
here, and an IR with no word element cannot be matched against a name. Both are named as not searched (tm_search
HELD_AS["WIPO"]). The pull starts at 1996, so older IRs are absent unless INPI lists them under a later month.
"""
import datetime
import glob
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

from tm_inpi_eu import merge  # same newest-revision-wins rule

DESIGNATING = {"FR", "EM"}
# Not "registered": INPI's copy cannot show whether protection was granted in France or the EU (for about half of
# older French designations no office event is recorded at all), so the status says what is known, and a report that
# calls one "registered" is refused by the citation check.
STATUS = "international registration"


def read(folder: Path) -> Iterator[Dict]:
    import pyarrow.parquet as pq
    for f in sorted(glob.glob(str(Path(folder) / "WO_*.parquet"))):
        yield from pq.read_table(f).to_pylist()


def current(folder: Path) -> Dict[str, Dict]:
    return merge(read(folder))


def _day(d: str) -> str:
    return f"{d[:4]}-{d[4:6]}-{d[6:8]}" if len(d or "") == 8 and d.isdigit() else ""


def data_date(state: Dict[str, Dict]) -> str:
    newest = max((r.get("application_date") or "" for r in state.values()), default="")
    return _day(newest) or "unknown"


def live(r: Dict, today: str) -> bool:
    designated = {c.strip() for c in (r.get("designated_countries") or "").split(",")}
    expiry = _day(r.get("expiry_date") or "")
    return bool(designated & DESIGNATING) and bool(expiry) and expiry >= today


def rows(state: Dict[str, Dict], today: Optional[str] = None) -> Iterator[Tuple]:
    today = today or datetime.date.today().isoformat()
    for number, r in state.items():
        text = (r.get("mark_text") or "").strip()
        if text and live(r, today):
            classes = sorted({str(int(c)) for c in (r.get("nice_classes") or "").split(",")
                              if c.strip().isdigit() and 1 <= int(c) <= 45})
            yield ("WO", number.lstrip("0") or "0", text, STATUS, classes, _day(r.get("application_date") or ""))
