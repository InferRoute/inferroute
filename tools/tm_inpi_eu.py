"""EU trade marks as INPI's open data republishes them (collection EU, monthly Parquet), to index rows.

Our side, not shipped. The pull writes one Parquet per filing month (EU_YYYYMM.parquet) with the columns
collection, application_number, mark_text, status, nice_classes, application_date, designated_countries,
inpi_revision. A number can appear more than once (the pull repeated some months); the record from the newest
inpi_revision wins, and identical repeats collapse.

As for the French register, a mark is kept when its status is live and it has a word element: a figurative
mark with no text cannot be matched against a name.
"""
import glob
from pathlib import Path
from typing import Dict, Iterable, Iterator, Tuple

LIVE = {
    "Registered", "Application published", "Application opposed", "Application under examination",
    "Registration cancellation pending", "Application filed", "Registration pending", "Appeal pending",
}
DEAD = {
    "Registration expired", "Application withdrawn", "Application refused", "Registration surrendered",
    "Registration cancelled",
}
REGISTERED = {"Registered", "Registration cancellation pending"}


def read(folder: Path) -> Iterator[Dict]:
    """Every record of every EU_*.parquet, in file order (pyarrow is needed here only, on the building side)."""
    import pyarrow.parquet as pq
    for f in sorted(glob.glob(str(Path(folder) / "EU_*.parquet"))):
        yield from pq.read_table(f).to_pylist()


def merge(records: Iterable[Dict]) -> Dict[str, Dict]:
    """number -> the record from the newest inpi_revision (a later record of the same revision wins)."""
    state: Dict[str, Dict] = {}
    for r in records:
        number = (r.get("application_number") or "").strip()
        if not number:
            continue
        prior = state.get(number)
        if prior is None or (r.get("inpi_revision") or "") >= (prior.get("inpi_revision") or ""):
            state[number] = r
    return state


def current(folder: Path) -> Dict[str, Dict]:
    return merge(read(folder))


def statuses(state: Dict[str, Dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in state.values():
        s = r.get("status") or ""
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def data_date(state: Dict[str, Dict]) -> str:
    """The newest filing date the pull holds, YYYY-MM-DD."""
    newest = max((r.get("application_date") or "" for r in state.values()), default="")
    return f"{newest[:4]}-{newest[4:6]}-{newest[6:8]}" if len(newest) == 8 else "unknown"


def rows(state: Dict[str, Dict], live: set = LIVE) -> Iterator[Tuple]:
    for number, r in state.items():
        text = (r.get("mark_text") or "").strip()
        if r.get("status") in live and text:
            classes = sorted({str(int(c)) for c in (r.get("nice_classes") or "").split(",")
                              if c.strip().isdigit() and 1 <= int(c) <= 45})
            d = r.get("application_date") or ""
            filed = f"{d[:4]}-{d[4:6]}-{d[6:8]}" if len(d) == 8 else ""
            yield ("EU", number, text, "registered" if r["status"] in REGISTERED else "pending", classes, filed)
