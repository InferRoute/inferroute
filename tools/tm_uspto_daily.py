"""USPTO trademarks from the daily-updated table (TRTYRAP annual backfile + TRTDXFAP daily files, merged by
sealed-research/index/merge_us_tm_daily.py into us_trademarks_current.parquet) to index rows.

Our side, not shipped. This is what keeps the server-side index weekly: the case-file dataset tools/tm_uspto.py reads
is published far less often. Live/dead comes from the SAME status table as tm_uspto (lookups_status.csv from the
case-file dataset), so both readers keep exactly the same marks for the same status codes. A status code missing
from that table stops the build rather than guessing.
"""
import csv
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

COLS = ["serial_number", "mark_text", "status_code", "nice_classes", "filing_date"]


def status_table(lookups_csv):
    return {r["code"]: (r["description"], r["live_dead_indicator"]) for r in csv.DictReader(open(lookups_csv))}


def data_date(current_parquet) -> str:
    """The newest daily file applied (apcYYMMDD), as YYYY-MM-DD."""
    stem = (Path(current_parquet).parent / "_current_applied.txt").read_text().strip()
    d = stem.replace("apc", "")
    return f"20{d[:2]}-{d[2:4]}-{d[4:6]}"


def rows(current_parquet, lookups_csv):
    status = status_table(lookups_csv)
    live = {c for c, (_, ind) in status.items() if ind.startswith("Live")}
    f = pq.ParquetFile(current_parquet)
    unknown = set()
    for b in f.iter_batches(columns=COLS, batch_size=1 << 18):
        # The daily files sometimes drop leading zeros ("0" for "000"); the lookup table is three digits.
        codes = pa.array([c.zfill(3) if c else c for c in b.column("status_code").to_pylist()], pa.string())
        unknown.update(c for c in codes.to_pylist() if c and c not in status)
        b = b.set_column(COLS.index("status_code"), "status_code", codes)
        b = b.filter(pc.is_in(b.column("status_code"), value_set=pa.array(sorted(live))))
        for s, text, st, cl, filed in zip(*(b.column(c).to_pylist() for c in COLS)):
            text = (text or "").strip()
            if not text:
                continue
            label = status[st][1].replace("Live/", "").lower() or "live"
            classes = sorted({str(int(c)) for c in (cl or "").replace(";", ",").split(",")
                              if c.strip().isdigit() and 1 <= int(c) <= 45})  # same order as tm_uspto
            filed = str(filed or "")
            if len(filed) == 8 and filed.isdigit():
                filed = f"{filed[:4]}-{filed[4:6]}-{filed[6:]}"
            yield ("US", s, text, label, classes, filed)
    if unknown:
        raise SystemExit(f"USPTO status codes not in lookups_status.csv: {sorted(unknown)[:20]}. Update the table.")
