"""USPTO case-file data (Parquet) to index rows (our side, not shipped).

Input: a folder with case_file/*.parquet, intl_class/*.parquet and lookups_status.csv laid out as in the
USPTO case-files dataset. Only live marks with a word element go in. Used by tools/build_tm_index.py.
"""
import csv
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq



def rows(src_dir):
    src = Path(src_dir)
    status = {r["code"]: (r["description"], r["live_dead_indicator"]) for r in csv.DictReader(open(src / "lookups_status.csv"))}
    live = sorted(c for c, (_, ind) in status.items() if ind.startswith("Live"))
    cols = ["serial_no", "mark_id_char", "status_cd", "filing_dt"]
    t = pa.concat_tables([pq.read_table(p, columns=cols) for p in sorted((src / "case_file").glob("*.parquet"))])
    t = t.filter(pc.is_in(t["status_cd"], value_set=pa.array(live)))
    t = t.filter(pc.and_(pc.is_valid(t["mark_id_char"]),
                         pc.greater(pc.utf8_length(pc.utf8_trim_whitespace(t["mark_id_char"])), 0)))
    keep = pa.array(sorted(set(t["serial_no"].to_pylist())))
    classes = {}
    for p in sorted((src / "intl_class").glob("*.parquet")):
        ic = pq.read_table(p, columns=["serial_no", "intl_class_cd"])
        ic = ic.filter(pc.is_in(ic["serial_no"], value_set=keep))
        for s, c in zip(ic["serial_no"].to_pylist(), ic["intl_class_cd"].to_pylist()):
            if c and c.strip().isdigit() and int(c) <= 45:
                classes.setdefault(s, set()).add(str(int(c)))
    for s, text, st, filed in zip(t["serial_no"].to_pylist(), t["mark_id_char"].to_pylist(),
                                  t["status_cd"].to_pylist(), t["filing_dt"].to_pylist()):
        label = status.get(st, ("", ""))[1].replace("Live/", "").lower() or "live"
        yield ("US", s, text.strip(), label, sorted(classes.get(s, ())), str(filed or ""))
