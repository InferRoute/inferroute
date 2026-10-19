"""Build the US part of the trademark index from USPTO case-file data in Parquet (our side, not shipped).

Input: a folder with case_file/*.parquet, intl_class/*.parquet and lookups/status_codes.csv laid out as in
the USPTO case-files dataset. Only live marks with a word element go in.

    python tools/build_tm_index_uspto.py SRC_DIR OUT.sqlite --data-date 2026-09-30
"""
import argparse
import csv
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inferroute_cli import tm_search as T  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src"); ap.add_argument("out"); ap.add_argument("--data-date", required=True)
    a = ap.parse_args()
    src = Path(a.src)
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

    def rows():
        for s, text, st, filed in zip(t["serial_no"].to_pylist(), t["mark_id_char"].to_pylist(),
                                      t["status_cd"].to_pylist(), t["filing_dt"].to_pylist()):
            label = status.get(st, ("", ""))[1].replace("Live/", "").lower() or "live"
            yield ("US", s, text.strip(), label, classes.get(s, ()), str(filed or ""))

    info = T.build(rows(), Path(a.out), a.data_date, ["USPTO (United States), live word marks"])
    print(info)


if __name__ == "__main__":
    main()
