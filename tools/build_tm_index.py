"""Build the trademark index the name check searches (our side; the output is the file a computer downloads).

    python tools/build_tm_index.py OUT.sqlite --uspto DIR --uspto-date 2026-09-30 --inpi DIR

--uspto: USPTO case-file Parquet (see tools/tm_uspto.py). --inpi: the INPI MARQ feed as fetched (backlog/ and
weekly/ zips, see tools/tm_inpi.py); its data date is the newest weekly file's date. Either may be omitted.
"""
import argparse
import itertools
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from inferroute_cli import tm_search as T  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--uspto"); ap.add_argument("--uspto-date")
    ap.add_argument("--inpi")
    a = ap.parse_args()
    parts, sources, dates = [], [], []
    if a.uspto:
        import tm_uspto
        if not a.uspto_date:
            ap.error("--uspto-date is required with --uspto")
        parts.append(tm_uspto.rows(a.uspto))
        sources.append("USPTO (United States)")
        dates.append(f"US {a.uspto_date}")
    if a.inpi:
        import tm_inpi
        state = tm_inpi.current(Path(a.inpi))
        counts = tm_inpi.statuses(state)
        print("INPI statuses:", counts)
        print(f"INPI files skipped as malformed: {len(tm_inpi.SKIPPED)}")
        for line in tm_inpi.SKIPPED[:20]:
            print("   ", line)
        unknown = [s for s in counts if s and s not in tm_inpi.LIVE and s not in tm_inpi.DEAD]
        if unknown:
            sys.exit(f"INPI statuses not classified as live or dead: {unknown}. Classify them in tools/tm_inpi.py.")
        parts.append(tm_inpi.rows(state))
        sources.append("INPI (France)")
        dates.append(f"FR {tm_inpi.data_date(Path(a.inpi))}")
    if not parts:
        ap.error("give --uspto and/or --inpi")
    info = T.build(itertools.chain(*parts), Path(a.out), ", ".join(dates), [f"{s}, live word marks" for s in sources])
    print(info)


if __name__ == "__main__":
    main()
