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
    ap.add_argument("--inpi-eu", help="folder of INPI open-data EU_YYYYMM.parquet files (see tools/tm_inpi_eu.py)")
    ap.add_argument("--inpi-wo", help="folder of INPI open-data WO_YYYYMM.parquet files (see tools/tm_inpi_wo.py)")
    ap.add_argument("--ipau", help="IP RAPID Parquet folder (tm_application/, tm_description/, …; see tools/tm_ipau.py)")
    ap.add_argument("--uibm", help="folder of UIBM month_YYYY-MM.parquet files (see tools/tm_uibm.py)")
    ap.add_argument("--today", help="build date YYYY-MM-DD for IR expiry (default: today)")
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
    if a.inpi_eu:
        import tm_inpi_eu
        state = tm_inpi_eu.current(Path(a.inpi_eu))
        counts = tm_inpi_eu.statuses(state)
        print("EU statuses:", counts)
        unknown = [s for s in counts if s and s not in tm_inpi_eu.LIVE and s not in tm_inpi_eu.DEAD]
        if unknown:
            sys.exit(f"EU statuses not classified as live or dead: {unknown}. Classify them in tools/tm_inpi_eu.py.")
        parts.append(tm_inpi_eu.rows(state))
        sources.append("EUIPO (EU trade marks, as republished in INPI open data)")
        dates.append(f"EU {tm_inpi_eu.data_date(state)}")
    if a.inpi_wo:
        import tm_inpi_wo
        state = tm_inpi_wo.current(Path(a.inpi_wo))
        parts.append(tm_inpi_wo.rows(state, a.today))
        sources.append("WIPO (international registrations designating France or the EU, as republished in INPI open data)")
        dates.append(f"WO {tm_inpi_wo.data_date(state)}")
    if a.ipau:
        import tm_ipau
        counts = tm_ipau.statuses(Path(a.ipau))
        print("AU statuses:", counts)
        unknown = [s for s in counts if s and s not in tm_ipau.LIVE and s not in tm_ipau.DEAD]
        if unknown:
            sys.exit(f"AU statuses not classified as live or dead: {unknown}. Classify them in tools/tm_ipau.py.")
        parts.append(tm_ipau.rows(Path(a.ipau)))
        sources.append("IP Australia (Australian trade marks, including international registrations designating Australia)")
        dates.append(f"AU {tm_ipau.data_date(Path(a.ipau))}")
    if a.uibm:
        import tm_uibm
        records = list(tm_uibm.read(Path(a.uibm)))
        counts = tm_uibm.statuses(records)
        print("IT statuses:", counts)
        unknown = [s for s in counts if s not in tm_uibm.LIVE and s not in tm_uibm.DEAD]
        if unknown:
            sys.exit(f"IT statuses not classified as live or dead: {unknown}. Classify them in tools/tm_uibm.py.")
        parts.append(tm_uibm.rows(records, a.today))
        sources.append(f"UIBM (Italian national trade marks, filed since {tm_uibm.since(a.today)})")
        dates.append(f"IT {tm_uibm.data_date(records)}")
    if not parts:
        ap.error("give --uspto, --inpi, --inpi-eu, --inpi-wo, --ipau and/or --uibm")
    info = T.build(itertools.chain(*parts), Path(a.out), ", ".join(dates), [f"{s}, live word marks" for s in sources])
    print(info)


if __name__ == "__main__":
    main()
