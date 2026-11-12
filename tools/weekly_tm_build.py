"""Weekly server-side trade mark index for the Anteriora naming backend (not the app's pinned index).

    python tools/weekly_tm_build.py --out-dir DIR --prev SERVED.sqlite [--today YYYY-MM-DD]

Builds from the feeds the estate already refreshes:
  US  us_trademarks_current.parquet (daily USPTO files, us-tm-daily.timer), live/dead from the case-file status table
  FR  INPI ST.66 backlog + weekly files (inpi-marks-weekly.timer pulls them; this script copies new weeks in, sha-checked)
  EU, WO  INPI open-data month files (sr-inpi-recent.timer re-fetches the last 3 months daily, count-verified)
  AU  the extracted IP RAPID rows (dated; refreshed by hand; opt-in register, built last as its own span)

FAIL-CLOSED: the new index is written as index-YYYYMMDD.sqlite with a .report.json. Only when every check passes is
a .sha256 written next to it; the installer (weekly_tm_install.sh) refuses an index without one. Checks, against the
index the backend serves now (--prev):
  - sqlite quick_check is ok, schema and spans present;
  - per register, mark count within a band of the previous (a broken feed shows as a cliff, a new month as a step);
  - per register, at least 97% of a fixed random sample of the previous index's marks are still present (marks do
    die, but not 3% in a week), and every miss is counted in the report;
  - search smoke: 30 previous marks searched by their own text must come back with "same spelling" and their number;
  - each register's data date is not older than the previous one's.
"""
import argparse
import datetime
import hashlib
import itertools
import json
import random
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from inferroute_cli import tm_search as T  # noqa: E402

US_CURRENT = "/media/henry/Extreme SSD/open-data/uspto-tm/us_trademarks_current.parquet"
US_LOOKUPS = "/home/henry/anteriora-tmdata/uspto-mirror/lookups_status.csv"
FR_BUILD = Path("/home/henry/anteriora-tmdata/inpi")                       # backlog/ + weekly/ as tm_inpi reads them
FR_PULLED = Path("/media/henry/Extreme SSD/trademark-data/inpi/MARQ")       # where inpi-marks-weekly lands new weeks
FR_MANIFEST = Path("/media/henry/Extreme SSD/trademark-data/inpi/MANIFEST.tsv")
EU_WO = Path("/mnt/sdc/open-data/inpi-eu-wo")
AU_ROWS = Path("/home/henry/anteriora-tmdata/crg-public-index/recall-work/au_rows.json")

BANDS = {"US": (0.98, 1.03), "FR": (0.98, 1.03), "EU": (0.97, 1.05), "WO": (0.97, 1.05), "AU": (1.0, 1.0)}
FR_MAX_LOST = 0          # records INPI's malformed weekly files lose outright
SAMPLE_PER_REGISTER = 3000
MIN_PRESENT = 0.97
SMOKE = 30


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def sync_fr_weeks() -> list:
    """Copy weekly ST.66 files inpi-marks-weekly has pulled into the build folder; each must match its manifest sha."""
    want = {}
    for line in FR_MANIFEST.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and re.fullmatch(r"MARQ/FR_FR(NEW|UPD)ST66_\d{4}-\d+\.zip", parts[1]):
            want[parts[1].split("/", 1)[1]] = parts[0]
    added = []
    for name, digest in sorted(want.items()):
        dst = FR_BUILD / "weekly" / name
        if dst.exists():
            continue
        src = FR_PULLED / name
        if not src.exists() or sha256(src) != digest:
            raise SystemExit(f"FR weekly {name}: missing or sha differs from the manifest; not building")
        shutil.copy2(src, dst.with_suffix(".part"))
        dst.with_suffix(".part").rename(dst)
        added.append(name)
    return added


def rows(today: str, log):
    import tm_inpi
    import tm_inpi_eu
    import tm_inpi_wo
    import tm_uspto_daily
    parts, sources, dates = [], [], []
    parts.append(tm_uspto_daily.rows(US_CURRENT, US_LOOKUPS))
    sources.append("USPTO (United States)")
    dates.append(f"US {tm_uspto_daily.data_date(US_CURRENT)}")

    fr = tm_inpi.current(FR_BUILD)
    counts = tm_inpi.statuses(fr)
    unknown = [s for s in counts if s and s not in tm_inpi.LIVE and s not in tm_inpi.DEAD]
    # A malformed file is read field by field and usually loses nothing ("0 unreadable"); only lost records count.
    lost = 0
    for line in tm_inpi.SKIPPED:
        m = re.search(r"(\d+) unreadable", line)
        lost += int(m.group(1)) if m else 1
    log(f"FR malformed files: {len(tm_inpi.SKIPPED)}, records lost: {lost}")
    if unknown or lost > FR_MAX_LOST:
        raise SystemExit(f"FR: unclassified statuses {unknown}, or {lost} unreadable records; not building")
    parts.append(tm_inpi.rows(fr))
    sources.append("INPI (France)")
    dates.append(f"FR {tm_inpi.data_date(FR_BUILD)}")

    eu = tm_inpi_eu.current(EU_WO)
    counts = tm_inpi_eu.statuses(eu)
    unknown = [s for s in counts if s and s not in tm_inpi_eu.LIVE and s not in tm_inpi_eu.DEAD]
    if unknown:
        raise SystemExit(f"EU: unclassified statuses {unknown}; not building")
    parts.append(tm_inpi_eu.rows(eu))
    sources.append("EUIPO (EU trade marks, as republished in INPI open data)")
    dates.append(f"EU {tm_inpi_eu.data_date(eu)}")

    wo = tm_inpi_wo.current(EU_WO)
    parts.append(tm_inpi_wo.rows(wo, today))
    sources.append("WIPO (international registrations designating France or the EU, as republished in INPI open data)")
    dates.append(f"WO {tm_inpi_wo.data_date(wo)}")

    au = json.loads(AU_ROWS.read_text())
    parts.append((tuple(r) for r in au["rows"]))  # optional register: last, one span
    sources.append("IP Australia (Australian trade marks, from IP RAPID, licensed CC BY 4.0)")
    dates.append(f"AU {au['data_date']}")
    log(f"data: {', '.join(dates)}")
    return itertools.chain(*parts), ", ".join(dates), [f"{s}, live word marks" for s in sources]


def by_register(con):
    return dict(con.execute("select register, count(*) from marks group by register").fetchall())


def dates_of(con):
    v = dict(con.execute("select k, v from meta").fetchall()).get("data_date", "")
    return {p.split(" ", 1)[0]: p.split(" ", 1)[1] for p in v.split(", ") if " " in p}


def check(new: Path, prev: Path, log) -> dict:
    rep = {"checks": {}, "ok": True}

    def fail(name, detail):
        rep["checks"][name] = {"ok": False, "detail": detail}
        rep["ok"] = False
        log(f"FAIL {name}: {detail}")

    def ok(name, detail):
        rep["checks"][name] = {"ok": True, "detail": detail}
        log(f"ok   {name}: {detail}")

    n = sqlite3.connect(f"file:{new}?mode=ro", uri=True)
    p = sqlite3.connect(f"file:{prev}?mode=ro", uri=True)
    qc = n.execute("pragma quick_check").fetchone()[0]
    (ok if qc == "ok" else fail)("quick_check", qc)
    meta = dict(n.execute("select k, v from meta").fetchall())
    (ok if meta.get("schema") == T.SCHEMA and meta.get("spans") else fail)("schema", meta.get("schema"))

    cn, cp = by_register(n), by_register(p)
    rep["counts"] = {"new": cn, "prev": cp}
    for reg, (lo, hi) in BANDS.items():
        a, b = cn.get(reg, 0), cp.get(reg, 0)
        r = a / b if b else 0
        (ok if b and lo <= r <= hi else fail)(f"count {reg}", f"{b:,} -> {a:,} ({r:.4f}, band {lo}-{hi})")

    dn, dp = dates_of(n), dates_of(p)
    for reg in BANDS:
        (ok if dn.get(reg, "") >= dp.get(reg, "") else fail)(f"date {reg}", f"{dp.get(reg)} -> {dn.get(reg)}")

    rng = random.Random(20261113)
    for reg in BANDS:
        ids = [i for (i,) in p.execute("select id from marks where register=?", (reg,))]
        sample = rng.sample(ids, min(SAMPLE_PER_REGISTER, len(ids)))
        nums = [x for (x,) in p.execute(f"select number from marks where id in ({','.join(map(str, sample))})")]
        have = {x for (x,) in n.execute(f"select number from marks where register=? and number in "
                                         f"({','.join('?' * len(nums))})", (reg, *nums))}
        frac = len(have) / len(nums) if nums else 0
        (ok if frac >= MIN_PRESENT else fail)(f"present {reg}", f"{len(have)}/{len(nums)} ({frac:.4f})")

    ix = T.Index(str(new))
    cands = p.execute("select register, number, text, classes from marks where register in ('US','FR','EU','WO') "
                      "and length(text) between 5 and 14 and text not like '% %' order by random() limit 400").fetchall()
    tried = hits = 0
    for reg, num, text, cl in cands:
        if not n.execute("select 1 from marks where register=? and number=?", (reg, num)).fetchone():
            continue
        tried += 1
        r = ix.search(text, classes=[c for c in (cl or "").split(",") if c][:2], limit=50)
        group = [h for h in r["hits"] if "same spelling" in h.get("reasons", [])]
        found = any(m.get("number") == num for h in group for m in [h] + list(h.get("also", [])))
        hits += found
        if tried >= SMOKE:
            break
    (ok if tried >= SMOKE and hits == tried else fail)("search smoke", f"{hits}/{tried} found by their own text")
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--prev", required=True, type=Path, help="the index the backend serves now")
    ap.add_argument("--today", default=datetime.date.today().isoformat())
    a = ap.parse_args()
    a.out_dir.mkdir(parents=True, exist_ok=True)
    out = a.out_dir / f"index-{a.today.replace('-', '')}.sqlite"
    report = a.out_dir / (out.stem + ".report.json")
    lines = []

    def log(s):
        lines.append(s)
        print(s, flush=True)

    t = time.time()
    added = sync_fr_weeks()
    log(f"FR weekly files added: {added or 'none'}")
    it, date, sources = rows(a.today, log)
    info = T.build(it, out, date, sources)
    log(f"built {out.name}: {info.get('marks')} marks in {round(time.time() - t)} s")
    rep = check(out, a.prev, log)
    rep.update({"index": out.name, "built": info.get("built"), "data_date": date, "prev": str(a.prev),
                "prev_sha256": sha256(a.prev), "log": lines})
    if rep["ok"]:
        rep["sha256"] = sha256(out)
        (a.out_dir / (out.name + ".sha256")).write_text(f"{rep['sha256']}  {out.name}\n")
    report.write_text(json.dumps(rep, indent=1))
    log(f"{'PASS' if rep['ok'] else 'FAIL'}: report {report}")
    sys.exit(0 if rep["ok"] else 1)


if __name__ == "__main__":
    main()
