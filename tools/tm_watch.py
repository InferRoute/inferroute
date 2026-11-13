"""Name watch, weekly (our side). Two steps, run after a weekly index passes its checks:

    python tools/tm_watch.py diff OLD.sqlite NEW.sqlite DELTA.sqlite
        Marks in NEW that OLD did not have, or whose text or classes changed (by register + number), into a small
        index of their own. Only these can trigger an alert this week, so a watched name is not re-alerted on
        marks that were already there when the watch started.

    python tools/tm_watch.py match DELTA.sqlite WATCHES.jsonl ALERTS.jsonl --state SENT.jsonl
        Each watch ({"id", "name", "classes": ["9", ...], "countries": "EU,US"}) is searched against the delta with
        the same lights as the naming page (red / amber in the watch's registers and classes). New conflicts are
        appended to ALERTS.jsonl as a queue; nothing is sent from here. SENT.jsonl remembers (watch, register,
        number) already queued, so a mark is queued once per watch.

The watch list itself (name + email, the explicit opt-in) lives with the site; this tool sees ids, names, classes
and countries only, never an email.
"""
import argparse
import datetime
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from inferroute_cli import tm_search as T  # noqa: E402
from inferroute_cli.naming_demo.server import COUNTRIES, judge  # noqa: E402


def diff(old: Path, new: Path, out: Path) -> dict:
    con = sqlite3.connect(":memory:")
    con.execute("attach database ? as o", (f"file:{old}?mode=ro",))
    con.execute("attach database ? as n", (f"file:{new}?mode=ro",))
    con.execute("create temp table om (register text, number text, text text, classes text, primary key (register, number))"
                " without rowid")
    con.execute("insert or ignore into om select register, number, text, classes from o.marks")
    rows = con.execute("""
        select m.register, m.number, m.text, m.status, m.classes, m.filed,
               case when om.number is null then 'new' else 'changed' end
        from n.marks m left join om on om.register = m.register and om.number = m.number
        where om.number is null or om.text <> m.text or om.classes <> m.classes""").fetchall()
    meta = dict(con.execute("select k, v from n.meta").fetchall())
    kinds = {}
    for r in rows:
        kinds[(r[0], r[6])] = kinds.get((r[0], r[6]), 0) + 1
    T.build(((r[0], r[1], r[2], r[3], [c for c in (r[4] or "").split(",") if c], r[5]) for r in rows), out,
            meta.get("data_date", ""), [f"delta of {new.name} over {old.name}"])
    summary = {"delta": out.name, "old": old.name, "new": new.name, "marks": len(rows),
               "by": {f"{reg} {k}": v for (reg, k), v in sorted(kinds.items())}, "data_date": meta.get("data_date")}
    out.with_suffix(".json").write_text(json.dumps(summary, indent=1))
    return summary


# Watch amber cut, from tools/watch_bench.py (13 Nov, dev): at 0.70 one-letter substitutions, insertions, deletions,
# sound-alikes and added words are all caught (transpositions 63%), at an upper-bound alert rate of 2.8% of watches
# a week. The page keeps 0.80: a watch alert costs an email, a page light costs a name.
WATCH_AMBER = 0.70


def match(delta: Path, watches: Path, alerts: Path, state: Path, amber_at: float = WATCH_AMBER) -> dict:
    ix = T.Index(str(delta))
    sent = set()
    if state.exists():
        for line in state.read_text().splitlines():
            d = json.loads(line)
            sent.add((d["watch"], d["register"], d["number"]))
    week = datetime.date.today().isoformat()
    n_w = n_new = 0
    with open(alerts, "a") as fa, open(state, "a") as fs:
        for line in watches.read_text().splitlines():
            if not line.strip():
                continue
            w = json.loads(line)
            n_w += 1
            countries = [c for c in str(w.get("countries", "EU,US")).split(",")
                         if c in COUNTRIES and COUNTRIES[c]["registers"]]
            registers = {r for c in countries for r in COUNTRIES[c]["registers"]}
            also = [COUNTRIES[c]["also"] for c in countries if COUNTRIES[c].get("also")]
            r = ix.search(w["name"], classes=[str(c) for c in w.get("classes", [])], limit=50, also=also)
            j = judge(r, registers, keep=25, amber_at=amber_at)
            fresh = [c for c in j["conflicts"] if (w["id"], c["register"], c["number"]) not in sent]
            if not fresh:
                continue
            fa.write(json.dumps({"watch": w["id"], "name": w["name"], "week": week, "light": j["light"],
                                 "conflicts": fresh, "delta": delta.name}) + "\n")
            for c in fresh:
                fs.write(json.dumps({"watch": w["id"], "register": c["register"], "number": c["number"]}) + "\n")
                sent.add((w["id"], c["register"], c["number"]))
            n_new += 1
    return {"watches": n_w, "alerts": n_new}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff")
    d.add_argument("old", type=Path)
    d.add_argument("new", type=Path)
    d.add_argument("out", type=Path)
    m = sub.add_parser("match")
    m.add_argument("delta", type=Path)
    m.add_argument("watches", type=Path)
    m.add_argument("alerts", type=Path)
    m.add_argument("--state", type=Path, required=True)
    m.add_argument("--amber", type=float, default=WATCH_AMBER)
    a = ap.parse_args()
    print(json.dumps(diff(a.old, a.new, a.out) if a.cmd == "diff" else match(a.delta, a.watches, a.alerts, a.state, a.amber)))


if __name__ == "__main__":
    main()
