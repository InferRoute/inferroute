"""Follow-up to watch_bench.py (13 Nov, dev): added noise of alerting on identical/sound-alike names in ANY class.
1,000 random watches against the real delta; prints per-watch-week rates. Run from the repo root."""
import sys, json, sqlite3, multiprocessing as mp, os
sys.path.insert(0, '.')
from inferroute_cli import tm_search as T
DELTA = os.path.expanduser('~/anteriora-tmdata/watch/delta-20261113.sqlite')
IDX = os.path.expanduser('~/anteriora-tmdata/cand-138/index-us-fr-eu-wo-au-20261112.sqlite')
RED = {"same spelling", "sounds alike"}; AMBER = {"spelled closely", "sounds close", "has your whole name inside it", "is part of your name"}
REGS = {"US", "FR", "EU", "WO"}; WEEKLY_NEW = 18_100
_IX = None
def init():
    global _IX; _IX = T.Index(DELTA)
def probe(w):
    name, cl = w
    r = _IX.search(name, classes=cl, limit=200)
    base = anyred = 0; anyred_ex = []
    for h in r["hits"]:
        g = [h] + list(h.get("also", [])); rs = set(h.get("reasons", []))
        inreg = [m for m in g if m.get("register") in REGS]
        if not inreg: continue
        withcls = [m for m in inreg if m.get("overlapping_classes")]
        if withcls and (rs & RED or (rs & AMBER and h.get("score", 0) >= 0.70)): base = 1
        if rs & RED and not withcls:
            anyred = 1; anyred_ex.append((h["text"], h.get("register"), h.get("classes"), sorted(rs & RED)))
    return name, cl, base, anyred, anyred_ex[:2]
if __name__ == "__main__":
    c = sqlite3.connect(f"file:{IDX}?mode=ro", uri=True)
    import random
    ws = [(t, [x for x in cl.split(",") if x][:3]) for t, cl in c.execute(
        "select text, classes from marks where register in ('US','EU','FR') and classes <> '' and length(text) between 4 and 20 order by random() limit 1000")]
    with mp.get_context("fork").Pool(10, initializer=init) as p:
        res = list(p.imap_unordered(probe, ws, chunksize=8))
    weeks = sqlite3.connect(f"file:{DELTA}?mode=ro", uri=True).execute("select count(*) from marks").fetchone()[0] / WEEKLY_NEW
    base = sum(r[2] for r in res); extra = sum(1 for r in res if r[3] and not r[2]); union = sum(1 for r in res if r[2] or r[3])
    print(json.dumps({"watches": len(res), "weeks": round(weeks, 2),
        "in_classes_0.70_per_watch_week": round(base / len(res) / weeks, 4),
        "added_by_any_class_red_per_watch_week": round(extra / len(res) / weeks, 4),
        "combined_per_watch_week": round(union / len(res) / weeks, 4)}))
    single = [r for r in res if len(r[0].split()) == 1]; multi = [r for r in res if len(r[0].split()) > 1]
    for lab, rs in (("single-word names", single), ("multi-word names", multi)):
        print(lab, len(rs), "added any-class rate/watch/week", round(sum(1 for r in rs if r[3] and not r[2]) / max(1, len(rs)) / weeks, 4))
    print("examples:", [(r[0], r[1], r[4][0]) for r in res if r[3] and not r[2]][:12])
