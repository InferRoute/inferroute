"""Sensitivity bench for the name watch (dev; our half of the oppositions only, h >= 0x80, as release-bench-v1).

    python tools/watch_bench.py --cases release-bench-v1/cases.jsonl --index SERVED.sqlite --delta DELTA.sqlite \
        --out bench.json [--real 1500] [--synthetic 400] [--noise 1000] [--workers 8]

A watch searches a week's NEW marks for its name. So the bench injects "new filings" into the real weekly delta
(as distractors) and asks whether each watch flags its own:
  real       an opposition turned around: the watched name is the EARLIER mark's text (from the index), the new
             filing is the LATER mark the office was asked to refuse because of it. Identical texts are reported
             apart (always red); the headline is the near-variant pairs.
  synthetic  real single-word marks as watched names; the new filing is a one-letter edit (substitute, insert,
             delete, swap), a sound-alike spelling, or the name plus a word.
  noise      random real marks as watched names against the REAL delta only: alerts there are an upper bound on
             false alerts (some are genuinely close new marks), reported per watch per week.
Each target's best hit (reasons, score) is recorded once; the decision rule is applied per threshold afterwards,
so recall and alert rate come out for every amber cut without re-searching.
"""
import argparse
import json
import multiprocessing as mp
import random
import re
import sqlite3
import statistics
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from inferroute_cli import tm_search as T  # noqa: E402

RED = {"same spelling", "sounds alike"}
AMBER = {"spelled closely", "sounds close", "has your whole name inside it", "is part of your name"}
THRESHOLDS = [0.60, 0.65, 0.70, 0.72, 0.74, 0.76, 0.78, 0.80, 0.82, 0.85]
WORDS = ["pro", "labs", "group", "go", "plus", "app", "the", "studio", "hub", "one"]
SOUNDS = [("ph", "f"), ("f", "ph"), ("c", "k"), ("k", "c"), ("s", "z"), ("z", "s"), ("i", "y"), ("y", "i"),
          ("ou", "u"), ("qu", "k"), ("x", "ks"), ("ee", "i"), ("oo", "u")]
WEEKLY_NEW = 18_100   # new marks a week across US+FR+EU+WO, from the 13 Nov lag measurement baselines


def decide(reasons, score, t, words_too=False):
    r = set(reasons)
    if r & RED:
        return "red"
    amber = AMBER | ({"shares the word"} if words_too else set())
    if any(x.startswith(tuple(amber)) for x in r) and score >= t:
        return "amber"
    return None


def variants(name: str, rng: random.Random):
    s = name.lower()
    out = []
    i = rng.randrange(1, len(s) - 1)
    out.append(("sub1", s[:i] + rng.choice([c for c in "aeioubcdfgklmnprst" if c != s[i]]) + s[i + 1:]))
    out.append(("ins1", s[:i] + rng.choice("aeioulnrst") + s[i:]))
    out.append(("del1", s[:i] + s[i + 1:]))
    j = rng.randrange(1, len(s) - 2)
    if s[j] != s[j + 1]:
        out.append(("swap", s[:j] + s[j + 1] + s[j] + s[j + 2:]))
    for a, b in SOUNDS:
        if a in s[1:]:
            k = s.index(a, 1)
            out.append(("sound", s[:k] + b + s[k + len(a):]))
            break
    w = rng.choice(WORDS)
    out.append(("addword", f"{s} {w}" if rng.random() < 0.6 else f"{w} {s}"))
    return [(k, v.upper()) for k, v in out if v.replace(" ", "") != s.replace(" ", "")]


_IX = None


def _init(path):
    global _IX
    _IX = T.Index(path)


def _probe(job):
    """(key, watched name, classes, target number) -> best hit on the target, and every alert-able hit's evidence."""
    key, name, classes, target, registers = job
    r = _IX.search(name, classes=classes, limit=200)
    best, best_any, others = None, None, []
    for h in r.get("hits", []):
        group = [h] + list(h.get("also", []))
        ev = {"reasons": h.get("reasons", []), "score": h.get("score", 0)}
        is_target = bool(target) and any(m.get("number") == target for m in group)
        if is_target and (best_any is None or ev["score"] > best_any["score"]):
            best_any = ev  # text resemblance alone, whatever the classes
        here = [m for m in group if m.get("register") in registers and m.get("overlapping_classes")]
        if not here:
            continue
        if is_target:
            if best is None or ev["score"] > best["score"]:
                best = ev
        else:
            others.append(ev)
    return key, (best, best_any), others


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True, type=Path)
    ap.add_argument("--index", required=True, type=Path, help="served index, for the earlier marks' text and classes")
    ap.add_argument("--delta", required=True, type=Path, help="a real weekly delta (distractors and noise)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--real", type=int, default=1500)
    ap.add_argument("--synthetic", type=int, default=400)
    ap.add_argument("--noise", type=int, default=1000)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    rng = random.Random(20261113)
    idx = sqlite3.connect(f"file:{a.index}?mode=ro", uri=True)
    norm = lambda n: re.sub(r"\D", "", str(n)).lstrip("0")  # noqa: E731
    flat = lambda s: re.sub(r"[^a-z0-9]", "", (s or "").lower())  # noqa: E731

    # ---- real: earlier text + classes from the index
    cases = [json.loads(x) for x in a.cases.read_text().splitlines() if x.strip()]
    rng.shuffle(cases)
    need = {}
    for c in cases:
        need.setdefault(c["ereg"], set()).add(c["e"])
    earlier = {}
    for reg, nums in need.items():
        for num, text, cl in idx.execute("select number, text, classes from marks where register=?", (reg,)):
            k = norm(num)
            if k in nums:
                earlier[(reg, k)] = (text, [x for x in (cl or "").split(",") if x])
    real, injected, seen = [], [], set()
    for c in cases:
        e = earlier.get((c["ereg"], c["e"]))
        if not e or not e[1] or not c["later"].strip() or c["id"] in seen:
            continue
        seen.add(c["id"])
        same = flat(e[0]) == flat(c["later"])
        lcls = c["classes"] or e[1]
        num = f"WB{len(real):06d}"
        real.append({"key": f"R{len(real)}", "name": e[0], "classes": e[1][:6], "target": num, "same": same,
                     "classes_src": "later" if c["classes"] else "assumed", "later": c["later"]})
        injected.append(("FR", num, c["later"], "registered", lcls, "2026-11-10"))
        if len(real) >= a.real:
            break

    # ---- synthetic: single-word real marks and their variants
    pool = idx.execute("select text, classes from marks where register in ('US','EU','FR') and length(text) between 6 "
                       "and 11 and text not like '% %' and text glob '[A-Za-z]*' and classes <> '' "
                       "order by random() limit ?", (a.synthetic * 3,)).fetchall()
    synth = []
    for text, cl in pool:
        if not re.fullmatch(r"[A-Za-z]+", text):
            continue
        cls = [x for x in cl.split(",") if x][:3]
        for kind, v in variants(text, rng):
            num = f"WS{len(synth):06d}"
            synth.append({"key": f"S{len(synth)}", "name": text, "classes": cls, "target": num, "kind": kind, "new": v})
            injected.append(("US", num, v, "pending", cls, "2026-11-10"))
        if len({s["name"] for s in synth}) >= a.synthetic:
            break

    # ---- bench index = real delta + injected new filings
    tmp = Path(tempfile.mkdtemp(prefix="watchbench-"))
    dcon = sqlite3.connect(f"file:{a.delta}?mode=ro", uri=True)
    base = [(r[0], r[1], r[2], r[3], [x for x in (r[4] or "").split(",") if x], r[5])
            for r in dcon.execute("select register, number, text, status, classes, filed from marks")]
    bench_ix = tmp / "bench.sqlite"
    T.build(iter(base + injected), bench_ix, "bench", ["watch bench"])
    regs = ["US", "FR", "EU", "WO"]

    noise = [{"key": f"N{i}", "name": t, "classes": [x for x in c.split(",") if x][:3]} for i, (t, c) in enumerate(
        idx.execute("select text, classes from marks where register in ('US','EU','FR') and classes <> '' and "
                    "length(text) between 4 and 20 order by random() limit ?", (a.noise,)))]

    jobs = [(x["key"], x["name"], x["classes"], x["target"], regs) for x in real + synth]
    with mp.get_context("fork").Pool(a.workers, initializer=_init, initargs=(str(bench_ix),)) as pool:
        got = {k: (b, o) for k, b, o in pool.imap_unordered(_probe, jobs, chunksize=8)}
    with mp.get_context("fork").Pool(a.workers, initializer=_init, initargs=(str(a.delta),)) as pool:
        ngot = {k: o for k, _b, o in pool.imap_unordered(_probe, [(x["key"], x["name"], x["classes"], None, regs)
                                                                  for x in noise], chunksize=8)}

    def recall(rows, t, words_too=False, classes=True):
        i = 0 if classes else 1
        hit = sum(1 for x in rows if got[x["key"]][0][i] and decide(got[x["key"]][0][i]["reasons"],
                                                                     got[x["key"]][0][i]["score"], t, words_too))
        return round(hit / len(rows), 4) if rows else None

    weeks = dcon.execute("select count(*) from marks").fetchone()[0] / WEEKLY_NEW
    res = {"n": {"real": len(real), "real_near": sum(not x["same"] for x in real), "synthetic": len(synth),
                 "noise_watches": len(noise), "delta_marks": len(base), "delta_weeks_equiv": round(weeks, 2)},
           "thresholds": {}}
    near = [x for x in real if not x["same"]]
    near_cls = [x for x in near if x["classes_src"] == "later"]
    kinds = sorted({x["kind"] for x in synth})
    for t in THRESHOLDS:
        for words_too in (False, True):
            alerting = [sum(1 for ev in ngot[x["key"]] if decide(ev["reasons"], ev["score"], t, words_too)) > 0
                        for x in noise]
            row = {"real_identical": recall([x for x in real if x["same"]], t, words_too),
                   "real_identical_text_only": recall([x for x in real if x["same"]], t, words_too, classes=False),
                   "real_near": recall(near, t, words_too), "real_near_with_classes": recall(near_cls, t, words_too),
                   "real_near_text_only": recall(near, t, words_too, classes=False),
                   **{f"syn_{k}": recall([x for x in synth if x["kind"] == k], t, words_too) for k in kinds},
                   "noise_watch_alerting_in_delta": round(sum(alerting) / len(noise), 4),
                   "noise_alert_rate_per_watch_week": round(sum(alerting) / len(noise) / weeks, 4)}
            res["thresholds"][f"{t:.2f}{'+words' if words_too else ''}"] = row
    scores = [got[x["key"]][0][1]["score"] for x in near if got[x["key"]][0][1]]
    res["real_near_target_found_any_rank"] = round(len(scores) / len(near), 4) if near else None
    res["real_near_score_quartiles"] = statistics.quantiles(scores, n=4) if len(scores) > 4 else scores
    res["misses_sample"] = [{"watched": x["name"], "new": x["later"]} for x in near if not got[x["key"]][0][1]][:25]
    res["syn_misses_at_0.80"] = [{"watched": x["name"], "new": x["new"], "kind": x["kind"],
                                  "evidence": got[x["key"]][0][1]} for x in synth
                                 if not (got[x["key"]][0][0] and decide(got[x["key"]][0][0]["reasons"],
                                                                        got[x["key"]][0][0]["score"], 0.80))][:25]
    a.out.write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1)[:4000])


if __name__ == "__main__":
    main()
