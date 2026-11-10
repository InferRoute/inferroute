"""Measure the trademark name check against tests/data/tm_eval.json (our side; needs a built index).

    python tools/tm_eval.py INDEX.sqlite [--show N] [--long SEARCHES]

Prints, for each conflict pair, the rank of the expected mark (or MISS), then recall in the top 20, and for each
clean name the hits that claim the same spelling or the same sound (there should be none).
With --long, every name is then searched again and again on the same index, as a long-running host does, until at
least SEARCHES searches have run, and every result (top 20 and scores) must stay what the first pass returned.
"""
import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from inferroute_cli import tm_search as T  # noqa: E402

STRONG = ("same spelling", "sounds alike")


def evaluate(ix, data, top=20, show=0):
    ranks, timings = {}, []
    for name, classes, want in data["conflicts"]:
        t = time.time()
        r = ix.search(name, [str(c) for c in classes], limit=500)
        timings.append(time.time() - t)
        rank = next((i + 1 for i, h in enumerate(r["hits"]) if T.compact(h["text"]) == want), None)
        ranks[name] = rank
        print(f"{name:14} -> {want:12} {'MISS' if rank is None else rank:>5}")
        for h in r["hits"][:show]:
            print(f"      {h['score']:.3f} {h['class_overlap']} {h['text'][:40]:40} {'; '.join(h['reasons'])}")
    found = sum(1 for v in ranks.values() if v and v <= top)
    print(f"\nrecall@{top}: {found}/{len(ranks)}")
    false_strong = {}
    for name in data["clean"]:
        t = time.time()
        r = ix.search(name, ["9", "42"], limit=top)
        timings.append(time.time() - t)
        bad = [h["text"] for h in r["hits"] if any(x in h["reasons"] for x in STRONG)]
        false_strong[name] = bad
        print(f"clean {name:12} hits={len(r['hits']):3} strong={bad}")
    timings.sort()
    print(f"search time: median {timings[len(timings) // 2]:.2f}s, max {timings[-1]:.2f}s")
    return {"recall": found, "of": len(ranks), "ranks": ranks, "clean_strong": false_strong}


def long_lived(ix, data, searches=250):
    """Every name of the set (conflicts and clean names) searched pass after pass on ONE index, as the host keeps it
    between sessions, until at least `searches` searches have run. Each search's top 20 (number and score) must be
    what the first pass returned, and each conflict's rank with it. A word cache trimmed before it was read scored
    about one search in 45 with every word as rare as can be (SUPERBIOTIX 1st alone, 25th inside a long run;
    9 Nov): a fresh process never shows that, and a rank alone rarely did (one top 20 in five such searches
    changed, no conflict's rank), so the scores are compared."""
    names = [(n, [str(c) for c in cl], want) for n, cl, want in data["conflicts"]] + \
            [(n, ["9", "42"], None) for n in data["clean"]]
    def one(name, classes, want):
        hits = ix.search(name, classes, limit=500)["hits"]
        rank = next((i + 1 for i, h in enumerate(hits) if T.compact(h["text"]) == want), None) if want else None
        return rank, [(h["register"], h["number"], round(h["score"], 6)) for h in hits[:20]]
    first = {n: one(n, cl, w) for n, cl, w in names}
    done, drift = len(names), []
    while done < searches:
        for n, cl, w in names:
            done += 1
            got = one(n, cl, w)
            if got != first[n]:
                drift.append((done, n, first[n][0], got[0]))
    print(f"long-lived: {done} searches on one index, "
          + ("every result as on the first pass" if not drift
             else f"{len(drift)} results changed (search, name, first rank, rank): {drift[:10]}"))
    return {"searches": done, "drift": drift}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("index"); ap.add_argument("--show", type=int, default=0)
    ap.add_argument("--long", type=int, default=0, help="then search on the same index until this many searches ran")
    a = ap.parse_args()
    data = json.loads((HERE.parent / "tests" / "data" / "tm_eval.json").read_text())
    ix = T.Index(Path(a.index))
    evaluate(ix, data, show=a.show)
    if a.long and long_lived(ix, data, a.long)["drift"]:
        sys.exit(1)
