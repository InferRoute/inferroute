"""Measure the trademark name check against tests/data/tm_eval.json (our side; needs a built index).

    python tools/tm_eval.py INDEX.sqlite [--show N]

Prints, for each conflict pair, the rank of the expected mark (or MISS), then recall in the top 20, and for each
clean name the hits that claim the same spelling or the same sound (there should be none).
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


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("index"); ap.add_argument("--show", type=int, default=0)
    a = ap.parse_args()
    data = json.loads((HERE.parent / "tests" / "data" / "tm_eval.json").read_text())
    evaluate(T.Index(Path(a.index)), data, show=a.show)
