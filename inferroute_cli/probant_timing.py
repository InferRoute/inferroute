"""How long a sealed search takes, measured on this computer — so the progress view can say what to expect.

Henry, 19 Sep: "we need better statistics for informing the progress view". It rested on one number measured by
hand ("usually a second or two") and a single previous search. The data says that was wrong in a way that
matters: across the 38 signed searches on this machine, a quick search spends ~0.4 s inside the search machine
and a broad one (50 results) ~1.7 s — over four times longer. One expectation cannot serve both.

Two sources, never blended, each labelled with what it measures:

- WAIT: what the person actually waited, per step (checking the machine, searching), recorded by the bridge
  from its own clock. Time spent reading the approval prompt is excluded — it is theirs, not the machine's.
- MACHINE: the search machine's own `search_seconds`, signed into every statement. Part of the wait, not all of
  it (the check, the network and opening the reply come on top), and said that way. It seeds the searching
  step until enough waits exist for that depth.

Numbers only: no query, no result, no matter name is written here.
"""
from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEPTH_K = {"quick": 10, "standard": 25, "broad": 50}    # the extension's own mapping (ir-attested.ts)
MIN_SAMPLES = 5                                         # below this a median is an anecdote; say so instead
KEEP = 400                                              # recent waits used; the machine changes between builds


def k_of(args: Dict[str, Any]) -> int:
    try:
        if args.get("k") is not None:
            return int(args["k"])
    except (TypeError, ValueError):
        pass
    return DEPTH_K.get(str(args.get("depth") or "quick"), 10)


def bucket(k: Optional[int]) -> str:
    """Measured: 10 and 25 results cost the same (~0.39 s inside the machine); 50 costs ~4x. Two buckets, not
    three, because the data draws the line there."""
    return "broad" if (k or 10) > 25 else "quick"


def _home() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential"


def waits_path() -> Path:
    return _home() / "search-timings.jsonl"


def record_wait(*, k: int, verifying_ms: Optional[float], searching_ms: Optional[float]) -> None:
    row = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "bucket": bucket(k), "k": k,
           "verifying_ms": None if verifying_ms is None else round(verifying_ms, 1),
           "searching_ms": None if searching_ms is None else round(searching_ms, 1)}
    try:
        p = waits_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass                                            # a missing statistic must never break a search


def _summary(values: List[float], source: str) -> Dict[str, Any]:
    v = sorted(values)
    n = len(v)
    mid = v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2
    return {"n": n, "median_ms": round(mid, 1), "p90_ms": round(v[max(0, math.ceil(0.9 * n) - 1)], 1),
            "source": source}


def _machine_times() -> Dict[str, List[float]]:
    """The search machine's own signed durations, from every sealed search recorded on this computer."""
    out: Dict[str, List[float]] = {"quick": [], "broad": []}
    root = _home() / "attested-records"
    for f in (root.rglob("*.searches.jsonl") if root.is_dir() else []):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                st = (json.loads(line).get("statement") or {})
            except ValueError:
                continue
            s = st.get("search_seconds")
            if st.get("sig") and isinstance(s, (int, float)) and s >= 0:
                out[bucket(st.get("k"))].append(float(s) * 1000)
    return out


def stats() -> Dict[str, Any]:
    """{"verifying": {...}|None, "searching": {"quick": {...}|None, "broad": {...}|None}}. Each summary says its
    `source` — "wait" (what a person waited here) or "machine" (the machine's own share, a lower bound)."""
    waits: List[Dict[str, Any]] = []
    try:
        for line in waits_path().read_text(encoding="utf-8").splitlines()[-KEEP:]:
            try:
                waits.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        pass
    ver = [w["verifying_ms"] for w in waits if isinstance(w.get("verifying_ms"), (int, float))]
    out: Dict[str, Any] = {"verifying": _summary(ver, "wait") if len(ver) >= MIN_SAMPLES else None, "searching": {}}
    machine = None
    for b in ("quick", "broad"):
        mine = [w["searching_ms"] for w in waits if w.get("bucket") == b and isinstance(w.get("searching_ms"), (int, float))]
        if len(mine) >= MIN_SAMPLES:
            out["searching"][b] = _summary(mine, "wait")
            continue
        if machine is None:
            machine = _machine_times()
        seed = machine.get(b) or []
        out["searching"][b] = _summary(seed, "machine") if len(seed) >= MIN_SAMPLES else None
    return out
