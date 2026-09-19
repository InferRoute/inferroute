"""A portfolio read by sealed sessions, clustered round after round until the clustering stops moving.

One document becomes matters by reading it (probant_intake). A PORTFOLIO — dozens of filings, briefs and
inventories, megabytes of them — does not: the same idea appears in six documents under six names, and what
the professional wants out is not a list of everything but the few themes the portfolio actually turns on,
and which of them most deserves a matter next.

The shape, and which side does what:

* **Extract** — one sealed session per document proposes candidate units, each with a verbatim quote. The
  HOST checks every quote against that document and drops the rest, counting the drops.
* **Cluster** — a sealed session sees only the candidates' titles and summaries (its own compact words, not
  the filings) and partitions them into named clusters.
* **Converge** — each round re-partitions the previous round's clusters, so ideas may merge or split as the
  abstraction rises. **The host decides when it has converged**, by comparing partitions between rounds. An
  agent asked whether it has converged will say yes; a partition compared with its predecessor cannot.
* **Rank** — the host computes the signals that are arithmetic (how many candidates, how many distinct
  documents, how many unfiled), the session argues a ranking against them, and both are kept. The computed
  numbers are never replaced by the argument.

Nothing here creates a matter, and no session in this pipeline is given a search tool: a whole portfolio is
in context, and none of it may leave for a search machine.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import probant as S

MAX_FILES = 400
MAX_BYTES = 40_000_000
MAX_ROUNDS = 6                 # a cap, not a target: rounds cost money and a partition that will not settle
CANDIDATES = "candidates.jsonl"
CLUSTERS = "clusters-round-%d.jsonl"
DOCS = "documents"


def portfolio_root() -> Path:
    return S.probant_root() / ".portfolio"


def _clean(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def stage(paths: Sequence[Path], name: str = "") -> Dict[str, Any]:
    """Copy the portfolio's documents where a sealed session can read them, and nowhere else.

    Copies rather than links: the session reads inside a sandbox, and a link out of it is either broken or a
    way back out. Each copy is read-only, and each document's sha256 is recorded, so a quote can later be
    checked against the bytes the session actually read.
    """
    files = [p for p in paths if p.is_file()]
    if not files:
        raise S.ProbantError("no readable documents in that portfolio")
    if len(files) > MAX_FILES:
        raise S.ProbantError(f"that portfolio has {len(files)} documents; this reads up to {MAX_FILES}")
    total = sum(p.stat().st_size for p in files)
    if total > MAX_BYTES:
        raise S.ProbantError(f"that portfolio is {total / 1e6:.0f} MB; this reads up to {MAX_BYTES / 1e6:.0f} MB")
    ident = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    d = portfolio_root() / ident
    (d / DOCS).mkdir(parents=True, exist_ok=False)
    for p in (S.probant_root(), portfolio_root(), d, d / DOCS):
        os.chmod(p, 0o700)
    documents = []
    seen: Dict[str, int] = {}
    for p in sorted(files):
        # A flat, unique name per document: the session works in one directory, and two "README.md" from
        # different folders must not become one file.
        base = re.sub(r"[^A-Za-z0-9._-]+", "-", p.name)[:80] or "document"
        if base in seen:
            seen[base] += 1
            base = f"{Path(base).stem}-{seen[base]}{Path(base).suffix}"
        else:
            seen[base] = 1
        body = p.read_bytes()
        (d / DOCS / base).write_bytes(body)
        os.chmod(d / DOCS / base, 0o400)
        documents.append({"name": base, "from": str(p), "bytes": len(body),
                          "sha256": hashlib.sha256(body).hexdigest()})
    meta = {"schema": "inferroute.probant-portfolio/1", "id": ident, "name": _clean(name, 80) or "portfolio",
            "staged_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "documents": documents, "bytes": total}
    (d / "meta.json").write_text(json.dumps(meta, indent=1))
    os.chmod(d / "meta.json", 0o600)
    return meta


def path_of(ident: str) -> Path:
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", ident or ""):
        raise S.ProbantError("no such portfolio")
    d = portfolio_root() / ident
    if not (d / "meta.json").is_file():
        raise S.ProbantError("no such portfolio")
    return d


def meta_of(ident: str) -> Dict[str, Any]:
    return json.loads((path_of(ident) / "meta.json").read_text())


def _rows(path: Path) -> List[Dict[str, Any]]:
    out = []
    for line in (path.read_text(encoding="utf-8").splitlines() if path.exists() else []):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def candidates(ident: str) -> List[Dict[str, Any]]:
    """The proposed units whose quote is really in the document they name.

    A quote is checked against ITS OWN document, not against the portfolio: "this sentence exists somewhere
    in three megabytes" is not evidence that this filing says it.
    """
    d = path_of(ident)
    flat: Dict[str, str] = {}
    for doc in meta_of(ident)["documents"]:
        flat[doc["name"]] = re.sub(r"\s+", " ", (d / DOCS / doc["name"]).read_text(encoding="utf-8", errors="replace"))
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in _rows(d / CANDIDATES):
        title, summary = _clean(row.get("title"), 90), _clean(row.get("summary"), 1200)
        quote, source = _clean(row.get("quote"), 600), _clean(row.get("source"), 120)
        if not title or not summary or len(quote) < 20:
            continue
        body = flat.get(source)
        if body is None or quote not in body:          # not in the document it names: dropped, never shown
            continue
        key = (source, title.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": f"c{len(out) + 1}", "title": title, "summary": summary, "quote": quote, "source": source})
    return out


def dropped(ident: str) -> int:
    return max(0, len(_rows(path_of(ident) / CANDIDATES)) - len(candidates(ident)))


def clusters(ident: str, round_no: int, valid_ids: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """One round's clustering, and what it did with every candidate.

    Returns the clusters AND the accounting: which ids were left out, which were claimed twice, which do not
    exist. A round that silently loses a third of the portfolio is the failure this reports rather than hides.
    """
    ids = list(valid_ids if valid_ids is not None else [c["id"] for c in candidates(ident)])
    known = set(ids)
    out, assigned, twice, unknown = [], set(), [], []
    for row in _rows(path_of(ident) / (CLUSTERS % round_no)):
        label, thesis = _clean(row.get("label"), 90), _clean(row.get("thesis"), 600)
        named = [_clean(m, 24) for m in (row.get("members") or []) if isinstance(m, str)]
        unknown.extend(m for m in named if m not in known)
        kept = []
        for m in (m for m in named if m in known):
            if m in assigned:
                twice.append(m)
                continue
            assigned.add(m)
            kept.append(m)
        if not label or not kept:
            continue
        out.append({"label": label, "thesis": thesis, "members": kept, "why": _clean(row.get("why"), 600)})
    return {"clusters": out, "missing": [i for i in ids if i not in assigned], "twice": sorted(set(twice)),
            "unknown": sorted(set(unknown)), "round": round_no}


def partition(clustered: Dict[str, Any]) -> List[frozenset]:
    """A clustering as the only thing worth comparing between rounds: its member sets, labels ignored."""
    return sorted((frozenset(c["members"]) for c in clustered["clusters"]), key=lambda s: (-len(s), sorted(s)))


def movement(before: List[frozenset], after: List[frozenset]) -> float:
    """How much the partition moved, 0.0 (identical grouping) to 1.0 (nothing grouped the same way).

    Counted over PAIRS of candidates: the share of pairs that were together and are now apart, or apart and
    now together. Labels are ignored, because they are the agent's prose and the membership is the result.

    Pairs, not best-overlap matching: matching each new group to the old one it overlaps most scores a pure
    split as no movement at all — ten candidates becoming nine-plus-one looks identical to every group having
    a home. The first version of this did exactly that and called a split converged.
    """
    def pairs(groups: List[frozenset]) -> set:
        out = set()
        for g in groups:
            members = sorted(g)
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    out.add((a, b))
        return out
    ids = {m for g in before for m in g} | {m for g in after for m in g}
    n = len(ids)
    if n < 2:
        return 0.0 if pairs(before) == pairs(after) else 1.0
    disagree = pairs(before) ^ pairs(after)
    return round(len(disagree) / (n * (n - 1) / 2), 4)


def converged(history: List[List[frozenset]], threshold: float = 0.02) -> Tuple[bool, str]:
    """Host-side, never the agent's word for it. Converged when the last round did not move the membership
    (or moved less than `threshold`), which needs two rounds to say at all."""
    if len(history) < 2:
        return False, "one round so far; convergence needs two to compare"
    moved = movement(history[-2], history[-1])
    if moved == 0.0:
        return True, "the clustering did not move: same membership as the round before"
    if moved <= threshold:
        return True, f"the clustering moved {moved:.1%}, within the {threshold:.0%} threshold"
    return False, f"the clustering moved {moved:.1%}"


def signals(ident: str, clustered: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What can be counted rather than argued: how big a cluster is, and how much of the portfolio it spans.

    A theme one document repeats ten times is not the same as one six documents arrive at independently, and
    the difference is arithmetic. The ranking session sees these; it does not get to change them.
    """
    by_id = {c["id"]: c for c in candidates(ident)}
    out = []
    for c in clustered["clusters"]:
        members = [by_id[m] for m in c["members"] if m in by_id]
        sources = sorted({m["source"] for m in members})
        out.append({"label": c["label"], "thesis": c["thesis"], "members": c["members"],
                    "candidates": len(members), "documents": len(sources), "sources": sources})
    return sorted(out, key=lambda s: (-s["documents"], -s["candidates"], s["label"]))


# ───────────────────────────── the run: extract, cluster, converge ─────────────────────────────

EXTRACT = ("Read {name} in the documents directory, all of it, and propose every distinct invention in it "
           "with propose_matter — one call each, source \"{name}\", quoting the document verbatim. Then stop: "
           "one line saying how many you proposed and what the document is. Nothing else.")

CLUSTER = ("Read candidates.json in this directory: {n} candidate inventions drawn from {docs} documents of "
           "one patent portfolio. Group them into themes with propose_cluster — one call per theme, every "
           "candidate in exactly one theme, ids exactly as given. Prefer the grouping a patent attorney would "
           "use to decide what to file next: shared technical mechanism, not shared vocabulary. Then stop: "
           "one line on what the portfolio turns out to be about. Nothing else.")

RECLUSTER = ("Read clusters.json in this directory: the themes you drew last round over the same {n} "
             "candidates, which are in candidates.json. Reconsider the grouping from the top — merge themes "
             "that share a mechanism, split one that holds two, move a candidate that sits in the wrong "
             "place. Call propose_cluster once per theme, every candidate in exactly one theme. If the "
             "grouping is already right, propose it again unchanged; that is a real answer and it ends the "
             "work. Then stop: one line on what changed and why. Nothing else.")


def round_dir(ident: str, round_no: int) -> Path:
    return path_of(ident) / f"round-{round_no}"


def write_round_inputs(ident: str, round_no: int) -> Dict[str, Any]:
    """The session's own, compact view of the portfolio: the candidates' titles and summaries — ITS words
    from the extract pass, never the filings again — and, from the second round, last round's grouping."""
    d = round_dir(ident, round_no)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    cands = candidates(ident)
    slim = [{"id": c["id"], "title": c["title"], "summary": c["summary"], "source": c["source"]} for c in cands]
    (d / "candidates.json").write_text(json.dumps(slim, indent=1, ensure_ascii=False))
    os.chmod(d / "candidates.json", 0o400)
    previous = clusters(ident, round_no - 1) if round_no > 1 else None
    if previous:
        by_id = {c["id"]: c["title"] for c in cands}
        view = [{"label": c["label"], "thesis": c["thesis"],
                 "members": [{"id": m, "title": by_id.get(m, "")} for m in c["members"]]}
                for c in previous["clusters"]]
        (d / "clusters.json").write_text(json.dumps(view, indent=1, ensure_ascii=False))
        os.chmod(d / "clusters.json", 0o400)
    return {"candidates": len(cands), "documents": len({c["source"] for c in cands}), "previous": bool(previous)}
