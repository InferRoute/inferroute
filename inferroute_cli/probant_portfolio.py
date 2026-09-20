"""A portfolio read by sealed sessions, clustered round after round until the clustering stops moving.

One document becomes matters by reading it (probant_intake). A PORTFOLIO — dozens of filings, briefs and
inventories, megabytes of them — does not: the same idea appears in six documents under six names, and what
the professional wants out is not a list of everything but the few themes the portfolio actually turns on,
and which of them most deserves a matter next.

The shape, and which side does what:

* **Extract** — one sealed session per document proposes candidate units, each with a verbatim quote. The
  HOST checks every quote against that document and drops the rest, counting the drops.
* **Evidence** — the host checks each quote verbatim against the document it NAMES (not the portfolio: "this
  sentence exists somewhere in three megabytes" is not evidence that this filing says it), records where it
  sits, and reports the largest span of a document no quote evidences.

What is NOT here, deliberately: a loop that re-groups its own groupings until the grouping stops moving. A
partition that agrees with itself measures the model's stability, not the corpus. See
docs/portfolio-analysis-proposal.md; `movement()` survives as a diagnostic for comparing two groupings, not
as a stopping rule.

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

MAX_FILES = 800
MAX_BYTES = 40_000_000
BRIEF = "brief.json"
JOBS = "jobs.jsonl"                      # what each reading job was, and what it produced
CANDIDATES = "candidates.jsonl"
DOCS = "documents"


def portfolio_root() -> Path:
    return S.probant_root() / ".portfolio"


def _write_readonly(path: Path, text: str) -> None:
    """Write a file the session may read but not change, and that the HOST rewrites every round.

    0400 is for the session, not for us: leaving it 0400 made the second job of a run die with
    PermissionError writing the brief it had itself written (20 Sep). Anything regenerated per job goes
    through here.
    """
    if path.exists():
        os.chmod(path, 0o600)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o400)


def _clean(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


# Markdown markers, removed from BOTH sides before a quote is checked. Measured 20 Sep: of 31 findings from
# one filing, 17 failed verbatim matching and every one of them failed on formatting — the model quotes the
# sentence, not the `**` and `#` around it. Unicode punctuation and case accounted for none of them, so
# neither is touched: this stays an EXACT match on a form both sides agree about, not a fuzzy one. A
# paraphrase still fails, which is the whole point of the check.
_MARKUP = re.compile(r"[*_`#>]+")


def canonical(text: str) -> str:
    return re.sub(r"\s+", " ", _MARKUP.sub("", str(text or ""))).strip()


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
    by_content: Dict[str, str] = {}
    duplicates: List[Dict[str, str]] = []
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
        # The same document filed in two places is one document. Measured here: 459 files, 385 distinct —
        # 74 exact copies, 1.6 MB. Reading a copy costs a session AND invents a "two documents agree"
        # signal, which is worse than the waste.
        digest = hashlib.sha256(body).hexdigest()
        if digest in by_content:
            duplicates.append({"from": str(p), "same_as": by_content[digest]})
            continue
        by_content[digest] = base
        (d / DOCS / base).write_bytes(body)
        os.chmod(d / DOCS / base, 0o400)
        documents.append({"name": base, "from": str(p), "bytes": len(body),
                          "sha256": hashlib.sha256(body).hexdigest()})
    meta = {"schema": "inferroute.probant-portfolio/1", "id": ident, "name": _clean(name, 80) or "portfolio",
            "staged_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "documents": documents, "bytes": sum(x["bytes"] for x in documents),
            "given": len(files), "bytes_given": total, "duplicates": duplicates}
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
        flat[doc["name"]] = canonical((d / DOCS / doc["name"]).read_text(encoding="utf-8", errors="replace"))
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in _rows(d / CANDIDATES):
        title, summary = _clean(row.get("title"), 90), _clean(row.get("summary"), 1200)
        quote, source = _clean(row.get("quote"), 600), _clean(row.get("source"), 120)
        if not title or not summary or len(quote) < 20:
            continue
        body = flat.get(source)
        needle = canonical(quote)
        if body is None or needle not in body:         # not in the document it names: dropped, never shown
            continue
        key = (source, title.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": f"c{len(out) + 1}", "title": title, "summary": summary, "quote": quote,
                    "source": source, "where": body.find(needle), "of": len(body)})
    return out


def dropped(ident: str) -> int:
    return max(0, len(_rows(path_of(ident) / CANDIDATES)) - len(candidates(ident)))


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




# ───────────────────────────── the reading jobs, and what they evidenced ─────────────────────────────

JOB_CHARS = 60_000             # one session's reading: a few dozen pages, well inside the model's context
OVERLAP = 2_000                # a range boundary must not cut an idea in half: ranges overlap by this much

# The session works in the portfolio directory and the documents sit in documents/. Naming the path wrongly
# here is not a typo: the first run said "in this directory", the read failed with ENOENT, and the session
# ended its turn cleanly having recorded nothing — a silent empty result (20 Sep).
EXTRACT_MANY = ("Read brief.json first — it says what this portfolio is and what has been recorded from the "
                "other documents so far. Then read each of these in documents/, all of them, all the way "
                "through: {names}. Record every distinct technical assertion they make with record_findings, "
                "all the findings for a document in ONE call, giving `source` as that document's file name "
                "and a verbatim quote for each. Then stop with one line: how many you recorded, from how "
                "many documents. Nothing else.")

EXTRACT_RANGE = ("Read brief.json first — it says what this portfolio is and what has been recorded from the "
                 "other documents so far. Then read documents/{name} from character {start} to character "
                 "{end} — that range only, and all of it — and record every distinct technical assertion it "
                 "makes with record_findings, all of them in one call per part you read: `source` "
                 "\"{name}\", a verbatim quote for each — copied character for character, in the document's "
                 "own language, never translated or tidied — each quote taken from within that range. Then stop "
                 "with one line saying how many you recorded. Nothing else.")


def brief(ident: str, register: Optional[Path] = None) -> Dict[str, Any]:
    """What every reading session is told about the portfolio before it reads its own part.

    A session that sees one file out of 385 records what looks notable IN THAT FILE — trivia from a thin
    document, and half of a thing that only matters because six others circle it. This is the "together"
    that fits: the register, the shape of the corpus, and the titles recorded so far, at a few thousand
    tokens rather than the 2.07M the corpus actually is (which no context on this lane holds).

    Titles only, never another document's text: a session reads one document — its own.
    """
    meta = meta_of(ident)
    seen = candidates(ident)
    out: Dict[str, Any] = {
        "portfolio": meta["name"],
        "documents": len(meta["documents"]),
        "documents_read_so_far": len({c["source"] for c in seen}),
        "recorded_so_far": [{"title": c["title"], "source": c["source"]} for c in seen][-400:],
        "note": ("Findings already recorded from other documents, titles only. Record what YOUR document "
                 "asserts, in its own words and with its own quote, even when a similar title is already "
                 "here — two documents saying the same thing is itself a finding. Never record anything you "
                 "cannot quote from your own document."),
    }
    if register and Path(register).is_file():
        try:
            out["register"] = json.loads(Path(register).read_text())
        except ValueError:
            pass
    _write_readonly(path_of(ident) / BRIEF, json.dumps(out, indent=1, ensure_ascii=False))
    return out


def record_job(ident: str, job: Dict[str, Any], *, first: int, last: int, model: str, prompt: str,
               seconds: float, exit_code: int) -> None:
    """What a finding came from: which job, which documents, which model, which instruction, when.

    Without this a finding is a sentence with a quote and no history, and the only way to answer "must we
    read it all again?" is to read it all again.
    """
    d = path_of(ident)
    row = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "documents": job.get("documents") or [job.get("document")],
           "range": None if job.get("whole") else [job.get("start"), job.get("end")],
           "lines": [first, last], "found": max(0, last - first), "model": model,
           "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()[:16],
           "seconds": round(seconds, 1), "exit": exit_code}
    with (d / JOBS).open("a") as fh:
        fh.write(json.dumps(row) + "\n")
    os.chmod(d / JOBS, 0o600)


def provenance(ident: str) -> Dict[str, Any]:
    """The run's account of itself: jobs, what each produced, which produced nothing, which models ran."""
    jobs = _rows(path_of(ident) / JOBS)
    empty = [j for j in jobs if not j.get("found")]
    return {"jobs": len(jobs), "empty_jobs": len(empty),
            "empty": [", ".join(j.get("documents") or []) for j in empty][:20],
            "models": sorted({j.get("model", "") for j in jobs}),
            "prompts": sorted({j.get("prompt_sha256", "") for j in jobs}),
            "seconds": round(sum(j.get("seconds", 0) for j in jobs)),
            "documents": {d["name"]: d["sha256"] for d in meta_of(ident)["documents"]}}


def unchanged_since(ident: str, previous: str) -> Dict[str, str]:
    """Documents whose bytes match a previous run's — what a re-run need not read again."""
    try:
        before = {d["sha256"]: d["name"] for d in meta_of(previous)["documents"]}
    except S.ProbantError:
        return {}
    return {d["name"]: before[d["sha256"]] for d in meta_of(ident)["documents"] if d["sha256"] in before}


def plan(ident: str, budget: int = JOB_CHARS) -> List[Dict[str, Any]]:
    """Split the portfolio into reading jobs: one per document, and a long document into overlapping ranges.

    Deterministic and host-side — no model decides what gets read. A range is not a chunk the session may
    skip: the instruction names its bounds, and `coverage()` afterwards says which parts of the document any
    quote actually evidences.
    """
    jobs: List[Dict[str, Any]] = []
    batch: List[Dict[str, Any]] = []
    batched = 0

    def flush() -> None:
        nonlocal batch, batched
        if batch:
            jobs.append({"documents": [b["name"] for b in batch], "bytes": batched, "whole": True})
            batch, batched = [], 0

    for doc in meta_of(ident)["documents"]:
        size = doc["bytes"]
        if size <= budget:
            # Several small documents per session: the mean file here is 24 KB and a session pays its
            # attestation, sandbox and warm-up before reading a byte. One file per session spends that
            # overhead 459 times for 9.8 MB.
            if batched + size > budget:
                flush()
            batch.append(doc)
            batched += size
            continue
        flush()
        start = 0
        while start < size:
            end = min(size, start + budget)
            jobs.append({"document": doc["name"], "start": start, "end": end, "whole": False})
            if end >= size:
                break
            start = end - OVERLAP
    flush()
    return jobs


def instruction_for(job: Dict[str, Any]) -> str:
    if job.get("whole"):
        return EXTRACT_MANY.format(names=", ".join(job["documents"]))
    return EXTRACT_RANGE.format(name=job["document"], start=job["start"], end=job["end"])


def coverage(ident: str) -> List[Dict[str, Any]]:
    """What the reading actually evidenced, per document.

    The measure is the LARGEST SPAN no quote falls in, not how far the last quote reached. A session that
    jumps to something at 95% and skips the middle reaches 95% and evidences almost nothing; the largest gap
    catches that, and the first version of this measure did not. (Corrected in review, 20 Sep.)

    It is reported as evidenced span, never as "read": nothing can show a model read a passage it chose not
    to quote, and the number must not pretend otherwise.
    """
    by_doc: Dict[str, List[int]] = {}
    for c in candidates(ident):
        by_doc.setdefault(c["source"], []).append(int(c["where"]))
    out = []
    for doc in meta_of(ident)["documents"]:
        size = max(1, doc["bytes"])
        spots = sorted(by_doc.get(doc["name"], []))
        # Gaps from the start of the document, between consecutive quotes, and to the end.
        edges = [0, *spots, size]
        gaps = [b - a for a, b in zip(edges, edges[1:])]
        biggest = max(gaps) if gaps else size
        out.append({"document": doc["name"], "bytes": doc["bytes"], "items": len(spots),
                    "largest_unevidenced": biggest, "largest_unevidenced_share": round(biggest / size, 3),
                    "first_at": spots[0] if spots else None, "last_at": spots[-1] if spots else None})
    return sorted(out, key=lambda r: -r["largest_unevidenced_share"])


# ───────────────────────────── the synthesis: every finding, one context ─────────────────────────────

THEMES = "themes.jsonl"

SYNTHESIS = ("Read findings.json in this directory: every distinct assertion recorded from all {docs} "
             "documents of this portfolio, {n} of them, each with the document it came from. This is the "
             "whole portfolio's content in one place — the documents themselves are far too large to hold "
             "at once, these are their findings. Read brief.json too if it is there; it holds the register "
             "this portfolio keeps of its own filings and candidates.\n\n"
             "Draw the themes the portfolio actually turns on, with propose_cluster, one call per theme. "
             "`members` are the finding ids (f1, f2 …) the theme rests on — only ids that are in the file. "
             "`thesis` is one sentence a patent attorney could act on: the shared technical mechanism, not a "
             "topic name. `why` says what made you draw the line there, and name anything that sits badly.\n\n"
             "Then stop with a short answer: what this portfolio is about, and what is thin in it — a theme "
             "resting on one document, or a claim asserted everywhere and evidenced nowhere. Nothing else.")


def write_findings(ident: str) -> Dict[str, Any]:
    """The synthesis session's input: every finding, compact, with the document each came from.

    Ids are assigned HERE and are the only ones the session may cite, so a theme can be checked back to the
    findings it claims — and through them to a verbatim quote in a named document.
    """
    items = candidates(ident)
    d = path_of(ident)
    rows = [{"id": f"f{i + 1}", "title": c["title"], "summary": c["summary"], "source": c["source"]}
            for i, c in enumerate(items)]
    _write_readonly(d / "findings.json", json.dumps(rows, indent=1, ensure_ascii=False))
    return {"n": len(rows), "documents": len({c["source"] for c in items}),
            "tokens_roughly": sum(len(r["title"]) + len(r["summary"]) for r in rows) // 4}


def themes(ident: str) -> Dict[str, Any]:
    """The themes drawn over the findings, with the accounting: which findings were cited, which were not,
    and which citations name nothing. A synthesis that quietly drops a third of the portfolio says so here."""
    items = candidates(ident)
    ids = {f"f{i + 1}": c for i, c in enumerate(items)}
    out, cited, unknown = [], set(), []
    for row in _rows(path_of(ident) / THEMES):
        label, thesis = _clean(row.get("label"), 90), _clean(row.get("thesis"), 600)
        named = [_clean(m, 24) for m in (row.get("members") or []) if isinstance(m, str)]
        unknown.extend(m for m in named if m not in ids)
        kept = [m for m in named if m in ids]
        if not label or not kept:
            continue
        cited.update(kept)
        sources = sorted({ids[m]["source"] for m in kept})
        out.append({"label": label, "thesis": thesis, "why": _clean(row.get("why"), 600),
                    "members": kept, "findings": len(kept), "documents": len(sources), "sources": sources})
    return {"themes": sorted(out, key=lambda x: (-x["documents"], -x["findings"])),
            "uncited": [i for i in ids if i not in cited], "unknown": sorted(set(unknown)),
            "findings": len(ids)}


# ───────────────────────── did it find what we already know is there? ─────────────────────────

def register_rows(register: Path) -> List[Dict[str, str]]:
    """The known items a reading of this portfolio OUGHT to surface: the register's own filings, their lead
    concepts, and its candidates. Shape-tolerant on purpose — a register is a document, not an API."""
    try:
        data = json.loads(Path(register).read_text())
    except (OSError, ValueError):
        return []
    rows: List[Dict[str, str]] = []

    def take(obj: Any, kind: str) -> None:
        if isinstance(obj, dict):
            ident = str(obj.get("id") or obj.get("code") or obj.get("key") or "")
            title = _clean(obj.get("title") or obj.get("name") or obj.get("label") or obj.get("mechanism"), 120)
            if ident and title:
                rows.append({"id": ident, "title": title, "kind": kind})
            for key in ("concepts", "lead_concepts", "claims", "items"):
                for child in (obj.get(key) or []):
                    # A concept may be a pair — ["C4", "what it is"] — as this register writes them, or an
                    # object, or a bare string. All three are the same thing to an answer key.
                    if isinstance(child, list) and len(child) >= 2 and all(isinstance(x, str) for x in child[:2]):
                        rows.append({"id": f"{ident}:{child[0]}" if ident else child[0],
                                     "title": _clean(child[1], 120), "kind": f"{kind}.{key}"})
                    elif isinstance(child, str) and len(child) > 8:
                        rows.append({"id": f"{ident}:{child[:12]}", "title": _clean(child, 120),
                                     "kind": f"{kind}.{key}"})
                    else:
                        take(child, f"{kind}.{key}")
        elif isinstance(obj, list):
            for child in obj:
                take(child, kind)

    for key in ("filed", "surplus", "records", "candidates"):
        take(data.get(key), key)
    return rows


def recall_against_register(ident: str, register: Path, floor: float = 0.6) -> Dict[str, Any]:
    """How much of what we ALREADY KNOW is in the portfolio did this run's findings surface?

    Precision is checkable by construction — every finding carries a quote verified against its document.
    Recall is not: nothing in a reading pass can say what the model chose not to record. But this portfolio
    keeps a register of its own filings and candidates, and that is an answer key. A run that misses a third
    of the register did not read the portfolio, whatever its totals say, and this is the number that says so
    before anyone trusts the output.

    Matching is deliberately generous (the register's words against the findings' words, both canonical): a
    generous match that still misses an item makes the miss worth believing.
    """
    rows = register_rows(register)
    found = candidates(ident)
    hay = [(canonical(c["title"]).lower(), canonical(c["summary"]).lower(), c) for c in found]
    hits, misses = [], []
    for row in rows:
        words = [w for w in re.split(r"\W+", canonical(row["title"]).lower()) if len(w) > 4]
        if not words:
            continue
        best, score = None, 0.0
        for title, summary, c in hay:
            text = f"{title} {summary}"
            share = sum(1 for w in words if w in text) / len(words)
            if share > score:
                best, score = c, share
        if score >= 0.5:
            hits.append({"register": row["id"], "title": row["title"], "matched": best["title"], "score": round(score, 2)})
        else:
            misses.append({"register": row["id"], "title": row["title"], "best": round(score, 2)})
    total = len(hits) + len(misses)
    rate = (len(hits) / total) if total else 0.0
    return {"known": total, "found": len(hits), "missed": len(misses), "recall": round(rate, 3),
            "accepted": bool(total) and rate >= floor, "floor": floor,
            "misses": misses[:30],
            "note": ("Recall against the register, not against the portfolio: it says how much of what we "
                     "already knew was surfaced. It cannot speak for anything the register does not list.")}
