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


WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def docx_text(data: bytes) -> str:
    """The visible text of a .docx, with the standard library only.

    A filing as DEPOSITED is a .docx — a zip of XML — and a sealed session handed those bytes reads markup,
    not an invention. The text extracted here is what gets staged, so the session and the host's verbatim
    quote check see exactly the same characters: fidelity to Word's rendering does not matter, agreement
    between the two sides does.

    Paragraphs (including those inside tables) become lines; tabs and breaks are kept because a claim set
    is numbered and indented and runs together without them. Deleted text is `w:delText`, never `w:t`, so
    tracked-change deletions are dropped by construction — the filing as it stands, not as it was drafted.
    """
    import io
    import zipfile
    import xml.etree.ElementTree as ET
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            xml = z.read("word/document.xml")
    except (zipfile.BadZipFile, KeyError) as e:
        raise S.ProbantError(f"that .docx could not be opened as a Word document ({type(e).__name__})") from e
    root = ET.fromstring(xml)
    lines = []
    for para in root.iter(f"{WORD_NS}p"):
        out = []
        for node in para.iter():
            tag = node.tag
            if tag == f"{WORD_NS}t":
                out.append(node.text or "")
            elif tag == f"{WORD_NS}tab":
                out.append("\t")
            elif tag in (f"{WORD_NS}br", f"{WORD_NS}cr"):
                out.append("\n")
        lines.append("".join(out))
    return "\n".join(lines).strip() + "\n"


READABLE = (".md", ".txt", ".json", ".text", ".docx")


def readable_text(path: Path) -> Tuple[bytes, str]:
    """The bytes to stage for a document, and what was done to get them ("" = used as they are).

    Returned as bytes so stage() hashes and writes one thing; the conversion is named so the staged copy can
    say it is not a byte-for-byte copy of the original.
    """
    raw = path.read_bytes()
    if path.suffix.lower() == ".docx":
        return docx_text(raw).encode("utf-8"), "docx"
    return raw, ""


def stage(paths: Sequence[Path], name: str = "", selection: str = "") -> Dict[str, Any]:
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
        name_on_disk = p.name if p.suffix.lower() != ".docx" else p.with_suffix(".txt").name
        base = re.sub(r"[^A-Za-z0-9._-]+", "-", name_on_disk)[:80] or "document"
        if base in seen:
            seen[base] += 1
            base = f"{Path(base).stem}-{seen[base]}{Path(base).suffix}"
        else:
            seen[base] = 1
        body, converted = readable_text(p)
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
        row = {"name": base, "from": str(p), "bytes": len(body), "sha256": digest}
        if converted:
            # TWO hashes, because they answer different questions. `sha256` is of the staged text, which is
            # what a session reads and what a quote is checked against. `original_sha256` is of the file as
            # deposited — the one that appears in the bundle's manifest — so a finding can be traced back to
            # the document of record, not merely to our rendering of it.
            row["converted_from"] = converted
            row["original_name"] = p.name
            row["original_bytes"] = p.stat().st_size
            row["original_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        documents.append(row)
    meta = {"schema": "inferroute.probant-portfolio/1", "id": ident, "name": _clean(name, 80) or "portfolio",
            "selection": selection or "whole corpus",
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


def _all_rows(d: Path) -> List[Dict[str, Any]]:
    """Every worker's findings, in a stable order. Parallel jobs each append to their OWN file: one file
    shared by several sessions is a write race, and a lost line is a finding nobody knows was found."""
    rows: List[Dict[str, Any]] = []
    for path in [d / CANDIDATES] + sorted(d.glob("candidates-*.jsonl")):
        rows.extend(_rows(path))
    return rows


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
    for row in _all_rows(d):
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
    return max(0, len(_all_rows(path_of(ident))) - len(candidates(ident)))


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
                "and a verbatim quote for each — copied character for character from the document, IN THE "
                "DOCUMENT'S OWN LANGUAGE. Do not translate a quote, do not tidy it, do not shorten it with an "
                "ellipsis: a quote that is not in the document is discarded and its finding with it. Write the "
                "title and summary in English whatever the document's language. Then stop with one line: how "
                "many you recorded, from how "
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
               seconds: float, exit_code: int, worked: bool = True, aborted: bool = False) -> None:
    """What a finding came from: which job, which documents, which model, which instruction, when.

    Without this a finding is a sentence with a quote and no history, and the only way to answer "must we
    read it all again?" is to read it all again.

    `worked` is whether the session got a usable answer at all (it made a tool call). A job that found
    nothing because the document holds nothing and a job that found nothing because the call failed are the
    same row without it, and they call for opposite things: leave it alone, or read it again.
    """
    d = path_of(ident)
    row = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "documents": job.get("documents") or [job.get("document")],
           "range": None if job.get("whole") else [job.get("start"), job.get("end")],
           "lines": [first, last], "found": max(0, last - first), "model": model,
           "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()[:16],
           "seconds": round(seconds, 1), "exit": exit_code, "worked": bool(worked),
           "aborted": bool(aborted)}
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


MAX_ATTEMPTS = 3        # after this many goes at a document that yields nothing, stop paying to re-read it


def attempts(ident: str) -> Dict[str, int]:
    """How many times each document has actually been READ by a session that ran to completion.

    A job that was KILLED is not an attempt. 20 Sep, caught on the real bundle: stopping a run for a
    hardware power-off left four in-flight jobs on the largest filing (279 KB) recorded with `exit=-15`
    and "aborted: Request aborted". They counted toward MAX_ATTEMPTS, so the retry cap retired a document
    that had never once been read, and the next resume skipped it silently — the cap turning a shutdown
    into permanent data loss.

    So: a non-zero exit does not count, and neither does a round the client aborted. A document that
    genuinely defeats a session still accumulates clean attempts and still terminates.
    """
    out: Dict[str, int] = {}
    for row in _rows(path_of(ident) / JOBS):
        if row.get("exit") not in (0, None) or row.get("aborted"):
            continue
        for name in (row.get("documents") or []):
            if name:
                out[name] = out.get(name, 0) + 1
    return out


def unread(ident: str) -> List[str]:
    """Documents no session has been given yet — what a resumed run still has to read.

    This used to mean "documents no finding names", which is a different thing and a costly one. A document
    that was read and honestly holds nothing quotable — a checksums file, a transcript manifest, a receipt —
    names no finding and so was "unread" forever: every resume planned it again, and the completeness gate,
    `not unread()`, could never be satisfied by any corpus containing one such file. Measured on the 20 Sep
    run before the fix: of 453 documents, 439 had been read and 192 of those produced nothing, yet the run
    reported 207 unread and was reading a 712 KB manifest for the eleventh time.

    So: never handed to a session. `barren()` is the other half — read, and nothing came back.
    """
    tried = attempts(ident)
    return [d["name"] for d in meta_of(ident)["documents"] if not tried.get(d["name"])]


def barren(ident: str) -> List[Dict[str, Any]]:
    """Documents that were read and produced nothing, with how often they have been tried.

    Emptiness here is not a verdict on the document: the host cannot tell "holds no technical assertion"
    from "the session fumbled it". What it can do is say which is which is UNKNOWN, show the size and the
    number of attempts, and stop spending after MAX_ATTEMPTS — a 2 KB receipt and a 60 KB specification that
    both came back empty deserve very different attention from a reader.
    """
    tried = attempts(ident)
    have = {c["source"] for c in candidates(ident)}
    out = []
    for d in meta_of(ident)["documents"]:
        n = tried.get(d["name"], 0)
        if n and d["name"] not in have:
            out.append({"document": d["name"], "bytes": d["bytes"], "attempts": n,
                        "give_up": n >= MAX_ATTEMPTS})
    return sorted(out, key=lambda r: -r["bytes"])


def plan_unread(ident: str, budget: int = JOB_CHARS) -> List[Dict[str, Any]]:
    """The same planner, over what a resumed run still owes: documents never read, plus documents that came
    back empty and have not yet had MAX_ATTEMPTS goes.

    A re-run is a delta — findings already held are kept — and it TERMINATES. Retrying an empty document is
    worth doing, because an empty result is often a failed call rather than an empty document; retrying it
    forever is worth nothing, and that is what this planner did until 20 Sep.
    """
    missing = set(unread(ident)) | {r["document"] for r in barren(ident) if not r["give_up"]}
    if not missing:
        return []
    sizes = {d["name"]: d["bytes"] for d in meta_of(ident)["documents"]}
    jobs, batch, batched = [], [], 0
    for name in sorted(missing):
        size = sizes.get(name, 0)
        if size > budget:
            start = 0
            while start < size:
                end = min(size, start + budget)
                jobs.append({"document": name, "start": start, "end": end, "whole": False})
                if end >= size:
                    break
                start = end - OVERLAP
            continue
        if batched + size > budget and batch:
            jobs.append({"documents": batch, "bytes": batched, "whole": True})
            batch, batched = [], 0
        batch.append(name)
        batched += size
    if batch:
        jobs.append({"documents": batch, "bytes": batched, "whole": True})
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


MEMORY_FLOOR_GB = 6.0          # below this much available, a reading run refuses to start


def memory_available_gb() -> Optional[float]:
    """Available memory in GiB, or None where this cannot be read (not Linux, /proc unavailable).

    AVAILABLE, not free: free counts only unused pages, so a machine with a large page cache reads as
    nearly full and a guard on it would refuse every time. MemAvailable is the kernel's own estimate of
    what a new workload can actually have.
    """
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return None
    return None


def refuse_if_memory_is_short(workers: int, floor_gb: float = MEMORY_FLOOR_GB) -> None:
    """Refuse to start a reading run on a machine that is already near the wall.

    20 Sep: three sealed sessions were launched onto a host sitting at 48 GB used with 13 available, on the
    afternoon it had already hit swap 8.0/8.0 GiB with 1.9 MiB free and was thrashing. That host has no ECC,
    and on it a contained out-of-memory kill becomes a machine reset — so "discover the wall" is not a
    recoverable outcome, and the job must refuse rather than find out.

    A floor, not a reservation: this cannot know what a session will grow to. It only refuses the case that
    is already lost. Where memory cannot be read it does not refuse — a guard that fires on the unknown
    would block every non-Linux host for a fact it never established.
    """
    have = memory_available_gb()
    if have is None:
        return
    need = floor_gb + max(0, workers - 1) * 1.5
    if have < need:
        raise S.ProbantError(
            f"refusing to start: {have:.1f} GB of memory available, and {workers} reading session(s) want "
            f"at least {need:.1f} GB. Wait for the machine to come back, or run with fewer --workers. "
            "One heavy job at a time on this host.")


MATTERS = (
    "Read findings.json in this directory: every distinct assertion recorded from the {docs} documents of "
    "this portfolio, {n} of them, each with the document it came from. Read register.json too — it is this "
    "portfolio's own index: `filed` are the {filed} filings already deposited (ids P1…, with their concepts) "
    "and `surplus` are the {surplus} candidates not yet filed (ids like TA-L3, with mechanism, status, risk "
    "and whether they are EP-urgent).\n\n"
    "Produce the MATTER LIST: the inventions this portfolio actually contains, one call to propose_cluster "
    "per matter. A matter is one invention a patent attorney would prosecute as a unit — not a topic, and "
    "not one per document: a filing may hold several, and several documents may describe one.\n\n"
    "For each: `label` names the invention; `thesis` is one sentence giving its technical mechanism — what "
    "it does and how, specific enough to tell it apart from a neighbour; `members` are the finding ids it "
    "rests on; `register` lists the register ids it covers (P1…P9, or surplus ids), empty only if it covers "
    "none; `aspects` are the features that would matter to a claim, one short line each, most important "
    "first; `detail` is what a reader needs beside them, compact — variants, what it depends on, what it "
    "does NOT cover, and for unfiled matters the status and risk the register gives.\n\n"
    "Cover every register id at least once across your matters. If one has nothing in the findings to rest "
    "on, still give it a matter, say so in `detail`, and leave `members` as the closest ids you have.\n\n"
    "Then stop with a short answer: how many matters, and which of them you are least sure about. Nothing "
    "else.")


def matter_list(ident: str, register: Optional[Path] = None) -> Dict[str, Any]:
    """The matter list, with the one check the host can make on it: did it account for the register?

    A synthesis is the step nothing can verify — no computation says a matter is the right matter. What IS
    computable is coverage of an index the portfolio already keeps: 9 filings and 27 candidates are a
    denominator, so "every one of them appears in some matter" is arithmetic, and a list that quietly drops
    eleven of them cannot read as complete. Measured today on the themes run this replaces: 10 themes citing
    285 of 4,420 findings, which looked like an answer and was a sixteenth of one.
    """
    drawn = themes(ident)
    reg = register or (path_of(ident) / "register.json")
    known: List[Dict[str, str]] = []
    if Path(reg).is_file():
        try:
            data = json.loads(Path(reg).read_text())
            for kind in ("filed", "surplus"):
                for row in (data.get(kind) or []):
                    if isinstance(row, dict) and row.get("id"):
                        known.append({"id": str(row["id"]), "kind": kind,
                                      "title": _clean(row.get("title") or row.get("mechanism"), 140),
                                      "ep_urgent": bool(row.get("ep_urgent")),
                                      "status": _clean(row.get("status"), 40),
                                      "risk": _clean(row.get("risk"), 40)})
        except ValueError:
            pass
    claimed: Dict[str, List[str]] = {}
    for m in drawn["themes"]:
        for rid in m["register"]:
            claimed.setdefault(rid, []).append(m["label"])
    ids = {k["id"] for k in known}
    missing = [k for k in known if k["id"] not in claimed]
    invented = sorted(r for r in claimed if r not in ids)
    return {"matters": drawn["themes"], "findings": drawn["findings"], "uncited": drawn["uncited"],
            "unknown": drawn["unknown"], "register": known, "claimed": claimed,
            "missing": missing, "invented": invented,
            "covered": len(ids) - len(missing), "known": len(ids)}


def render_matters(ident: str, register: Optional[Path] = None) -> str:
    """The matter list as plain text: one list, each matter with its aspects and its detail, and the
    accounting underneath. Written to a file rather than a console — it is the client's material."""
    m = matter_list(ident, register)
    reg_by_id = {k["id"]: k for k in m["register"]}
    lines = [f"MATTERS — {meta_of(ident)['name']}", "=" * 72, ""]
    lines.append(f"{len(m['matters'])} matter(s) over {m['findings']} evidenced findings; "
                 f"{m['covered']}/{m['known']} register entries accounted for.")
    lines.append("Every finding cited below is a verbatim quote checked against the document it names.")
    lines.append("")
    for i, x in enumerate(m["matters"], 1):
        marks = [reg_by_id[r] for r in x["register"] if r in reg_by_id]
        filed = [r["id"] for r in marks if r["kind"] == "filed"]
        unfiled = [r["id"] for r in marks if r["kind"] == "surplus"]
        urgent = " ** EP-URGENT **" if any(r["ep_urgent"] for r in marks) else ""
        lines.append(f"{i}. {x['label'].upper()}{urgent}")
        status = []
        if filed:
            status.append("FILED: " + ", ".join(filed))
        if unfiled:
            status.append("UNFILED: " + ", ".join(unfiled))
        if not marks:
            status.append("not in the register")
        lines.append(f"   {' | '.join(status)}")
        lines.append(f"   {x['thesis']}")
        if x["aspects"]:
            lines.append("   Key aspects:")
            lines.extend(f"     - {a}" for a in x["aspects"])
        if x["detail"]:
            lines.append(f"   Detail: {x['detail']}")
        lines.append(f"   Evidence: {x['findings']} finding(s) across {x['documents']} document(s) "
                     f"({', '.join(x['sources'][:4])}{' …' if len(x['sources']) > 4 else ''})")
        if x["why"]:
            lines.append(f"   Drawn because: {x['why']}")
        lines.append("")
    lines += ["-" * 72, "WHAT THIS LIST DOES NOT COVER", ""]
    if m["missing"]:
        lines.append(f"{len(m['missing'])} register entr(ies) no matter claims — these are NOT covered above:")
        for k in m["missing"]:
            lines.append(f"  - {k['id']} ({k['kind']}){' EP-URGENT' if k['ep_urgent'] else ''}: {k['title']}")
    else:
        lines.append("Every register entry is claimed by at least one matter.")
    lines.append("")
    if m["invented"]:
        lines.append(f"Register ids cited that do not exist: {', '.join(m['invented'])}")
    lines.append(f"{len(m['uncited'])} of {m['findings']} findings are in no matter.")
    lines.append("This list ORGANISES; it does not rule. File/no-file, novelty and claim scope are "
                 "Henry + counsel.")
    return "\n".join(lines) + "\n"


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
                    # Present only when the synthesis was asked for matters (a register was there to map to);
                    # a themes-only run leaves them empty and reads exactly as it did before.
                    "register": [_clean(x, 40) for x in (row.get("register") or []) if isinstance(x, str)],
                    "aspects": [_clean(x, 300) for x in (row.get("aspects") or []) if isinstance(x, str)],
                    "detail": _clean(row.get("detail"), 1500),
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


def recall_against_register(ident: str, register: Path, floor: float = 0.6,
                            complete: bool = True) -> Dict[str, Any]:
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
    # The verdict belongs to a run that claims to have read the portfolio. Measured against a run that
    # staged 8 documents of 385 it reported 13% and "NOT ACCEPTED" — true, useless, and the kind of control
    # that fires every time and therefore stops being read. A partial run reports the number and says what
    # it is: an incomplete denominator, not a failure.
    return {"known": total, "found": len(hits), "missed": len(misses), "recall": round(rate, 3),
            "accepted": bool(total) and rate >= floor if complete else None,
            "complete": complete, "floor": floor, "misses": misses[:30],
            "note": ("Recall against the register, not against the portfolio: it says how much of what we "
                     "already knew was surfaced. It cannot speak for anything the register does not list."
                     if complete else
                     "This run did not read the whole portfolio, so the register is the wrong denominator "
                     "for it: the number is shown, the verdict is not. Read the corpus in full, or resume "
                     "this run until every document has been read, before judging recall.")}


def last_round_aborted(ident: str) -> bool:
    """Whether the round that just ended was aborted rather than finished — a stopped run, a killed
    session. Its zero says nothing about the document, so it must not be counted as a reading of it."""
    rows = _rows(path_of(ident) / "rounds.jsonl")
    if not rows:
        return False
    return "abort" in str(rows[-1].get("error", "")).lower()


def last_round_worked(ident: str) -> bool:
    """Did the last reading round get a usable answer at all? A round with no tool call is a failed call,
    not a document that had nothing in it — the difference between retrying and believing a zero."""
    rows = _rows(path_of(ident) / "rounds.jsonl")
    return bool(rows) and bool(rows[-1].get("worked"))


# A quota refusal is not a per-job failure to retry immediately, nor a permanent one to stop on. Measured
# 20 Sep: a run read for 3.5 hours, then every round from 06:27 came back "upstream 402: Quota exceeded /
# Subscription usage cap exceeded" — and the same account answered normally ~20 minutes later. So the cap
# resets over a window: wait it out, and give up only after refusals persist far longer than any window.
OUT_OF_QUOTA = ("quota exceeded", "usage cap exceeded", "insufficient balance", "402")


def last_round_blocked(ident: str) -> str:
    """The account's own refusal, if that is why the last round did nothing. Empty when it is not."""
    rows = _rows(path_of(ident) / "rounds.jsonl")
    err = str(rows[-1].get("error") or "").lower() if rows else ""
    return err if any(m in err for m in OUT_OF_QUOTA) else ""
