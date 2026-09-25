"""Reading a long document and proposing matters from it.

A professional often starts from a document, not from a matter: a client's technical report, a draft
specification, a family of related filings. This stages that document on this computer, hands a sealed
session nothing but the document and one tool, and collects what it proposes — one matter per invention it
finds, each with the passage it came from, so the professional can check the proposal against the source
before creating anything.

Three rules shape it:

* **Nothing is created by the agent.** `propose_matter` records a proposal; matters are created by the
  professional, from the page, one click at a time. The agent cannot make a matter any more than it can make
  a relevance mark.
* **The document is read, never sent.** The staged copy lives in an owner-only folder under the Probant
  folder — the session's working directory, because that is the one place the sandbox lets it write its
  proposals; the document itself is read-only there, and its hash is re-checked before any proposal is
  read, so the session cannot edit the text its quotes are checked against. The agent
  reads it with its ordinary file tools inside the sandbox; what reaches the sealed model is whatever it
  quotes while reasoning, under the same sealed lane as a session's conversation. No search tool is offered
  during intake, so nothing can leave for a search machine while a whole document is in context.
* **A proposal says where it came from.** Every proposal carries a verbatim quote and its character offset.
  A proposal whose quote is not in the document is dropped on the way in, because the one thing a reader
  cannot check by eye is whether the agent invented the passage.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probant as S

MAX_CHARS = 4_000_000          # ~2000 pages; beyond this, intake is not the right tool and says so
PROPOSALS = "proposals.jsonl"
DOCUMENT = "document.txt"


def intake_root() -> Path:
    """Under the Probant folder, not under confidential/: the session runs IN this directory, and what a
    session's working directory is, the sandbox lets it write. confidential/ is write-denied to the agent on
    purpose and must stay that way."""
    return S.probant_root() / ".intake"


def _slug(name: str) -> str:
    out = re.sub(r"[^A-Za-z0-9 ._-]+", "-", (name or "document").strip())[:60].strip(" -.")
    return out or "document"


def stage(text: str, source_name: str = "") -> Dict[str, Any]:
    """Write the document where a sealed session can read it and nothing else can. Returns its meta."""
    body = (text or "").replace("\r\n", "\n")
    if not body.strip():
        raise S.ProbantError("that document is empty — nothing to read")
    if len(body) > MAX_CHARS:
        raise S.ProbantError(f"that document is {len(body):,} characters; this reads up to {MAX_CHARS:,}. "
                              "Split it, or point at the part that matters.")
    ident = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    d = intake_root() / ident
    d.mkdir(parents=True, exist_ok=False)
    for p in (S.probant_root(), intake_root(), d):
        os.chmod(p, 0o700)
    doc = d / DOCUMENT
    doc.write_text(body, encoding="utf-8")
    # Read-only: the session works in this directory, so it CAN write here (that is how it records proposals).
    # The document it is summarising is the one thing it must not be able to edit — a changed document would
    # make an invented quote check out against itself.
    os.chmod(doc, 0o400)
    meta = {"schema": "inferroute.probant-intake/1", "id": ident, "source_name": _slug(source_name),
            "staged_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "chars": len(body), "lines": body.count("\n") + 1,
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest()}
    (d / "meta.json").write_text(json.dumps(meta, indent=1))
    os.chmod(d / "meta.json", 0o600)
    return meta


def path_of(ident: str) -> Path:
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", ident or ""):
        raise S.ProbantError("no such document")
    d = intake_root() / ident
    if not (d / "meta.json").is_file():
        raise S.ProbantError("no such document")
    return d


def meta_of(ident: str) -> Dict[str, Any]:
    return json.loads((path_of(ident) / "meta.json").read_text())


def _clean(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def read_proposals(ident: str) -> List[Dict[str, Any]]:
    """What the session proposed, checked against the document it was reading.

    A proposal is kept only if its quote appears verbatim in the document: the professional is being asked to
    trust a summary of a document they have not read closely, and a quote that is not there is the one error
    that reading the proposal cannot catch. `where` is recomputed here, never taken from the agent.
    """
    d = path_of(ident)
    meta = json.loads((d / "meta.json").read_text())
    body = (d / DOCUMENT).read_text(encoding="utf-8")
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != meta.get("sha256"):
        raise S.ProbantError("the staged document changed after it was staged; refusing to read proposals "
                              "against it. Stage it again.")
    from .probant_cluster import canonical      # markdown markers off both sides; see there for why
    flat = canonical(body)
    out: List[Dict[str, Any]] = []
    seen = set()
    for line in (d / PROPOSALS).read_text(encoding="utf-8").splitlines() if (d / PROPOSALS).exists() else []:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        title = _clean(row.get("title"), 80)
        summary = _clean(row.get("summary"), 1200)
        quote = _clean(row.get("quote"), 600)
        if not title or not summary or len(quote) < 20:
            continue
        at = flat.find(canonical(quote))
        if at < 0:                                  # not in the document: dropped, never shown
            continue
        key = title.lower()
        if key in seen:
            continue
        seen.add(key)
        date = str(row.get("priority_date") or "").strip()
        out.append({"title": title, "summary": summary, "quote": quote, "where": at,
                    "priority_date": date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else "",
                    "suggested_matter": _slug(title).lower().replace(" ", "-")[:40]})
    return out


def dropped_count(ident: str) -> int:
    """How many proposals were written but not kept — said out loud rather than quietly swallowed."""
    d = path_of(ident)
    written = 0
    if (d / PROPOSALS).exists():
        for line in (d / PROPOSALS).read_text(encoding="utf-8").splitlines():
            try:
                written += 1 if isinstance(json.loads(line), dict) else 0
            except ValueError:
                continue
    return max(0, written - len(read_proposals(ident)))


def create_matter(ident: str, client: str, matter: str, proposal_index: int,
                  priority_date: Optional[str] = None) -> str:
    """Create a matter from one proposal, with its summary as the disclosure and the document named as its
    source. The professional supplies the client and matter names; nothing here invents them."""
    proposals = read_proposals(ident)
    if not 0 <= proposal_index < len(proposals):
        raise S.ProbantError("no such proposal")
    p = proposals[proposal_index]
    meta = meta_of(ident)
    date = priority_date or p["priority_date"] or None
    rc = S.cmd_new(client, matter, date)
    if rc != 0:
        raise S.ProbantError("the matter could not be created")
    client, matter = S.sanitize(client, "client"), S.sanitize(matter, "matter")
    doc = S.workspace_path(client, matter) / "disclosure.md"
    doc.write_text(f"# {p['title']}\n\n{p['summary']}\n\n"
                   f"## From the source document\n\n> {p['quote']}\n\n"
                   f"Read from {meta['source_name']} ({meta['chars']:,} characters, "
                   f"sha256 {meta['sha256'][:16]}…), staged {meta['staged_at']}.\n", encoding="utf-8")
    os.chmod(doc, 0o600)
    return f"{client}/{matter}"
