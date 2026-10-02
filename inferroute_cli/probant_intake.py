"""Read uploaded documents and create source-linked draft matters through a host capability.

The reading agent sees the staged document and sends text encrypted to the checked AI model.
It has no search tools. Its creation tool calls the parent host, bound to one source and client;
it cannot choose paths or write matter records. A protected host archive supplies the source
check even if the staged copy is replaced. Complete summaries are saved without truncation.
Drafts require human disclosure/date review before searching or sharing. Existing proposal-only
and cluster reading workflows remain available.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probant as S

MAX_CHARS = 4_000_000          # ~2000 pages; beyond this, intake is not the right tool and says so
PROPOSALS = "proposals.jsonl"
DOCUMENT = "document.txt"
MAX_SUMMARY = 20_000
MAX_QUOTE = 8_000
MAX_DRAFTS = 200


def authority_dir(ident: str) -> Path:
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", ident or ""):
        raise S.ProbantError("no such document")
    return S._irhome() / "confidential" / "intakes" / ident


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + "-" + secrets.token_hex(6) + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=1)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def draft_lock():
    """Serialize host writers across sessions and processes on both Linux and macOS."""
    with S.matter_creation_lock():
        yield


def source_snapshot(ident: str) -> tuple[dict, str]:
    """Prefer the host's archive, outside the reading agent's write scope."""
    protected = authority_dir(ident)
    d = protected if (protected / "meta.json").is_file() else path_of(ident)
    meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
    doc = d / DOCUMENT
    if doc.is_symlink() or doc.stat().st_size > MAX_CHARS * 4:
        raise S.ProbantError("the source document cannot be read safely; upload it again")
    body = doc.read_text(encoding="utf-8")
    if hashlib.sha256(body.encode()).hexdigest() != meta.get("sha256"):
        raise S.ProbantError("the source document changed; upload it again before creating matters")
    if meta.get("id") != ident or len(body) > MAX_CHARS:
        raise S.ProbantError("the source record is invalid; upload the document again")
    return meta, body


def _draft_entries(ident: str) -> List[dict]:
    path = authority_dir(ident) / "drafts.json"
    if not path.exists():
        return []
    state = json.loads(path.read_text(encoding="utf-8"))
    return state.get("drafts") or []


def created_drafts(ident: str) -> List[dict]:
    out = []
    for row in _draft_entries(ident):
        c, m = S._split_matter(row["id"])
        try:
            rec = S.load_record(c, m)
        except S.ProbantError:
            continue
        if (rec.get("intake_origin") or {}).get("intake") == ident:
            out.append({**row, "needs_review": bool(rec.get("needs_review"))})
    return out


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
    # Preserve the source before any agent starts. Its working directory is writable;
    # chmod alone cannot prevent replacing a file there. This archive is host-only.
    archive = authority_dir(ident)
    archive.mkdir(parents=True, exist_ok=False, mode=0o700)
    (archive / DOCUMENT).write_text(body, encoding="utf-8")
    os.chmod(archive / DOCUMENT, 0o600)
    _atomic_json(archive / "meta.json", meta)
    return meta


def path_of(ident: str) -> Path:
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", ident or ""):
        raise S.ProbantError("no such document")
    d = intake_root() / ident
    if not (d / "meta.json").is_file():
        raise S.ProbantError("no such document")
    return d


def meta_of(ident: str) -> Dict[str, Any]:
    return source_snapshot(ident)[0]


def _clean(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def read_proposals(ident: str) -> List[Dict[str, Any]]:
    """What the session proposed, checked against the document it was reading.

    A proposal is kept only if its quote appears verbatim in the document: the professional is being asked to
    trust a summary of a document they have not read closely, and a quote that is not there is the one error
    that reading the proposal cannot catch. `where` is recomputed here, never taken from the agent.
    """
    d = path_of(ident)
    meta, body = source_snapshot(ident)
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
        title = re.sub(r"\s+", " ", str(row.get("title") or "")).strip()
        summary = str(row.get("summary") or "").strip()
        quote = str(row.get("quote") or "").strip()
        if len(title) > 160 or len(summary) > MAX_SUMMARY or len(quote) > MAX_QUOTE:
            continue
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


class DraftCreator:
    """A host capability bound to one source and one client, never to caller paths."""

    def __init__(self, ident: str, client: str):
        self.ident = ident
        self.client = S.sanitize(client, "client")
        self.meta, self.body = source_snapshot(ident)

    def create(self, finding: dict) -> dict:
        import shutil
        allowed = {"title", "summary", "quote", "priority_date", "source"}
        if not isinstance(finding, dict) or set(finding) - allowed:
            raise S.ProbantError("provide only a title, summary, source passage and optional suggested date")
        for key in allowed:
            if key in finding and not isinstance(finding[key], str):
                raise S.ProbantError(f"{key} must be text")
        title = re.sub(r"\s+", " ", finding.get("title", "")).strip()
        summary = finding.get("summary", "").strip()
        quote = finding.get("quote", "").strip()
        if not title or len(title) > 160:
            raise S.ProbantError("give the invention a title of 160 characters or fewer")
        if not summary or len(summary) > MAX_SUMMARY:
            raise S.ProbantError(f"give a complete summary of {MAX_SUMMARY:,} characters or fewer; it will not be truncated")
        if not 20 <= len(quote) <= MAX_QUOTE:
            raise S.ProbantError(f"copy a supporting passage of 20–{MAX_QUOTE:,} characters from the document")
        # Some models include a section locator (for example, "document.txt — Concept A").
        # `source` is descriptive only: it never selects a file. This creator is already bound
        # to the uploaded document, and the supporting quote is checked against that exact source.
        # Allow line-wrap whitespace only. Save the actual source slice, not a rewritten quote.
        match = re.search(r"\s+".join(re.escape(part) for part in quote.split()), self.body)
        if match is None:
            raise S.ProbantError("that passage is not in the uploaded document; nothing was created")
        quote = match.group(0)
        date = finding.get("priority_date", "").strip()
        if date:
            try:
                dt.date.fromisoformat(date)
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
                    raise ValueError
            except ValueError:
                raise S.ProbantError("a suggested priority date must be YYYY-MM-DD; omit it if the document gives none")
        title_key = title.casefold()
        summary_key = hashlib.sha256(re.sub(r"\s+", " ", summary).encode()).hexdigest()
        quote_key = hashlib.sha256(re.sub(r"\s+", " ", quote).encode()).hexdigest()
        with draft_lock():
            drafts = _draft_entries(self.ident)
            for prior in drafts:
                if prior["client"] != self.client:
                    continue
                same_passage = prior["quote_key"] == quote_key
                same_title = prior["title_key"] == title_key
                if same_title and not same_passage:
                    raise S.ProbantError("a draft with this title already exists with another passage; use a distinct title for a distinct invention")
                if same_passage and (same_title or prior.get("summary_key") == summary_key):
                    c, m = S._split_matter(prior["id"])
                    if not S.record_path(c, m).exists():
                        if prior.get("status") == "created":
                            raise S.ProbantError("this draft was already created and then removed; restore it from Deleted matters")
                        drafts = [row for row in drafts if row is not prior]
                        break  # interrupted intent; retry without overwriting any existing directory
                    rec = S.load_record(c, m)
                    if (rec.get("intake_origin") or {}).get("intake") != self.ident:
                        raise S.ProbantError("this draft name now belongs to another matter; nothing was changed")
                    return {**prior, "already_created": True}
            if len(drafts) >= MAX_DRAFTS:
                raise S.ProbantError(f"this reading has already created {MAX_DRAFTS} drafts; split a larger document")
            base = _slug(title).lower().replace(" ", "-").strip("-._ ")[:48] or "invention"
            if not base[0].isalnum() or not base[0].isascii():
                base = "invention-" + base
            for n in range(1, 1001):
                name = base if n == 1 else f"{base}-{n}"
                ws = S.workspace_path(self.client, name)
                record = S.record_path(self.client, name)
                if not ws.exists() and not record.exists():
                    break
            else:
                raise S.ProbantError("could not find an unused matter name; rename existing drafts first")
            S.sanitize(name, "matter")
            sync = S._under_sync_root(ws)
            if sync:
                raise S.ProbantError("store matters on local disk before creating drafts; this folder is cloud-synchronised")
            origin = {"intake": self.ident, "source_name": self.meta["source_name"],
                      "source_sha256": self.meta["sha256"], "quote": quote, "where": match.start(),
                      "suggested_priority_date": date, "title": title,
                      "title_key": title_key, "quote_key": quote_key, "summary_key": summary_key}
            rec = {"schema": "inferroute.probant.matter/1", "client": self.client, "matter": name,
                   "date_bound": S._today(), "pre_filing_default": True,
                   "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "workspace": str(ws.resolve()), "changes": [], "needs_review": True,
                   "intake_origin": origin}
            disclosure = (f"# {title}\n\n{summary}\n\n## From the source document\n\n"
                          + "\n".join("> " + line for line in quote.splitlines())
                          + f"\n\nSource: {self.meta['source_name']}\nSHA-256: {self.meta['sha256']}\n")
            row = {"id": f"{self.client}/{name}", "client": self.client,
                   "title": title, "summary": summary, "quote": quote,
                   "suggested_priority_date": date, "title_key": title_key, "quote_key": quote_key, "summary_key": summary_key,
                   "status": "creating"}
            drafts.append(row)
            # Journal before publication: a retry can recognise a committed record even if
            # the final journal update fails. Only records with matching provenance are shown.
            _atomic_json(authority_dir(self.ident) / "drafts.json", {"drafts": drafts})
            # Reserve the workspace exclusively. Write the complete disclosure before publishing
            # its host record; failures remove only this newly reserved directory.
            ws.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            ws.mkdir(mode=0o700)
            try:
                (ws / "disclosure.md").write_text(disclosure, encoding="utf-8")
                os.chmod(ws / "disclosure.md", 0o600)
                record.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _atomic_json(record, rec)
            except Exception:
                shutil.rmtree(ws)
                raise
            row["status"] = "created"
            try:
                _atomic_json(authority_dir(self.ident) / "drafts.json", {"drafts": drafts})
            except OSError:
                pass  # The matter record is committed; the journal's intent remains recoverable.
            return {**row, "already_created": False}


def install_creation_route(app, creator: DraftCreator) -> None:
    """Install behind the sealed proxy's per-session authentication middleware."""
    import asyncio
    from fastapi import Request
    from fastapi.responses import JSONResponse

    async def create_draft(request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 160_000:
                return JSONResponse({"error": "this draft is too large; shorten its summary"}, status_code=413)
        try:
            finding = json.loads(raw)
            row = await asyncio.to_thread(creator.create, finding)
        except (ValueError, TypeError) as error:
            return JSONResponse({"error": str(error)}, status_code=400)
        except OSError:
            return JSONResponse({"error": "the draft could not be saved; check free disk space and try again"}, status_code=500)
        return {"ok": True, "draft": row}

    create_draft.__annotations__["request"] = Request
    app.add_api_route("/probant/intake/create-draft", create_draft, methods=["POST"])
