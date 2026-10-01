"""Folders: how a professional organises matters, and the unit a corpus is sealed from.

Henry, 2026-10-01: "it would be nice if that was also a feature of the home to be able to organise
matters in clusters, just like file and folders", and later "we should not have freeform extra files we
should just have certain go to file types that make sense for this spot".

TWO OBJECTS, ONE FLOW — and keeping them two is the point. A FOLDER is local and mutable: matters move in
and out as work evolves. A CORPUS DELIVERY is immutable: it was sealed, signed, dated, and the recipient
holds a copy. If they were one object, reorganising in April would silently change what you claim to have
sent in March and the signature would describe nothing stable. So sealing a folder takes a SNAPSHOT of its
matters into the delivery that already exists; the folder is free to change afterwards.

WHERE: beside the matter records under confidential/, which is outside the agent's sandbox and already
where host-held state lives. The agent can neither read nor write this.

AT MOST ONE FOLDER PER MATTER, like files in folders: that is the mental model Henry named, and a matter in
two places is a question nobody wants to answer when sealing. A matter in none is "unfiled", which is
COMPUTED rather than stored — a folder you have to create before you can see your own matters would be a
worse product than no folders at all.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probant as S

SCHEMA = "inferroute.probant-folders/1"

# THE FIXED SET. Henry: "we should just have certain go to file types that make sense for this spot" and
# "prioritize compact formats for those files so that they are straight to point and easily editable".
#
# Four kinds, each answering a question a matter-level disclosure cannot. Freeform files were considered and
# rejected: a folder that accepts anything becomes a folder nobody reads, and an assistant given arbitrary
# context cannot tell the reader which part of an answer came from where.
#
# `prompt` is what the drafting pass is asked to produce. Every one of them is short on purpose — these are
# read before a survey, not filed.
CONTEXT_KINDS: Dict[str, Dict[str, str]] = {
    "brief": {
        "file": "brief.md",
        "title": "Engagement brief",
        "about": "What this folder is for, in a few lines: what the client wants to know, and what is "
                 "already ruled out.",
        "prompt": "Write the engagement brief for this folder of matters. At most 150 words. State what "
                  "the inventions have in common, what question the professional is trying to answer "
                  "across them, and anything the matters show has already been settled. No preamble, no "
                  "headings, no restating the matter list.",
    },
    "known-art": {
        "file": "known-art.md",
        "title": "Art already held",
        "about": "References the professional already has, so searches do not spend themselves "
                 "re-surfacing them.",
        "prompt": "List the publication numbers this folder's matters have already marked relevant or "
                  "discussed, one per line, each with at most eight words saying why it matters. No "
                  "commentary around the list. If there are none, say so in one line.",
    },
    "scope": {
        "file": "scope.md",
        "title": "Scope",
        "about": "Jurisdictions, date bounds and competitors that apply across the folder.",
        "prompt": "State the search scope these matters share: jurisdictions, the earliest priority date "
                  "among them, and any competitors or assignees that recur. At most 80 words, as short "
                  "lines, not prose.",
    },
    "reading-guide": {
        "file": "reading-guide.md",
        "title": "Reading guide",
        "about": "What a recipient should read first. This is what travels with a sealed corpus.",
        "prompt": "Write the reading guide a recipient of this corpus opens first. At most 200 words: "
                  "what the set of matters is, the order to read them in, and what to look at first in "
                  "each. Name every matter exactly once.",
    },
}


def folders_path() -> Path:
    return S._irhome() / "confidential" / "folders.json"


def folder_dir(folder_id: str) -> Path:
    """Where a folder's own context files live: beside the matters, readable by a person.

    Not under confidential/ — these are documents the professional writes and a recipient reads, not
    host-held state. Named so nobody mistakes the directory for a matter.
    """
    return S.probant_root() / "_folders" / re.sub(r"[^A-Za-z0-9-]+", "-", folder_id)[:60]


def _load() -> Dict[str, Any]:
    try:
        d = json.loads(folders_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema": SCHEMA, "folders": []}
    if not isinstance(d, dict) or not isinstance(d.get("folders"), list):
        return {"schema": SCHEMA, "folders": []}
    return d


def _save(d: Dict[str, Any]) -> None:
    p = folders_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({**d, "schema": SCHEMA}, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create(name: str) -> Dict[str, Any]:
    name = str(name or "").strip()
    if not name:
        raise S.ProbantError("a folder needs a name")
    if len(name) > 80:
        raise S.ProbantError("a folder name is at most 80 characters")
    d = _load()
    if any(f["name"].casefold() == name.casefold() for f in d["folders"]):
        raise S.ProbantError(f"you already have a folder called {name}")
    f = {"id": f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3)}",
         "name": name, "created_at": _now(), "matters": []}
    d["folders"].append(f)
    _save(d)
    return f


def rename(folder_id: str, name: str) -> Dict[str, Any]:
    name = str(name or "").strip()
    if not name:
        raise S.ProbantError("a folder needs a name")
    d = _load()
    for f in d["folders"]:
        if f["id"] == folder_id:
            f["name"] = name
            _save(d)
            return f
    raise S.ProbantError("no such folder")


def delete(folder_id: str) -> Dict[str, Any]:
    """Remove the folder. Its matters become unfiled — a folder is organisation, never ownership, and
    deleting one must never look like it could delete work.

    Its OWN documents go with it, into the same 30-day bin a deleted matter goes to. Leaving them on disk was
    the first version's bug: the listing walks the store, so a deleted folder's brief and known-art stayed
    readable at ~/Probant/_folders/<id>/ while appearing nowhere — client context material surviving a delete
    the person was told had happened. Destroying them outright is the other wrong answer: a hand-written brief
    is work. So they are moved, dated, and recoverable for as long as a matter would be.
    """
    from . import probant_delete as D
    d = _load()
    d["folders"] = [f for f in d["folders"] if f["id"] != folder_id]
    _save(d)
    src = folder_dir(folder_id)
    if not src.is_dir():
        return {"documents_moved": None}
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = D.trash_root() / f"{stamp}__folder__{re.sub(r'[^A-Za-z0-9-]+', '-', folder_id)[:60]}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    for x in (dest.parent.parent, dest.parent):
        os.chmod(x, 0o700)
    shutil.move(str(src), str(dest))
    os.chmod(dest, 0o700)
    (dest / "deleted.json").write_text(json.dumps({
        "schema": "inferroute.probant-deleted-folder/1", "folder": folder_id,
        "deleted_at": _now(),
        "erase_after": (dt.datetime.now(dt.timezone.utc)
                        + dt.timedelta(days=D.RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=1) + "\n", encoding="utf-8")
    os.chmod(dest / "deleted.json", 0o600)
    return {"documents_moved": str(dest)}


def assign(matter_id: str, folder_id: Optional[str]) -> None:
    """Put a matter in a folder, or (with None) take it out of whichever one holds it.

    At most one folder per matter, enforced here rather than hoped for: the matter is removed from every
    folder before it is added to one, so a double-add cannot leave it in two.
    """
    d = _load()
    for f in d["folders"]:
        f["matters"] = [m for m in f["matters"] if m != matter_id]
    if folder_id:
        for f in d["folders"]:
            if f["id"] == folder_id:
                f["matters"].append(matter_id)
                break
        else:
            raise S.ProbantError("no such folder")
    _save(d)


def listing(matter_ids: List[str]) -> Dict[str, Any]:
    """Folders with their matters, plus the unfiled ones — against the matters that ACTUALLY exist.

    A matter deleted from disk leaves its id behind in a folder; returning it would show a card that opens
    nothing. So membership is intersected with what exists, and the stored list is left alone (a restore
    from the 30-day bin then finds its folder again).
    """
    live = set(matter_ids)
    d = _load()
    out, placed = [], set()
    for f in d["folders"]:
        members = [m for m in f["matters"] if m in live]
        placed.update(members)
        out.append({"id": f["id"], "name": f["name"], "created_at": f.get("created_at"),
                    "matters": members, "documents": documents(f["id"])})
    return {"folders": out, "unfiled": [m for m in matter_ids if m not in placed]}


def folder_of(matter_id: str) -> Optional[Dict[str, Any]]:
    for f in _load()["folders"]:
        if matter_id in f["matters"]:
            return {"id": f["id"], "name": f["name"]}
    return None


def get(folder_id: str) -> Optional[Dict[str, Any]]:
    for f in _load()["folders"]:
        if f["id"] == folder_id:
            return f
    return None


# ── the folder's own documents ────────────────────────────────────────────────────────────────────

def _require(folder_id: str) -> Dict[str, Any]:
    """A document belongs to a folder that EXISTS.

    Without this, writing to an id nobody has creates ~/Probant/_folders/<whatever>/brief.md and accepts it.
    Nothing lists it afterwards — the listing walks the store, not the directory — so the professional writes
    a brief, is told it saved, and never sees it again. An accepted write that cannot be found is worse than
    a refused one, and the layer to refuse at is the store, so no route can forget.
    """
    f = get(folder_id)
    if not f:
        raise S.ProbantError("no such folder")
    return f


def documents(folder_id: str) -> List[Dict[str, Any]]:
    """The fixed kinds, each present or not. Never a free listing of the directory: the set is the four
    above, so a reader always sees the same four slots and knows which are empty."""
    _require(folder_id)
    d = folder_dir(folder_id)
    out = []
    for kind, spec in CONTEXT_KINDS.items():
        p = d / spec["file"]
        try:
            text = p.read_text(encoding="utf-8") if p.exists() else ""
        except OSError:
            text = ""
        out.append({"kind": kind, "title": spec["title"], "about": spec["about"],
                    "file": spec["file"], "words": len(text.split()), "present": bool(text.strip())})
    return out


def read_document(folder_id: str, kind: str) -> str:
    spec = CONTEXT_KINDS.get(kind)
    if not spec:
        raise S.ProbantError("no such document kind")
    _require(folder_id)
    p = folder_dir(folder_id) / spec["file"]
    try:
        return p.read_text(encoding="utf-8") if p.exists() else ""
    except OSError:
        return ""


def write_document(folder_id: str, kind: str, text: str) -> Dict[str, Any]:
    """The professional's own file, written by them or by them accepting a draft. Capped because these are
    meant to be read before a survey: a context file nobody reads is worse than none, since it still
    enters the assistant's context and is still asserted to a recipient."""
    spec = CONTEXT_KINDS.get(kind)
    if not spec:
        raise S.ProbantError("no such document kind")
    text = str(text or "")
    if len(text) > 20000:
        raise S.ProbantError(f"{spec['title']} is at most 20,000 characters — these are meant to be short")
    _require(folder_id)
    d = folder_dir(folder_id)
    d.mkdir(parents=True, exist_ok=True)
    p = d / spec["file"]
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    return {"kind": kind, "words": len(text.split()), "present": bool(text.strip())}


# ── drafting a context file over the sealed lane ──────────────────────────────────────────────────

def draft_material(folder_id: str, matter_ids: List[str]) -> str:
    """What the drafting pass is shown: each matter's name and its disclosure, nothing else.

    NOT the searches, marks or records. A context file describes the engagement, and feeding a draft the
    whole history would produce a summary of the work rather than a statement of the question — and would
    put far more of the client's material through one request than the task needs.
    """
    parts = []
    for mid in matter_ids:
        try:
            client, matter = S._split_matter(mid)
            rec = S.load_record(client, matter)
            ws = Path(str(rec.get("workspace") or ""))
            text = (ws / "disclosure.md").read_text(encoding="utf-8") if (ws / "disclosure.md").exists() else ""
        except Exception:                                    # noqa: BLE001 — one unreadable matter is not a failure
            continue
        if text.strip():
            parts.append(f"## {mid}\n\n{text.strip()[:6000]}")
    return "\n\n".join(parts)


def draft_prompt(kind: str, folder_name: str, material: str) -> str:
    spec = CONTEXT_KINDS.get(kind)
    if not spec:
        raise S.ProbantError("no such document kind")
    if not material.strip():
        raise S.ProbantError("this folder's matters have no disclosures yet, so there is nothing to draft from")
    return (f"You are drafting one short file for a folder of patent matters called {folder_name!r}.\n\n"
            f"{spec['prompt']}\n\n"
            "Write only the file's contents. No preamble, no sign-off, no markdown headings unless the "
            "instruction asks for them. The professional will edit what you write.\n\n"
            f"The matters:\n\n{material}")
