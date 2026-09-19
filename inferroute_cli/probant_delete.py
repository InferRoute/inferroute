"""Deleting a matter — recoverably first, then for good.

A matter lives in several places: its record and state (marks, approvals) under confidential/matters/, its
session records under confidential/attested-records/, its workspace (the disclosure) under the Probant folder,
and its exported records beside it. Deleting moves ALL of them into one owner-only folder under
confidential/deleted-matters/, where the matter can be restored as it was, or erased at once. Anything left
there is erased after RETENTION_DAYS.

Why not erase at once: a matter holds signed search records that can never be made again, and one click on
the wrong row must not cost them. Why not keep forever: the whole point of deleting a client matter is that
the client's words stop existing on this computer, so "deleted" has a date by which it becomes true.

Nothing is moved from outside the places Probant itself creates. A workspace that points elsewhere (an older
matter record, a hand edit) is left where it is, and the result says so rather than reaching out to delete a
folder Probant did not make.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probant as S

RETENTION_DAYS = 30
MANIFEST = "deleted.json"


def trash_root() -> Path:
    return S._irhome() / "confidential" / "deleted-matters"


def _within(child: Path, parent: Path) -> bool:
    c, p = os.path.realpath(child), os.path.realpath(parent)
    return c != p and c.startswith(p.rstrip("/") + "/")


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _exports_of(client: str, matter: str) -> List[Path]:
    """The matter's exported records, and every audit pack made from one of them. A pack's name carries no
    matter name on purpose, so it is recognised by the record manifest it says it was derived from."""
    root = S.probant_root() / client / "exports"
    if not root.is_dir():
        return []
    records = [d for d in root.iterdir() if d.is_dir() and d.name.startswith(f"{matter}-prior-art-record-")]
    shas = set()
    for d in records:
        try:
            shas.add(_sha256(d / "MANIFEST.json"))
        except OSError:
            pass
    packs = []
    for d in root.iterdir():
        if d.is_dir() and d.name.startswith("audit-pack-"):
            try:
                m = json.loads((d / "MANIFEST.json").read_text())
            except (OSError, ValueError):
                continue
            if m.get("derived_from_manifest_sha256") in shas:
                packs.append(d)
    return sorted(records) + sorted(packs)


def sessions_open_on(client: str, matter: str) -> List[int]:
    """Processes on this computer working on the matter right now — started from the home page OR from a
    terminal. A Probant session carries its matter's state file in its environment; Linux lets the owner read
    that. Elsewhere this returns nothing and the home page's own record of what it started is the only check."""
    want = str(S.state_path(client, matter))
    pids = []
    proc = Path("/proc")
    if not proc.is_dir():
        return pids
    for d in proc.iterdir():
        if not d.name.isdigit() or int(d.name) == os.getpid():
            continue
        try:
            env = (d / "environ").read_bytes().split(b"\0")
        except OSError:
            continue
        if f"IR_MATTER_STATE_FILE={want}".encode() in env:
            pids.append(int(d.name))
    return sorted(pids)


def _any_session_open() -> bool:
    proc = Path("/proc")
    if not proc.is_dir():
        return True                                  # cannot tell: assume yes, and leave the file for the next launch
    for d in proc.iterdir():
        if d.name.isdigit() and int(d.name) != os.getpid():
            try:
                if b"IR_MATTER_STATE_FILE=" in (d / "environ").read_bytes():
                    return True
            except OSError:
                continue
    return False


def delete(client: str, matter: str) -> Dict[str, Any]:
    """Move everything of one matter into the deleted-matters folder. Refuses while a session is open on it."""
    client, matter = S.sanitize(client, "client"), S.sanitize(matter, "matter")
    rec = S.load_record(client, matter)                         # raises for an unknown matter
    if sessions_open_on(client, matter):
        raise S.ProbantError("a session is still open on this matter. End it (and close its page) first.")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = trash_root() / f"{stamp}__{client}__{matter}"
    dest.mkdir(parents=True)
    for d in (trash_root().parent, trash_root(), dest):
        os.chmod(d, 0o700)

    moved: List[Dict[str, str]] = []
    left: List[str] = []

    def move(src: Path, name: str) -> None:
        if not src.exists():
            return
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(target))
        moved.append({"from": str(src), "to": name})

    now = dt.datetime.now(dt.timezone.utc)
    info = {"schema": "inferroute.probant-deleted/1", "client": client, "matter": matter,
            "deleted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "erase_after": (now + dt.timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "moved": moved, "left_in_place": left}
    # Written in a finally: if a move fails halfway, what DID move is still listed, so it can be restored.
    try:
        # Only the matter's OWN folder is ever moved: exactly <Probant folder>/<client>/<matter>. An empty
        # field must not become Path("") — the current directory — and a record pointing anywhere else is
        # left alone and reported.
        named = str(rec.get("workspace") or "")
        own = S.workspace_path(client, matter)
        move(S.record_path(client, matter), "matter.json")
        move(S.state_path(client, matter), "state.json")
        move(S.records_dir(client, matter), "records")
        if named and os.path.realpath(named) == os.path.realpath(own) and _within(own, S.probant_root()):
            move(own, "workspace")
        elif named and Path(named).exists():
            left.append(named)
        for d in _exports_of(client, matter):
            move(d, f"exports/{d.name}")
    finally:
        (dest / MANIFEST).write_text(json.dumps(info, indent=1))
        os.chmod(dest / MANIFEST, 0o600)
    # The titles of the documents the matter's searches returned, handed to the last session that ran; it is
    # rewritten on every launch, so if it is this matter's it goes now rather than at the next one.
    # Only when no session is running at all: a running session of another matter may be reading its own.
    docs = S._irhome() / "pi-attested" / "matter-docs.json"
    if docs.exists() and not _any_session_open():
        try:
            docs.unlink()
        except OSError:
            pass
    return {"id": dest.name, **info}


def list_deleted() -> List[Dict[str, Any]]:
    root = trash_root()
    out = []
    for d in (sorted(root.iterdir(), reverse=True) if root.is_dir() else []):
        try:
            info = json.loads((d / MANIFEST).read_text())
        except (OSError, ValueError):
            continue
        out.append({"id": d.name, "matter": f"{info.get('client')}/{info.get('matter')}",
                    "deleted_at": info.get("deleted_at"), "erase_after": info.get("erase_after"),
                    "left_in_place": info.get("left_in_place") or []})
    return out


def _entry(entry_id: str) -> Path:
    if "/" in entry_id or entry_id.startswith(".") or "__" not in entry_id:
        raise S.ProbantError("no such deleted matter")
    d = trash_root() / entry_id
    if not (d / MANIFEST).is_file():
        raise S.ProbantError("no such deleted matter")
    return d


def restore(entry_id: str) -> str:
    """Put a deleted matter back exactly where it was. Refuses if anything now occupies one of its places."""
    d = _entry(entry_id)
    info = json.loads((d / MANIFEST).read_text())
    moves = info.get("moved") or []
    taken = [m["from"] for m in moves if Path(m["from"]).exists()]
    if taken:
        raise S.ProbantError("a matter with the same name exists again. Rename or delete it, then restore.")
    homes = (S.probant_root(), S._irhome() / "confidential")
    for m in moves:                                   # checked in full BEFORE anything moves back
        if not _within(d / m["to"], d) or not any(_within(Path(m["from"]), h) for h in homes):
            raise S.ProbantError("this deleted matter's list of files is not valid; it was not restored")
    for m in moves:
        src, back = d / m["to"], Path(m["from"])
        back.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(back))
    shutil.rmtree(d)
    S.make_private(info["client"], info["matter"])
    return f"{info['client']}/{info['matter']}"


def erase(entry_id: str) -> None:
    shutil.rmtree(_entry(entry_id))


def erase_expired(now: Optional[dt.datetime] = None) -> List[str]:
    """Erase what has been in the deleted folder longer than RETENTION_DAYS. Run when the home page starts."""
    now = now or dt.datetime.now(dt.timezone.utc)
    gone = []
    for e in list_deleted():
        try:
            due = dt.datetime.fromisoformat(str(e["erase_after"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        if due <= now:
            erase(e["id"])
            gone.append(e["id"])
    return gone


def cmd_delete(spec: str, yes: bool = False) -> int:
    client, matter = S._split_matter(spec)
    S.load_record(client, matter)
    if not yes:
        if not sys.stdin.isatty():
            raise S.ProbantError("to delete without a terminal to confirm in, pass --yes")
        typed = input(f"  Delete {client}/{matter}? It can be restored for {RETENTION_DAYS} days, then it is erased.\n"
                      f"  Type the matter name ({matter}) to confirm: ").strip()
        if typed != matter:
            print("  Not deleted.")
            return 1
    out = delete(client, matter)
    print(f"  Deleted {client}/{matter}. Restore it from Probant home within {RETENTION_DAYS} days.")
    for p in out["left_in_place"]:
        print(f"  Left in place (outside the Probant folder, so not Probant's to move): {p}")
    return 0
