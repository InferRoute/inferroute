"""Mine the per-session OTEL raw-API-bodies file for the wire DELTA, then delete it.

Native CC transcripts omit the ``system`` prompt and ``tools`` array sent on each
request. When wire capture is enabled (``IR_CAPTURE_WIRE=1``), the ``ir`` launcher
points Claude Code's OTEL raw-body logging at a per-session scratch directory
under ``~/.inferroute/wire/<sessionId>/`` (see inferroute_cli/launch.py). At
ingest time we mine ONLY a system-prompt HASH and the tool-name LIST from those
bodies, fold them into the turn event, and DELETE the scratch directory — none of
the raw payload is kept (decision A, 2026-06-15: "wire via OTEL-to-file, as long
as it leaves nothing behind").

Everything here is best-effort and fail-soft. Pure-native sessions (not launched
through ``ir``) produce no wire directory, so this returns None. The exact on-disk
format of CC's ``OTEL_LOG_RAW_API_BODIES=file:`` sink is parsed defensively (any
JSON object/line that contains a ``system``/``tools``/``messages`` shape), so a
format change degrades to "no wire delta" rather than an error — and the feature
is opt-in (default off) until verified against a live CC run.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger("inferroute_local.wire")


def wire_root(base: Path) -> Path:
    return Path(base) / "wire"


def session_dir(base: Path, session_id: str) -> Path:
    safe = "".join(c for c in str(session_id) if c.isalnum() or c in "-_.")
    return wire_root(base) / safe


def _canon_system(system) -> Optional[str]:
    if not system:
        return None
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts = []
        for b in system:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                parts.append(b["text"])
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts) if parts else None
    return None


def _tool_names(tools) -> list[str]:
    names = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                names.append(str(t["name"]))
    return sorted(set(names))


def _find_request_body(obj):
    """Locate the Anthropic request body inside an arbitrarily-wrapped OTEL log
    record. Returns the dict that has `system`/`tools`/`messages`, or None."""
    seen = 0
    stack = [obj]
    while stack and seen < 200:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, dict):
            if "system" in cur or "tools" in cur or "messages" in cur:
                return cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def _iter_records(sdir: Path) -> Iterator[dict]:
    """Yield parsed JSON records from every file in the session wire dir,
    tolerating both single-JSON-object files and JSONL."""
    for f in sorted(sdir.glob("**/*")):
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        text = text.strip()
        if not text:
            continue
        # Whole-file JSON first; fall back to line-by-line.
        try:
            yield json.loads(text)
            continue
        except Exception:
            pass
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def mine_and_consume(base, transcript_path) -> Optional[dict]:
    """Mine the wire delta for the transcript's session, then delete the scratch
    dir. Returns {request_id: {system_hash, tool_names}, "_session": {...}} or
    None. The session id is the transcript filename stem (CC names transcripts
    ``<sessionId>.jsonl``)."""
    base = Path(base)
    sid = Path(transcript_path).stem
    sdir = session_dir(base, sid)
    if not sdir.exists():
        return None

    out: dict = {}
    last_system_hash = None
    tool_union: set[str] = set()
    try:
        for rec in _iter_records(sdir):
            body = _find_request_body(rec) or (rec if isinstance(rec, dict) else None)
            if not isinstance(body, dict):
                continue
            sys_text = _canon_system(body.get("system"))
            names = _tool_names(body.get("tools"))
            sys_hash = (
                hashlib.sha256(sys_text.encode("utf-8", "ignore")).hexdigest()
                if sys_text else None
            )
            if sys_hash:
                last_system_hash = sys_hash
            tool_union.update(names)
            # Correlate per-request when the record exposes an id.
            rid = None
            if isinstance(rec, dict):
                rid = rec.get("request_id") or rec.get("requestId")
            if rid:
                out[rid] = {"system_hash": sys_hash, "tool_names": names}
    except Exception as e:
        logger.debug(f"wire mine failed ({e})")
    finally:
        shutil.rmtree(sdir, ignore_errors=True)  # leave nothing behind

    if last_system_hash or tool_union:
        out["_session"] = {
            "system_hash": last_system_hash,
            "tool_names": sorted(tool_union),
        }
    return out or None


def gc(base, ttl_days: float = 2.0) -> None:
    """Delete wire session dirs older than ttl_days — covers sessions that ended
    without a SessionEnd ingest (so raw bodies never linger). Best-effort."""
    root = wire_root(base)
    if not root.exists() or ttl_days <= 0:
        return
    cutoff = time.time() - ttl_days * 86400
    try:
        for d in root.iterdir():
            try:
                if d.is_dir() and d.stat().st_mtime < cutoff:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass
    except OSError:
        pass
