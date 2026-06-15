"""Ingest native Claude Code transcripts into the local decision corpus.

Native CC transcripts (``~/.claude/projects/**/<sessionId>.jsonl``) are the
content spine: they already record, for native AND routed sessions, the served
model, token ``usage``, requestId / sessionId / cwd / gitBranch / version, and
the full content. This module reads that spine and records only inferroute's
metadata DELTA — one ``turn`` event per assistant message — so the corpus never
duplicates transcript content (the whole point of the 2026-06 redesign).

Invoked OUT of the request hot path by the Claude Code ``SessionEnd`` hook
(``inferroute-daemon ingest --stdin``), once per session. Idempotent: a resumed
(appended) transcript only contributes its new turns on re-ingest, tracked by a
per-transcript line-count marker under ``<base>/ingested/``.

Cost is not recorded here. The only cost inferroute tracks is what it actually
billed — the server-reported ``usage.cost`` on ROUTED turns (captured by the
daemon as outcome events, joinable to a turn by ``request_id``). Native Claude
turns aren't served by inferroute, so they carry no inferroute cost; we do not
estimate them against any external price list. Token counts are still recorded
as useful spine metadata. See shared-docs/inferroute/local-decision-recorder-spec.md.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inferroute_local.ingest")


def _iso_to_epoch(iso: Optional[str]) -> Optional[float]:
    if not iso or not isinstance(iso, str):
        return None
    try:
        # CC stamps UTC ISO-8601 with a trailing 'Z'.
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _marker_path(base_dir: Path, transcript: Path) -> Path:
    """Per-transcript progress marker, keyed by a hash of the absolute path so
    concurrent SessionEnd hooks (different sessions ending at once) never contend
    on a shared index file."""
    h = hashlib.sha1(str(transcript.resolve()).encode("utf-8", "ignore")).hexdigest()[:16]
    return base_dir / "ingested" / f"{h}.json"


def _read_marker(path: Path) -> int:
    try:
        return int(json.loads(path.read_text()).get("lines", 0))
    except Exception:
        return 0


def _write_marker(path: Path, transcript: Path, lines: int) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"path": str(transcript), "lines": lines}))
        tmp.replace(path)
    except Exception as e:
        logger.debug(f"ingest marker write skipped ({e})")


def _tool_names(content) -> list[str]:
    out = []
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name"):
                out.append(b["name"])
    return out


def _extract_turn(record: dict, wire: Optional[dict]) -> Optional[dict]:
    """Map one CC transcript assistant record → a metadata `turn` event payload.
    Returns None for non-assistant records (user, summary, file-history, …)."""
    if not isinstance(record, dict) or record.get("type") != "assistant":
        return None
    msg = record.get("message") or {}
    usage = msg.get("usage") or {}
    cache_creation = usage.get("cache_creation") or {}
    iso = record.get("timestamp")
    fields = {
        "session_id": record.get("sessionId"),
        "request_id": record.get("requestId"),
        "message_id": msg.get("id"),
        "uuid": record.get("uuid"),
        "ts": _iso_to_epoch(iso),
        "iso": iso,
        "served_model": msg.get("model"),
        "stop_reason": msg.get("stop_reason"),
        "tokens_in": usage.get("input_tokens"),
        "tokens_out": usage.get("output_tokens"),
        "cache_read_tokens": usage.get("cache_read_input_tokens"),
        "cache_creation_tokens": usage.get("cache_creation_input_tokens"),
        "cache_ephemeral_1h": cache_creation.get("ephemeral_1h_input_tokens"),
        "cache_ephemeral_5m": cache_creation.get("ephemeral_5m_input_tokens"),
        "service_tier": usage.get("service_tier"),
        "speed": usage.get("speed"),
        "tool_names": _tool_names(msg.get("content")),
        "is_sidechain": bool(record.get("isSidechain")),
        "cwd": record.get("cwd"),
        "git_branch": record.get("gitBranch"),
        "cc_version": record.get("version"),
        "source": "transcript",
    }
    # Wire delta (system-prompt hash + tool list) mined from the per-session OTEL
    # raw-bodies file, when present. Joined by request_id. See wire.py.
    if wire:
        w = wire.get(fields.get("request_id")) or wire.get("_session")
        if w:
            fields["system_hash"] = w.get("system_hash")
            fields["wire_tool_names"] = w.get("tool_names")
    return {k: v for k, v in fields.items() if v is not None}


def ingest_transcript(
    transcript: Path,
    recorder,
    *,
    wire: Optional[dict] = None,
    force: bool = False,
) -> dict:
    """Ingest new assistant turns from one transcript into `recorder`.

    Returns a summary dict. Idempotent via a per-transcript line-count marker:
    only lines beyond the last ingest are processed (transcripts are append-only;
    on the rare case the file shrank, we reprocess from the top).
    """
    transcript = Path(transcript)
    if not transcript.exists():
        return {"ok": False, "error": "transcript not found", "path": str(transcript)}
    if not getattr(recorder, "enabled", False):
        return {"ok": True, "turns": 0, "skipped": "recording off"}

    marker = _marker_path(recorder.base_dir, transcript)
    already = 0 if force else _read_marker(marker)

    try:
        lines = transcript.read_text(errors="replace").splitlines()
    except Exception as e:
        return {"ok": False, "error": f"read failed: {e}", "path": str(transcript)}

    total = len(lines)
    start = 0 if total < already else already  # file shrank → reprocess all
    turns = 0
    session_id = None
    for line in lines[start:]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        ev = _extract_turn(record, wire)
        if ev is None:
            continue
        session_id = session_id or ev.get("session_id")
        recorder.record_turn(ev)
        turns += 1

    try:
        recorder.flush()
    except Exception:
        pass
    _write_marker(marker, transcript, total)
    return {"ok": True, "turns": turns, "lines": total, "from_line": start,
            "session_id": session_id, "path": str(transcript)}


def transcript_path_from_hook_payload(payload: dict) -> Optional[str]:
    """Pull the transcript path out of a Claude Code hook JSON payload.
    SessionEnd (and most hooks) provide `transcript_path`."""
    if not isinstance(payload, dict):
        return None
    return payload.get("transcript_path") or payload.get("transcriptPath")
