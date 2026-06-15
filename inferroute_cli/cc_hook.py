"""Install / remove the Claude Code ``SessionEnd`` hook that ingests transcripts.

The recorder's content path is a CC hook, not the proxy: when a session ends, CC
runs our command with the session's ``transcript_path`` on stdin, and we record
the metadata spine out of the request hot path (see inferroute_local/ingest.py).

This module edits the user's CC ``settings.json`` (honoring ``CLAUDE_CONFIG_DIR``,
default ``~/.claude``) by MERGING our hook in without disturbing any existing
settings or hooks. It is idempotent and fully reversible, writes a one-time
timestamped backup before its first change, and refuses to clobber a SessionEnd
value that isn't the list shape CC expects. The hook command:

    <inferroute-daemon> ingest --stdin --quiet

needs neither the daemon running nor the [local] extra.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from shutil import which

# Stable marker substring identifying OUR hook command, so install is idempotent
# and remove only ever strips the hook we added.
HOOK_MARKER = "ingest --stdin"


def _config_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude"))


def _settings_path() -> Path:
    return _config_dir() / "settings.json"


def _daemon_command() -> str:
    binary = which("inferroute-daemon") or str(Path.home() / ".local/bin/inferroute-daemon")
    return f"{binary} ingest --stdin --quiet"


def _load(path: Path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None  # None = unexpected shape
    except Exception:
        return None


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)


def _backup_once(path: Path) -> None:
    if path.exists():
        bak = path.with_suffix(f".json.bak-{int(time.time())}")
        try:
            bak.write_text(path.read_text())
        except Exception:
            pass


def _group_has_our_hook(group) -> bool:
    if not isinstance(group, dict):
        return False
    for h in group.get("hooks", []) or []:
        if isinstance(h, dict) and HOOK_MARKER in str(h.get("command", "")):
            return True
    return False


def install() -> str:
    """Add (or refresh) the SessionEnd ingest hook. Returns a status string:
    'installed' | 'updated' | 'exists' | 'skipped: <reason>'."""
    path = _settings_path()
    settings = _load(path)
    if settings is None:
        return "skipped: settings.json is not valid JSON (left untouched)"

    cmd = _daemon_command()
    hooks = settings.get("hooks")
    if hooks is None:
        hooks = settings["hooks"] = {}
    if not isinstance(hooks, dict):
        return "skipped: settings.hooks is not an object (left untouched)"

    se = hooks.get("SessionEnd")
    if se is None:
        se = hooks["SessionEnd"] = []
    if not isinstance(se, list):
        return "skipped: settings.hooks.SessionEnd is not a list (left untouched)"

    # Already present? Refresh the command (the binary path may have moved).
    for group in se:
        if _group_has_our_hook(group):
            changed = False
            for h in group.get("hooks", []):
                if isinstance(h, dict) and HOOK_MARKER in str(h.get("command", "")):
                    if h.get("command") != cmd:
                        h["command"] = cmd
                        changed = True
            if changed:
                _backup_once(path)
                _atomic_write(path, settings)
                return "updated"
            return "exists"

    _backup_once(path)
    se.append({"hooks": [{"type": "command", "command": cmd}]})
    _atomic_write(path, settings)
    return "installed"


def remove() -> str:
    """Strip the SessionEnd ingest hook (and tidy empty containers). Returns
    'removed' | 'absent' | 'skipped: <reason>'."""
    path = _settings_path()
    settings = _load(path)
    if settings is None:
        return "skipped: settings.json is not valid JSON (left untouched)"
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return "absent"
    se = hooks.get("SessionEnd")
    if not isinstance(se, list):
        return "absent"

    kept = [g for g in se if not _group_has_our_hook(g)]
    if len(kept) == len(se):
        return "absent"

    _backup_once(path)
    if kept:
        hooks["SessionEnd"] = kept
    else:
        hooks.pop("SessionEnd", None)
    if not hooks:
        settings.pop("hooks", None)
    _atomic_write(path, settings)
    return "removed"
