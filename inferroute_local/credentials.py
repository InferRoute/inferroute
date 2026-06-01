"""Local credential storage at ~/.inferroute/credentials.json.

v1 is intentionally minimal: a token paste-in flow. OAuth and refresh tokens
can come later. The file is created with 0600 permissions.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

CRED_DIR = Path.home() / ".inferroute"
CRED_FILE = CRED_DIR / "credentials.json"


def load() -> dict:
    if not CRED_FILE.exists():
        return {}
    try:
        return json.loads(CRED_FILE.read_text())
    except Exception:
        return {}


def save(data: dict) -> None:
    CRED_DIR.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(data, indent=2))
    os.chmod(CRED_FILE, 0o600)


def get_api_key() -> str:
    """Resolve the inferroute API key, preferring env var over file."""
    if key := os.environ.get("INFERROUTE_API_KEY"):
        return key
    return load().get("inferroute_token", "")
