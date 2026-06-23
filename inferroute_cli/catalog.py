"""Model catalog (list + per-lane prices) fetched from the inferroute backend.

Source of truth is the backend's public ``GET /pricing`` (no auth — same data as
inferroute.ai/pricing). `ir` refreshes it at launch into a local cache; `models.py`
reads the cache so the offered list + prices stay current without an `ir` release.
Everything is fail-soft: a missing/slow backend falls back to the cache, and an
empty cache falls back to the bundled defaults in `models.py`.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path


def _cache_path() -> Path:
    # Mirror the recorder's dir resolution so everything lives under one base.
    base = os.environ.get("INFERROUTE_RECORD_DIR") or os.environ.get("INFERROUTE_LOG_DIR") or ""
    return (Path(base) if base else Path.home() / ".inferroute") / "catalog.json"


def refresh(api_url: str, timeout: float = 0.6) -> bool:
    """Fetch the catalog from ``{api_url}/pricing`` and cache it. Returns True on a
    successful refresh; fail-soft (False) on any network/parse error — the caller
    keeps using whatever is cached (or the bundled fallback)."""
    if not api_url:
        return False
    try:
        req = urllib.request.Request(api_url.rstrip("/") + "/pricing",
                                     headers={"accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        if not isinstance(data.get("models"), list) or not data["models"]:
            return False
        p = _cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(p)
        return True
    except Exception:
        return False


def load() -> list[dict] | None:
    """The cached catalog model list, or None if there's no usable cache."""
    try:
        models = json.loads(_cache_path().read_text()).get("models")
        return models if isinstance(models, list) and models else None
    except Exception:
        return None
