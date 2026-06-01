"""First-run model bootstrap: download classifier ONNX from a URL on daemon start.

Why a bootstrap step
--------------------
The classifier ONNX is ~150MB (FP32 with INT8 weights — actual filesize varies).
Bundling that in the Python wheel would bloat installs for users who don't want
the local-classifier feature, and would couple model versioning to package
versioning. Instead we ship the daemon with no model, and on first start the
daemon fetches the artifacts from a CDN URL into the default model dir.

Layout written to disk
----------------------
    ~/.inferroute/models/classifier-v0/
        onnx/model.onnx          (and model.onnx.data if external)
        tokenizer.json
        tokenizer_config.json
        special_tokens_map.json
        calibration.json
        label_to_int.json
        VERSION                   (just the version string we fetched)

The classifier_v2.RoutingClassifier loader picks up this directory by default.

Atomicity
---------
We download into a sibling temp dir and rename it into place ONLY after every
required file has landed. A partial download never becomes the active model
dir. If the daemon dies mid-fetch, the next start sees no model and retries.

Failure mode
------------
ALWAYS fail-soft. Bootstrap failures leave the daemon running without a local
classifier (the proxy falls back to the legacy server route). We log the error
loudly so users notice, but we don't refuse to start the daemon over a model
fetch that didn't work.

Configuration
-------------
Off by default until we have a public artifacts URL. Users (or our installer)
opt in by setting `INFERROUTE_CLASSIFIER_BOOTSTRAP_URL` to a manifest URL.

Manifest format (JSON):
    {
      "version": "v0-longer-2026-06",
      "files": [
        {"path": "onnx/model.onnx", "url": "https://.../model.onnx", "sha256": "..."},
        {"path": "tokenizer.json",  "url": "https://.../tokenizer.json", "sha256": "..."},
        ...
      ]
    }

sha256 fields are optional but verified when present.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("inferroute_local.bootstrap")

# Files we require before swapping the model dir into place. Everything else
# in the manifest is downloaded but considered optional.
REQUIRED_FILES = {"onnx/model.onnx", "tokenizer.json", "calibration.json", "label_to_int.json"}

# Hard cap on bootstrap time so daemon startup can't hang on a slow CDN.
BOOTSTRAP_TIMEOUT_S = 300.0


def maybe_bootstrap_classifier(
    target_dir: Path,
    manifest_url: Optional[str],
    *,
    force: bool = False,
    timeout_s: float = BOOTSTRAP_TIMEOUT_S,
) -> Optional[str]:
    """Ensure a classifier-v0 model exists at target_dir, fetching if needed.

    Returns the version string written to VERSION on success, or None if no
    fetch was attempted or it failed (logged separately). Existing model dirs
    are left alone unless `force=True`.

    Calling without a manifest_url is a no-op (we just check whether a model
    already exists locally).
    """
    if target_dir.exists() and not force:
        if _looks_complete(target_dir):
            return None  # nothing to do — model already in place
        logger.info(
            f"bootstrap: {target_dir} exists but is incomplete; will re-download"
        )

    if not manifest_url:
        return None  # bootstrap disabled by config

    try:
        return _do_bootstrap(target_dir, manifest_url, timeout_s)
    except Exception as e:
        logger.error(
            f"bootstrap failed ({type(e).__name__}: {e}); "
            "daemon will continue without local classifier (legacy server route)"
        )
        return None


# ──────────────────────────────────────────────────────────────────────────
# Implementation details
# ──────────────────────────────────────────────────────────────────────────

def _looks_complete(model_dir: Path) -> bool:
    for rel in REQUIRED_FILES:
        if not (model_dir / rel).exists():
            return False
    return True


def _do_bootstrap(target_dir: Path, manifest_url: str, timeout_s: float) -> str:
    """Atomically populate target_dir from the manifest. Raises on error."""
    logger.info(f"bootstrap: fetching manifest from {manifest_url}")
    with httpx.Client(timeout=httpx.Timeout(timeout_s), follow_redirects=True) as client:
        manifest = _fetch_manifest(client, manifest_url)
        version = manifest.get("version") or "unknown"
        files = manifest.get("files") or []
        if not files:
            raise ValueError("manifest contained no files")

        target_dir.parent.mkdir(parents=True, exist_ok=True)
        # Stage in a sibling temp dir so we either succeed or leave no trace.
        with tempfile.TemporaryDirectory(
            prefix=f"{target_dir.name}.staging-", dir=target_dir.parent
        ) as staging_str:
            staging = Path(staging_str)
            logger.info(f"bootstrap: staging into {staging}")
            for entry in files:
                _download_file(client, entry, staging)
            (staging / "VERSION").write_text(version + "\n")
            if not _looks_complete(staging):
                missing = [f for f in REQUIRED_FILES if not (staging / f).exists()]
                raise FileNotFoundError(f"manifest missing required files: {missing}")

            # Atomic swap. If target_dir exists, archive it briefly so we can
            # roll back on a failed rename (extremely rare on POSIX, but cheap
            # to defend against).
            if target_dir.exists():
                backup = target_dir.with_suffix(".prev")
                if backup.exists():
                    shutil.rmtree(backup)
                target_dir.rename(backup)
                try:
                    staging.rename(target_dir)
                except Exception:
                    backup.rename(target_dir)
                    raise
                shutil.rmtree(backup, ignore_errors=True)
            else:
                staging.rename(target_dir)

            # tempdir cleanup will be a no-op since we renamed it away; suppress
            # the resulting FileNotFoundError by re-creating the now-missing dir.
            Path(staging_str).mkdir(exist_ok=True)

    logger.info(f"bootstrap: installed classifier version {version} at {target_dir}")
    return version


def _fetch_manifest(client: httpx.Client, url: str) -> dict:
    resp = client.get(url)
    resp.raise_for_status()
    return resp.json()


def _download_file(client: httpx.Client, entry: dict, staging: Path) -> None:
    """Fetch one manifest entry into staging/<path>, verifying sha256 if given."""
    rel_path = entry.get("path")
    url = entry.get("url")
    expected_sha = entry.get("sha256")
    if not rel_path or not url:
        raise ValueError(f"manifest entry missing path/url: {entry!r}")

    dest = staging / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256() if expected_sha else None
    bytes_written = 0
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        with dest.open("wb") as f:
            for chunk in resp.iter_bytes(chunk_size=1 << 16):
                f.write(chunk)
                if hasher is not None:
                    hasher.update(chunk)
                bytes_written += len(chunk)

    if hasher is not None:
        got = hasher.hexdigest()
        if got != expected_sha:
            raise ValueError(
                f"sha256 mismatch for {rel_path}: expected {expected_sha}, got {got}"
            )
    logger.info(f"bootstrap:  fetched {rel_path} ({bytes_written/1024/1024:.1f} MB)")
