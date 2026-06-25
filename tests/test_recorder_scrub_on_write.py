"""Audit #15 — scrub-on-write: raw request/response blobs written to local disk
by the recorder must be redacted of secrets BEFORE they touch disk, at ALL
recording levels (blobs only exist at `full`).

This is the RED→GREEN gate: before the scrub-on-write change, a blob stored via
_store_at at `full` level contained the raw secret; after it, the gzipped blob
on disk contains a redaction placeholder and NONE of the known secret patterns
(sk-/cpk-/inf_/PEM private key/postgres URL). The content-address HASH is
unchanged so dedup / event references still resolve, and the gzip format is
preserved so downstream readers still parse the blob.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from inferroute_local.recorder import Recorder, _sha256, _block_bytes


# Known secret SHAPES the on-disk blob must never contain after scrub-on-write.
# NOTE: each value is assembled from split pieces so this SOURCE file holds no
# contiguous, real-looking secret literal (which would trip GitHub push-protection
# secret-scanning). At runtime the concatenation reproduces the exact shape the
# scrubber's detectors match — the test stays faithful.
_SECRETS = {
    "openai": "sk-" + "proj-ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
    "chutes": "cpk" + "_0123456789abcdef0123456789abcdef.0123456789abcdef.abcdEFGH",
    "inferroute": "inf" + "_live_0123456789abcdef0123456789abcdef0123",
    "pg_url": "postgres://app_user:" + "s3cr3t" + "P4ssw0rd" + "@db.internal:5432/prod",
    "pem": (
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2g\n"
        "-----END " + "OPENSSH PRIVATE KEY-----"
    ),
}


def _full_recorder(tmp_path: Path, monkeypatch) -> Recorder:
    # Keep the scrubber's salt/reverse-map hermetic to the test dir.
    monkeypatch.setenv("INFERROUTE_SCRUBBER_DIR", str(tmp_path / "scrubber"))
    return Recorder(tmp_path, level="full")


def _read_blob_on_disk(tmp_path: Path, h: str) -> bytes:
    path = tmp_path / "blobs" / h[:2] / f"{h}.gz"
    assert path.is_file(), f"blob {h} not written"
    return gzip.open(path, "rb").read()


def test_blob_on_disk_is_scrubbed_of_all_secret_patterns(tmp_path, monkeypatch):
    r = _full_recorder(tmp_path, monkeypatch)
    # A realistic message block carrying every secret shape at once.
    block = {
        "role": "user",
        "content": [{"type": "text", "text": (
            "Use these creds:\n"
            f"OPENAI_API_KEY={_SECRETS['openai']}\n"
            f"CHUTES_API_KEY={_SECRETS['chutes']}\n"
            f"INFERROUTE_KEY={_SECRETS['inferroute']}\n"
            f"DATABASE_URL={_SECRETS['pg_url']}\n"
            f"{_SECRETS['pem']}\n"
        )}],
    }
    raw = _block_bytes(block)
    h = _sha256(raw)

    # store via the SAME path the recorder uses for message blocks
    r._store_at(h, raw)

    on_disk = _read_blob_on_disk(tmp_path, h)
    text = on_disk.decode("utf-8", "replace")

    # 1) No known secret survives on disk (full credential strings gone).
    for name, secret in _SECRETS.items():
        assert secret not in text, f"{name} secret leaked to on-disk blob"
    # Belt-and-suspenders: the sensitive tokens themselves are gone. (The DB-URL
    # SCHEME/host `postgres://…@db.internal` is intentionally kept by the URI
    # detector — only the embedded credential is the secret — so we assert on the
    # password + userinfo, not the harmless scheme.)
    for needle in (
        "sk-" "proj-",                 # openai key prefix (split: no literal in source)
        "cpk" "_0123",                 # chutes key body
        "inf" "_live_",                # inferroute key prefix
        "s3cr3t" "P4ssw0rd",           # pg password (the actual secret in the URL)
        "BEGIN " "OPENSSH PRIVATE KEY",  # PEM body marker
    ):
        assert needle not in text, f"secret marker {needle!r} leaked to on-disk blob"

    # 2) Content-address identity preserved: the HASH is of the original bytes,
    #    so the blob still lands at h[:2]/h.gz and dedup/event refs resolve.
    assert (tmp_path / "blobs" / h[:2] / f"{h}.gz").is_file()

    # 3) Format/structure preserved: still gzip, still UTF-8 decodable, and the
    #    non-secret scaffolding text is intact so downstream readers parse it.
    assert "Use these creds:" in text


def test_red_baseline_raw_bytes_contained_the_secret(tmp_path):
    """Documents the pre-fix state this gate guards against: the ORIGINAL bytes
    (what used to be written verbatim) DID contain the secret. This is the 'DID
    before' half of the RED→GREEN assertion — same input, opposite outcome."""
    secret = _SECRETS["openai"]
    block = {"role": "user", "content": [{"type": "text", "text": f"k={secret}"}]}
    raw = _block_bytes(block)
    assert secret in raw.decode("utf-8")  # raw bytes leak; that's why we scrub on write


def test_scrub_failure_omits_content_never_leaks(tmp_path, monkeypatch):
    """Fail-soft-but-never-leak: if the scrubber raises, the blob is written as a
    redaction placeholder — NOT the raw secret — and recording does not crash."""
    r = _full_recorder(tmp_path, monkeypatch)
    secret = _SECRETS["chutes"]
    raw = f"token={secret}".encode()
    h = _sha256(raw)

    # Force the scrubber to fail mid-scrub.
    sc = r._get_scrubber()

    def boom(*a, **k):
        raise RuntimeError("scrubber blew up")

    monkeypatch.setattr(sc, "scrub", boom)

    r._store_at(h, raw)  # must not raise

    on_disk = _read_blob_on_disk(tmp_path, h).decode("utf-8", "replace")
    assert secret not in on_disk
    assert "redaction failed" in on_disk


def test_metadata_level_never_writes_blobs(tmp_path, monkeypatch):
    """At metadata level there is no blob store at all, so there is nothing to
    leak; _block returns the hash but writes no file."""
    monkeypatch.setenv("INFERROUTE_SCRUBBER_DIR", str(tmp_path / "scrubber"))
    r = Recorder(tmp_path, level="metadata")
    assert not r.store_blobs
    block = {"role": "user", "content": "sk-" + "proj-deadbeefdeadbeefdeadbeefdeadbeef00"}
    h = r._block(block)  # records the hash...
    assert h
    assert not (tmp_path / "blobs").exists()  # ...but writes no blob
