"""The receipt: everything the session verified, counted, and could not verify — as a file the
user keeps. The display renders THIS, so nothing shown can be stronger than what is recorded."""
from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import attest

SCHEMA = "inferroute.confidential.receipt/1"


def receipts_dir() -> Path:
    base = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    d = base / "confidential" / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Receipt:
    session_id: str
    model_short: str
    upstream_model: str
    chute_id: str
    transport: str
    started_at: str = field(default_factory=_now)
    ended_at: str = ""
    instance: dict = field(default_factory=dict)        # id, gpu_count, mrtd, rtmrs, chain
    checks: dict = field(default_factory=dict)          # name → {ok, why, label, explain}
    fleet: dict = field(default_factory=dict)           # {instances, verified, e2ee_capable, eligible}
    limitations: list = field(default_factory=lambda: [{"id": k, "text": t} for k, t in attest.LIMITATIONS])
    e2ee: dict = field(default_factory=dict)            # kem, aead, kdf, backend
    counters: dict = field(default_factory=lambda: {
        "requests": 0, "plaintext_bytes_sealed_here": 0, "ciphertext_bytes_sent": 0,
        "ciphertext_frames_received": 0, "response_bytes_opened_here": 0, "errors": 0,
        "input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0})
    events: list = field(default_factory=list)          # [{ts, kind, detail}] — pins, switches, re-verifications
    verified_at: str = ""
    claim: str = ""
    verdict: str = "unopened"                           # unopened | confidential | refused | degraded
    refusal: str = ""
    schema: str = SCHEMA
    path: str = ""

    @property
    def is_confidential(self) -> bool:
        return self.verdict == "confidential"

    def note(self, kind: str, detail: str) -> None:
        self.events.append({"ts": _now(), "kind": kind, "detail": detail})

    def save(self) -> Path:
        if not self.path:
            stamp = self.started_at.replace(":", "-")
            self.path = str(receipts_dir() / f"{stamp}-{self.session_id[:8]}.json")
        p = Path(self.path)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=1, ensure_ascii=False) + "\n")
        os.replace(tmp, p)
        return p

    @classmethod
    def load(cls, p: Path) -> "Receipt":
        d = json.loads(Path(p).read_text())
        d.pop("schema", None)
        r = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        r.path = str(p)
        return r


def latest() -> Receipt | None:
    files = sorted(receipts_dir().glob("*.json"))
    return Receipt.load(files[-1]) if files else None


CLAIM_CONFIDENTIAL = (
    "This session's requests were encrypted on this device with ML-KEM-768 + ChaCha20-Poly1305 to "
    "an encryption key that an Intel TDX hardware quote, verified on this device against a fresh "
    "challenge, commits to. No relay, and no provider, could substitute the key without failing that "
    "check. The relay carried ciphertext only. Stated limitations apply and are listed in this receipt."
)
