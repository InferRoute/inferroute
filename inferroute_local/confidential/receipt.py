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


def _client_version() -> str:
    try:
        from inferroute_cli import __version__
        return f"ir {__version__}"
    except Exception:                                       # noqa: BLE001
        return ""


@dataclass
class Receipt:
    session_id: str
    model_short: str
    upstream_model: str
    fleet_id: str
    transport: str
    started_at: str = field(default_factory=_now)
    ended_at: str = ""
    instance: dict = field(default_factory=dict)        # id, gpu_count, mrtd, rtmrs, chain
    # The evidence row this device verified: the TDX quote, the enclave-signed attested body, its
    # certificate and signature, and every GPU report. Kept because without it the fifteen verdicts below
    # are THIS DEVICE'S WORD and nothing else — two independent auditors said so on 24 Sep, in the same
    # sentence: "the receipts are data, not proof I can recompute". We hold these bytes at verification
    # time and were throwing them away, which made a checkable claim uncheckable for no reason.
    # No conversation content is in here: measurements, our own challenge, and public keys.
    attestation: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)          # name → {ok, why, label, explain}
    fleet: dict = field(default_factory=dict)           # {instances, verified, e2ee_capable, eligible}
    limitations: list = field(default_factory=lambda: [{"id": k, "text": t} for k, t in attest.LIMITATIONS])
    e2ee: dict = field(default_factory=dict)            # kem, aead, kdf, backend
    counters: dict = field(default_factory=lambda: {
        "requests": 0, "plaintext_bytes_sealed_here": 0, "ciphertext_bytes_sent": 0,
        "ciphertext_frames_received": 0, "response_bytes_opened_here": 0, "errors": 0,
        "input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "estimated_cost_usd": 0.0})
    events: list = field(default_factory=list)          # [{ts, kind, detail}] — pins, switches, re-verifications
    verified_at: str = ""
    # Which client wrote this receipt. An auditor reading an OLD receipt cannot otherwise tell a defect
    # that was real and has since been fixed from one that is live — and it will keep reporting the fossil
    # as a finding, correctly, forever. Found on 24 Sep: an auditor flagged a 22 Sep receipt asserting
    # "this session's requests were encrypted" with a zero request counter, which `_restate_claim` had
    # already fixed; the 24 Sep receipt beside it was correct, and nothing in either said why they differed.
    # Self-reported, like everything else a receipt says about the device that wrote it.
    written_by: str = field(default_factory=lambda: _client_version())
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


# What is true of a session that verified and then sent nothing. 77 of the 712 receipts on the machine
# this was found on asserted the paragraph below — in the past tense, about requests — over `requests: 0`.
# The sentence was true of the LANE and was being read as a finding about the session it sat in.
CLAIM_OPENED = (
    "This device verified an Intel TDX hardware quote for this session against a fresh challenge, and "
    "pinned the encryption key that quote commits to (ML-KEM-768 + ChaCha20-Poly1305). No request has been "
    "sent in this session, so nothing has been sealed here and nothing has been carried. Stated limitations "
    "are listed in this receipt."
)

CLAIM_CONFIDENTIAL = (
    "This session's requests were encrypted on this device (ML-KEM-768 + ChaCha20-Poly1305) to an "
    "encryption key that an Intel TDX hardware quote commits to. This device verified that quote against "
    "a fresh challenge: Intel's Quoting Enclave signature, Intel's pinned root of trust, revocation lists, "
    "the platform's TCB status and Quoting Enclave identity (from Intel), every GPU's report (by NVIDIA, for "
    "this session's challenge), the operator's published measurements, and InferRoute's own record of the "
    "enclave build. No relay, and no provider, could substitute the key or the hardware without failing a "
    "check on this device. The relay carried ciphertext only. Stated limitations are listed in this receipt."
)


def lane_preamble(r: "Receipt") -> str:
    """What the model is told about its own situation, derived from the receipt so it can never
    say more than was verified. Kept short: it rides on every request."""
    if r.verdict != "confidential":
        return ""
    inst = r.instance or {}
    passed = [v.get("label", k) for k, v in (r.checks or {}).items() if v.get("ok")]
    lims = "; ".join(lim["text"].rstrip(".") for lim in r.limitations)
    return (
        "# Confidential session (InferRoute)\n"
        f"The assistant in this session is {r.upstream_model}, running inside a hardware enclave (Intel TDX "
        f"confidential VM with NVIDIA confidential-computing GPUs), instance {str(inst.get('id') or '')[:8]}, "
        "reached through InferRoute's confidential lane. Before this session opened, the user's own machine verified the "
        f"enclave's attestation against a fresh challenge ({', '.join(passed)}) and every request in this "
        "session is encrypted on the user's machine to a key that hardware quote commits to (ML-KEM-768 + "
        "ChaCha20-Poly1305); replies are encrypted back. InferRoute and the enclave operator relay ciphertext "
        "and can see sizes, timing, model and instance id — not the words. This session is NOT running on Anthropic's "
        "servers and is not subject to Anthropic's data policies; never say otherwise.\n"
        "If asked whether or how this session is private, answer from the facts above, point to the panel "
        "printed when the session opened, the receipt at "
        f"{r.path or '~/.inferroute/confidential/receipts/'}, and `ir confidential show`; and state the "
        f"limitations plainly: {lims}. Do not overstate: the words are private, the metadata is not.\n"
        "Otherwise behave exactly as you normally would; this note changes nothing about the task."
    )
