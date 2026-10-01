"""SEV-SNP attestation: build the binding, parse the report, and verify it — or refuse.

WHICH LANE THIS GOVERNS. Two REPORT_DATA schemes live in this tree, one per lane:
  * the SELF-HOSTED lane (Verda / bare CVM): the length-prefixed SHA-512 over six fields built by
    `binding()` below — that is what THIS module's docstring describes;
  * the AZURE ACI lane (enclave/azure, sealedresearch/aci_evidence, search_verifier, and the bundled
    verify_record.py): REPORT_DATA = SHA-256(runtime_data) ‖ 32 zero bytes, see aci_evidence.report_data_for.
`parse()` and `tcb_params()` serve both; `binding()` is self-hosted only.

This is the keystone of ASSURANCE-ARCHITECTURE.md. The enclave generates its keypair inside the TEE
and folds everything a firm must trust into one hardware-signed field:

    REPORT_DATA = sha512( enclave_pubkey ‖ image_measurement ‖ policy_hash
                          ‖ index_manifest_hash ‖ model_weights_hash ‖ job_id )

The firm's client then verifies that report against AMD's roots BEFORE encrypting the disclosure to
the key. That inversion is the whole design: we cannot cheat, because a bad attestation means the
plaintext is never released.

MEASURED ON REAL HARDWARE 2026-08-27 (Verda 1RTXPRO6000.30V.CC, EPYC Turin), see
`enclave/results/snp-probe/`:

  * `/dev/sev-guest` present; "Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP".
  * configfs-tsm works — no AMD `snpguest` binary needed. Write 64 bytes to `inblob`, read a
    1184-byte report from `outblob`. **REPORT_DATA round-tripped exactly.**
  * MEASUREMENT is real and non-zero (`c505fe538d74717d…`), signing_key = VCEK (per-chip, verifiable
    directly against AMD rather than against the cloud provider), MASK_CHIP_ID = 0, DEBUG = 0.
  * **The chain to AMD verifies END TO END**, cross-checked with AMD's own `snpguest` 0.10.0:
    "The AMD ARK was self-signed / The AMD ASK was signed by the AMD ARK / The VCEK was signed by the
    AMD ASK / VEK signed the Attestation Report", with all five reported-TCB fields in the VCEK
    matching the report. `auxblob` being empty is a non-issue: the VCEK is fetchable from AMD's KDS.

TWO TRAPS, both found by getting them wrong first:

1. **HWID is 8 bytes on Turin, not 64.** CHIP_ID is a 64-byte *field* that Turin fills with 8 bytes
   and zero-pads. AMD KDS wants the 8 significant bytes (16 hex chars); sending the padded field
   returns 404. Measured directly: 16 hex chars -> 200, 128 hex chars -> 404.
2. **Turin (Zen 5) reordered TCB_VERSION.** Reading the Zen3/4 order gives snp=0 — a plausible-looking
   wrong answer that also produces a silently wrong VCEK URL.

Both failures look identical from the outside (404), and both invite the conclusion that the platform
is at fault rather than the client. It is worth being slow about that conclusion.
"""
from __future__ import annotations

import hashlib
import warnings
import os
import struct
from typing import Any, Dict, Optional

TSM = "/sys/kernel/config/tsm/report"
REPORT_LEN = 1184
# Offsets into the SNP ATTESTATION_REPORT (stable across v2..v5 for the fields we use).
_OFF = {"version": 0x000, "guest_svn": 0x004, "policy": 0x008, "vmpl": 0x030,
        "current_tcb": 0x038, "flags": 0x048, "report_data": 0x050, "measurement": 0x090,
        "host_data": 0x0C0, "report_id": 0x140, "reported_tcb": 0x180, "chip_id": 0x1A0,
        "signature": 0x2A0}
SIGNING_KEY = {0: "VCEK", 1: "VLEK", 7: "NONE"}


def binding(*, enclave_pubkey: bytes, image_measurement: bytes, policy_hash: bytes,
            index_manifest_hash: bytes, model_weights_hash: bytes, job_id: bytes) -> bytes:
    """The 64 bytes that go into REPORT_DATA. Order is fixed and must never change silently.

    Everything the firm must trust collapses into one hardware-signed value: the key they encrypt to,
    the software that will run, the egress policy in force, the corpus that will be searched, and the
    model that will read the disclosure.
    """
    h = hashlib.sha512()
    for part in (enclave_pubkey, image_measurement, policy_hash,
                 index_manifest_hash, model_weights_hash, job_id):
        h.update(len(part).to_bytes(4, "big"))     # length-prefixed: no ambiguity between fields
        h.update(part)
    return h.digest()                               # 64 bytes, exactly REPORT_DATA's width


def request_report(report_data: bytes, *, entry: str = "sealedresearch") -> bytes:
    """Ask the TEE for a fresh report over `report_data`. Runs INSIDE the enclave."""
    if len(report_data) != 64:
        raise ValueError(f"REPORT_DATA must be exactly 64 bytes, got {len(report_data)}")
    d = os.path.join(TSM, entry)
    if not os.path.isdir(TSM):
        raise RuntimeError(f"{TSM} missing — no confidential-compute TSM on this machine. "
                           f"This is not a CVM, or configfs is not mounted.")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "inblob"), "wb") as fh:
        fh.write(report_data)
    with open(os.path.join(d, "outblob"), "rb") as fh:
        rep = fh.read()
    if len(rep) != REPORT_LEN:
        raise RuntimeError(f"unexpected report length {len(rep)} (expected {REPORT_LEN})")
    return rep


def parse(report: bytes) -> Dict[str, Any]:
    if len(report) != REPORT_LEN:
        raise ValueError(f"report must be {REPORT_LEN} bytes, got {len(report)}")
    g = lambda k, n: report[_OFF[k]:_OFF[k] + n]                       # noqa: E731
    flags, = struct.unpack("<I", g("flags", 4))
    policy, = struct.unpack("<Q", g("policy", 8))
    ver, = struct.unpack("<I", g("version", 4))
    return {
        "version": ver,
        "policy": policy,
        "debug_allowed": bool((policy >> 19) & 1),   # a DEBUG-enabled guest can be inspected: fatal
        "smt_allowed": bool((policy >> 16) & 1),
        "vmpl": struct.unpack("<I", g("vmpl", 4))[0],
        "mask_chip_id": bool((flags >> 1) & 1),
        "signing_key": SIGNING_KEY.get((flags >> 2) & 0x7, "reserved"),
        "report_data": g("report_data", 64),
        "measurement": g("measurement", 48),
        "host_data": g("host_data", 32),
        "chip_id": g("chip_id", 64),
        "reported_tcb": g("reported_tcb", 8),
        "signature": g("signature", 512),
        "signed_bytes": report[:_OFF["signature"]],
    }


def hwid_hex(chip_id: bytes) -> str:
    """The chip identifier as AMD KDS wants it.

    CHIP_ID is a fixed 64-byte field. Turin populates only the first 8 bytes and zero-pads the rest,
    and KDS 404s if you send the padding. Measured: 16 hex chars -> 200, 128 -> 404. Trailing zeros
    are stripped rather than a fixed length assumed, so this stays correct on parts that use the
    full width.
    """
    trimmed = chip_id.rstrip(b"\x00")
    return (trimmed or chip_id[:8]).hex()


def vcek_url(report: bytes, *, product: str = "Turin", zen5: bool = True) -> str:
    """The AMD KDS URL for this report's VCEK. Verified to return 200 for a real Turin report."""
    p = parse(report)
    q = "&".join(f"{k}={v}" for k, v in tcb_params(p["reported_tcb"], zen5=zen5).items())
    return f"https://kdsintf.amd.com/vcek/v1/{product}/{hwid_hex(p['chip_id'])}?{q}"


def tcb_params(reported_tcb: bytes, *, zen5: bool = True) -> Dict[str, int]:
    """TCB fields for the AMD KDS VCEK URL.

    Zen 5 (Turin) reordered this structure. Reading it with the Zen 3/4 layout yields snp=0 — which
    looks like a legitimate value and silently produces the wrong VCEK URL, so the generation is an
    explicit argument rather than a guess.
    """
    b = list(reported_tcb)
    if zen5:
        return {"fmcSPL": b[0], "blSPL": b[1], "teeSPL": b[2], "snpSPL": b[3], "ucodeSPL": b[7]}
    return {"blSPL": b[0], "teeSPL": b[1], "snpSPL": b[6], "ucodeSPL": b[7]}


def verify_chain(report: bytes, vcek_der: Optional[bytes], ask_ark_pem: Optional[bytes]) -> Dict[str, Any]:
    """Verify the report against AMD's roots. REFUSES when the chain cannot be completed.

    This deliberately has no "best effort" mode. An unverifiable attestation is worth exactly nothing
    — reporting it as a soft pass is how "we proved it" gets said about a report nobody checked, and
    that failure mode has already cost this project one quarantined artifact.
    """
    p = parse(report)
    problems = []
    # A report that is not even structurally a hardware report is refused before anything else —
    # enclave_job's --fake-attestation produces exactly this shape, and the client must never
    # mistake a phase-test fixture for silicon.
    if p["version"] < 2:
        problems.append(f"report version {p['version']} is not a hardware report")
    if p["signature"] == b"\x00" * 512:
        problems.append("report signature is all zeros — unsigned, not from hardware")
    if p["debug_allowed"]:
        problems.append("guest policy allows DEBUG — the host can inspect this VM; attestation is void")
    if p["signing_key"] not in ("VCEK", "VLEK"):
        problems.append(f"report is not signed by an endorsement key (signing_key={p['signing_key']})")
    if vcek_der is None:
        problems.append("no VCEK supplied — fetch it from AMD KDS (see vcek_url()). Without it the "
                        "report is BOUND but NOT VERIFIABLE.")
    if ask_ark_pem is None:
        problems.append("no ASK/ARK chain to anchor the VCEK to AMD's root")
    if problems:
        return {"verified": False, "problems": problems, "parsed": p}

    # The chain itself — VCEK <- ASK <- ARK with AMD's published root PINNED per product line, the chip
    # id, the firmware TCB and the report signature — is verified by amd_chain, which is the single
    # implementation of that predicate. This module deliberately carries no second copy: until
    # 2026-09-16 it had one that checked `ask_ark_pem is not None` and then never used it, verified the
    # report under whatever VCEK it was handed, and returned verified=True. A self-generated key passed,
    # while the client narrated "Fetching AMD's certificate for this exact chip". Found by the attested
    # session; the test that should have caught it passed the literal bytes b"present" as the chain.
    try:
        from . import amd_chain
    except Exception as exc:                                    # noqa: BLE001
        return {"verified": False, "parsed": p, "problems": [
            f"this build carries no AMD chain verifier ({type(exc).__name__}): the report is BOUND to its "
            "runtime data but NOT VERIFIED against AMD's root"]}
    steps = amd_chain.verify_report(report, vcek_der, ask_ark_pem)
    if not steps.ok:
        return {"verified": False, "problems": list(steps.problems), "parsed": p}
    return {"verified": True, "problems": [], "parsed": p, "steps": list(steps)}


def check_binding(report: bytes, expected: bytes) -> bool:
    """Does this report actually commit to the binding we expect? Constant-time."""
    import hmac
    return hmac.compare_digest(parse(report)["report_data"], expected)
