"""Evidence from an Azure confidential container, verified on the user's machine with no call to a cloud
attestation service: the hardware report, AMD's endorsement of the chip, Microsoft's endorsement of
the utility VM, the container policy, and the data the enclave bound into the report.

    combined = {"evidence": b64 report, "endorsements": b64 PEM (VCEK, ASK, ARK),
                "uvm_endorsements": b64 COSE_Sign1, ...}      as the attestation sidecar returns it

What each part establishes:
  AMD chain       the report was signed by a genuine AMD chip at the firmware level it states
  UVM endorsement the report's MEASUREMENT is a utility VM image Microsoft signed for this feed
  HOST_DATA       the container policy in force is the one this client expects (a hash it pins)
  REPORT_DATA     the report commits to exactly `runtime_data`: the enclave's keys and manifests

Refuses rather than degrades. A client that does not pin a container policy is refused, because
without it the evidence proves genuine hardware running some container, not ours.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any, Dict, Optional, Sequence, Tuple

from . import amd_chain, cose, snp


def policy_host_data(policy_b64: str) -> str:
    """HOST_DATA for a container policy as it is written into a deployment (base64 of the policy text)."""
    return hashlib.sha256(base64.b64decode(policy_b64)).hexdigest()


def report_data_for(runtime_data: bytes) -> bytes:
    return hashlib.sha256(runtime_data).digest() + b"\x00" * 32


def verify_combined(combined: Dict[str, Any], runtime_data: bytes, *,
                    expect_host_data: "Optional[str] | Sequence[str]",
                    amd_pins: Optional[Dict[str, str]] = None, uvm_root: str = cose.UVM_ROOT_SHA256_B64URL,
                    uvm_min_svn: int = cose.UVM_MIN_SVN, now=None) -> Tuple[amd_chain.Steps, Dict[str, Any]]:
    steps, info = amd_chain.Steps(), {}
    try:
        report = base64.b64decode(combined["evidence"], validate=True)
        certs = amd_chain.load_certs(base64.b64decode(combined["endorsements"], validate=True))
        uvm_blob = base64.b64decode(combined["uvm_endorsements"], validate=True)
        if len(certs) < 3:
            raise ValueError("endorsements must carry VCEK, ASK and ARK")
    except (KeyError, ValueError, TypeError) as exc:
        steps.add(False, "evidence structure", f"{type(exc).__name__}: {str(exc)[:80]}")
        return steps, info
    steps.extend(amd_chain.verify_report(report, amd_chain.chain_pem(certs[:1]), amd_chain.chain_pem(certs[1:]),
                                         now=now, pins=amd_pins))
    uvm_steps, uvm = cose.verify_uvm_endorsement(uvm_blob, root_sha256_b64url=uvm_root, min_svn=uvm_min_svn)
    steps.extend(uvm_steps)
    try:
        p = snp.parse(report)
    except ValueError:
        return steps, info
    measured = p["measurement"].hex()
    steps.add(bool(uvm) and hmac.compare_digest(measured, uvm.get("measurement", "")), "UVM measurement matches report",
              f"report MEASUREMENT {measured[:16]}…" + (" is the endorsed utility VM" if uvm and measured == uvm.get("measurement")
                                                       else " is NOT the endorsed launch measurement"))
    host = p["host_data"].hex()
    # One pinned policy, or several: after a supersession the signed reference carries more than one, and the
    # enclave is accepted when it attests ANY policy that reference makes current. Never "none accepted".
    wanted = [expect_host_data] if isinstance(expect_host_data, str) else list(expect_host_data or [])
    wanted = [w.lower() for w in wanted if w]
    if not wanted:
        steps.add(False, "container policy", "this client pins no expected container policy; refusing")
    else:
        ok = any(hmac.compare_digest(host, w) for w in wanted)
        named = wanted[0][:16] + "…" if len(wanted) == 1 else ", ".join(w[:16] + "…" for w in wanted)
        steps.add(ok, "container policy", f"HOST_DATA {host[:16]}…" +
                  (f" is the pinned policy" if ok and len(wanted) == 1 else
                   " is one of the policies this reference makes current" if ok else
                   f" is NOT {'the pinned policy' if len(wanted) == 1 else 'any policy this reference makes current'} ({named})"))
    bound = hmac.compare_digest(p["report_data"], report_data_for(runtime_data))
    steps.add(bound, "report data binds runtime data", "REPORT_DATA = SHA-256(runtime data) ‖ zeros"
              if bound else "REPORT_DATA does NOT commit to the runtime data offered")
    info.update({"measurement": measured, "host_data": host, "report_version": p["version"],
                 "uvm_svn": uvm.get("svn"), "runtime_data_sha256": hashlib.sha256(runtime_data).hexdigest()})
    return steps, info
