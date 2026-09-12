"""Recorded enclave builds — the allowlist behind the "Known, recorded build" check.

"Known build" (measurement_ok) proves the enclave runs an image whose measurements the OPERATOR
publishes. That is the one place the proof leans on the operator: an operator who published and
ran a backdoored image would pass every other check (Intel would truthfully sign its quote, NVIDIA
would verify its GPUs). This module closes the loop on our side: InferRoute keeps its own record of
the builds it has seen and reviewed, and a session refuses a build that is not on it.

A build is identified by MRTD + RTMR1..3 (the VM image: firmware image, kernel, initrd/cmdline,
root filesystem/app). RTMR0 is deliberately NOT part of the identity — it measures the host's boot
firmware configuration and legitimately varies across hosts of one fleet (8 variants observed on
2026-09-12 for one build); Intel's TCB status covers the firmware side.

Statuses:
  reviewed  — InferRoute reproduced or audited the image behind these measurements.
  observed  — InferRoute has recorded this build in production and watches it; reproduction pending.

`reproduced` lists the registers InferRoute has recomputed ITSELF, from artifacts published by
the operator but fetched and measured on our own machine — not taken from the attestation path
being checked. `scripts/reproduce_enclave_build.py` is that computation; anyone can re-run it.
A register in this list no longer rests on the operator's word:
  mrtd   derived from the guest firmware blob alone (independent of host RAM/vCPU/ACPI, which
         is why one MRTD covers a whole fleet of differently-shaped hosts).
  rtmr1  the bootloader chain: partition table, then shim and GRUB, Authenticode-hashed.
Registers NOT listed are still recorded-and-watched rather than reproduced. For this image that
is rtmr2 (kernel cmdline + initramfs: the bootloader contributes log entries we do not yet model)
and rtmr3 (hashes root-filesystem files; that filesystem is encrypted in the published image).
  (absent)  — a build InferRoute has never seen: the session REFUSES unless
              IR_CONFIDENTIAL_ALLOW_NEW_BUILD=1, in which case it opens with a warning on the panel.

The bundled list is merged with the one the relay serves (GET /confidential/builds), so a new
operator build can be recorded within minutes, without a client release. Only additions are taken
from the relay; a build can never be promoted to `reviewed` by the relay alone.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

BUNDLED: list[dict] = [
    {
        "id": "tee-vm-2026-09-12",
        "status": "observed",
        "first_seen": "2026-09-12",
        "mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
        "rtmr1": "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
        "rtmr2": "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
        "rtmr3": "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433",
        "reproduced": ["mrtd", "rtmr1"],
        "reproduced_on": "2026-09-12",
        "note": "the single VM image serving every enclave-backed catalog model on 2026-09-12 (8 RTMR0 host variants)",
    },
]

_EXTRA: list[dict] = []          # builds fetched from the relay this process


def key_of(mrtd: str, rtmrs: list[str]) -> tuple:
    r = list(rtmrs) + ["", "", "", ""]
    return (mrtd.lower(), r[1].lower(), r[2].lower(), r[3].lower())


def known() -> dict[tuple, dict]:
    out: dict[tuple, dict] = {}
    for b in BUNDLED + _EXTRA:
        k = key_of(b.get("mrtd", ""), ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")])
        prev = out.get(k)
        if prev is None or (prev.get("status") != "reviewed" and b.get("status") == "reviewed" and b.get("_bundled")):
            out[k] = b
    return out


def absorb_remote(rows) -> int:
    """Merge builds served by the relay: additions only, never a status promotion to `reviewed`."""
    n = 0
    have = {key_of(b.get("mrtd", ""), ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")]) for b in BUNDLED + _EXTRA}
    for b in rows or []:
        if not isinstance(b, dict) or not b.get("mrtd"):
            continue
        k = key_of(b["mrtd"], ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")])
        if k in have:
            continue
        _EXTRA.append({**b, "status": "observed" if b.get("status") not in ("observed",) else b["status"]})
        have.add(k)
        n += 1
    return n


def lookup(mrtd: str, rtmrs: list[str]) -> dict | None:
    return known().get(key_of(mrtd, rtmrs))


def allow_new_builds() -> bool:
    return os.environ.get("IR_CONFIDENTIAL_ALLOW_NEW_BUILD", "").strip().lower() in ("1", "true", "yes")


def user_overrides_path() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential" / "builds.json"


def load_user_overrides() -> int:
    """An operator/developer can record builds locally (same shape as BUNDLED entries)."""
    p = user_overrides_path()
    try:
        return absorb_remote(json.loads(p.read_text()))
    except (OSError, ValueError):
        return 0
