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
  rtmr2  the owner-key variables, then the kernel command line and the initramfs.
Registers NOT listed are still recorded-and-watched rather than reproduced. For this image that
is rtmr3, which hashes a list of root-filesystem files — and that filesystem is encrypted in the
published image, so it cannot be recomputed from the download.
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
        "reproduced": ["mrtd", "rtmr1", "rtmr2"],
        "reproduced_on": "2026-09-12",
        # SHA-256 of the exact inputs that produced the reproduced registers, so the claim can be
        # re-checked without re-deriving it, and so a silently changed artifact is detectable.
        #
        # Controls, measured the same day, INCLUDING WHERE THEY STOP. MRTD covers the firmware's
        # BOOT volume, not the whole 4 MB file: a flipped bit at 0x200000 or 0x300000 moves it
        # (9f10f227…, 93f0195c…), while a flipped bit at 0x1000 or 0x40000 — the configuration
        # volume that holds the variable store — leaves it at 261ce538…, unchanged. Only RTMR0
        # moves there. So "any change to the firmware changes MRTD" would be false; the true
        # statement is that any change to the MEASURED volume does. A stock Ubuntu OVMF gives
        # e2fca2d0…, so the measurement does discriminate between firmwares.
        #
        # The recorded values came from live production quotes at 09:24, before the published image
        # was ever fetched (10:05), so the match is not circular. And the firmware itself is not
        # taken on trust: rebuilding upstream edk2 at tag edk2-stable202605 (which resolves to
        # b03a21a63e3bd001f52c527e5a57feddb53a690b, the tag the operator's own build script pins)
        # with the platform that script names reproduces the committed blob BYTE-IDENTICALLY, so
        # MRTD traces to public source rather than to a binary we were handed.
        "reproduced_from": {
            "firmware": "01731a86fa3665caccaa4a1906cdd9276b0a53fc5921dbcc70970219ac942169",
            "shim": "6fe6e1bcbe6cf6baec8e056d40361ca1aa715cc04ddcc2855351de060b84350b",
            "grub": "a831af01e4fb5e3c9457120e1d08ea13d98a0a47b62728c284b7f502d535965c",
        },
        "note": "the single VM image serving every enclave-backed catalog model on 2026-09-12 (8 RTMR0 host variants)",
    },
]

# ── the signing key that makes a run-time build OUR record rather than our server's ──
#
# The relay serves build additions so a genuine new operator build can be recognised within
# minutes of appearing, without waiting for a client release. That convenience is also the one
# seam an attacker holding our relay could use: point the client at an enclave they control and
# supply the row that legitimises it, and every other check passes truthfully.
#
# A signature closes it. The private half NEVER goes near the relay — it lives offline, and a new
# build is signed deliberately. The relay can then only carry what was already signed: it cannot
# mint one. An unsigned addition is still accepted (an operator rolling a build at 3am should not
# take the lane down) but it is marked `pending`, which the panel, the receipt and the model
# preamble all report as "not InferRoute's record".
#
# Rotation: add the new key here alongside the old one, ship a release, then stop signing with
# the old. Verification accepts any key in this tuple, so the two overlap without a flag day.
SIGNING_KEYS: tuple[str, ...] = ()   # Ed25519 public keys, hex, 32 bytes each

_EXTRA: list[dict] = []          # builds fetched from the relay this process


def key_of(mrtd: str, rtmrs: list[str]) -> tuple:
    r = list(rtmrs) + ["", "", "", ""]
    return (mrtd.lower(), r[1].lower(), r[2].lower(), r[3].lower())


def known() -> dict[tuple, dict]:
    out: dict[tuple, dict] = {}
    for b in [{**x, "origin": "bundled"} for x in BUNDLED] + _EXTRA:
        k = key_of(b.get("mrtd", ""), ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")])
        # First writer wins, and BUNDLED is iterated first, so a run-time row can never displace
        # our own record of the same measurements. (The previous condition referenced a `_bundled`
        # key that nothing ever set, so it could not fire; the ordering was doing the work.)
        if k not in out:
            out[k] = b
    return out


def signed_bytes(row: dict) -> bytes:
    """The exact bytes a signature covers: the measurements and the identity, nothing else.

    Deliberately narrow. Signing the whole row would mean a re-sign whenever a note or a
    timestamp changed, and would let anything we later add to the shape ride along unexamined.
    What must not be forgeable is WHICH ENCLAVE this row blesses — that is the four measurements
    — plus the id, so one signature cannot be replayed onto a different entry."""
    fields = ("id", "mrtd", "rtmr1", "rtmr2", "rtmr3")
    return json.dumps({k: str(row.get(k, "")).lower() for k in fields},
                      sort_keys=True, separators=(",", ":")).encode()


def verify_signature(row: dict) -> bool:
    """True when the row carries a signature by a key this client ships."""
    sig = row.get("sig")
    if not sig or not SIGNING_KEYS:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw, msg = bytes.fromhex(str(sig)), signed_bytes(row)
    except (ImportError, ValueError):
        return False
    for pub in SIGNING_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(raw, msg)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def absorb_remote(rows, origin: str = "relay") -> int:
    """Merge builds served by the relay: additions only, never a status promotion to `reviewed`.

    A build that arrives this way is marked `pending` and carries its origin, because it is NOT
    what the label "recorded by InferRoute" is supposed to mean. Only the bundled list is our own
    record, shipped in a released client and reviewable in the repository. Anything served at run
    time is, at best, InferRoute vouching for InferRoute — and if our relay were compromised this
    is the seam an attacker would use, since every other check would then pass truthfully against
    an enclave they control. The session still opens, because refusing would break the ability to
    record a genuine new operator build within minutes, but the panel, the receipt and the model
    preamble all say plainly that this build is pending rather than recorded.""" 
    n = 0
    have = {key_of(b.get("mrtd", ""), ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")]) for b in BUNDLED + _EXTRA}
    for b in rows or []:
        if not isinstance(b, dict) or not b.get("mrtd"):
            continue
        k = key_of(b["mrtd"], ["", b.get("rtmr1", ""), b.get("rtmr2", ""), b.get("rtmr3", "")])
        if k in have:
            continue
        signed = verify_signature(b)
        _EXTRA.append({**b, "status": "signed" if signed else "pending",
                       "origin": ("signed" if signed else origin)})
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
