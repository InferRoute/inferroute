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
  refused   — InferRoute has recorded this build and REFUSES it, for the reason in `refused_because`.
              A refused build is never opened: not by IR_CONFIDENTIAL_ALLOW_NEW_BUILD, not by a row
              the relay serves, not by a local override (all three are additions, and the bundled
              row for the same measurements always wins).

`reproduced` lists the registers InferRoute has recomputed ITSELF, from artifacts published by
the operator but fetched and measured on our own machine — not taken from the attestation path
being checked. `scripts/reproduce_enclave_build.py` is that computation; anyone can re-run it.
A register in this list no longer rests on the operator's word:
  mrtd   derived from the guest firmware blob alone (independent of host RAM/vCPU/ACPI, which
         is why one MRTD covers a whole fleet of differently-shaped hosts).
  rtmr1  the bootloader chain: partition table, then shim and GRUB, Authenticode-hashed.
  rtmr2  the owner-key variables, then the kernel command line and the initramfs.
  rtmr3  the root-filesystem file list. Only for direct-boot images (1.4.x): there it is one extend
         over the sorted file-hash list the build bakes into the initramfs, and the initramfs is
         itself in rtmr2 — so the list is pinned by a register we derive, and rtmr3 follows from it.
         On the 1.3.x images the root filesystem is encrypted in the download and rtmr3 cannot be
         recomputed. In neither case have we rebuilt that filesystem from source: rtmr3 in this list
         means "the measured file list is the published one", not "the files are what the recipe makes".
Registers NOT listed are still recorded-and-watched rather than reproduced.
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
        # REFUSED 2026-10-06. This is the operator's guest image 1.3.1, and it carries the overlayroot
        # defect we reported to the operator on 2026-09-13: an unmeasured /etc/overlayroot.local.conf
        # enables a host-attached config disk (LABEL=OROOTCFG), and overlayroot runs immediately
        # before the RTMR3 measurement, so whoever attaches disks to the VM can shadow /usr, /opt and
        # /etc/systemd with RTMR3 unchanged. The operator fixed it in 1.4.0 (hooks and the local conf
        # removed, both conf paths measured), but its registry still lists 1.3.x as accepted and 3 of
        # 16 kimi-k2.6 instances were still running it on 2026-10-06. A measurement that a known
        # defect leaves unchanged cannot vouch for that image, so we stop opening it rather than
        # caveat it. The row stays, with its reproduction, so the record of what we checked survives
        # and so no run-time row can re-admit the same measurements.
        "status": "refused",
        "refused_on": "2026-10-06",
        "refused_because": "guest image 1.3.1 lets the host shadow the root filesystem without changing RTMR3 (overlayroot config disk, fixed by the operator in 1.4.0)",
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
    {
        # Operator guest image 1.4.1, published 2026-09-20 — the build 7 of the 14 kimi-k2.6
        # instances were running on 2026-09-30 and this device was refusing as "not recorded".
        #
        # `observed`, NOT `reviewed`, and the difference is stated rather than smoothed over:
        #   reproduced  RTMR1 and RTMR2, by us, on 2026-09-30, from the operator's published
        #               kernel / initramfs / command line (`scripts/reproduce_enclave_build.py
        #               --direct`). Both matched the LIVE quotes exactly, so the model was
        #               validated against hardware, not only against the tool that computes it.
        #   reproduced  RTMR3, by us, on 2026-10-06. From 1.4.0 the boot measurement is one extend over
        #               the sorted "<sha384> <path>" list of 49,177 measured files, and the build bakes
        #               that list into the initramfs (/etc/tdx-rtmr3-expected-hashes). The initramfs is
        #               in RTMR2, which we reproduce, so the list is pinned by a register we derive; the
        #               computed RTMR3 matched 12 live kimi-k2.6 quotes the same day. Coverage is now the
        #               OS itself (/usr/lib, /usr/bin, the service venv, kernel modules, systemd units),
        #               not only configuration. We did NOT rebuild the root filesystem from the operator's
        #               pinned recipe, so the 49k file hashes are the operator's output, checked for
        #               consistency, not reproduced from source.
        #   NOT         MRTD (not recomputed today: the firmware blob is byte-identical to the one
        #               MRTD was reproduced from on 2026-09-12 and the register is unchanged, but
        #               that is an identity, not a recomputation).
        #   NOT         audited: the 1.3.1 -> 1.4.1 diff was not read, only its changelog.
        # The measurements are also on the operator's own published list, which is what
        # `measurement_ok` checks; that is the operator agreeing with itself and counts for nothing here.
        "id": "tee-vm-2026-09-20",
        "status": "observed",
        "first_seen": "2026-09-30",
        "mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
        "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed",
        "rtmr2": "da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153",
        "rtmr3": "d9dc4c6079fb12a21ad2aa8e329d8bfa61aaa13d3ffd10a93a2c4e82f0e35efbf28f5cf3bed0c0c1b517a7c327a25226",
        "reproduced": ["rtmr1", "rtmr2", "rtmr3"],
        "reproduced_on": "2026-10-06",
        # Direct boot: the host hands the firmware kernel + initramfs + command line, so shim and GRUB
        # are not in this chain (see the reproduction script). SHA-256 of the three files, which also
        # equal the sha256 the operator's manifest.json lists for them.
        "reproduced_from": {
            "vmlinuz": "d5d71ed32239eaa9bcb0528227a7adb62688250ce9f163b3e04e9675ddf86cff",
            "initrd": "69ff9c75a88cbea772664ad5ec6c8174c657074845170f82ea0dc67493a2b0a0",
            "cmdline": "27cf61470fee944b05843b78e18fdb596ed8c4db299c0d5153410604b4dd550a",
            # the RTMR3 file list, as extracted from that initramfs
            "rtmr3_manifest": "c9ac615e2233ebca19bdfafdeb1275c99c174bc88c048c72b92dfe46d8197cd3",
        },
        "note": "operator guest image 1.4.1 (direct boot); RTMR1+RTMR2+RTMR3 recomputed from the published kernel/initramfs/cmdline (RTMR3 from the file list baked into the initramfs; root filesystem not rebuilt from source); MRTD not recomputed; 1.4.0 is NOT recorded (its artifacts are no longer published)",
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
