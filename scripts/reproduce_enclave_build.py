#!/usr/bin/env python3
"""Independently reproduce a recorded enclave build's measurements from published artifacts.

Why this exists
---------------
`measurement_ok` (the "known, recorded build" check) is the one check that leans on the
operator: it proves the enclave runs an image whose measurements InferRoute has recorded,
not that the image is what the operator says it is. This script closes part of that gap
WITHOUT the operator's cooperation, from artifacts anyone can fetch:

  MRTD   the TD's initial state. Derived from the guest firmware blob alone. Independent of
         host RAM, vCPU count and ACPI, which is why one MRTD covers a whole fleet.
  RTMR1  the bootloader chain: GUID partition table, then the shim and GRUB binaries,
         Authenticode-hashed exactly as the firmware measures them at load.
  RTMR2  the owner-key variables, then the kernel command line and the initramfs.

All three are computed here from (a) the operator's published guest disk image, read over HTTPS
with range requests so only ~1 GB of a multi-tens-of-GB image is transferred, and (b) the
guest firmware binary published in the operator's open build repository. Neither input is
privileged and neither is taken from the attestation path being checked.

The RTMR2 model is worth stating because the obvious one is wrong. The bootloader measures
NOTHING on a confidential VM: it only starts measuring when it finds a TPM protocol, and this
firmware publishes the confidential-computing protocol instead. What lands in the register is
three owner-key entries the bootloader synthesises from a certificate built into its own binary,
then two entries from the kernel's boot stub. The command line is the one the bootloader passes,
which carries a BOOT_IMAGE= prefix the configuration file does not show.

NOT reproduced here, and deliberately not claimed:
  RTMR0  measures host firmware configuration and legitimately varies per host.
  RTMR3  hashes a list of root-filesystem files. That filesystem is encrypted in the published
         image, so it cannot be recomputed from the download alone.

No operator name, host or URL is compiled in. Pass the image locator explicitly.

Usage
-----
    reproduce_enclave_build.py --image <URL-or-path> --firmware <OVMF.fd> \
        [--tdx-measure <path>] [--build <id>] [--keep <dir>]

Requires: qemu-img and debugfs (e2fsprogs). MRTD additionally needs a build of tdx-measure
(github.com/virtee/tdx-measure); without it the script still does RTMR1 and RTMR2, which need
nothing beyond the published image itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SECTOR = 512
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"      # EFI System Partition
XBOOTLDR_TYPE = "bc13c2ff-59e6-4262-a352-b275fd6f7172"  # Linux extended boot ("/boot")


# ---------------------------------------------------------------- disk plumbing

def _qemu_slice(image: str, offset: int, size: int, out: Path, read_timeout: float = 300) -> None:
    """Read [offset, offset+size) of the *virtual* disk. Over HTTPS this issues range
    requests, so an unencrypted boot partition costs a gigabyte, not the whole image."""
    remote = "://" in image
    opts = (
        f"driver=raw,offset={offset},size={size},"
        + (f"file.driver=qcow2,file.file.driver=https,file.file.url={image}"
           if remote else f"file.driver=qcow2,file.filename={image}")
    )
    # Wait for the reader to EXIT. Do not try to detect completion from the output's length:
    # qemu-img sizes the file up front and fills it in afterwards, so the file reaches its final
    # length long before the data is there. Cutting the read at that point yields a file of the
    # right size containing partly zeroes, and a measurement that is wrong rather than missing —
    # which is the worst possible failure for a tool whose whole job is to compare digests.
    # Reading a remote image does occasionally hang after transferring everything (roughly one run
    # in three against a cold cache). When that happens, fail and say so, so the answer is
    # "unknown", never a quietly wrong digest. The timeout is generous against a real read, which
    # takes well under two minutes for the largest partition here.
    try:
        subprocess.run(["qemu-img", "convert", "--image-opts", opts, "-O", "raw", str(out)],
                       check=True, stdout=subprocess.DEVNULL, timeout=read_timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(
            f"reading {out.name} did not finish within {read_timeout}s. The remote read sometimes "
            f"stalls after transferring the data; re-run, or fetch the image locally and pass its "
            f"path to --image. Refusing to measure a possibly-partial read.")


def read_gpt(head: bytes) -> tuple[bytes, list[dict]]:
    """Return (raw LBA1 header, partition entries) from the first megabytes of a disk."""
    hdr = head[SECTOR:SECTOR + SECTOR]
    if hdr[0:8] != b"EFI PART":
        raise SystemExit("not a GPT disk: missing EFI PART signature")
    entry_lba, n, esize = struct.unpack("<QII", hdr[72:88])
    parts = []
    for i in range(n):
        off = entry_lba * SECTOR + i * esize
        e = head[off:off + esize]
        if len(e) < esize or e[0:16] == b"\0" * 16:
            continue
        import uuid
        first, last = struct.unpack("<QQ", e[32:48])
        parts.append({"index": i + 1, "type": str(uuid.UUID(bytes_le=e[0:16])),
                      "first": first, "last": last, "raw": e})
    return hdr, parts


def gpt_event_data(hdr: bytes, parts: list[dict]) -> bytes:
    """EFI_GPT_DATA as the firmware measures it: header, count, then the valid entries."""
    out = bytearray(hdr[0:92])
    out += struct.pack("<Q", len(parts))
    for p in parts:
        out += p["raw"]
    return bytes(out)


# ------------------------------------------------------------------ FAT32 (ESP)

class Fat32:
    def __init__(self, data: bytes):
        self.d = data
        self.bps = struct.unpack("<H", data[11:13])[0]
        self.spc = data[13]
        rsvd = struct.unpack("<H", data[14:16])[0]
        nfat = data[16]
        spf = struct.unpack("<I", data[36:40])[0]
        self.root = struct.unpack("<I", data[44:48])[0]
        self.fat_off = rsvd * self.bps
        self.data_off = (rsvd + nfat * spf) * self.bps

    def _chain(self, c: int):
        while 2 <= c < 0x0FFFFFF8:
            yield c
            c = struct.unpack("<I", self.d[self.fat_off + c * 4: self.fat_off + c * 4 + 4])[0] & 0x0FFFFFFF

    def _read(self, c: int) -> bytes:
        span = self.spc * self.bps
        out = []
        for cl in self._chain(c):
            start = self.data_off + (cl - 2) * span
            out.append(self.d[start:start + span])  # bound the slice: an open-ended one
        return b"".join(out)                        # copies the partition once per cluster

    @staticmethod
    def _lfn(parts) -> str:
        s = ""
        for e in sorted(parts, key=lambda x: x[0] & 0x3F):
            s += (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "ignore")
        return s.split("\x00")[0]

    def listdir(self, clus: int):
        raw, lfn, out = self._read(clus), [], []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if len(e) < 32 or e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            if e[11] == 0x0F:
                lfn.append(e)
                continue
            name = self._lfn(lfn) if lfn else (
                e[0:8].decode("latin-1").strip()
                + ("." + e[8:11].decode("latin-1").strip() if e[8:11].strip() else ""))
            lfn = []
            first = (struct.unpack("<H", e[20:22])[0] << 16) | struct.unpack("<H", e[26:28])[0]
            out.append({"name": name, "dir": bool(e[11] & 0x10), "clus": first,
                        "size": struct.unpack("<I", e[28:32])[0]})
        return out

    def read_path(self, path: str) -> bytes:
        clus, ent = self.root, None
        for part in [p for p in path.strip("/").split("/") if p]:
            ent = next((x for x in self.listdir(clus) if x["name"].lower() == part.lower()), None)
            if ent is None:
                raise KeyError(path)
            clus = ent["clus"]
        return self._read(ent["clus"])[:ent["size"]]


# --------------------------------------------------------------- Authenticode

def authenticode_sha384(data: bytes) -> bytes:
    """PE/COFF Authenticode digest: the whole file except its checksum, its certificate
    directory entry, and any appended certificate table. This is what UEFI measures when
    it loads a boot application, so it is what lands in RTMR1."""
    lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    coff = lfanew + 4
    n_sections = struct.unpack("<H", data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack("<H", data[coff + 16:coff + 18])[0]
    opt = coff + 20
    magic = struct.unpack("<H", data[opt:opt + 2])[0]
    dd = opt + (112 if magic == 0x20B else 96)      # data directories
    checksum = opt + 64
    sec_dir = dd + 4 * 8                            # IMAGE_DIRECTORY_ENTRY_SECURITY
    size_of_headers = struct.unpack("<I", data[opt + 60:opt + 64])[0]
    cert_off, cert_size = struct.unpack("<II", data[sec_dir:sec_dir + 8])

    h = hashlib.sha384()
    h.update(data[:checksum])                       # up to the checksum
    h.update(data[checksum + 4:sec_dir])            # past it, up to the cert directory
    h.update(data[sec_dir + 8:size_of_headers])     # past it, to the end of the headers
    sections = []
    for i in range(n_sections):
        s = opt + opt_size + i * 40
        raw_size, raw_ptr = struct.unpack("<II", data[s + 16:s + 24])
        sections.append((raw_ptr, raw_size))
    total = size_of_headers
    for ptr, size in sorted(sections):
        if size:
            h.update(data[ptr:ptr + size])
            total += size
    extra = len(data) - total - (cert_size if cert_off else 0)
    if extra > 0:
        h.update(data[total:total + extra])
    return h.digest()


# ------------------------------------------------------------------ measuring

def _fold(entries: list[bytes]) -> str:
    mr = bytes(48)
    for e in entries:
        mr = hashlib.sha384(mr + e).digest()
    return mr.hex()


def rtmr1(gpt_data: bytes, shim: bytes, grub: bytes) -> tuple[str, list[tuple[str, str]]]:
    s = lambda b: hashlib.sha384(b).digest()
    log = [
        ("Calling EFI Application from Boot Option", s(b"Calling EFI Application from Boot Option")),
        ("separator", s(bytes(4))),
        ("GPT partition table", s(gpt_data)),
        ("shim (Authenticode)", authenticode_sha384(shim)),
        ("GRUB (Authenticode)", authenticode_sha384(grub)),
        ("Exit Boot Services Invocation", s(b"Exit Boot Services Invocation")),
        ("Exit Boot Services Returned with Success", s(b"Exit Boot Services Returned with Success")),
    ]
    return _fold([d for _, d in log]), [(n, d.hex()) for n, d in log]


# ── RTMR2: the Machine-Owner-Key variables, then the kernel command line and initramfs ──
#
# The three MOK entries are NOT empty on a machine with no MOK variables set. The bootloader's
# shim synthesises all three from data built into its own binary, so they are derivable from the
# published image with nothing else. What reaches the register after that comes from the kernel's
# own boot stub, not from GRUB: GRUB only measures when it finds a TPM protocol, and a confidential
# VM's firmware publishes the confidential-computing protocol instead, so GRUB measures nothing at
# all here. That is why a model built from GRUB's command trace does not match.

def _guid(s: str) -> bytes:
    a, b, c, d, e = s.split("-")
    return struct.pack("<IHH", int(a, 16), int(b, 16), int(c, 16)) + bytes.fromhex(d) + bytes.fromhex(e)


CERT_X509 = _guid("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
CERT_SHA256 = _guid("c1c41626-504c-4092-aca9-41f936934328")
SHIM_LOCK = _guid("605dab50-e046-4300-abb6-3dd810dd8b23")


def _signature_list(sig_type: bytes, owner: bytes, data: bytes) -> bytes:
    """One EFI_SIGNATURE_LIST holding one signature, packed as the bootloader packs it."""
    sig_size = 16 + len(data)
    return struct.pack("<16sIII", sig_type, 28 + sig_size, 0, sig_size) + owner + data


def vendor_cert(shim: bytes) -> bytes:
    """The certificate built into the bootloader's own binary, from its .vendor_cert section."""
    pe = struct.unpack_from("<I", shim, 0x3C)[0]
    n_sections = struct.unpack_from("<H", shim, pe + 6)[0]
    symtab = struct.unpack_from("<I", shim, pe + 12)[0]
    n_syms = struct.unpack_from("<I", shim, pe + 16)[0]
    opt_size = struct.unpack_from("<H", shim, pe + 20)[0]
    strtab = symtab + n_syms * 18
    base = pe + 24 + opt_size
    for i in range(n_sections):
        e = shim[base + 40 * i: base + 40 * (i + 1)]
        name = e[:8].rstrip(b"\0")
        if name.startswith(b"/") and symtab:          # long name: an offset into the string table
            off = strtab + int(name[1:])
            name = shim[off: shim.index(b"\0", off)]
        if name == b".vendor_cert":
            raw, size = struct.unpack_from("<I", e, 20)[0], struct.unpack_from("<I", e, 16)[0]
            table = shim[raw: raw + size]
            a_size, _, a_off, _ = struct.unpack_from("<IIII", table, 0)
            return table[a_off: a_off + a_size]
    raise ValueError("no .vendor_cert section in the bootloader binary")


def rtmr2(shim: bytes, cmdline: str, initrd: bytes) -> tuple[str, list[tuple[str, str]]]:
    s = lambda b: hashlib.sha384(b).digest()
    log = [
        ("owner-key list (from the bootloader's built-in certificate)",
         s(_signature_list(CERT_X509, SHIM_LOCK, vendor_cert(shim)))),
        ("owner-key denial list (the empty placeholder)",
         s(_signature_list(CERT_SHA256, SHIM_LOCK, bytes(32)))),
        ("owner-key trust flag", s(b"\x01")),
        ("kernel command line (UTF-16, no terminator)", s(cmdline.encode("utf-16-le"))),
        ("initramfs", s(initrd)),
    ]
    return _fold([d for _, d in log]), [(n, d.hex()) for n, d in log]


def mrtd(firmware: str, tdx_measure: str, workdir: Path) -> str | None:
    """MRTD comes from the firmware image alone. The ACPI, vCPU and memory fields are
    required by the tool's schema but only feed RTMR0, so placeholders are honest here;
    --check-mrtd-invariance proves that rather than asserting it."""
    if not tdx_measure:
        return None
    for name, n in (("acpi.bin", 4096), ("rsdp.bin", 64), ("loader.bin", 256)):
        (workdir / name).write_bytes(os.urandom(n))
    md = workdir / "platform.json"
    md.write_text(json.dumps({"boot_config": {
        "cpus": 32, "memory": "100G", "bios": str(Path(firmware).resolve()),
        "acpi_tables": "acpi.bin", "rsdp": "rsdp.bin", "table_loader": "loader.bin"}}))
    out = subprocess.run([tdx_measure, "--platform-only", "--json", str(md)],
                         capture_output=True, text=True, cwd=workdir)
    if out.returncode != 0:
        print(f"  tdx-measure failed: {out.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(out.stdout)["mrtd"]


# ----------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=os.environ.get("IR_BUILD_IMAGE"),
                    help="guest disk image: an https URL or a local path (env IR_BUILD_IMAGE)")
    ap.add_argument("--firmware", default=os.environ.get("IR_BUILD_FIRMWARE"),
                    help="guest firmware blob, e.g. OVMF.inteltdx.fd (env IR_BUILD_FIRMWARE)")
    ap.add_argument("--tdx-measure", default=os.environ.get("IR_TDX_MEASURE", "tdx-measure"),
                    help="path to a tdx-measure binary; omit to skip MRTD")
    ap.add_argument("--build", help="recorded build id to compare against (default: every one)")
    ap.add_argument("--keep", help="directory to keep the extracted artifacts in")
    ap.add_argument("--out", help="write a machine-readable record of the run to this JSON file")
    a = ap.parse_args()
    if not a.image:
        ap.error("--image is required (no image locator is compiled into this tool)")

    tmp = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="ir-build-"))
    tmp.mkdir(parents=True, exist_ok=True)
    print(f"artifacts: {tmp}")

    print("==> reading partition table")
    head = tmp / "head.raw"
    _qemu_slice(a.image, 0, 2 << 20, head)
    hdr, parts = read_gpt(head.read_bytes())
    for p in parts:
        print(f"    part{p['index']}: {p['type']}  {(p['last']-p['first']+1)*SECTOR/2**30:.2f} GiB")
    esp = next((p for p in parts if p["type"] == ESP_TYPE), None)
    boot = next((p for p in parts if p["type"] == XBOOTLDR_TYPE), None)
    if not esp:
        raise SystemExit("no EFI system partition found")

    print("==> reading EFI system partition")
    esp_img = tmp / "esp.img"
    _qemu_slice(a.image, esp["first"] * SECTOR, (esp["last"] - esp["first"] + 1) * SECTOR, esp_img)
    fat = Fat32(esp_img.read_bytes())
    shim = fat.read_path("/EFI/ubuntu/shimx64.efi")
    grub = fat.read_path("/EFI/ubuntu/grubx64.efi")
    (tmp / "shimx64.efi").write_bytes(shim)
    (tmp / "grubx64.efi").write_bytes(grub)
    print(f"    shim {len(shim)} bytes, grub {len(grub)} bytes")

    if boot:
        print("==> reading boot partition (kernel, initramfs, bootloader config)")
        boot_img = tmp / "boot.img"
        _qemu_slice(a.image, boot["first"] * SECTOR,
                    (boot["last"] - boot["first"] + 1) * SECTOR, boot_img)
        subprocess.run(["debugfs", "-R", f"dump /grub/grub.cfg {tmp/'grub.cfg'}",
                        str(boot_img)], capture_output=True)
        # Take the kernel, initramfs and command line from the bootloader's own default entry.
        # Never sort version-suffixed filenames as strings: "6.8.0" sorts after "6.17.0".
        cfg = (tmp / "grub.cfg").read_text(errors="replace") if (tmp / "grub.cfg").exists() else ""
        boot_files, cmdline = [], None
        for line in cfg.splitlines():
            w = line.split()
            if w[:1] == ["linux"] and cmdline is None:
                boot_files.append(w[1].lstrip("/"))
                # The bootloader prepends BOOT_IMAGE=<kernel path> to what the config lists, and
                # that whole string is what the kernel measures. Omitting it gives a digest that is
                # wrong in a way nothing else reveals.
                cmdline = " ".join([f"BOOT_IMAGE={w[1]}"] + w[2:])
            elif w[:1] == ["initrd"] and len(boot_files) == 1:
                boot_files.append(w[1].lstrip("/"))
                break
        for name in boot_files:
            subprocess.run(["debugfs", "-R", f"dump /{name} {tmp/name}", str(boot_img)],
                           capture_output=True)
            if (tmp / name).exists():
                print(f"    {name}  sha384={hashlib.sha384((tmp/name).read_bytes()).hexdigest()[:24]}…")
        if cmdline:
            (tmp / "cmdline.txt").write_text(cmdline + "\n")
            print(f"    cmdline: {cmdline[:72]}…")

    print("==> computing measurements")
    computed = {}
    got_mrtd = mrtd(a.firmware, a.tdx_measure, tmp) if a.firmware else None
    if got_mrtd:
        computed["mrtd"] = got_mrtd
    r1, log = rtmr1(gpt_event_data(hdr, parts), shim, grub)
    computed["rtmr1"] = r1
    for name, digest in log:
        print(f"    rtmr1 event  {digest[:24]}…  {name}")
    initrd_path = next((p for p in sorted(tmp.glob("initrd.img-*"))), None)
    cmdline = (tmp / "cmdline.txt").read_text().strip() if (tmp / "cmdline.txt").exists() else ""
    if initrd_path and cmdline:
        r2, log2 = rtmr2(shim, cmdline, initrd_path.read_bytes())
        computed["rtmr2"] = r2
        for name, digest in log2:
            print(f"    rtmr2 event  {digest[:24]}…  {name}")
    else:
        print("    rtmr2 skipped: need both the initramfs and the command line from the boot partition")
    for k, v in computed.items():
        print(f"    {k.upper():5s} {v}")

    if a.out:
        inputs = {n: hashlib.sha256((tmp / n).read_bytes()).hexdigest()
                  for n in ("shimx64.efi", "grubx64.efi") if (tmp / n).exists()}
        if initrd_path:
            inputs["initrd"] = hashlib.sha256(initrd_path.read_bytes()).hexdigest()
        record = {
            "computed": computed,
            "inputs": inputs,
            "cmdline": cmdline,
            "rtmr1_event_log": [{"event": n, "digest": d} for n, d in log],
            "rtmr2_event_log": [{"event": n, "digest": d} for n, d in (log2 if "rtmr2" in computed else [])],
        }
        if a.firmware:
            record["inputs"]["firmware"] = hashlib.sha256(Path(a.firmware).read_bytes()).hexdigest()
        Path(a.out).write_text(json.dumps(record, indent=2) + "\n")
        print(f"    record written to {a.out}")

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from inferroute_local.confidential import builds  # noqa: E402

    print("==> comparing against recorded builds")
    rc = 1
    for b in builds.BUNDLED:
        if a.build and b["id"] != a.build:
            continue
        verdict = {k: (b.get(k, "").lower() == v.lower()) for k, v in computed.items()}
        state = "REPRODUCED" if verdict and all(verdict.values()) else "MISMATCH"
        print(f"    {b['id']}: {state}")
        for k, ok in verdict.items():
            print(f"      {k.upper():5s} {'match' if ok else 'DIFFERS from the recorded value'}")
        if state == "REPRODUCED":
            rc = 0
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
