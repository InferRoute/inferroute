"""Mechanical checks of the Intel TDX boot image behind a record: the published UKI and root filesystem.

A TDX record proves which image booted (the UKI's Authenticode hash in RTMR1) and the UKI's command line pins the
root filesystem (roothash= over a dm-verity tree). This module turns the PUBLISHED artefacts of that image into
rows a verifier can print: that the published UKI is the one the quote names, that its command line is the closed
one, that the root bytes hash to the roothash, and that the root's files are the published source, run under the
published units (v13: two unprivileged services and a root quote helper), with the published firewall loaded before
the network comes up and emptied of its fetch allowance before the search starts, and the seal ordered before the
engine is imported and before the first request.

Artefact directory layout (published per image):
    uki.efi        the unified kernel image, byte for byte (its Authenticode SHA-384 is the reference value)
    root.img       the root partition (erofs), byte for byte
    verity.img     the dm-verity hash partition (its superblock carries the salt and block sizes)
    esp.img        optional: the EFI system partition, as built (the running ESP is NOT measured; see row D9)

Every row names what it compared. A tool this program needs but cannot find (fsck.erofs to open the root, mtools to
list the ESP) makes the row SKIP, never PASS. The result is "posture verified" only when every REQUIRED row passed.

Standalone:  python -m sealedresearch.tdx_image DIR [--source PATH] [--root-tree DIR] [--expect-image-sha384 HEX]
From a record: verify_record.py BUNDLE --tdx-image DIR --tdx-source PATH
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ──────────────────────────────────────────── what the closed box must look like ────────────────────────────────────

# The UKI's command line, token by token. Every token must be in one of these three sets; every token of REQUIRED
# must be present. `systemd.import_credentials=no` is what stops PID 1 from taking configuration from unmeasured host
# inputs (SMBIOS OEM strings, files on the ESP) — v12.
CMDLINE_REQUIRED = ("systemd.volatile=overlay", "systemd.show_status=0", "quiet", "loglevel=0", "panic=-1",
                    "accept_memory=eager", "systemd.import_credentials=no")
IMAGE_NAME = "ir-sealed-search-tdx-v13"          # the posture below is v13's; an older image fails row B by name
CMDLINE_PATTERNS = (re.compile(r"roothash=[0-9a-f]{64}"), re.compile(r"inferroute\.image=" + re.escape(IMAGE_NAME)))
# Said explicitly so a reader sees what a refusal is about; the allowlist above refuses them anyway.
CMDLINE_FORBIDDEN_PREFIXES = ("console=", "root=", "init=", "systemd.unit=", "rd.", "systemd.debug_shell",
                              "systemd.import_credentials=yes", "systemd.import_credentials=1", "enforcing=",
                              "systemd.set_credential", "systemd.gpt_auto", "earlycon", "systemd.log_target",
                              "systemd.journald.forward_to_console", "resume=")
UKI_SECTIONS = frozenset({".text", ".rodata", ".data", ".sbat", ".sdmagic", ".reloc", ".osrel", ".cmdline", ".uname",
                          ".initrd", ".linux"})

# The image's firewall, /etc/nftables.conf, loaded by nftables.service before the NIC comes up (v13; v12 had the
# search program install it, with egress open until then). Output: loopback; DHCP from networkd's uid only (v12
# exempted the ports for every process); replies on the search port from the search uid only; and a `fetch` chain
# holding the fetch uid's and the resolver's allowance, which ir_box.sh close-fetch EMPTIES before the search starts.
EGRESS_OUTPUT_EXPECTED = ("type filter hook output priority 0; policy drop;", 'oif "lo" accept',
                          'meta skuid "systemd-network" udp sport 68 udp dport 67 accept',
                          'meta skuid "ir-search" tcp sport {port} ct state established accept', "jump fetch")
EGRESS_FETCH_EXPECTED = ('meta skuid "ir-fetch" accept', 'meta skuid "systemd-resolve" udp dport 53 accept',
                         'meta skuid "systemd-resolve" tcp dport 53 accept')
EGRESS_INPUT_EXPECTED = ("type filter hook input priority 0; policy drop;", 'iif "lo" accept',
                         "ct state established,related accept", "udp sport 67 udp dport 68 accept",
                         "tcp dport {port} accept")
FETCH_CLOSE_STEP = "+/bin/sh /opt/ir/app/ir_box.sh close-fetch"
# What ir_box.sh's close-fetch step must do, line by line (the file is ALSO compared byte for byte with the source).
FETCH_CLOSE_LINES = ("nft flush chain $TABLE fetch", '[ "$(fetch_rules)" -eq 0 ]', "ruleset_live",
                     'mount -o remount,ro "$RAM"')
NFT_TABLE_LINE = 'TABLE="inet ir_closed_box"'

# The sandbox every InferRoute service in the image shares: no capability, no new privilege, no device, read-only
# system, kernel interfaces hidden, W^X, one syscall allowlist. Each unit then adds its own lines.
SANDBOX_REQUIRED = {"NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
                    "PrivateDevices": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
                    "ProtectControlGroups": "yes", "ProtectClock": "yes", "LockPersonality": "yes",
                    "MemoryDenyWriteExecute": "yes", "RestrictNamespaces": "yes", "RestrictRealtime": "yes",
                    "RestrictSUIDSGID": "yes", "SystemCallArchitectures": "native", "SystemCallFilter": "@system-service",
                    "StandardOutput": "null", "StandardError": "null", "LimitCORE": "0"}
SEARCH_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "User": "ir-search", "Group": "ir-search", "Restart": "no",
                        "ExecStart": "/opt/ir/venv/bin/python -u /opt/ir/app/tdx_entry.py",
                        "ExecStartPre": "+/bin/sh /opt/ir/app/ir_box.sh pre-search",
                        "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "ReadOnlyPaths": "/ram",
                        "FailureAction": "poweroff-force"}
FETCH_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "User": "ir-fetch", "Group": "ir-fetch", "Type": "oneshot",
                       "RemainAfterExit": "yes", "ExecStart": "/opt/ir/venv/bin/python -u /opt/ir/app/tdx_fetch.py",
                       "ExecStartPre": "+/bin/sh /opt/ir/app/ir_box.sh pre-fetch", "ExecStartPost": FETCH_CLOSE_STEP,
                       "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "ReadWritePaths": "/ram",
                       "FailureAction": "poweroff-force"}
QUOTE_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "ExecStart": "/usr/bin/python3 -I /opt/ir/app/ir_quote.py",
                       "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX",
                       "ReadWritePaths": "/sys/kernel/config", "Restart": "no"}
QUOTE_SOCKET_REQUIRED = {"ListenStream": "/run/ir-quote.sock", "SocketUser": "root", "SocketGroup": "ir-quote",
                         "SocketMode": "0660"}
# Unit -> (required properties, dependencies that must appear in Requires= AND After=).
UNITS_EXPECTED = {
    "ir-search.service": (SEARCH_UNIT_REQUIRED, ("ir-fetch.service", "ir-quote.socket")),
    "ir-fetch.service": (FETCH_UNIT_REQUIRED, ("nftables.service", "network-online.target", "ir-quote.socket")),
    "ir-quote.service": (QUOTE_UNIT_REQUIRED, ("ir-quote.socket", "sys-kernel-config.mount")),
    "ir-quote.socket": (QUOTE_SOCKET_REQUIRED, ()),
}
UNIT_FORBIDDEN_KEYS = ("StandardInput", "TTYPath")
# The accounts the units and the firewall name: present, no login shell, no password.
ACCOUNTS_REQUIRED = ("ir-fetch", "ir-search")
# The modules whose source is not published (the ranking engine): the TDX entry may import them only after the seal.
CLOSED_MODULES = ("enclave.azure.m2_ranker", "enclave.azure.m2_searcher", "enclave.azure", "torch", "faiss",
                  "sentence_transformers", "lightgbm")

# Units that must be masked (/etc/systemd/system/<name> -> /dev/null): every console login path, the ESP automounts
# (a writable, host-readable partition), and every timer or service that reaches the network on its own.
MASKED_REQUIRED = ("getty.target", "getty@.service", "serial-getty@.service", "console-getty.service",
                   "autovt@.service", "efi.automount", "efi.mount", "boot.automount", "boot.mount", "motd-news.timer",
                   "systemd-sysupdate.timer", "systemd-sysupdate-reboot.timer", "systemd-boot-update.service")
# Every enabled unit under /etc/systemd/system/*.wants (the administrator layer mkosi and we control). Anything
# else is a FAIL that names the unit. Masked units may stay linked here; the mask wins.
ENABLED_ALLOWED = {
    "multi-user.target.wants": {"e2scrub_reap.service", "ir-search.service", "remote-cryptsetup.target",
                                "remote-fs.target", "remote-veritysetup.target", "systemd-networkd.service"},
    "sysinit.target.wants": {"nftables.service", "systemd-boot-update.service", "systemd-confext.service",
                             "systemd-network-generator.service", "systemd-pcrlock-file-system.service",
                             "systemd-pcrlock-firmware-code.service", "systemd-pcrlock-firmware-config.service",
                             "systemd-pcrlock-machine-id.service", "systemd-pcrlock-make-policy.service",
                             "systemd-pcrlock-secureboot-authority.service", "systemd-pcrlock-secureboot-policy.service",
                             "systemd-pstore.service", "systemd-resolved.service", "systemd-sysext.service"},
    "getty.target.wants": {"getty@tty1.service"},             # inert: getty.target and getty@.service are masked
    "network-online.target.wants": {"systemd-networkd-wait-online.service"},
    "timers.target.wants": {"dpkg-db-backup.timer", "e2scrub_all.timer", "fstrim.timer", "motd-news.timer",
                            "systemd-sysupdate-reboot.timer", "systemd-sysupdate.timer"},
    "systemd-journald.service.wants": {"systemd-journald-audit.socket"},
    "sockets.target.wants": {"ir-quote.socket", "systemd-journald-audit.socket", "systemd-networkd.socket",
                             "systemd-pcrextend.socket", "systemd-sysext.socket"},
}
# Names that must not be enabled anywhere (vendor layer included).
UNIT_FORBIDDEN_RE = re.compile(r"^(ssh|sshd|dropbear|debug-shell|google-.*|gce-.*|cloud-init.*|systemd-timesyncd|chrony.*|"
                               r"ntp.*|rsync|telnet.*|nfs.*|serial-getty@.*|getty@.*|console-getty|autovt@.*|"
                               r"emergency|rescue)\.(service|socket|timer|target|path)$")
FORBIDDEN_BINARIES = ("usr/sbin/sshd", "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent",
                      "usr/bin/cloud-init", "usr/sbin/dropbear")

INITRD_REQUIRED = ("usr/lib/systemd/system-generators/systemd-veritysetup-generator", "dm-verity.ko", "erofs.ko")
INITRD_FORBIDDEN = ("sshd", "dropbear")
ESP_FORBIDDEN = (".extra.d", "addons", "credentials")

# How the image tree was staged from the source tree (enclave/gcp-tdx/stage_app.sh + Dockerfile.m2's COPY list).
STAGE_FIXED = {"tdx_entry.py": "enclave/gcp-tdx/app/tdx_entry.py", "tdx_attest.py": "enclave/gcp-tdx/app/tdx_attest.py",
               "tdx_fetch.py": "enclave/gcp-tdx/app/tdx_fetch.py", "ir_quote.py": "enclave/gcp-tdx/app/ir_quote.py",
               "ir_box.sh": "enclave/gcp-tdx/app/ir_box.sh",
               "sealedresearch/verify_record.py": "sealedresearch/verify_record.py",
               "sealedresearch/tdx_collateral.py": "sealedresearch/tdx_collateral.py"}
REQUIREMENTS_SRC = "enclave/azure/requirements.txt"
MKOSI_EXTRA = "enclave/gcp-tdx/image/mkosi.extra"
SOURCE_COMMIT_FILE = "etc/inferroute-source-commit"
APP_DIR, VENV_SP = "opt/ir/app", "opt/ir/venv/lib/python3.12/site-packages"

REQUIRED_ROWS = (
    "A. published UKI is the measured image", "A. published UKI loads the named kernel",
    "B. UKI sections", "B. UKI command line",
    "C. root bytes hash to the roothash",
    "D. root opened",
    "D1. application files equal the source", "D1. image names its source commit",
    "D2. bytecode names its sources", "D2. bytecode recompiles identically",
    "D3. installed packages match their RECORDs", "D3. requirements equal the source",
    "D4. units and firewall files equal the source", "D4. search unit properties", "D4. fetch unit properties",
    "D4. quote helper properties",
    "D5. unit census", "D5. listening sockets", "D5. accounts, mounts, repart, binaries",
    "D6. firewall rules", "D7. seal before serve",
    "D8. initrd",
)


class ImageReport:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str]] = []
        self.values: Dict[str, Any] = {}

    def add(self, ok: Optional[bool], name: str, detail: str) -> bool:
        self.rows.append(("SKIP" if ok is None else "PASS" if ok else "FAIL", name, detail))
        return bool(ok)

    @property
    def posture_verified(self) -> bool:
        """True only if every REQUIRED row is present and PASSED and no row at all FAILED."""
        status = {n: s for s, n, _ in self.rows}
        return all(status.get(n) == "PASS" for n in REQUIRED_ROWS) and all(s != "FAIL" for s, _, _ in self.rows)

    def dump(self, indent: str = "  ") -> None:
        for s, n, d in self.rows:
            print(f"{indent}{s:4} {n}: {d}")

    def rows_for_measured(self, image_sha384: Optional[str], boot_apps: Optional[List[str]]) -> Tuple[List[Tuple[str, str, str]], bool]:
        """This report's rows re-anchored to ONE measured boot: row A compares the published UKI with the image the
        quote names and the applications it then loaded. Returns (rows, posture_verified) — verified only if every
        required row, these two included, passed and nothing failed. A record verifier computes the image once and
        judges it against each search's own quote through this."""
        return rows_for_measured(self, image_sha384, boot_apps)


# ──────────────────────────────────────────── A/B: the UKI ───────────────────────────────────────────────────────────

def pe_sections(d: bytes) -> Dict[str, bytes]:
    """Section name -> bytes (trimmed to the virtual size, which is the section's real length)."""
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    st = pe + 24 + optsz
    out: Dict[str, bytes] = {}
    for i in range(nsec):
        name, vs, _va, rs, ro = struct.unpack_from("<8sIIII", d, st + i * 40)
        out[name.rstrip(b"\0").decode("ascii", "replace")] = d[ro:ro + min(vs, rs)] if vs else d[ro:ro + rs]
    return out


def authenticode_sha384(d: bytes) -> str:
    """PE Authenticode digest (SHA-384), as the firmware measures an EFI application: everything but the checksum
    field, the certificate-table directory entry and the certificate table itself."""
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    ce = opt + (112 if magic == 0x20B else 96) + 4 * 8            # data directory entry 4: certificate table
    hs = struct.unpack_from("<I", d, opt + 60)[0]                  # SizeOfHeaders
    h = hashlib.sha384(d[:opt + 64] + d[opt + 68:ce] + d[ce + 8:hs])
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    st = pe + 24 + struct.unpack_from("<H", d, pe + 20)[0]
    end = hs
    for sz, ptr in sorted([struct.unpack_from("<II", d, st + 40 * i + 16) for i in range(nsec)], key=lambda x: x[1]):
        if sz:
            h.update(d[ptr:ptr + sz])
            end = ptr + sz
    cl = struct.unpack_from("<II", d, ce)[1]
    tail = len(d) - cl if cl else len(d)
    if tail > end:
        h.update(d[end:tail])
    return h.hexdigest()


def cmdline_tokens(section: bytes) -> List[str]:
    return section.rstrip(b"\0").decode("utf-8", "replace").split()


def check_cmdline(tokens: List[str]) -> Tuple[bool, str]:
    """Every token allowed, every required token present, exactly one roothash= and one inferroute.image=."""
    problems: List[str] = []
    for t in tokens:
        if any(t.startswith(p) for p in CMDLINE_FORBIDDEN_PREFIXES):
            problems.append(f"forbidden token {t!r}")
        elif t not in CMDLINE_REQUIRED and not any(p.fullmatch(t) for p in CMDLINE_PATTERNS):
            problems.append(f"unexpected token {t!r}")
    for r in CMDLINE_REQUIRED:
        if r not in tokens:
            problems.append(f"missing {r!r}")
    for p in CMDLINE_PATTERNS:
        n = sum(1 for t in tokens if p.fullmatch(t))
        if n != 1:
            problems.append(f"{n} tokens match {p.pattern!r}, expected exactly one")
    if problems:
        return False, "; ".join(problems)
    return True, " ".join(tokens)


def roothash_of(tokens: List[str]) -> Optional[str]:
    for t in tokens:
        if t.startswith("roothash="):
            return t[9:].lower()
    return None


# ──────────────────────────────────────────── C: dm-verity ───────────────────────────────────────────────────────────

def verity_superblock(d: bytes) -> Dict[str, Any]:
    if d[:8] != b"verity\0\0":
        raise ValueError("no dm-verity superblock")
    version, hash_type = struct.unpack_from("<II", d, 8)
    alg = d[32:64].rstrip(b"\0").decode("ascii")
    data_bs, hash_bs = struct.unpack_from("<II", d, 64)
    data_blocks = struct.unpack_from("<Q", d, 72)[0]
    salt_size = struct.unpack_from("<H", d, 80)[0]
    return {"version": version, "hash_type": hash_type, "algorithm": alg, "data_block_size": data_bs,
            "hash_block_size": hash_bs, "data_blocks": data_blocks, "salt": d[88:88 + salt_size]}


def verity_roothash(root_path: str, sb: Dict[str, Any], chunk_blocks: int = 1 << 15) -> str:
    """Recompute the dm-verity root hash over the root partition: hash every data block, then every level up to
    the root, exactly as veritysetup format does. Streams the data; memory is one level of hashes."""
    alg, salt, dbs, hbs = sb["algorithm"], sb["salt"], sb["data_block_size"], sb["hash_block_size"]
    hash_type = sb["hash_type"]

    def H(b: bytes) -> bytes:
        return hashlib.new(alg, salt + b if hash_type == 1 else b + salt).digest()

    hl = hashlib.new(alg).digest_size
    per = hbs // hl
    level = bytearray()
    with open(root_path, "rb") as fh:
        remaining = sb["data_blocks"]
        while remaining:
            n = min(chunk_blocks, remaining)
            buf = fh.read(n * dbs)
            if len(buf) != n * dbs:
                raise ValueError(f"root image shorter than its {sb['data_blocks']} declared blocks")
            for i in range(n):
                level += H(buf[i * dbs:(i + 1) * dbs])
            remaining -= n
    while len(level) > hl:
        nxt = bytearray()
        for i in range(0, len(level), per * hl):
            blk = bytes(level[i:i + per * hl])
            nxt += H(blk + b"\0" * (hbs - len(blk)))
        level = nxt
    return bytes(level).hex()


# ──────────────────────────────────────────── D: the root tree ───────────────────────────────────────────────────────

def extract_erofs(img: str, dest: str) -> Optional[str]:
    """Open the erofs root with fsck.erofs --extract. None if the tool is absent (the caller SKIPs)."""
    tool = shutil.which("fsck.erofs")
    if not tool:
        return None
    os.makedirs(dest, exist_ok=True)
    r = subprocess.run([tool, f"--extract={dest}", img], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"fsck.erofs failed: {(r.stderr or r.stdout).strip()[-200:]}")
    return dest


class Source:
    """The published source: a git checkout (files read at the stated commit) or a plain tree (a tarball unpacked,
    optionally carrying SOURCE_COMMIT at its root)."""

    def __init__(self, path: str) -> None:
        self.path = path
        # A worktree's .git is a file, so ask git rather than looking for a directory.
        self.git = bool(shutil.which("git")) and subprocess.run(["git", "-C", path, "rev-parse", "--git-dir"],
                                                               capture_output=True).returncode == 0
        self.commit: Optional[str] = None               # the commit files are read at, once bound

    def bind(self, commit: str) -> Tuple[Optional[bool], str]:
        """Bind reads to `commit`. In a checkout the commit must exist (files then come from it, not the working
        tree); in a plain tree a SOURCE_COMMIT file may state it (a statement, not a derivation)."""
        if self.git:
            r = subprocess.run(["git", "-C", self.path, "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True)
            if r.returncode != 0:
                return False, f"commit {commit} is not in the checkout at {self.path}"
            self.commit = commit
            head = subprocess.run(["git", "-C", self.path, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            return True, f"files read from git object {commit[:12]} ({'HEAD' if head == commit else 'not HEAD, HEAD is ' + head[:12]})"
        stated = os.path.join(self.path, "SOURCE_COMMIT")
        if os.path.isfile(stated):
            s = open(stated).read().strip()
            if s == commit:
                return True, f"plain source tree states the same commit {commit[:12]} (stated by its publisher, not derived)"
            return False, f"plain source tree states commit {s[:12]}, the image says {commit[:12]}"
        return None, f"plain source tree without SOURCE_COMMIT: the image's commit {commit[:12]} is not cross-checked"

    def read(self, rel: str) -> Optional[bytes]:
        if self.git and self.commit:
            r = subprocess.run(["git", "-C", self.path, "show", f"{self.commit}:{rel}"], capture_output=True)
            return r.stdout if r.returncode == 0 else None
        p = os.path.join(self.path, rel)
        if os.path.islink(p):
            return os.readlink(p).encode()
        return open(p, "rb").read() if os.path.isfile(p) else None

    def readlink(self, rel: str) -> Optional[str]:
        """A symlink's target in the source (git stores it as the blob's content, mode 120000)."""
        if self.git and self.commit:
            r = subprocess.run(["git", "-C", self.path, "ls-tree", self.commit, rel], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.startswith("120000"):
                return self.read(rel).decode() if self.read(rel) is not None else None
            return None
        p = os.path.join(self.path, rel)
        return os.readlink(p) if os.path.islink(p) else None

    def list_dir(self, rel: str) -> List[str]:
        if self.git and self.commit:
            r = subprocess.run(["git", "-C", self.path, "ls-tree", "-r", "--name-only", self.commit, rel],
                               capture_output=True, text=True)
            return [x for x in r.stdout.split("\n") if x]
        out = []
        for dp, _dn, fs in os.walk(os.path.join(self.path, rel)):
            for f in fs:
                out.append(os.path.relpath(os.path.join(dp, f), self.path))
        return sorted(out)

    def staging_map(self) -> Dict[str, str]:
        """image path under /opt/ir/app -> source path, from Dockerfile.m2's COPY lines plus the TDX files."""
        m = dict(STAGE_FIXED)
        df = self.read("enclave/azure/Dockerfile.m2")
        for line in (df or b"").decode("utf-8", "replace").splitlines():
            if line.startswith("COPY ") and re.match(r"COPY (sealedresearch|enclave)/", line) and "requirements" not in line:
                _, src, dst = line.split()
                m[dst] = src
        return m


def _walk_files(root: str, rel: str) -> List[str]:
    base = os.path.join(root, rel)
    out = []
    for dp, _dn, fs in os.walk(base):
        for f in fs:
            out.append(os.path.relpath(os.path.join(dp, f), base))
    return sorted(out)


def check_sources(rep: ImageReport, tree: str, src: Optional[Source], stated_commit: Optional[str] = None) -> None:
    """D1: every file under /opt/ir/app is the published source at the image's commit, and nothing else is there.
    `stated_commit` is an auditor-supplied commit for an image that carries no commit file (v11 and earlier): the
    commit row still FAILS, but the files are compared at that commit so the reader learns what they are."""
    commit_path = os.path.join(tree, SOURCE_COMMIT_FILE)
    commit = open(commit_path).read().strip() if os.path.isfile(commit_path) else None
    if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        rep.add(False, "D1. image names its source commit", f"/{SOURCE_COMMIT_FILE} missing or not a commit id"
                + (f"; comparing files at the auditor-supplied commit {stated_commit[:12]} instead" if stated_commit else ""))
        if stated_commit and src is not None:
            src.bind(stated_commit)
            commit = stated_commit
    elif src is None:
        rep.add(None, "D1. image names its source commit", f"image says {commit[:12]}; no source supplied to compare")
    else:
        ok, why = src.bind(commit)
        rep.add(ok, "D1. image names its source commit", why)
    rep.values["source_commit"] = commit
    if src is None:
        rep.add(None, "D1. application files equal the source", "no --source supplied; files only hashed")
        rep.values["app_sha256"] = {f: hashlib.sha256(open(os.path.join(tree, APP_DIR, f), "rb").read()).hexdigest()
                                   for f in _walk_files(tree, APP_DIR) if not f.endswith(".pyc")}
        return
    m = src.staging_map()
    present = [f for f in _walk_files(tree, APP_DIR) if not f.endswith(".pyc")]
    diff, missing, extra = [], [], [f for f in present if f not in m]
    for dst, s in sorted(m.items()):
        want = src.read(s)
        p = os.path.join(tree, APP_DIR, dst)
        if want is None:
            missing.append(f"{s} (not in source)")
        elif not os.path.isfile(p):
            missing.append(f"{dst} (not in image)")
        elif open(p, "rb").read() != want:
            diff.append(dst)
    same = len(m) - len(diff) - len(missing)
    ok = not (diff or missing or extra)
    rep.add(ok, "D1. application files equal the source",
            f"{same} of {len(m)} staged files byte-equal to the source" + (f"; DIFFER: {diff}" if diff else "")
            + (f"; MISSING: {missing}" if missing else "") + (f"; EXTRA in image: {extra}" if extra else ""))


def _norm_code(obj: Any) -> Any:
    """A comparable form of a marshalled code object: marshal's byte layout is not deterministic (frozenset order,
    reference flags), its meaning is."""
    if hasattr(obj, "co_code"):
        c = obj
        return ("code", c.co_name, c.co_qualname, c.co_filename, c.co_firstlineno, c.co_flags, c.co_argcount,
                c.co_posonlyargcount, c.co_kwonlyargcount, c.co_nlocals, c.co_stacksize, c.co_code, c.co_names,
                c.co_varnames, c.co_freevars, c.co_cellvars, c.co_linetable, c.co_exceptiontable,
                tuple(_norm_code(x) for x in c.co_consts))
    if isinstance(obj, frozenset):
        return ("frozenset", tuple(sorted((_norm_code(x) for x in obj), key=repr)))
    if isinstance(obj, tuple):
        return tuple(_norm_code(x) for x in obj)
    return obj


def check_bytecode(rep: ImageReport, tree: str) -> None:
    """D2: every .pyc under /opt/ir is unchecked-hash bytecode whose header names its .py, and recompiling that .py
    with the same CPython gives the same code. Python loads the .pyc, not the .py — so the .py being right is not
    enough on its own."""
    pycs = [os.path.join(dp, f) for sub in (APP_DIR, "opt/ir/venv") for dp, _d, fs in os.walk(os.path.join(tree, sub))
            for f in fs if f.endswith(".pyc")]
    bad_hdr, orphan, bad_code, recompiled, magic_mismatch = [], [], [], 0, None
    for pyc in sorted(pycs):
        rel = os.path.relpath(pyc, tree)
        d = os.path.dirname(os.path.dirname(pyc))
        src = os.path.join(d, os.path.basename(pyc).split(".")[0] + ".py")
        head = open(pyc, "rb").read(16)
        if not os.path.isfile(src):
            orphan.append(rel)
            continue
        source = open(src, "rb").read()
        flags = struct.unpack_from("<I", head, 4)[0]
        if flags != 1 or head[8:16] != importlib.util.source_hash(source):
            bad_hdr.append(rel)
            continue
        if head[:4] != importlib.util.MAGIC_NUMBER:
            magic_mismatch = head[:4].hex()
            continue
        try:
            code = compile(source, "/" + os.path.relpath(src, tree), "exec", dont_inherit=True, optimize=0)
            if _norm_code(marshal.loads(open(pyc, "rb").read()[16:])) != _norm_code(code):
                bad_code.append(rel)
            else:
                recompiled += 1
        except Exception as exc:                            # noqa: BLE001
            bad_code.append(f"{rel} ({type(exc).__name__})")
    hdr_ok = not (bad_hdr or orphan)
    rep.add(hdr_ok, "D2. bytecode names its sources",
            f"{len(pycs)} .pyc files, all unchecked-hash with the header hash of their .py" if hdr_ok else
            (f"header/flags wrong: {bad_hdr[:5]}" if bad_hdr else "") + (f" orphans without a .py: {orphan[:5]}" if orphan else ""))
    if magic_mismatch:
        rep.add(None, "D2. bytecode recompiles identically",
                f"image bytecode magic {magic_mismatch} is not this interpreter's ({importlib.util.MAGIC_NUMBER.hex()}); "
                f"run under the image's CPython (python{sys.version_info[0]}.{sys.version_info[1]} here)")
    else:
        rep.add(not bad_code and recompiled == len(pycs) - len(orphan) - len(bad_hdr), "D2. bytecode recompiles identically",
                f"{recompiled} of {len(pycs)} recompiled from their .py to the same code objects"
                + (f"; DIFFER: {bad_code[:5]}" if bad_code else ""))


def check_records(rep: ImageReport, tree: str, src: Optional[Source]) -> None:
    """D3: every installed distribution's RECORD hashes match the files, nothing lives outside a RECORD, and the
    image's requirements file is the published one (each wheel pinned by SHA-256 there)."""
    sp = os.path.join(tree, VENV_SP)
    if not os.path.isdir(sp):
        rep.add(False, "D3. installed packages match their RECORDs", f"/{VENV_SP} missing")
    else:
        listed, bad, dists = set(), [], 0
        for name in sorted(os.listdir(sp)):
            rec = os.path.join(sp, name, "RECORD")
            if not (name.endswith(".dist-info") and os.path.isfile(rec)):
                continue
            dists += 1
            for line in open(rec, encoding="utf-8"):
                parts = line.rstrip("\n").split(",")
                if len(parts) < 2:
                    continue
                path, digest = parts[0], parts[1]
                listed.add(os.path.normpath(path))
                if not digest.startswith("sha256="):
                    continue
                p = os.path.normpath(os.path.join(sp, path))
                if not os.path.isfile(p):
                    bad.append(f"{path} (missing)")
                    continue
                want = base64.urlsafe_b64decode(digest[7:] + "=" * (-len(digest[7:]) % 4))
                if hashlib.sha256(open(p, "rb").read()).digest() != want:
                    bad.append(path)
        extra = [f for f in _walk_files(tree, VENV_SP) if not f.endswith(".pyc") and os.path.normpath(f) not in listed
                 and "/__pycache__/" not in f]
        ok = not bad and not extra
        rep.add(ok, "D3. installed packages match their RECORDs",
                f"{dists} distributions, {len(listed)} recorded files hash as recorded" if ok else
                (f"mismatch: {bad[:5]}" if bad else "") + (f" outside any RECORD: {extra[:5]}" if extra else ""))
    req = os.path.join(tree, "opt/ir/requirements.txt")
    if src is None:
        rep.add(None, "D3. requirements equal the source", "no --source supplied")
    else:
        want = src.read(REQUIREMENTS_SRC)
        same = os.path.isfile(req) and want is not None and open(req, "rb").read() == want
        pins = len(re.findall(r"--hash=sha256:", (want or b"").decode("utf-8", "replace")))
        rep.add(same, "D3. requirements equal the source",
                f"/opt/ir/requirements.txt byte-equal to {REQUIREMENTS_SRC} ({pins} wheel hashes pinned)" if same
                else f"/opt/ir/requirements.txt differs from {REQUIREMENTS_SRC} or is missing")


def _parse_unit(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;[":
            continue
        k, _, v = line.partition("=")
        out.setdefault(k.strip(), []).append(v.strip())
    return out


def _unit_problems(u: Dict[str, List[str]], required: Dict[str, str], deps: Tuple[str, ...]) -> List[str]:
    problems = [f"{k}={u.get(k)} (want {v!r})" for k, v in required.items() if u.get(k) != [v]]
    problems += [f"{k} present" for k in UNIT_FORBIDDEN_KEYS if k in u]
    for dep in deps:
        for key in ("Requires", "After"):
            if not any(dep in v.split() for v in u.get(key, [])):
                problems.append(f"{key}= lacks {dep}")
    return problems


def check_unit(rep: ImageReport, tree: str, src: Optional[Source]) -> None:
    """D4: every file we put in the image's /etc and /usr (units, drop-ins, the firewall, the accounts) is the published
    one, byte for byte; and the three units have the closed-box properties, property by property."""
    if src is None:
        rep.add(None, "D4. units and firewall files equal the source", "no --source supplied")
    else:
        diff, missing, same = [], [], 0
        for rel in sorted(r for sub in ("etc", "usr") for r in src.list_dir(f"{MKOSI_EXTRA}/{sub}")):
            if rel.startswith(f"{MKOSI_EXTRA}/opt/"):
                continue
            img_rel = os.path.relpath(rel, MKOSI_EXTRA)
            p = os.path.join(tree, img_rel)
            link = src.readlink(rel)
            if link is not None:
                ok = os.path.islink(p) and os.readlink(p) == link
            else:
                want = src.read(rel)
                ok = os.path.isfile(p) and not os.path.islink(p) and open(p, "rb").read() == want
            if not os.path.lexists(p):
                missing.append(img_rel)
            elif not ok:
                diff.append(img_rel)
            else:
                same += 1
        ok_all = not (diff or missing) and same > 0
        rep.add(ok_all, "D4. units and firewall files equal the source",
                f"{same} files under /etc and /usr byte-equal to {MKOSI_EXTRA}" if ok_all else
                (f"DIFFER: {diff}" if diff else "") + (f" MISSING: {missing}" if missing else "") + ("" if same else " nothing compared"))
    for unit, row in (("ir-search.service", "D4. search unit properties"), ("ir-fetch.service", "D4. fetch unit properties")):
        required, deps = UNITS_EXPECTED[unit]
        p = os.path.join(tree, "etc/systemd/system", unit)
        if not os.path.isfile(p):
            rep.add(False, row, f"/etc/systemd/system/{unit} missing")
            continue
        problems = _unit_problems(_parse_unit(open(p, encoding="utf-8").read()), required, deps)
        if unit == "ir-search.service" and not os.path.islink(os.path.join(tree, "etc/systemd/system/multi-user.target.wants/ir-search.service")):
            problems.append("not wanted by multi-user.target")
        rep.add(not problems, row,
                f"{unit}: User={required['User']}, no capability, no new privilege, read-only system, no device, W^X, "
                f"@system-service, stdout and stderr to null, no core dumps, root steps {required['ExecStartPre']!r}"
                + (f" and {required['ExecStartPost']!r}" if "ExecStartPost" in required else "")
                + f", ordered after {', '.join(deps)}" if not problems else "; ".join(problems))
    problems = []
    for unit in ("ir-quote.service", "ir-quote.socket"):
        required, deps = UNITS_EXPECTED[unit]
        p = os.path.join(tree, "etc/systemd/system", unit)
        if not os.path.isfile(p):
            problems.append(f"{unit} missing")
            continue
        problems += [f"{unit}: {x}" for x in _unit_problems(_parse_unit(open(p, encoding="utf-8").read()), required, deps)]
    if not os.path.islink(os.path.join(tree, "etc/systemd/system/sockets.target.wants/ir-quote.socket")):
        problems.append("ir-quote.socket not wanted by sockets.target")
    rep.add(not problems, "D4. quote helper properties",
            "ir-quote.service: root with no capability, no network namespace, AF_UNIX only, read-only system but "
            "/sys/kernel/config, stdlib interpreter in isolated mode; ir-quote.socket: /run/ir-quote.sock, root:ir-quote 0660"
            if not problems else "; ".join(problems))


def _masked(tree: str, name: str) -> bool:
    """Masked in /etc: the unit itself, or for an instance (getty@tty1.service) its template (getty@.service)."""
    candidates = [name]
    if "@" in name:
        stem, _, rest = name.partition("@")
        candidates.append(f"{stem}@.{rest.rsplit('.', 1)[-1]}")
    for n in candidates:
        p = os.path.join(tree, "etc/systemd/system", n)
        if os.path.islink(p) and os.readlink(p) == "/dev/null":
            return True
    return False


def check_units(rep: ImageReport, tree: str) -> None:
    """D5: which units are enabled, which are masked, what listens, and the account/mount/partition hygiene."""
    problems = []
    for name in MASKED_REQUIRED:
        if not _masked(tree, name):
            problems.append(f"{name} not masked")
    etc = os.path.join(tree, "etc/systemd/system")
    enabled: List[Tuple[str, str]] = []
    for layer in ("etc/systemd/system", "usr/lib/systemd/system"):
        base = os.path.join(tree, layer)
        if not os.path.isdir(base):
            continue
        for wants in sorted(os.listdir(base)):
            wd = os.path.join(base, wants)
            if not (wants.endswith(".wants") and os.path.isdir(wd)):
                continue
            for unit in sorted(os.listdir(wd)):
                enabled.append((layer, wants, unit))
    for layer, wants, unit in enabled:
        if UNIT_FORBIDDEN_RE.match(unit) and not _masked(tree, unit):
            problems.append(f"{unit} enabled via {layer}/{wants}")
        if layer == "etc/systemd/system" and unit not in ENABLED_ALLOWED.get(wants, set()):
            problems.append(f"{unit} enabled via {wants} is not on the allowlist")
    n_etc = sum(1 for l, _w, _u in enabled if l == "etc/systemd/system")
    rep.add(not problems, "D5. unit census",
            f"{len(MASKED_REQUIRED)} units masked; {n_etc} administrator-enabled units all on the allowlist; "
            f"{len(enabled) - n_etc} vendor-enabled units, none forbidden" if not problems else "; ".join(problems[:8]))
    # Listening sockets: every enabled .socket must listen on a unix path or loopback only.
    listen_problems, sockets = [], 0
    for layer, wants, unit in enabled:
        if not unit.endswith(".socket") or _masked(tree, unit):
            continue
        for cand in (os.path.join(etc, unit), os.path.join(tree, "usr/lib/systemd/system", unit)):
            if os.path.isfile(cand):
                sockets += 1
                for k, vals in _parse_unit(open(cand, encoding="utf-8").read()).items():
                    if k in ("ListenStream", "ListenDatagram", "ListenSequentialPacket"):
                        for v in vals:
                            if v.startswith(("/", "@")):
                                continue
                            host = v.rsplit(":", 1)[0] if ":" in v else ""
                            if host not in ("127.0.0.1", "[::1]", "localhost"):
                                listen_problems.append(f"{unit} {k}={v}")
                break
    rep.add(not listen_problems, "D5. listening sockets",
            f"{sockets} enabled socket units, all unix or loopback" if not listen_problems else "; ".join(listen_problems))
    # Accounts, mounts, repart, binaries.
    hyg = []
    shadow = os.path.join(tree, "etc/shadow")
    root_line = next((l for l in open(shadow, errors="replace") if l.startswith("root:")), None) if os.path.isfile(shadow) else None
    if not root_line or root_line.split(":")[1] not in ("*", "!", "!*", "!!", ""):
        hyg.append("root password not locked in /etc/shadow" if root_line else "/etc/shadow missing")
    passwd = os.path.join(tree, "etc/passwd")
    accounts = {l.split(":")[0]: l.rstrip("\n").split(":") for l in open(passwd, errors="replace")} if os.path.isfile(passwd) else {}
    shadow_lines = {l.split(":")[0]: l.split(":") for l in open(shadow, errors="replace")} if os.path.isfile(shadow) else {}
    for name in ACCOUNTS_REQUIRED:
        if name not in accounts:
            hyg.append(f"account {name} missing from /etc/passwd")
            continue
        if not accounts[name][-1].endswith(("nologin", "false")):
            hyg.append(f"account {name} has a login shell")
        if name in shadow_lines and shadow_lines[name][1] not in ("*", "!", "!*", "!!", ""):
            hyg.append(f"account {name} has a password")
    fstab = os.path.join(tree, "etc/fstab")
    if os.path.isfile(fstab) and any(l.strip() and not l.startswith("#") for l in open(fstab)):
        hyg.append("/etc/fstab has entries")
    for rel in ("etc/kernel/cmdline", "usr/lib/kernel/cmdline"):
        if os.path.exists(os.path.join(tree, rel)):
            hyg.append(f"/{rel} present (would prepend to the measured command line)")
    for rel in ("etc/repart.d", "usr/lib/repart.d"):
        d = os.path.join(tree, rel)
        if os.path.isdir(d) and os.listdir(d):
            hyg.append(f"/{rel} has definitions")
    for rel in FORBIDDEN_BINARIES:
        if os.path.exists(os.path.join(tree, rel)):
            hyg.append(f"/{rel} present")
    rep.add(not hyg, "D5. accounts, mounts, repart, binaries",
            f"root locked; {', '.join(ACCOUNTS_REQUIRED)} present without shell or password; no fstab entries, no cmdline file, "
            "no repart definitions, no ssh/agent binaries" if not hyg else "; ".join(hyg))


def _assigned_string(tree_file: str, name: str) -> Optional[str]:
    mod = ast.parse(open(tree_file, encoding="utf-8").read())
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
    return None


def _chain_lines(rules: str, chain: str) -> List[str]:
    out, inside = [], False
    for line in rules.splitlines():
        s = line.strip()
        if s.startswith(f"chain {chain} "):
            inside = True
            continue
        if inside:
            if s == "}":
                break
            out.append(s)
    return out


def _shell_case_body(text: str, label: str) -> List[str]:
    """The lines of one `label)` case of a POSIX shell case statement, stripped, comments dropped."""
    out, inside = [], False
    for line in text.splitlines():
        st = line.strip()
        if st == f"{label})":
            inside = True
            continue
        if inside:
            if st == ";;":
                break
            if st and not st.startswith("#"):
                out.append(st)
    return out


def check_egress(rep: ImageReport, tree: str, port: int = 8000) -> None:
    """D6: the firewall loaded before the network comes up (/etc/nftables.conf), chain by chain, and the step that
    empties its fetch allowance before the search starts (ir_box.sh close-fetch, run by ir-fetch.service)."""
    conf = os.path.join(tree, "etc/nftables.conf")
    if not os.path.isfile(conf):
        rep.add(False, "D6. firewall rules", "/etc/nftables.conf missing")
        return
    text = open(conf, encoding="utf-8").read()
    problems = []
    body = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not body or body[0] != "flush ruleset":
        problems.append("the first statement is not `flush ruleset`")
    if "table inet ir_closed_box {" not in text:
        problems.append("no `table inet ir_closed_box`")
    for chain, expected in (("output", EGRESS_OUTPUT_EXPECTED), ("fetch", EGRESS_FETCH_EXPECTED), ("input", EGRESS_INPUT_EXPECTED)):
        got = _chain_lines(text, chain)
        want = [l.format(port=port) for l in expected]
        if got != want:
            problems.append(f"{chain} chain is {got}, expected {want}")
    if not os.path.islink(os.path.join(tree, "etc/systemd/system/sysinit.target.wants/nftables.service")):
        problems.append("nftables.service not wanted by sysinit.target")
    dropin = os.path.join(tree, "etc/systemd/system/systemd-networkd.service.d/ir-closed-box.conf")
    d = _parse_unit(open(dropin, encoding="utf-8").read()) if os.path.isfile(dropin) else {}
    if d.get("Requires") != ["nftables.service"] or d.get("After") != ["nftables.service"]:
        problems.append("systemd-networkd does not require and follow nftables.service")
    # The close: the fetch unit's ExecStartPost runs ir_box.sh close-fetch, which flushes the chain, reads it back,
    # re-checks the policies and makes /ram read-only.
    unit = os.path.join(tree, "etc/systemd/system/ir-fetch.service")
    u = _parse_unit(open(unit, encoding="utf-8").read()) if os.path.isfile(unit) else {}
    if u.get("ExecStartPost") != [FETCH_CLOSE_STEP]:
        problems.append(f"ir-fetch.service ExecStartPost is {u.get('ExecStartPost')}, expected [{FETCH_CLOSE_STEP!r}]")
    box = os.path.join(tree, APP_DIR, "ir_box.sh")
    if not os.path.isfile(box):
        problems.append("/opt/ir/app/ir_box.sh missing")
    else:
        bt = open(box, encoding="utf-8").read()
        close = _shell_case_body(bt, "close-fetch")
        if NFT_TABLE_LINE not in bt:
            problems.append(f"ir_box.sh does not set {NFT_TABLE_LINE}")
        for want in FETCH_CLOSE_LINES:
            if want not in close:
                problems.append(f"ir_box.sh close-fetch lacks {want!r}")
        pre = _shell_case_body(bt, "pre-search")
        if '[ "$(fetch_rules)" -eq 0 ]' not in pre or "ruleset_live" not in pre:
            problems.append("ir_box.sh pre-search does not re-check that the fetch chain is empty and the policy is drop")
    rep.add(not problems, "D6. firewall rules",
            f"output: policy drop; loopback, DHCP from systemd-network only, replies from tcp port {port} by ir-search only, "
            "a fetch chain (ir-fetch, resolver DNS) that close-fetch empties and reads back before the search starts; "
            f"input: policy drop, loopback, established, DHCP, tcp port {port}; loaded before networkd"
            if not problems else "; ".join(problems))


def _call_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Call):
        f = node.func
        return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
    return None


def _stmt_index_calling(body: List[ast.stmt], name: str) -> Optional[int]:
    for i, stmt in enumerate(body):
        for node in ast.walk(stmt):
            if _call_name(node) == name:
                return i
    return None


def _function(mod: ast.Module, name: str) -> Optional[ast.FunctionDef]:
    for node in ast.walk(mod):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _imports_closed(stmt: ast.AST) -> bool:
    for node in ast.walk(stmt):
        if isinstance(node, ast.Import):
            if any(a.name == m or a.name.startswith(m + ".") for a in node.names for m in CLOSED_MODULES):
                return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(mod == m or mod.startswith(m + ".") for m in CLOSED_MODULES):
                return True
            if mod == "enclave" and any(a.name == "azure" for a in node.names):
                return True
    return False


def _syscall_passes_tsync(seal: ast.FunctionDef) -> bool:
    for node in ast.walk(seal):
        if _call_name(node) == "syscall" and isinstance(node, ast.Call):
            if any(isinstance(a, ast.Name) and a.id == "SECCOMP_FILTER_FLAG_TSYNC" for a in node.args):
                return True
    return False


def check_seal_order(rep: ImageReport, tree: str) -> None:
    """D7: in the image's own entry points the listener is bound, THEN the process is sealed (no-new-privs + seccomp
    over EVERY thread: TSYNC, read back per task), THEN — in the TDX entry — the closed ranking modules are imported
    and the engine built, THEN requests are served. The quote channel is opened before the seal."""
    problems = []
    m2 = os.path.join(tree, APP_DIR, "m2_entry.py")
    te = os.path.join(tree, APP_DIR, "tdx_entry.py")
    for p in (m2, te):
        if not os.path.isfile(p):
            rep.add(False, "D7. seal before serve", f"/{os.path.relpath(p, tree)} missing")
            return
    m2_text = open(m2, encoding="utf-8").read()
    mod = ast.parse(m2_text)
    main = _function(mod, "main")
    seal = _function(mod, "seal_network")
    if main is None or seal is None:
        problems.append("m2_entry.main or seal_network not found")
    else:
        i_bind = _stmt_index_calling(main.body, "make_server")
        i_seal = _stmt_index_calling(main.body, "seal_network")
        i_serve = _stmt_index_calling(main.body, "serve_forever")
        if None in (i_bind, i_seal, i_serve) or not (i_bind < i_seal < i_serve):
            problems.append(f"m2_entry.main order make_server={i_bind} seal_network={i_seal} serve_forever={i_serve}")
        if not any(isinstance(s, ast.Expr) and _call_name(s.value) == "seal_network" for s in main.body):
            problems.append("seal_network() is not an unconditional top-level statement of main")
        calls = {_call_name(n) for n in ast.walk(seal) if isinstance(n, ast.Call)}
        if not {"prctl", "syscall"} <= calls:
            problems.append("seal_network does not call prctl and syscall")
        flag = next((n.value.value for n in mod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                     and any(isinstance(t, ast.Name) and t.id == "SECCOMP_FILTER_FLAG_TSYNC" for t in n.targets)), None)
        if flag != 1 or not _syscall_passes_tsync(seal):
            problems.append("seal_network does not install the filter with SECCOMP_FILTER_FLAG_TSYNC (= 1): threads alive at the seal stay unsealed")
        src_seal = ast.get_source_segment(m2_text, seal) or ""
        if "/proc/self/task" not in src_seal or "Seccomp:" not in src_seal:
            problems.append("seal_network does not read the seccomp mode back for every thread (/proc/self/task/*/status)")
    te_text = open(te, encoding="utf-8").read()
    tmod = ast.parse(te_text)
    tmain = _function(tmod, "main")
    if tmain is None:
        problems.append("tdx_entry.main not found")
    else:
        if any(_imports_closed(stmt) for stmt in tmod.body if not isinstance(stmt, ast.FunctionDef)):
            problems.append("tdx_entry imports a closed module at module level (before the seal)")
        i_chan = _stmt_index_calling(tmain.body, "open_quote_channel")
        i_bind = _stmt_index_calling(tmain.body, "bind_server")
        i_seal = _stmt_index_calling(tmain.body, "seal_network")
        i_engine = next((i for i, st in enumerate(tmain.body) if _imports_closed(st)
                         or any(_call_name(n) == "build_service" for n in ast.walk(st))), None)
        i_serve = _stmt_index_calling(tmain.body, "serve_forever")
        if None in (i_chan, i_bind, i_seal, i_engine, i_serve) or not (i_chan < i_seal and i_bind < i_seal < i_engine < i_serve):
            problems.append(f"tdx_entry.main order open_quote_channel={i_chan} bind_server={i_bind} seal_network={i_seal} "
                            f"engine={i_engine} serve_forever={i_serve}; want channel and bind, then seal, then engine, then serve")
        if not any(isinstance(s, ast.Expr) and _call_name(s.value) == "seal_network" for s in tmain.body):
            problems.append("seal_network() is not an unconditional top-level statement of tdx_entry.main")
        if _stmt_index_calling(tmain.body, "make_server") is not None:
            problems.append("tdx_entry.main calls make_server (binding and the engine in one step)")
    rep.add(not problems, "D7. seal before serve",
            "m2_entry.main: make_server, then seal_network (no-new-privs + seccomp with TSYNC, mode read back for every thread), "
            "then serve_forever; tdx_entry.main: quote channel and bind_server, then seal_network, then the closed engine "
            "(build_service), then serve_forever; no closed module imported before the seal"
            if not problems else "; ".join(problems))


# ──────────────────────────────────────────── D8/D9: initrd and ESP ─────────────────────────────────────────────────

def zstd_frames(data: bytes) -> List[bytes]:
    """Decompress a sequence of zstd frames separated by NUL padding (how mkosi appends the kernel-modules initrd).
    Uses the zstandard module if present, else the zstd CLI. Raises if neither."""
    out, pos = [], 0
    try:
        zstandard = importlib.import_module("zstandard")  # optional; the client ships stdlib-only code
        dctx = zstandard.ZstdDecompressor(max_window_size=2 ** 31)
        while pos < len(data):
            while pos < len(data) and data[pos] == 0:
                pos += 1
            if pos >= len(data):
                break
            dobj = dctx.decompressobj()
            out.append(dobj.decompress(data[pos:]))
            pos = len(data) - len(dobj.unused_data)
        return out
    except ImportError:
        pass
    tool = shutil.which("zstd")
    if not tool:
        raise RuntimeError("neither the zstandard module nor the zstd tool is available")
    while pos < len(data):
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos >= len(data):
            break
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zst") as tf:
            tf.write(data[pos:])
            name = tf.name
        try:
            # zstd stops at the frame end and reports the consumed size with -v; simpler: decompress the first frame
            r = subprocess.run([tool, "-dc", "--long=31", "--memory=2048MB", "--no-check", name], capture_output=True)
            out.append(r.stdout)
            # consumed = total minus what -l reports? Not exposed; fall back to the frame header walk below.
            pos = _zstd_frame_end(data, pos)
        finally:
            os.unlink(name)
    return out


def _zstd_frame_end(data: bytes, start: int) -> int:
    """Walk one zstd frame's blocks to find where it ends (RFC 8878), without decompressing."""
    p = start + 4
    fhd = data[p]
    p += 1
    single = (fhd >> 5) & 1
    fcs_flag = fhd >> 6
    did = fhd & 3
    if not single:
        p += 1
    p += (0, 1, 2, 4)[did]
    p += (1 if single else 0, 2, 4, 8)[fcs_flag]
    while True:
        hdr = int.from_bytes(data[p:p + 3], "little")
        last, btype, bsize = hdr & 1, (hdr >> 1) & 3, hdr >> 3
        p += 3 + (1 if btype == 1 else bsize)
        if last:
            break
    if (fhd >> 2) & 1:                                       # content checksum
        p += 4
    return p


def cpio_names(d: bytes) -> List[str]:
    """Entry names of a newc cpio archive (concatenated archives included)."""
    names, p = [], 0
    while p + 110 <= len(d):
        if d[p:p + 6] != b"070701":
            if d[p:p + 4] == b"\0\0\0\0":
                p += 4
                continue
            break
        h = d[p:p + 110]
        fsize, nsize = int(h[54:62], 16), int(h[94:102], 16)
        name = d[p + 110:p + 110 + nsize - 1].decode("utf-8", "replace")
        p = (p + 110 + nsize + 3) & ~3
        p = (p + fsize + 3) & ~3
        if name != "TRAILER!!!":
            names.append(name)
    return names


def check_initrd(rep: ImageReport, initrd: bytes) -> None:
    """D8: the initrd inside the UKI carries what mounts the verity root and nothing that opens a door."""
    try:
        frames = zstd_frames(initrd)
    except Exception as exc:                                # noqa: BLE001
        rep.add(None, "D8. initrd", f"could not decompress ({exc})")
        return
    names = [n for f in frames for n in cpio_names(f)]
    missing = [r for r in INITRD_REQUIRED if not any(r in n for n in names)]
    bad = [n for n in names if any(f in os.path.basename(n) for f in INITRD_FORBIDDEN)]
    ok = bool(names) and not missing and not bad
    rep.add(ok, "D8. initrd", f"{len(frames)} archive(s), {len(names)} entries; veritysetup generator, dm-verity and erofs present; no ssh"
            if ok else (f"missing {missing}" if missing else "") + (f" forbidden {bad[:3]}" if bad else "") + ("" if names else " empty"))
    rep.values["initrd_entries"] = len(names)


def check_esp(rep: ImageReport, esp_img: Optional[str], uki_sha256: str) -> None:
    """D9: the ESP as PUBLISHED holds only the UKI and no stub pick-up directories. The ESP a machine boots from is
    not measured, so this is a statement about the published image, never about a boot."""
    if not esp_img:
        rep.add(None, "D9. published ESP", "no esp.img supplied")
        return
    mdir, mcopy = shutil.which("mdir"), shutil.which("mcopy")
    if not (mdir and mcopy):
        rep.add(None, "D9. published ESP", "mtools (mdir, mcopy) not available to read the FAT partition")
        return
    r = subprocess.run([mdir, "-i", esp_img, "-/", "-b", "::/"], capture_output=True, text=True)
    entries = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    bad = [e for e in entries if any(f in e.lower() for f in ESP_FORBIDDEN)]
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "boot.efi")
        subprocess.run([mcopy, "-i", esp_img, "-n", "::/EFI/BOOT/BOOTX64.EFI", out], capture_output=True)
        same = os.path.isfile(out) and hashlib.sha256(open(out, "rb").read()).hexdigest() == uki_sha256
    rep.add(same and not bad, "D9. published ESP",
            f"{len(entries)} entries; /EFI/BOOT/BOOTX64.EFI is the published UKI; no .extra.d, addons or credentials "
            "directories (as published — the running ESP is not measured)" if same and not bad else
            ("BOOTX64.EFI is not the published UKI; " if not same else "") + (f"stub pick-up paths present: {bad[:4]}" if bad else ""))


# ──────────────────────────────────────────── the whole image ───────────────────────────────────────────────────────

def verify_image(artefacts: str, *, source: Optional[str] = None, root_tree: Optional[str] = None,
                 expect_image_sha384: Optional[str] = None, expect_loads: Optional[List[str]] = None,
                 keep_tree: Optional[str] = None, stated_commit: Optional[str] = None) -> ImageReport:
    """Every row for one published image. `root_tree` is an already-opened root (skips fsck.erofs); `keep_tree`
    names where to extract to (else a temporary directory, removed afterwards)."""
    rep = ImageReport()
    uki_path, root_path = os.path.join(artefacts, "uki.efi"), os.path.join(artefacts, "root.img")
    verity_path, esp_path = os.path.join(artefacts, "verity.img"), os.path.join(artefacts, "esp.img")
    src = Source(source) if source else None
    # A/B: the UKI
    if not os.path.isfile(uki_path):
        rep.add(False, "A. published UKI is the measured image", f"{uki_path} missing")
        return rep
    uki = open(uki_path, "rb").read()
    rep.values["uki_sha256"] = hashlib.sha256(uki).hexdigest()
    try:
        sections = pe_sections(uki)
        image_sha384 = authenticode_sha384(uki)
    except Exception as exc:                                # noqa: BLE001
        rep.add(False, "A. published UKI is the measured image", f"uki.efi is not a PE image ({type(exc).__name__})")
        return rep
    rep.values["image_sha384"] = image_sha384
    if expect_image_sha384:
        same = image_sha384 == expect_image_sha384.lower()
        rep.add(same, "A. published UKI is the measured image",
                f"Authenticode SHA-384 of uki.efi {image_sha384[:16]}… {'==' if same else '!='} the measured image {expect_image_sha384[:16]}…")
    else:
        rep.add(None, "A. published UKI is the measured image", f"Authenticode SHA-384 {image_sha384[:16]}…; nothing to compare it with")
    kernel_sha384 = None
    if ".linux" in sections:
        try:
            kernel_sha384 = authenticode_sha384(sections[".linux"])
        except Exception:                                   # noqa: BLE001
            kernel_sha384 = None
    rep.values["kernel_sha384"] = kernel_sha384
    if expect_loads is not None:
        same = kernel_sha384 is not None and [kernel_sha384] == [x.lower() for x in expect_loads]
        rep.add(same, "A. published UKI loads the named kernel",
                f"Authenticode SHA-384 of the embedded kernel {str(kernel_sha384)[:16]}… {'==' if same else '!='} the application the reference says it loads")
    else:
        rep.add(None, "A. published UKI loads the named kernel", f"embedded kernel {str(kernel_sha384)[:16]}…; nothing to compare it with")
    names = set(sections)
    rep.add(names == UKI_SECTIONS, "B. UKI sections",
            f"exactly the expected sections ({', '.join(sorted(names))})" if names == UKI_SECTIONS else
            f"unexpected {sorted(names - UKI_SECTIONS)}, missing {sorted(UKI_SECTIONS - names)}")
    tokens = cmdline_tokens(sections.get(".cmdline", b""))
    ok, why = check_cmdline(tokens)
    rep.add(ok, "B. UKI command line", why)
    rep.values["cmdline"] = " ".join(tokens)
    roothash = roothash_of(tokens)
    rep.values["roothash"] = roothash
    # C: the root bytes
    if not os.path.isfile(root_path):
        rep.add(False, "C. root bytes hash to the roothash", f"{root_path} missing")
    elif not roothash:
        rep.add(False, "C. root bytes hash to the roothash", "no roothash= on the command line")
    elif not os.path.isfile(verity_path):
        rep.add(False, "C. root bytes hash to the roothash", f"{verity_path} missing (it carries the salt and block sizes)")
    else:
        try:
            sb = verity_superblock(open(verity_path, "rb").read(512))
            got = verity_roothash(root_path, sb)
            rep.values["root_sha256"] = _sha256_file(root_path)
            rep.values["verity_sha256"] = _sha256_file(verity_path)
            rep.add(got == roothash, "C. root bytes hash to the roothash",
                    f"{sb['algorithm']} over {sb['data_blocks']} blocks of {sb['data_block_size']} B recomputes to {got[:16]}… "
                    f"{'==' if got == roothash else '!='} the command line's roothash")
        except Exception as exc:                            # noqa: BLE001
            rep.add(False, "C. root bytes hash to the roothash", f"could not recompute ({type(exc).__name__}: {exc})")
    # D: inside the root
    tmp = None
    tree = root_tree
    try:
        if tree is None and os.path.isfile(root_path):
            dest = keep_tree or (tmp := tempfile.mkdtemp(prefix="ir-root-"))
            try:
                tree = extract_erofs(root_path, dest)
            except Exception as exc:                        # noqa: BLE001
                rep.add(False, "D. root opened", str(exc))
                tree = None
        if tree is None:
            rep.add(None if os.path.isfile(root_path) else False, "D. root opened",
                    "fsck.erofs not available to open root.img — rows D1-D7 not assessed (pass --root-tree with an extracted root)"
                    if os.path.isfile(root_path) else "no root.img")
        else:
            rep.add(True, "D. root opened", f"{sum(len(f) for _d, _s, f in os.walk(tree))} files" + (" (pre-extracted tree supplied)" if root_tree else ""))
            check_sources(rep, tree, src, stated_commit)
            check_bytecode(rep, tree)
            check_records(rep, tree, src)
            check_unit(rep, tree, src)
            check_units(rep, tree)
            check_egress(rep, tree)
            check_seal_order(rep, tree)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    check_initrd(rep, sections.get(".initrd", b""))
    check_esp(rep, esp_path if os.path.isfile(esp_path) else None, rep.values["uki_sha256"])
    return rep


def rows_for_measured(report: ImageReport, image_sha384: Optional[str], boot_apps: Optional[List[str]]) -> Tuple[List[Tuple[str, str, str]], bool]:
    """The report's rows re-anchored to ONE measured boot: row A compares the published UKI with the image the quote
    names and the applications it then loaded. Returns (rows, posture_verified) — verified only if every required
    row, these two included, passed and nothing failed. Lets a record verifier compute the image once and judge it
    against each search's own quote."""
    out = ImageReport()
    pub, kern = report.values.get("image_sha384"), report.values.get("kernel_sha384")
    if not image_sha384:
        out.add(False, "A. published UKI is the measured image", "this search's quote names no measured image")
    else:
        same = pub is not None and pub == image_sha384.lower()
        out.add(same, "A. published UKI is the measured image",
                f"Authenticode SHA-384 of the published uki.efi {str(pub)[:16]}… {'==' if same else '!='} the image this quote measured {image_sha384[:16]}…")
    later = [x.lower() for x in (boot_apps or [])[1:]]
    same_k = kern is not None and later == [kern]
    out.add(same_k, "A. published UKI loads the named kernel",
            f"after the image the firmware measured {len(later)} application(s); the published UKI's embedded kernel is {str(kern)[:16]}… "
            + ("and that is the one" if same_k else "and that is NOT what was loaded"))
    for row in report.rows:
        if not row[1].startswith("A. "):
            out.rows.append(row)
    return out.rows, out.posture_verified


def _sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 24), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Check a published Intel TDX image (uki.efi, root.img, verity.img) mechanically.")
    ap.add_argument("artefacts", help="directory holding uki.efi, root.img, verity.img (and optionally esp.img)")
    ap.add_argument("--source", default=None, metavar="PATH", help="the published source: a git checkout or an unpacked tarball")
    ap.add_argument("--root-tree", default=None, metavar="DIR", help="an already-extracted root (skips fsck.erofs)")
    ap.add_argument("--keep-tree", default=None, metavar="DIR", help="extract the root here and keep it")
    ap.add_argument("--expect-image-sha384", default=None, help="the measured image (the record's RTMR1 first application)")
    ap.add_argument("--expect-loads", default=None, help="comma-separated Authenticode hashes the image may load (reference `loads`)")
    ap.add_argument("--commit", default=None, metavar="HEX", help="for an image without /etc/inferroute-source-commit: compare files at this commit (that row still fails)")
    ap.add_argument("--json", action="store_true", help="also print the rows and computed values as JSON")
    a = ap.parse_args(argv)
    rep = verify_image(a.artefacts, source=a.source, root_tree=a.root_tree, keep_tree=a.keep_tree,
                       expect_image_sha384=a.expect_image_sha384, stated_commit=a.commit,
                       expect_loads=a.expect_loads.split(",") if a.expect_loads else None)
    print("Published image checks")
    rep.dump()
    print()
    for k in ("uki_sha256", "image_sha384", "kernel_sha384", "roothash", "root_sha256", "verity_sha256", "source_commit", "cmdline"):
        if rep.values.get(k):
            print(f"  {k}: {rep.values[k]}")
    print()
    print("POSTURE: " + ("VERIFIED — every required row passed" if rep.posture_verified else
                         "NOT VERIFIED — " + ", ".join(f"{s} {n}" for s, n, _ in rep.rows if s != "PASS" and n in REQUIRED_ROWS)))
    if a.json:
        print(json.dumps({"rows": rep.rows, "values": rep.values, "posture_verified": rep.posture_verified}, indent=1, default=str))
    return 0 if rep.posture_verified else 1


if __name__ == "__main__":
    sys.exit(main())
