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
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ──────────────────────────────────────────── what the closed box must look like ────────────────────────────────────

# The UKI's command line, token by token. Every token must be in one of these three sets; every token of REQUIRED
# must be present. `systemd.import_credentials=no` is what stops PID 1 from taking configuration from unmeasured host
# inputs (SMBIOS OEM strings, files on the ESP) — v12.
CMDLINE_REQUIRED = ("systemd.volatile=overlay", "systemd.show_status=0", "quiet", "loglevel=0", "panic=-1",
                    "accept_memory=eager", "systemd.import_credentials=no")
# v13 is RETIRED: this checker accepts v14 only; a v13 image fails row B by name and reaches no level-1 sentence. The
# verifier keeps v13's wording for reports a v13-era checker produced, never for an image this one checked.
IMAGE_NAME = "ir-sealed-search-tdx-v17"          # the current release
# v15 (8 Nov 2026) adds idle=poll: the guest never halts, which removes the halt exits that show the hypervisor when a
# vCPU is idle (measured: Google's per-minute cpu/utilization of a v14 box reads idle 0.03 % vs searching 1.26 %; with
# idle=poll a flat 99.8-99.97 %, shared/qa/2026-11-08/idle-poll-test). NOT removed: per-request bursts of
# interprocessor interrupts (TLB shootdowns from the engine child's fork/exit), virtio interrupts, power and frequency,
# cache and memory-bandwidth contention. v14 stays accepted exactly as before, so records made on
# signed v14 images keep their level; each version must carry exactly its own required tokens.
# v16 (9 Nov 2026) keeps v15's command line (idle=poll); what changed is inside the root (front exception fix, encoder
# allowlist, a root pin that sees the whole root, reproducible build). The rows decide; the name only selects the tokens.
# v17 (10 Nov 2026) keeps v16's command line; inside the root the engine does a fixed amount of work per request
# (open_rank/shape.py), checked by row "D7. the engine does a fixed amount of work per request".
IMAGE_NAMES = ("ir-sealed-search-tdx-v14", "ir-sealed-search-tdx-v15", "ir-sealed-search-tdx-v16", "ir-sealed-search-tdx-v17")
CMDLINE_REQUIRED_BY_IMAGE = {"ir-sealed-search-tdx-v14": (), "ir-sealed-search-tdx-v15": ("idle=poll",),
                             "ir-sealed-search-tdx-v16": ("idle=poll",), "ir-sealed-search-tdx-v17": ("idle=poll",)}
CMDLINE_PATTERNS = (re.compile(r"roothash=[0-9a-f]{64}"),
                    re.compile(r"inferroute\.image=(?:" + "|".join(re.escape(n) for n in IMAGE_NAMES) + r")"))
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
EGRESS_OUTPUT_EXPECTED = ("type filter hook output priority 0; policy drop;", 'meta skuid "ir-engine" drop', 'oif "lo" accept',
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
# system, kernel interfaces hidden, W^X with no executable scratch (v14: NoExecPaths over every mount the process can
# write, memfd_create refused — a written file mapped executable is how W^X is sidestepped), one syscall allowlist.
# Each unit then adds its own lines. A value may be a list when the key is given more than once.
NOEXEC_SCRATCH = "/tmp /var/tmp /dev/shm /run /ram"
SANDBOX_REQUIRED = {"NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
                    "PrivateDevices": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                    "NoExecPaths": NOEXEC_SCRATCH,
                    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
                    "ProtectControlGroups": "yes", "ProtectClock": "yes", "LockPersonality": "yes",
                    "MemoryDenyWriteExecute": "yes", "RestrictNamespaces": "yes", "RestrictRealtime": "yes",
                    "RestrictSUIDSGID": "yes", "SystemCallArchitectures": "native",
                    "SystemCallFilter": ["@system-service", "~memfd_create:EPERM"],
                    "StandardOutput": "null", "StandardError": "null", "LimitCORE": "0"}
# The interpreters run in isolated mode (-I: no site, no PYTHON* environment, no script-directory path entry); each
# program sets its own sys.path (v14 round 3; -u before).
# seccomp(2) is not in @system-service; the two units that seal themselves allow it (measured: SIGSYS otherwise).
SEARCH_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "User": "ir-search", "Group": "ir-search", "Restart": "no",
                        "SystemCallFilter": ["@system-service", "seccomp", "~memfd_create:EPERM"],
                        "ExecStart": "/opt/ir/venv/bin/python -I /opt/ir/app/tdx_entry.py",
                        "ExecStartPre": "+/bin/sh /opt/ir/app/ir_box.sh pre-search",
                        "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "ReadOnlyPaths": "/ram -/dev/mqueue",
                        "InaccessiblePaths": "-/dev/mqueue", "LimitMSGQUEUE": "0", "FailureAction": "poweroff-force"}
# The engine (v14 round 3): no FailureAction (the closed code must not be able to power the box off at a chosen
# moment: a dead engine leaves the front up, refusing with signed engine_errors of the same size at the same slot),
# NO writable path (no runtime directory, no private /tmp: read-only empty tmpfs at /tmp and /var/tmp, /dev/shm
# read-only), the rest of the root hidden, and no way to another process's descriptors.
ENGINE_INACCESSIBLE = "-/dev/mqueue /var /usr/share /etc/systemd /etc/nftables.conf -/boot -/efi -/usr/local -/usr/src -/usr/include -/srv -/mnt -/media -/etc/ssl"
ENGINE_TMPFS = "/tmp:ro,noexec,nosuid,nodev /var/tmp:ro,noexec,nosuid,nodev"
ENGINE_UNIT_REQUIRED = {**{k: v for k, v in SANDBOX_REQUIRED.items() if k != "PrivateTmp"},
                        "User": "ir-engine", "Group": "ir-engine", "Restart": "no",
                        # a socket-activated crash loop ends (rc2 restarted a failing engine for an hour)
                        "StartLimitIntervalSec": "10min", "StartLimitBurst": "3",
                        "ExecStart": "/opt/ir/venv/bin/python -I /opt/ir/app/tdx_engine.py",
                        "ExecStartPre": "+/bin/sh /opt/ir/app/ir_box.sh pre-engine",
                        "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX",
                        "ReadOnlyPaths": "/ram /dev/shm -/dev/hugepages -/dev/mqueue", "LimitMSGQUEUE": "0",
                        "DevicePolicy": "strict", "DeviceAllow": ["/dev/null rw", "/dev/zero r", "/dev/urandom r", "/dev/random r"],
                        "TemporaryFileSystem": ENGINE_TMPFS, "InaccessiblePaths": ENGINE_INACCESSIBLE,
                        "SystemCallFilter": ["@system-service", "seccomp", "~memfd_create:EPERM",
                                             "~ptrace pidfd_getfd process_vm_readv process_vm_writev:EPERM"]}
# Keys the engine unit must not carry, in any section, after drop-ins are applied.
ENGINE_UNIT_FORBIDDEN = ("FailureAction", "OnFailure", "RuntimeDirectory", "StateDirectory", "CacheDirectory",
                         "LogsDirectory", "ConfigurationDirectory", "PrivateTmp", "ReadWritePaths", "BindPaths")
# The root pin (v14 round 3): root with CAP_IPC_LOCK (mlockall) and CAP_DAC_READ_SEARCH (read every file), notify.
# v16: the pin must SEE the whole root, so no key that hides a path from it (ProtectKernelModules hid /usr/lib/modules,
# measured on the 8 Nov diagnostic boot: 174 MB unpinned while the pin's own check passed).
PIN_UNIT_REQUIRED = {**{k: v for k, v in SANDBOX_REQUIRED.items() if k not in ("ProtectKernelModules", "ProtectHome")},
                     "NoExecPaths": "/tmp /var/tmp /dev/shm /run",
                     "CapabilityBoundingSet": "CAP_IPC_LOCK CAP_DAC_READ_SEARCH",
                     "AmbientCapabilities": "CAP_IPC_LOCK CAP_DAC_READ_SEARCH", "LimitMEMLOCK": "infinity",
                     "Type": "notify", "NotifyAccess": "main", "ExecStart": "/usr/bin/python3 -I /opt/ir/app/ir_pin.py",
                     "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX", "Restart": "no",
                     # one descriptor per root file (mmap keeps a dup); the read-and-lock took ~86 s on pd-balanced
                     "LimitNOFILE": "1048576", "TimeoutStartSec": "20min",
                     "FailureAction": "poweroff-force"}
PIN_UNIT_FORBIDDEN = ("ProtectKernelModules", "ProtectHome", "InaccessiblePaths", "TemporaryFileSystem", "BindPaths",
                      "BindReadOnlyPaths", "RootDirectory", "RootImage", "MountImages", "ExtensionImages", "PrivateMounts",
                      "ReadOnlyPaths", "ReadWritePaths")
# The only directories of the root the pin may leave unwalked (another filesystem; each empty in the image).
PIN_OTHER_FILESYSTEMS = frozenset({"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/ram", "/efi", "/boot"})
# Images released before v16 are checked, on rows "D4. pin unit properties" and "D7. the warm parent parses data, not
# code", by exactly the rules the v15-era checker (dcb384a) applied, so a record made on a signed v14/v15 image keeps
# its level. Every other name -- v16, later, unknown or absent -- gets the v16 rules (fail closed). The v15 pin rules
# are KNOWN to pass a pin that could not see the whole root (ProtectKernelModules hid /usr/lib/modules: 174 MB
# unpinned, shared/qa/2026-11-09/v16-diag); the record verifier therefore never prints the pin clause for these images.
V15_RULES_IMAGES = ("ir-sealed-search-tdx-v14", "ir-sealed-search-tdx-v15")
V15_RULES_PREFIX = "v15 rules: "
# The v15-era pin unit: the whole sandbox set (ProtectKernelModules and ProtectHome included), no forbidden key.
V15_PIN_UNIT_REQUIRED = {**SANDBOX_REQUIRED, **PIN_UNIT_REQUIRED}


def rules_for(rep: "ImageReport") -> str:
    """Which rule set rows D4 pin and D7 parses-data apply: "v15" only when the checked command line names exactly one
    image and it is v14 or v15; "v16" otherwise (v16, later, unknown, absent, or two names: the strict rules)."""
    names = [t.split("=", 1)[1] for t in str(rep.values.get("cmdline") or "").split() if t.startswith("inferroute.image=")]
    return "v15" if len(names) == 1 and names[0] in V15_RULES_IMAGES else "v16"
# One reply slot and one engine budget, in the units' Environment= (both numbers in seconds; the engine's budget
# must equal the front's and lie below the slot).
ENV_SLOT, ENV_BUDGET = "IR_REPLY_SLOT_SECONDS", "IR_ENGINE_BUDGET_SECONDS"
ENV_SURVEY_SLOT, ENV_SURVEY_BUDGET = "IR_SURVEY_SLOT_SECONDS", "IR_SURVEY_BUDGET_SECONDS"   # rc9: the survey's own slot
ENGINE_SOCKET_REQUIRED = {"ListenStream": "/run/ir-engine.sock", "SocketUser": "root", "SocketGroup": "ir-search",
                          "SocketMode": "0660"}
# Group=ir-index (v14 rc2): what the fetch writes is created in the group the front and the engine read through.
FETCH_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "User": "ir-fetch", "Group": "ir-index", "Type": "oneshot",
                       "RemainAfterExit": "yes", "ExecStart": "/opt/ir/venv/bin/python -I /opt/ir/app/tdx_fetch.py",
                       "ExecStartPre": "+/bin/sh /opt/ir/app/ir_box.sh pre-fetch", "ExecStartPost": FETCH_CLOSE_STEP,
                       "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "ReadWritePaths": "/ram",
                       "FailureAction": "poweroff-force"}
# The /ram mount (v14 rc2): its own root oneshot, in the host's mount namespace (no sandboxing that would give it a
# private one), CAP_SYS_ADMIN only, before the fetch, and fatal to the box if it fails. ir_box.sh mount-ram is checked
# line by line below (RAM_MOUNT_LINES).
RAM_UNIT = "ir-ram.service"
RAM_UNIT_REQUIRED = {"Type": "oneshot", "RemainAfterExit": "yes", "ExecStart": "/bin/sh /opt/ir/app/ir_box.sh mount-ram",
                     "NoNewPrivileges": "yes", "CapabilityBoundingSet": "CAP_SYS_ADMIN", "StandardOutput": "null",
                     "StandardError": "null", "LimitCORE": "0", "FailureAction": "poweroff-force",
                     "Before": "ir-fetch.service"}
RAM_MOUNT_LINES = ('if mountpoint -q "$RAM"; then exit 1; fi', "noexec,nosuid,nodev", "size=${size_kb}k", "mode=0750",
                   "uid=$(id -u ir-fetch),gid=$(getent group ir-index | cut -d: -f3)")
QUOTE_UNIT_REQUIRED = {**SANDBOX_REQUIRED, "NoExecPaths": "/tmp /var/tmp /dev/shm /run",
                       "ExecStart": "/usr/bin/python3 -I /opt/ir/app/ir_quote.py",
                       "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX",
                       "ReadWritePaths": "/sys/kernel/config", "Restart": "no",
                       # the once-per-boot markers survive a restart of the helper
                       "RuntimeDirectory": "ir-quote", "RuntimeDirectoryMode": "0700", "RuntimeDirectoryPreserve": "yes"}
QUOTE_SOCKET_REQUIRED = {"ListenStream": "/run/ir-quote.sock", "SocketUser": "root", "SocketGroup": "ir-quote",
                         "SocketMode": "0660"}
# Unit -> (required properties, dependencies that must appear in Requires= AND After=).
UNITS_EXPECTED = {
    "ir-search.service": (SEARCH_UNIT_REQUIRED, ("ir-fetch.service", "ir-pin.service", "ir-quote.socket", "ir-engine.socket")),
    "ir-engine.service": (ENGINE_UNIT_REQUIRED, ("ir-fetch.service", "ir-pin.service", "ir-engine.socket")),
    "ir-engine.socket": (ENGINE_SOCKET_REQUIRED, ()),
    "ir-fetch.service": (FETCH_UNIT_REQUIRED, ("nftables.service", "network-online.target", "ir-quote.socket", RAM_UNIT)),
    "ir-quote.service": (QUOTE_UNIT_REQUIRED, ("ir-quote.socket", "sys-kernel-config.mount")),
    "ir-quote.socket": (QUOTE_SOCKET_REQUIRED, ()),
    "ir-pin.service": (PIN_UNIT_REQUIRED, ()),
}
UNIT_FORBIDDEN_KEYS = ("StandardInput", "TTYPath")
# Keys systemd reads from [Unit]; every other required key is read from [Service] (or [Socket]). A key under the
# wrong section is one systemd IGNORES: the old section-blind parser passed `NoNewPrivileges=yes` under [Install].
UNIT_SECTION_KEYS = frozenset({"Description", "Documentation", "Requires", "Requisite", "Wants", "BindsTo", "PartOf",
                               "Conflicts", "Before", "After", "OnFailure", "OnSuccess", "FailureAction", "SuccessAction",
                               "RequiresMountsFor", "StartLimitIntervalSec", "StartLimitBurst", "DefaultDependencies"})
# Where systemd looks for units and drop-ins, in precedence order (the image tree never carries /run; said anyway).
UNIT_LAYERS = ("run/systemd/generator.early", "etc/systemd/system", "run/systemd/system", "run/systemd/generator",
               "usr/local/lib/systemd/system", "usr/lib/systemd/system", "run/systemd/generator.late")
# Units whose drop-in directories, in every layer, may hold only what the source stages (the two drop-ins under
# etc/systemd/system/*.d in mkosi.extra), and which may exist in no layer but the one the source puts them in.
DROPIN_GUARDED = ("ir-search.service", "ir-engine.service", "ir-engine.socket", "ir-fetch.service", RAM_UNIT, "ir-quote.service",
                  "ir-quote.socket", "ir-pin.service", "nftables.service", "systemd-networkd.service", "systemd-sysctl.service")
GENERATOR_ADMIN_DIRS = ("etc/systemd/system-generators", "usr/local/lib/systemd/system-generators", "run/systemd/system-generators")
GENERATOR_FORBIDDEN = ("usr/lib/systemd/system-generators/systemd-getty-generator",)
MANAGER_CONF_DIRS = ("etc/systemd/system.conf.d", "usr/lib/systemd/system.conf.d", "run/systemd/system.conf.d",
                     "etc/systemd/system.control", "run/systemd/system.control", "etc/systemd/system.attached",
                     "run/systemd/system.attached", "run/systemd/transient")
NFT_VENDOR_UNIT = "usr/lib/systemd/system/nftables.service"
NFT_EXEC_START = "/usr/sbin/nft -f /etc/nftables.conf"
SYSCTL_FILE = "etc/sysctl.d/50-ir-closed-box.conf"
SYSCTL_REQUIRED = {"kernel.yama.ptrace_scope": "3", "vm.max_map_count": "1048576"}
# The accounts the units and the firewall name: present, no login shell, no password.
ACCOUNTS_REQUIRED = ("ir-fetch", "ir-search", "ir-engine")
# Their fixed ids (usr/lib/sysusers.d/ir-sealed.conf; rc1 got dynamic ones because sysusers rejected its descriptions),
# the two shared groups, and exactly who is in them. The fetch unit runs with Group=ir-index, but that is the process's
# group, set by systemd: in /etc/passwd ir-fetch's primary group is its own (850), and NO account has a shared group as
# its passwd primary group, which would make it an unlisted member.
ACCOUNT_UIDS = {"ir-fetch": 850, "ir-search": 851, "ir-engine": 853}
GROUP_GIDS = {"ir-quote": 852, "ir-index": 854}
GROUP_MEMBERS = {"ir-quote": {"ir-fetch", "ir-search"}, "ir-index": {"ir-search", "ir-engine"}}
# The files whose source was not published (the ranking engine, v14 and v15), as paths under /opt/ir/app. They ran in
# the engine process only; the front's import graph (row D7) must not reach them, and row D1 checks them by published
# hash. v16 (design A) stages NONE of them: the engine is sealedresearch.open_rank, published, and what stays private
# is data under the index root. Which files a release treats as closed is read from its source's CLOSED_PINS_SRC
# (v15: these 7; v16: none), so one checker verifies both; with no pins, row D1 refuses any of these paths in the
# image and any staged file importing one of CLOSED_FILE_MODULES (closed_residue).
CLOSED_FILES = ("enclave/azure/m2_ranker.py", "enclave/azure/m2_searcher.py", "sealedresearch/rank_pipeline.py",
                "sealedresearch/survey_legs.py", "sealedresearch/survey_run.py", "sealedresearch/passages.py",
                "sealedresearch/patent_ann.py")
CLOSED_PINS_SRC = "enclave/gcp-tdx/closed-files.sha256"       # "<sha256>  <path under /opt/ir/app>" per closed file
CLOSED_FILE_MODULES = tuple(f[:-3].replace("/", ".") for f in CLOSED_FILES)
# v16: the published engine. The child must reach it (or, v15, the closed modules); the warm parent and the front
# must not reach it, exactly as they must not reach the closed modules.
ENGINE_OPEN = ("sealedresearch.open_rank",)
# What confine.seal_memory must refuse before the closed import (x86_64 numbers), checked against the source's own
# table AND the assembled BPF program: every one of these as a jeq target, plus mmap's argument rule.
MEMORY_SEAL_REQUIRED = {"shmget": 29, "shmat": 30, "shmctl": 31, "shmdt": 67, "semget": 64, "semop": 65, "semctl": 66,
                        "semtimedop": 220, "msgget": 68, "msgsnd": 69, "msgrcv": 70, "msgctl": 71, "mq_open": 240,
                        "mq_unlink": 241, "mq_timedsend": 242, "mq_timedreceive": 243, "mq_notify": 244, "mq_getsetattr": 245,
                        "add_key": 248, "request_key": 249, "keyctl": 250, "userfaultfd": 323, "process_madvise": 440,
                        "mremap": 25, "remap_file_pages": 216, "memfd_create": 319, "memfd_secret": 447, "io_uring_setup": 425,
                        "io_uring_enter": 426, "io_uring_register": 427, "creat": 85, "openat2": 437, "mknod": 133,
                        "mknodat": 259, "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "pidfd_getfd": 438,
                        "kcmp": 312}
# Modules the published front must never import, directly or through any module it imports (CLOSED_FILES as
# module names, the Azure entry whose functions import them, and the engine's libraries).
CLOSED_MODULES = ("enclave.azure.m2_ranker", "enclave.azure.m2_searcher", "enclave.azure", "m2_entry", "torch", "faiss",
                  "sentence_transformers", "lightgbm", "numpy", "bm25s", "duckdb", "pyarrow", "sealedresearch.rank_pipeline",
                  "sealedresearch.survey_legs", "sealedresearch.survey_run", "sealedresearch.passages",
                  "sealedresearch.patent_ann", "tdx_engine", "tdx_fetch") + ENGINE_OPEN
# The closed modules PROPER (the Azure entry, the ranking code, the child's entry): what the engine's warm parent may
# not reach by import either. The libraries in CLOSED_MODULES are the parent's to hold (engine_preload), not the front's.
CLOSED_PROPER = ("enclave.azure.m2_ranker", "enclave.azure.m2_searcher", "enclave.azure", "m2_entry", "sealedresearch.rank_pipeline",
                 "sealedresearch.survey_legs", "sealedresearch.survey_run", "sealedresearch.passages", "sealedresearch.patent_ann",
                 "tdx_child")
ENGINE_PROPER = CLOSED_PROPER + ENGINE_OPEN       # what the warm parent may not reach, and what the child must
ENGINE_ENTRY = "tdx_engine.py"
FRONT_ENTRY = "tdx_entry.py"
FETCH_ENTRY = "tdx_fetch.py"                      # runs while egress is open: its import graph is checked like the front's
STDLIB_ONLY = ("ir_quote.py", "ir_pin.py")        # root helpers on the system interpreter: stdlib imports only

# Units that must be masked (/etc/systemd/system/<name> -> /dev/null): every console login path, the ESP automounts
# (a writable, host-readable partition), and every timer or service that reaches the network on its own.
MASKED_REQUIRED = ("getty.target", "getty@.service", "serial-getty@.service", "console-getty.service",
                   "autovt@.service", "efi.automount", "efi.mount", "boot.automount", "boot.mount", "motd-news.timer",
                   "systemd-sysupdate.timer", "systemd-sysupdate-reboot.timer", "systemd-boot-update.service")
# Every enabled unit under /etc/systemd/system/*.wants (the administrator layer mkosi and we control). Anything
# else is a FAIL that names the unit. Masked units may stay linked here; the mask wins.
ENABLED_ALLOWED = {
    "multi-user.target.wants": {"e2scrub_reap.service", "ir-engine.service", "ir-pin.service", "ir-search.service", "remote-cryptsetup.target",
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
    "sockets.target.wants": {"ir-engine.socket", "ir-quote.socket", "systemd-journald-audit.socket", "systemd-networkd.socket",
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
               "tdx_engine.py": "enclave/gcp-tdx/app/tdx_engine.py",
               "tdx_fetch.py": "enclave/gcp-tdx/app/tdx_fetch.py", "ir_quote.py": "enclave/gcp-tdx/app/ir_quote.py",
               "ir_pin.py": "enclave/gcp-tdx/app/ir_pin.py", "tdx_child.py": "enclave/gcp-tdx/app/tdx_child.py",
               "FIRST-BOOT.md": "enclave/gcp-tdx/FIRST-BOOT.md",
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
    "D. root opened", "D. root tree is root.img's contents",
    "D1. published files equal the source", "D1. closed engine files match their published hashes",
    "D1. image names its source commit",
    "D2. bytecode names its sources", "D2. bytecode recompiles identically",
    "D3. installed packages match their RECORDs", "D3. requirements equal the source",
    "D3. installed distributions are the pinned requirements", "D3. no interpreter start-up hook",
    "D4. units and firewall files equal the source", "D4. search unit properties", "D4. fetch unit properties",
    "D4. engine unit properties", "D4. quote helper properties", "D4. pin unit properties",
    "D4. drop-ins, generators and manager configuration",
    "D5. unit census", "D5. listening sockets", "D5. accounts, mounts, repart, binaries",
    "D6. firewall rules", "D7. seal before serve", "D7. front imports no closed module", "D7. fetch imports no closed module",
    "D7. one quote per boot", "D7. offer served from immutable bytes", "D7. a reply is delivered before its socket is let go", "D7. one engine process per request",
    "D7. one reply size and two reply slots", "D7. results reduced to the published shape",
    "D7. no memory outlives a request", "D7. the warm parent imports no closed module", "D7. no writable kernel object",
    "D7. the warm parent parses data, not code", "D7. the front names its private keys only to open and sign",
    "D8. initrd",
)


class ImageReport:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str]] = []
        self.values: Dict[str, Any] = {}
        # Why a row is not PASS, machine-readable: "missing" (an input the READER supplies was not: an artefact file,
        # --source, a quote field), "tool" (a program this checker needs failed or is absent), "differs" (a real
        # comparison found a difference — a file absent from INSIDE the image is one). A SKIP counts as "missing".
        # "malformed": a supplied file that could not be read as what it should be. A FAIL with no reason given is "differs".
        self.reasons: Dict[str, str] = {}

    def add(self, ok: Optional[bool], name: str, detail: str, reason: Optional[str] = None) -> bool:
        self.rows.append(("SKIP" if ok is None else "PASS" if ok else "FAIL", name, detail))
        if ok is None:
            self.reasons[name] = reason or "missing"
        elif not ok:
            self.reasons[name] = reason or "differs"
        else:
            self.reasons.pop(name, None)
        return bool(ok)

    def state(self) -> str:
        """"verified" (every required row PASS, nothing FAIL), "differs" (a FAIL from a real comparison), else
        "incomplete" (a required row SKIP, or a FAIL that comes only from something missing or a tool)."""
        if self.posture_verified:
            return "verified"
        for s, n, _d in self.rows:
            if s == "FAIL" and self.reasons.get(n, "differs") == "differs":
                return "differs"
        return "incomplete"

    def required_not_passed(self) -> List[str]:
        """The required rows that did not PASS (SKIP, FAIL or absent), in REQUIRED_ROWS order: what stands between
        this report and "verified"."""
        passed = {n for s, n, _d in self.rows if s == "PASS"}
        return [n for n in REQUIRED_ROWS if n not in passed]

    @property
    def posture_verified(self) -> bool:
        """True only if every REQUIRED row is present and PASSED and no row at all FAILED."""
        status = {n: s for s, n, _ in self.rows}
        return all(status.get(n) == "PASS" for n in REQUIRED_ROWS) and all(s != "FAIL" for s, _, _ in self.rows)

    def dump(self, indent: str = "  ") -> None:
        for s, n, d in self.rows:
            print(f"{indent}{s:4} {n}: {d}")

    def rows_for_measured_report(self, info: "Optional[Dict[str, Any]]") -> "ImageReport":
        """This report re-anchored to one measured boot (rows, reasons, and state(): verified / incomplete / differs)."""
        return rows_for_measured_report(self, (info or {}).get("image_sha384"), (info or {}).get("boot_apps"))

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
    names = [t.split("=", 1)[1] for t in tokens if t.startswith("inferroute.image=")]
    required = CMDLINE_REQUIRED + (CMDLINE_REQUIRED_BY_IMAGE.get(names[0], ()) if len(names) == 1 else ())
    for t in tokens:
        if any(t.startswith(p) for p in CMDLINE_FORBIDDEN_PREFIXES):
            problems.append(f"forbidden token {t!r}")
        elif t not in required and not any(p.fullmatch(t) for p in CMDLINE_PATTERNS):
            problems.append(f"unexpected token {t!r}")
    for r in required:
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


class ImageContent(Exception):
    """In-image content the checker could not read as what it should be: an entry that is not a regular file (a
    dangling link, a FIFO, a socket, a device: never opened), bytes that are not UTF-8 text, a .py that is not
    Python. Named by path. It is in the image, so it is a difference, never a tool fault."""

    def __init__(self, path: str, why: str) -> None:
        super().__init__(f"{path}: {why}")
        self.path, self.why = path, why


def _kind(st: os.stat_result) -> str:
    m = st.st_mode
    return ("symlink" if stat.S_ISLNK(m) else "fifo" if stat.S_ISFIFO(m) else "socket" if stat.S_ISSOCK(m) else
            "device" if stat.S_ISCHR(m) or stat.S_ISBLK(m) else "directory" if stat.S_ISDIR(m) else "other")


def _regular(p: str) -> bool:
    """A regular file by lstat: a link to one is not (the walkers never follow links), nor is a FIFO (open() would
    block on it for ever), a socket or a device."""
    try:
        return stat.S_ISREG(os.lstat(p).st_mode)
    except OSError:
        return False


def _irregular(root: str, rel: str) -> List[str]:
    """Every entry a walk of root/rel lists as a file that is not a regular file, with its kind: these are never
    opened, and each is a difference by name. (Symlinked directories are _linked_dirs'.)"""
    base, out = os.path.join(root, rel), []
    for dp, _dn, fs in os.walk(base):
        for f in fs:
            p = os.path.join(dp, f)
            try:
                st = os.lstat(p)
            except OSError:
                out.append(f"/{os.path.relpath(p, root)} (unreadable)")
                continue
            if not stat.S_ISREG(st.st_mode):
                out.append(f"/{os.path.relpath(p, root)} ({_kind(st)})")
    return sorted(out)


def _walk_files(root: str, rel: str) -> List[str]:
    """The regular files under root/rel (lstat: a symlink, FIFO, socket or device is not listed and never opened;
    _irregular() names those)."""
    base = os.path.join(root, rel)
    out = []
    for dp, _dn, fs in os.walk(base):
        for f in fs:
            if _regular(os.path.join(dp, f)):
                out.append(os.path.relpath(os.path.join(dp, f), base))
    return sorted(out)


class _Text(str):
    """Text read from an in-image file, remembering the path it came from (so a parse failure can name it)."""
    path: str

    def __new__(cls, s: str, path: str) -> "_Text":
        obj = super().__new__(cls, s)
        obj.path = path
        return obj


def _text(p: str) -> str:
    """An in-image file as strict UTF-8 text. Anything else raises ImageContent naming the path: an entry that is
    not a regular file is never opened (a FIFO would block for ever), undecodable bytes are not read "with
    replacement" into a text the checker then vouches for."""
    try:
        st = os.lstat(p)
    except OSError:
        raise ImageContent(p, "missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise ImageContent(p, f"not a regular file ({_kind(st)}); not opened")
    try:
        return _Text(open(p, "rb").read().decode("utf-8"), p)
    except UnicodeDecodeError as exc:
        raise ImageContent(p, f"not UTF-8 text ({exc.reason} at byte {exc.start})") from None


def _ast_parse(text: str) -> ast.Module:
    """ast.parse over text read by _text(): a file that is not Python raises ImageContent naming it. (Every
    ast.parse in this module goes through here; the verifier's own confine.py text parses or the suite is broken.)"""
    try:
        return ast.parse(text)
    except SyntaxError as exc:
        raise ImageContent(getattr(text, "path", "<text>"), f"not Python ({type(exc).__name__}: line {exc.lineno})") from None


def _parse(p: str) -> ast.Module:
    """An in-image .py parsed as Python; a file that is not raises ImageContent naming it."""
    return _ast_parse(_text(p))


def _linked_components(root: str, rel: str) -> List[str]:
    """Every path component of root/rel that is a symlink (opt, opt/ir, opt/ir/app for the app directory): a walk
    that starts below one reads wherever it points, not the directory the image names."""
    parts = rel.split("/")
    return [f"/{'/'.join(parts[:i])} -> {os.readlink(os.path.join(root, *parts[:i]))} (a path component)"
            for i in range(1, len(parts) + 1) if os.path.islink(os.path.join(root, *parts[:i]))]


def _linked_dirs(root: str, rel: str, allow_inside: bool = False) -> List[str]:
    """The symlinked directories a walk of root/rel does not enter: its linked path components, and every directory
    entry under it that is a link. os.walk(followlinks=False) lists such a link among the directories and never
    descends it, so nothing behind it is hashed, recompiled or counted as an extra: a finding, never a file. With
    `allow_inside`, a link whose target (an absolute target is the image's own path, read against root) normalises
    to a directory inside the same walk is allowed: a venv's lib64 -> lib aliases what the walk already reads."""
    base = os.path.join(root, rel)
    out = _linked_components(root, rel)
    for dp, dns, _fs in os.walk(base):
        for d in dns:
            p = os.path.join(dp, d)
            if not os.path.islink(p):
                continue
            target = os.readlink(p)
            resolved = os.path.normpath(os.path.join(root, target.lstrip("/")) if target.startswith("/") else os.path.join(dp, target))
            if allow_inside and (resolved == base or resolved.startswith(base + os.sep)):
                continue
            out.append(f"/{os.path.relpath(p, root)} -> {target}")
    return sorted(out)


def _parse_pins(pins_text: bytes) -> Dict[str, str]:
    pins: Dict[str, str] = {}
    for line in pins_text.decode("utf-8", "replace").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, _, path = line.strip().partition("  ")
            pins[path.strip()] = digest.strip().lower()
    return pins


def closed_residue(app: str) -> List[str]:
    """v16: what of the closed engine is left in a staged /opt/ir/app (the image's, or the build's before mkosi): any
    of CLOSED_FILES by path (source or bytecode), and any .py there that imports one of CLOSED_FILE_MODULES (every
    import statement, functions included, relative imports resolved). Empty = none. Used by row D1 and by
    pin_closed_files.py --check, which refuses the build."""
    out: List[str] = []
    for f in CLOSED_FILES:
        base = f[:-3]
        cands = [f, base + ".pyc"] + [os.path.join(os.path.dirname(f), "__pycache__", os.path.basename(base) + x)
                                      for x in (".cpython-312.pyc", ".pyc")]     # base.pyc: Python imports a sourceless .pyc
        out += [f"{c} is in the image" for c in cands if os.path.lexists(os.path.join(app, c))]
    for dp, _dn, fs in os.walk(app):
        for name in fs:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dp, name)
            try:
                names = _local_imports(path, app)
            except Exception as exc:                          # noqa: BLE001 — unparseable is itself a finding
                out.append(f"{os.path.relpath(path, app)} not parseable ({type(exc).__name__})")
                continue
            hit = sorted({n for n in names for m in CLOSED_FILE_MODULES if n == m or n.startswith(m + ".")})
            if hit:
                out.append(f"{os.path.relpath(path, app)} imports {', '.join(hit)}")
    return out


def check_sources(rep: ImageReport, tree: str, src: Optional[Source], stated_commit: Optional[str] = None) -> None:
    """D1: every file under /opt/ir/app is the published source at the image's commit, and nothing else is there.
    `stated_commit` is an auditor-supplied commit for an image that carries no commit file (v11 and earlier): the
    commit row still FAILS, but the files are compared at that commit so the reader learns what they are."""
    commit_path = os.path.join(tree, SOURCE_COMMIT_FILE)
    commit_why = "missing or not a commit id"
    try:
        commit = _text(commit_path).strip() if os.path.lexists(commit_path) else None
    except ImageContent as exc:
        commit, commit_why = None, exc.why
    if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        rep.add(False, "D1. image names its source commit", f"/{SOURCE_COMMIT_FILE} {commit_why}"
                + (f"; comparing files at the auditor-supplied commit {stated_commit[:12]} instead" if stated_commit else ""))
        if stated_commit and src is not None:
            src.bind(stated_commit)
            commit = stated_commit
    elif src is None:
        rep.add(None, "D1. image names its source commit", f"image says {commit[:12]}; no source supplied to compare")
    else:
        ok, why = src.bind(commit)
        rep.add(ok, "D1. image names its source commit", why, reason="missing" if ok is False else None)
    rep.values["source_commit"] = commit
    rep.values["app_sha256"] = {f: hashlib.sha256(open(os.path.join(tree, APP_DIR, f), "rb").read()).hexdigest()
                               for f in _walk_files(tree, APP_DIR) if not f.endswith(".pyc")}
    # A symlinked directory under /opt/ir/app is a finding with or without a source: the walk above never entered it,
    # so whatever it holds was neither hashed nor counted, and Python would import from it all the same.
    linked = _linked_dirs(tree, APP_DIR)
    irregular = _irregular(tree, APP_DIR)           # a dangling link, a FIFO, a socket, a device: named, never opened
    if src is None:
        rep.add(False if linked or irregular else None, "D1. published files equal the source", "no --source supplied; files only hashed"
                + (f"; SYMLINKED DIRECTORIES in the image (nothing behind them was read): {linked}" if linked else "")
                + (f"; IRREGULAR entries (not regular files; not opened): {irregular}" if irregular else ""))
        rep.add(None, "D1. closed engine files match their published hashes", "no --source supplied; files only hashed")
        return
    m = src.staging_map()
    pins_text = src.read(CLOSED_PINS_SRC)
    pins = _parse_pins(pins_text) if pins_text is not None else {}
    closed_here = CLOSED_FILES if pins else ()           # v15: the 7 pinned files; v16: the source pins none
    present = [f for f in _walk_files(tree, APP_DIR) if not f.endswith(".pyc")]
    diff, missing, extra = [], [], [f for f in present if f not in m]
    # The PUBLISHED files: everything staged but the closed engine. An outsider holds these sources and can run this
    # row; a closed file missing from their tree is reported under the next row, by hash, not here.
    published = {dst: s for dst, s in m.items() if dst not in closed_here}
    for dst, s in sorted(published.items()):
        want = src.read(s)
        p = os.path.join(tree, APP_DIR, dst)
        if want is None:
            missing.append(f"{s} (not in source)")
        elif not os.path.isfile(p):
            missing.append(f"{dst} (not in image)")
        elif os.path.islink(p) or open(p, "rb").read() != want:
            diff.append(dst)
    same = len(published) - len(diff) - len(missing)
    ok = not (diff or missing or extra or linked or irregular)
    rep.add(ok, "D1. published files equal the source", detail=
            f"{same} of {len(published)} published staged files byte-equal to the source" + (f"; DIFFER: {diff}" if diff else "")
            + (f"; MISSING: {missing}" if missing else "") + (f"; EXTRA in image: {extra}" if extra else "")
            + (f"; SYMLINKED DIRECTORIES in the image (nothing behind them was read): {linked}" if linked else "")
            + (f"; IRREGULAR entries (not regular files; not opened): {irregular}" if irregular else ""))
    # The CLOSED files, by the hashes InferRoute publishes (CLOSED_PINS_SRC): their content is not checkable here,
    # their identity is. A closed file the image holds that the pins do not name, or vice versa, fails.
    if pins_text is None:
        rep.add(False, "D1. closed engine files match their published hashes", f"{CLOSED_PINS_SRC} missing from the source")
        return
    if not pins:
        # v16 (design A): the source pins no closed file, so none may be in the image, by path or by import.
        residue = closed_residue(os.path.join(tree, APP_DIR))
        rep.add(not residue, "D1. closed engine files match their published hashes",
                f"no closed engine file: {CLOSED_PINS_SRC} pins none; none of the {len(CLOSED_FILES)} files closed through "
                f"v15 is under /opt/ir/app, and no file there imports one (the engine is sealedresearch.open_rank, "
                "published, checked by the row above)" if not residue else "; ".join(residue))
        return
    problems = []
    for dst in CLOSED_FILES:
        p = os.path.join(tree, APP_DIR, dst)
        if dst not in pins:
            problems.append(f"{dst} not pinned")
        elif not os.path.isfile(p):
            problems.append(f"{dst} not in image")
        elif hashlib.sha256(open(p, "rb").read()).hexdigest() != pins[dst]:
            problems.append(f"{dst} differs from its pin")
    for extra_pin in sorted(set(pins) - set(CLOSED_FILES)):
        problems.append(f"{extra_pin} pinned but not a closed file")
    rep.add(not problems, "D1. closed engine files match their published hashes",
            f"{len(CLOSED_FILES)} closed files hash as {CLOSED_PINS_SRC} publishes (content unpublished: identity checked, "
            "not behaviour; they run in the engine process only, see D7)" if not problems else "; ".join(problems))


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
            for f in fs if f.endswith(".pyc") and _regular(os.path.join(dp, f))]     # an irregular .pyc is D1's/D3's finding
    bad_hdr, orphan, bad_code, recompiled, magic_mismatch = [], [], [], 0, None
    for pyc in sorted(pycs):
        rel = os.path.relpath(pyc, tree)
        d = os.path.dirname(os.path.dirname(pyc))
        src = os.path.join(d, os.path.basename(pyc).split(".")[0] + ".py")
        head = open(pyc, "rb").read(16)
        if not _regular(src):                                # a .py that is a link or a FIFO is not its source
            orphan.append(rel)
            continue
        source = open(src, "rb").read()
        flags = struct.unpack_from("<I", head, 4)[0] if len(head) >= 16 else None
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
    # The walk above lists a symlinked directory and never enters it: bytecode behind one was not recompiled. A link
    # that stays inside the walked tree (the venv's lib64 -> lib) aliases files the walk did read, and is allowed.
    linked = sorted(set(_linked_dirs(tree, APP_DIR) + _linked_dirs(tree, "opt/ir/venv", allow_inside=True)))
    hdr_ok = not (bad_hdr or orphan or linked)
    rep.add(hdr_ok, "D2. bytecode names its sources",
            f"{len(pycs)} .pyc files, all unchecked-hash with the header hash of their .py" if hdr_ok else
            (f"header/flags wrong: {bad_hdr[:5]}" if bad_hdr else "") + (f" orphans without a .py: {orphan[:5]}" if orphan else "")
            + (f" SYMLINKED DIRECTORIES not walked (bytecode behind them unchecked): {linked}" if linked else ""))
    if magic_mismatch:
        rep.add(None, "D2. bytecode recompiles identically",
                f"image bytecode magic {magic_mismatch} is not this interpreter's ({importlib.util.MAGIC_NUMBER.hex()}); "
                f"run under the image's CPython (python{sys.version_info[0]}.{sys.version_info[1]} here)", reason="tool")
    else:
        rep.add(not bad_code and recompiled == len(pycs) - len(orphan) - len(bad_hdr), "D2. bytecode recompiles identically",
                f"{recompiled} of {len(pycs)} recompiled from their .py to the same code objects"
                + (f"; DIFFER: {bad_code[:5]}" if bad_code else ""))


def check_records(rep: ImageReport, tree: str, src: Optional[Source]) -> None:
    """D3: every installed distribution's RECORD hashes match the files, nothing lives outside a RECORD, and the
    image's requirements file is the published one (each wheel pinned by SHA-256 there)."""
    sp = os.path.join(tree, VENV_SP)
    listed: set = set()
    if not os.path.isdir(sp):
        rep.add(False, "D3. installed packages match their RECORDs", f"/{VENV_SP} missing")
    else:
        bad, dists = [], 0
        for name in sorted(os.listdir(sp)):
            rec = os.path.join(sp, name, "RECORD")
            if not (name.endswith(".dist-info") and os.path.lexists(rec)):
                continue
            dists += 1
            try:
                lines = _text(rec).splitlines()
            except ImageContent as exc:
                bad.append(f"{name}/RECORD ({exc.why})")
                continue
            for line in lines:
                parts = line.split(",")
                if len(parts) < 2:
                    continue
                path, digest = parts[0], parts[1]
                listed.add(os.path.normpath(path))
                if not digest.startswith("sha256="):
                    # pip records itself and the bytecode it wrote without a hash; any other unhashed entry would be a
                    # file this row vouches for without reading it.
                    if not (path.endswith("/RECORD") or path.endswith(".pyc")):
                        bad.append(f"{path} (no hash in RECORD)")
                    continue
                p = os.path.normpath(os.path.join(sp, path))
                if not _regular(p):
                    bad.append(f"{path} (missing or not a regular file)")
                    continue
                want = base64.urlsafe_b64decode(digest[7:] + "=" * (-len(digest[7:]) % 4))
                if hashlib.sha256(open(p, "rb").read()).digest() != want:
                    bad.append(path)
        extra = [f for f in _walk_files(tree, VENV_SP) if not f.endswith(".pyc") and os.path.normpath(f) not in listed
                 and "/__pycache__/" not in f]
        linked = _linked_dirs(tree, VENV_SP)                  # not walked: whatever is behind one is outside every RECORD
        irregular = _irregular(tree, VENV_SP)
        ok = not bad and not extra and not linked and not irregular
        rep.add(ok, "D3. installed packages match their RECORDs",
                f"{dists} distributions, {len(listed)} recorded files hash as recorded (the records travel inside the image: "
                "not an independent hash)" if ok else
                (f"mismatch: {bad[:5]}" if bad else "") + (f" outside any RECORD: {extra[:5]}" if extra else "")
                + (f" SYMLINKED DIRECTORIES not walked: {linked}" if linked else "")
                + (f" IRREGULAR entries (not opened): {irregular[:5]}" if irregular else ""))
    check_startup_hooks(rep, tree, listed)
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
    # Installed distributions against the pins, by name and version. What is NOT checkable from an installed tree:
    # the wheel hashes themselves (a hash is over the wheel archive, which pip does not keep); only a rebuild from
    # the same requirements file reproduces them.
    if not os.path.isfile(req):
        rep.add(False, "D3. installed distributions are the pinned requirements", "/opt/ir/requirements.txt missing")
    else:
        pinned = {}
        for line in _text(req).splitlines():
            mm = re.match(r"\s*([A-Za-z0-9_.-]+)==([^\s\\]+)", line)
            if mm:
                pinned[_dist_norm(mm.group(1))] = mm.group(2)
        installed = {}
        if os.path.isdir(sp):
            for name in os.listdir(sp):
                mm = re.fullmatch(r"(.+)-([^-]+)\.dist-info", name)
                if mm and os.path.isfile(os.path.join(sp, name, "RECORD")):
                    installed[_dist_norm(mm.group(1))] = mm.group(2)
        unpinned = sorted(n for n in installed if n not in pinned and n not in ("pip",))
        not_installed = sorted(n for n in pinned if n not in installed)
        wrong = sorted(n for n in pinned if n in installed and installed[n] != pinned[n])
        ok = not (unpinned or not_installed or wrong) and bool(pinned)
        rep.add(ok, "D3. installed distributions are the pinned requirements",
                f"{len(installed)} distributions installed, every one pinned by name and version in requirements.txt "
                "(wheel hashes are not re-derivable from an installed tree: not checked)" if ok else
                (f"installed but unpinned: {unpinned}; " if unpinned else "") + (f"pinned but not installed: {not_installed}; " if not_installed else "")
                + (f"version differs: {wrong}" if wrong else "") + ("" if pinned else "no pins parsed"))


# Interpreter start-up hooks. site runs, at EVERY interpreter start and under -I too, before tdx_entry or tdx_engine
# get a line in: every sitecustomize / usercustomize module importable from sys.path, and every `import` line of
# every *.pth file in a site directory. A library file matching its own RECORD says nothing against that: the hook
# is on the path by name. So none may exist, with two byte-pinned exceptions measured on 2 Nov 2026:
#  - setuptools 81.0.0 (pinned via torch; wheel sha256 fdd925d5…10d6) ships distutils-precedence.pth, one import
#    line that calls _distutils_hack.add_shim(); that file and its target are pinned here by hash, the target must
#    also be inside setuptools' RECORD;
#  - Ubuntu noble's python3.12 ships /usr/lib/python3.12/sitecustomize.py -> /etc/python3.12/sitecustomize.py, which
#    imports apport_python_hook if it exists; the link, the bytes and the ABSENCE of that module are required.
PTH_ALLOWED: Dict[str, Tuple[str, str]] = {
    "distutils-precedence.pth": ("2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224", "_distutils_hack/__init__.py"),
}
STDLIB_SITECUSTOMIZE = ("usr/lib/python3.12/sitecustomize.py", "/etc/python3.12/sitecustomize.py",
                        "43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e")
# sys.path of the venv interpreter (-I) and of /usr/bin/python3 -I (ir_quote, ir_pin), plus the app directory.
PATH_DIRS = ("usr/lib/python3.12", "usr/lib/python3.12/lib-dynload", VENV_SP, "usr/lib/python3/dist-packages",
             "usr/local/lib/python3.12/dist-packages", APP_DIR)
SITE_DIRS = (VENV_SP, "usr/lib/python3/dist-packages", "usr/local/lib/python3.12/dist-packages")
HOOK_NAMES = ("sitecustomize.py", "sitecustomize.pyc", "usercustomize.py", "usercustomize.pyc",
              "apport_python_hook.py", "apport_python_hook.pyc", "apport_python_hook")


def check_startup_hooks(rep: ImageReport, tree: str, listed: set) -> None:
    """D3: no interpreter start-up hook. `listed` is the set of paths the RECORDs cover (relative to site-packages)."""
    hooks, stock, pinned = [], [], []
    for d in PATH_DIRS:
        for n in HOOK_NAMES:
            p = os.path.join(tree, d, n)
            if not os.path.lexists(p):
                continue
            if (d, n) == (STDLIB_SITECUSTOMIZE[0].rsplit("/", 1)[0], "sitecustomize.py") and os.path.islink(p) \
                    and os.readlink(p) == STDLIB_SITECUSTOMIZE[1]:
                target = os.path.join(tree, STDLIB_SITECUSTOMIZE[1].lstrip("/"))
                if _regular(target) and hashlib.sha256(open(target, "rb").read()).hexdigest() == STDLIB_SITECUSTOMIZE[2]:
                    stock.append(f"/{d}/{n}")
                    continue
            hooks.append(f"/{d}/{n}")
    if os.path.lexists(os.path.join(tree, "usr/lib/python312.zip")):
        hooks.append("/usr/lib/python312.zip (an archive on sys.path)")
    for d in SITE_DIRS:
        dp = os.path.join(tree, d)
        if not os.path.isdir(dp):
            continue
        for n in sorted(os.listdir(dp)):
            if not n.endswith(".pth"):
                continue
            p = os.path.join(dp, n)
            if not _regular(p):
                hooks.append(f"/{d}/{n} (not a regular file)")
                continue
            data = open(p, "rb").read()
            pin = PTH_ALLOWED.get(n) if d == VENV_SP else None
            if pin and hashlib.sha256(data).hexdigest() == pin[0]:
                if os.path.normpath(pin[1]) in listed:
                    pinned.append(n)
                else:
                    hooks.append(f"/{d}/{n} (byte-pinned, but its import target {pin[1]} is outside every RECORD)")
                continue
            executable = any(l.startswith(("import ", "import\t")) for l in data.decode("utf-8", "replace").splitlines())
            hooks.append(f"/{d}/{n} (a .pth not pinned by hash" + ("; site runs its import line at every start)" if executable else ")"))
    rep.add(not hooks, "D3. no interpreter start-up hook",
            ("no sitecustomize, usercustomize or apport hook on the interpreters' paths; no archive on sys.path"
             + (f"; the stock Ubuntu sitecustomize {stock} is byte-pinned (it imports an apport hook the image does not hold)" if stock else "")
             + (f"; .pth under site-packages: {pinned} byte-pinned, import target inside its RECORD" if pinned else
                "; no .pth file under site-packages")) if not hooks else f"start-up hooks: {hooks}")


def _dist_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_unit(text: str) -> Dict[str, Dict[str, List[str]]]:
    """Section -> key -> values, as systemd reads it: a key outside the section it belongs to is NOT the property."""
    out: Dict[str, Dict[str, List[str]]] = {}
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            out.setdefault(section, {})
            continue
        k, _, v = line.partition("=")
        out.setdefault(section, {}).setdefault(k.strip(), []).append(v.strip())
    return out


def _dropin_dirs(unit: str) -> List[str]:
    """The drop-in directories systemd applies to `unit`, most specific first: <unit>.d, every dash-prefix
    directory (ir-.service.d for ir-engine.service), and the type-wide service.d / -.service.d."""
    name, _, kind = unit.rpartition(".")
    dirs = [f"{unit}.d"]
    parts = name.split("-")
    for i in range(len(parts) - 1, 0, -1):
        dirs.append("-".join(parts[:i]) + f"-.{kind}.d")
    dirs += [f"-.{kind}.d", f"{kind}.d"]
    return dirs


def effective_unit(tree: str, unit: str) -> Tuple[Dict[str, Dict[str, List[str]]], Optional[str], List[str]]:
    """What systemd would load for `unit` from the tree: the unit file of the highest-precedence layer with every
    applicable drop-in merged in (lexical order by file name; an empty value resets the list). Returns
    (sections, unit file path, drop-in paths)."""
    unit_path = None
    for layer in UNIT_LAYERS:
        cand = os.path.join(tree, layer, unit)
        if os.path.isfile(cand):
            unit_path = cand
            break
    merged: Dict[str, Dict[str, List[str]]] = _parse_unit(_text(unit_path)) if unit_path else {}
    dropins: Dict[str, str] = {}
    for layer in UNIT_LAYERS:
        for d in _dropin_dirs(unit):
            dp = os.path.join(tree, layer, d)
            if not os.path.isdir(dp):
                continue
            for f in sorted(os.listdir(dp)):
                if f.endswith(".conf") and f not in dropins and os.path.isfile(os.path.join(dp, f)):
                    dropins[f] = os.path.join(dp, f)
    for f in sorted(dropins):
        for sec, kv in _parse_unit(_text(dropins[f])).items():
            for k, vals in kv.items():
                for v in vals:
                    if v == "":
                        merged.setdefault(sec, {})[k] = []
                    else:
                        merged.setdefault(sec, {}).setdefault(k, []).append(v)
    return merged, unit_path, sorted(dropins.values())


def _unit_problems(u: Dict[str, Dict[str, List[str]]], required: Dict[str, Any], deps: Tuple[str, ...],
                   kind: str = "service", forbidden: Tuple[str, ...] = ()) -> List[str]:
    """Required keys read from the section systemd reads them from ([Unit] for UNIT_SECTION_KEYS, else [Service]
    or [Socket]); a required key found under another section is named as ignored there."""
    main = "Socket" if kind == "socket" else "Service"
    problems = []
    for k, v in required.items():
        sec = "Unit" if k in UNIT_SECTION_KEYS else main
        got = u.get(sec, {}).get(k)
        if got != (list(v) if isinstance(v, list) else [v]):
            elsewhere = [s for s, kv in u.items() if s != sec and k in kv]
            problems.append(f"{k}={got} (want {v!r})" + (f"; found under [{elsewhere[0]}], where systemd ignores it" if elsewhere else ""))
    problems += [f"{k} present" for k in UNIT_FORBIDDEN_KEYS if k in u.get(main, {})]
    problems += [f"{k} present (forbidden)" for k in forbidden if any(k in kv for kv in u.values())]
    for dep in deps:
        for key in ("Requires", "After"):
            if not any(dep in v.split() for v in u.get("Unit", {}).get(key, [])):
                problems.append(f"{key}= lacks {dep}")
    return problems


def _environment(u: Dict[str, Dict[str, List[str]]]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for line in u.get("Service", {}).get("Environment", []):
        for tok in line.split():
            k, _, v = tok.partition("=")
            env[k] = v
    return env


def _slot_and_budget(tree: str) -> Tuple[Optional[float], Optional[float], Optional[float], List[str]]:
    """(slot, front budget, engine budget, problems): the front's reply slot and the budget both units hold. rc9: the
    survey slot and survey budget are checked here too (_survey_slot_and_budget returns them)."""
    slot, fb, eb, _ss, _sb, problems = _slots_and_budgets(tree)
    return slot, fb, eb, problems


def _survey_slot_and_budget(tree: str) -> Tuple[Optional[float], Optional[float]]:
    _slot, _fb, _eb, ss, sb, _problems = _slots_and_budgets(tree)
    return ss, sb


def _slots_and_budgets(tree: str):
    """(slot, front budget, engine budget, survey slot, survey budget, problems). Both units must hold the same two
    budgets; each budget lies below its slot; the survey slot is at least the reply slot; the reply slot in (0, 60], the survey slot in (0, 300]."""
    problems = []
    su, _p, _d = effective_unit(tree, "ir-search.service")
    eu, _p, _d = effective_unit(tree, "ir-engine.service")
    senv, eenv = _environment(su), _environment(eu)

    def num(env: Dict[str, str], name: str, unit: str) -> Optional[float]:
        try:
            return float(env[name])
        except (KeyError, ValueError):
            problems.append(f"{unit} does not set {name} to a number")
            return None
    slot, fb, eb = num(senv, ENV_SLOT, "ir-search.service"), num(senv, ENV_BUDGET, "ir-search.service"), num(eenv, ENV_BUDGET, "ir-engine.service")
    ss, sfb, seb = (num(senv, ENV_SURVEY_SLOT, "ir-search.service"), num(senv, ENV_SURVEY_BUDGET, "ir-search.service"),
                    num(eenv, ENV_SURVEY_BUDGET, "ir-engine.service"))
    if slot is not None and fb is not None and not (0 < fb < slot):
        problems.append(f"{ENV_BUDGET}={fb} is not below {ENV_SLOT}={slot}: a late engine could push a reply past its slot")
    if ss is not None and sfb is not None and not (0 < sfb < ss):
        problems.append(f"{ENV_SURVEY_BUDGET}={sfb} is not below {ENV_SURVEY_SLOT}={ss}: a late survey could push a reply past its slot")
    if slot is not None and not (0 < slot <= 60):
        problems.append(f"{ENV_SLOT}={slot} is not in (0, 60]")
    if ss is not None and not (0 < ss <= 300):
        problems.append(f"{ENV_SURVEY_SLOT}={ss} is not in (0, 300]")
    if slot is not None and ss is not None and ss < slot:
        problems.append(f"{ENV_SURVEY_SLOT}={ss} is shorter than {ENV_SLOT}={slot}")
    if fb is not None and sfb is not None and sfb < fb:
        problems.append(f"{ENV_SURVEY_BUDGET}={sfb} is below {ENV_BUDGET}={fb}")
    if fb is not None and eb is not None and fb != eb:
        problems.append(f"the front's {ENV_BUDGET} ({fb}) and the engine's ({eb}) differ")
    if sfb is not None and seb is not None and sfb != seb:
        problems.append(f"the front's {ENV_SURVEY_BUDGET} ({sfb}) and the engine's ({seb}) differ")
    return slot, fb, eb, ss, sfb, problems


def check_unit(rep: ImageReport, tree: str, src: Optional[Source]) -> None:
    """D4: every file we put in the image's /etc and /usr (units, drop-ins, the firewall, the accounts, the sysctl)
    is the published one, byte for byte, and nothing else sits under /etc/systemd/system; and each unit has the
    closed-box properties, property by property, as systemd would load it (drop-ins merged, sections honoured)."""
    if src is None:
        rep.add(None, "D4. units and firewall files equal the source", "no --source supplied")
    else:
        diff, missing, same = [], [], 0
        staged = set()
        for rel in sorted(r for sub in ("etc", "usr") for r in src.list_dir(f"{MKOSI_EXTRA}/{sub}")):
            if rel.startswith(f"{MKOSI_EXTRA}/opt/"):
                continue
            img_rel = os.path.relpath(rel, MKOSI_EXTRA)
            staged.add(img_rel)
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
        # Nothing else under /etc/systemd/system: a unit, a drop-in or a link the source did not stage is a FAIL
        # that names it. Enablement links (*.wants, *.requires) are the D5 census's, allowlisted there.
        extra = _linked_components(tree, "etc/systemd/system")   # the walk below would read wherever one points
        base = os.path.join(tree, "etc/systemd/system")
        for dp, dns, fs in os.walk(base):
            for f in fs + [d for d in dns if os.path.islink(os.path.join(dp, d))]:
                full = os.path.join(dp, f)
                rel = os.path.relpath(full, tree)
                parent = os.path.basename(dp)
                if rel in staged or (os.path.islink(full) and (parent.endswith(".wants") or parent.endswith(".requires"))):
                    continue
                extra.append(rel)
        ok_all = not (diff or missing or extra) and same > 0
        rep.add(ok_all, "D4. units and firewall files equal the source", detail=
                f"{same} files under /etc and /usr byte-equal to {MKOSI_EXTRA}; nothing else under /etc/systemd/system" if ok_all else
                (f"DIFFER: {diff}" if diff else "") + (f" MISSING: {missing}" if missing else "")
                + (f" NOT IN SOURCE: {sorted(extra)}" if extra else "") + ("" if same else " nothing compared"))
    slot, fb, eb, env_problems = _slot_and_budget(tree)
    rep.values["reply_slot_seconds"], rep.values["engine_budget_seconds"] = slot, fb
    rep.values["survey_slot_seconds"], rep.values["survey_budget_seconds"] = _survey_slot_and_budget(tree)
    for unit, row in (("ir-search.service", "D4. search unit properties"), ("ir-fetch.service", "D4. fetch unit properties"),
                      ("ir-engine.service", "D4. engine unit properties"), ("ir-pin.service", "D4. pin unit properties")):
        required, deps = UNITS_EXPECTED[unit]
        v15_pin = unit == "ir-pin.service" and rules_for(rep) == "v15"     # a v14/v15 image: the v15-era pin rules
        if v15_pin:
            required = V15_PIN_UNIT_REQUIRED
        prefix = V15_RULES_PREFIX if v15_pin else ""
        u, unit_path, dropins = effective_unit(tree, unit)
        if unit_path is None:
            rep.add(False, row, f"{prefix}{unit} missing from every unit directory")
            continue
        problems = _unit_problems(u, required, deps, forbidden=ENGINE_UNIT_FORBIDDEN if unit == "ir-engine.service"
                                  else PIN_UNIT_FORBIDDEN if unit == "ir-pin.service" and not v15_pin else ())
        if not unit_path.startswith(os.path.join(tree, "etc/systemd/system")):
            problems.append(f"loaded from {os.path.relpath(unit_path, tree)}, not /etc/systemd/system")
        if dropins:
            problems.append(f"drop-ins applied: {[os.path.relpath(d, tree) for d in dropins]}")
        if unit != "ir-fetch.service" and not os.path.islink(os.path.join(tree, f"etc/systemd/system/multi-user.target.wants/{unit}")):
            problems.append("not wanted by multi-user.target")
        if unit == "ir-engine.service":
            su, _sp, _sd = effective_unit(tree, "ir-engine.socket")
            problems += [f"ir-engine.socket: {x}" for x in _unit_problems(su, ENGINE_SOCKET_REQUIRED, (), kind="socket")]
            if not os.path.islink(os.path.join(tree, "etc/systemd/system/sockets.target.wants/ir-engine.socket")):
                problems.append("ir-engine.socket not wanted by sockets.target")
            if _environment(u).get("HOME") != "/nonexistent":
                problems.append("HOME is not /nonexistent")
            sysctl = _sysctl(tree)
            if sysctl.get("kernel.yama.ptrace_scope") != "3":
                problems.append(f"{SYSCTL_FILE} does not set kernel.yama.ptrace_scope = 3 (a per-request child could reach the parent's descriptors)")
        if unit in ("ir-search.service", "ir-engine.service"):
            problems += env_problems
        if unit == "ir-pin.service":
            problems += _pin_program_problems(tree, v15=v15_pin)
        if unit == "ir-fetch.service":
            problems += _ram_unit_problems(tree)
        rep.add(not problems, row, prefix +
                (f"{unit}: User={required.get('User', 'root')}, "
                + ("CAP_IPC_LOCK and CAP_DAC_READ_SEARCH only" if unit == "ir-pin.service" else "no capability")
                + ", no new privilege, read-only system, no device, W^X with "
                f"noexec scratch and memfd_create refused, @system-service, stdout and stderr to null, no core dumps, -I interpreter"
                + (f", root step {required['ExecStartPre']!r}" if "ExecStartPre" in required else "")
                + (f" and {required['ExecStartPost']!r}" if "ExecStartPost" in required else "")
                + (f"; no network namespace, AF_UNIX only, reached by the front through /run/ir-engine.sock (root:ir-search 0660); "
                   f"no FailureAction, no writable path (no runtime directory, /tmp and /var/tmp read-only tmpfs, /dev/shm read-only), "
                   f"the rest of the root hidden, ptrace and pidfd_getfd refused, Yama scope 3, budget {eb} s"
                   if unit == "ir-engine.service" else "")
                + (f"; reply slot {slot} s, engine budget {fb} s" if unit == "ir-search.service" else "")
                + ("; notify, mlockall over the whole root before the engine and the front start" if unit == "ir-pin.service" else "")
                + ("; /ram mounted by ir-ram.service (root, CAP_SYS_ADMIN only, the host's mount namespace, before the fetch, "
                   "poweroff on failure): a tmpfs ir-fetch:ir-index mode 0750 noexec,nosuid,nodev, refused if already mounted"
                   if unit == "ir-fetch.service" else "")
                + (f", ordered after {', '.join(deps)}" if deps else "") if not problems else "; ".join(problems)))
    problems = []
    for unit in ("ir-quote.service", "ir-quote.socket"):
        required, deps = UNITS_EXPECTED[unit]
        u, unit_path, dropins = effective_unit(tree, unit)
        if unit_path is None:
            problems.append(f"{unit} missing")
            continue
        problems += [f"{unit}: {x}" for x in _unit_problems(u, required, deps, kind="socket" if unit.endswith(".socket") else "service")]
        if dropins:
            problems.append(f"{unit}: drop-ins applied: {[os.path.relpath(d, tree) for d in dropins]}")
    if not os.path.islink(os.path.join(tree, "etc/systemd/system/sockets.target.wants/ir-quote.socket")):
        problems.append("ir-quote.socket not wanted by sockets.target")
    rep.add(not problems, "D4. quote helper properties",
            "ir-quote.service: root with no capability, no network namespace, AF_UNIX only, read-only system but "
            "/sys/kernel/config and its marker directory (/run/ir-quote, kept across restarts), stdlib interpreter in "
            "isolated mode; ir-quote.socket: /run/ir-quote.sock, root:ir-quote 0660"
            if not problems else "; ".join(problems))
    check_dropins(rep, tree, src)


def _pin_v16_problems(tree: str, text: str, mod: ast.Module, rf: str) -> List[str]:
    """The v16 additions to row D4 pin (db2142c): the pin sees the whole root -- another filesystem is skipped only at
    a listed, empty mountpoint, and an unreadable directory is refused."""
    out: List[str] = []
    # v16: another filesystem is skipped only when listed; anything else, or an unreadable directory, is refused
    if "elif p not in OTHER_FILESYSTEMS:" not in rf or "raise SystemExit" not in rf:
        out.append("ir_pin.regular_files does not refuse a directory on another filesystem outside OTHER_FILESYSTEMS")
    if "except OSError" in rf:
        out.append("ir_pin.regular_files swallows OSError (an unreadable path would be skipped in silence)")
    ref = _function(mod, "_refuse_unreadable")
    body = [st for st in (ref.body if ref else []) if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    if not body or not isinstance(body[-1], ast.Raise) or any(isinstance(st, ast.Return) for st in body) \
            or any(isinstance(st, ast.If) and not ("FileNotFoundError" in (ast.get_source_segment(text, st.test) or "")) for st in body):
        out.append("ir_pin._refuse_unreadable missing or does not raise (only a vanished path may return early)")
    other = None
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "OTHER_FILESYSTEMS" for t in node.targets):
            try:
                v = node.value
                if isinstance(v, ast.Call) and _call_name(v) == "frozenset" and len(v.args) == 1:
                    other = frozenset(ast.literal_eval(v.args[0]))
            except ValueError:
                other = None
    if other != PIN_OTHER_FILESYSTEMS:
        out.append(f"ir_pin.OTHER_FILESYSTEMS = {sorted(other) if other else other} (want {sorted(PIN_OTHER_FILESYSTEMS)})")
    for d in PIN_OTHER_FILESYSTEMS:                 # each skipped mountpoint must be empty in the image
        full = os.path.join(tree, d.lstrip("/"))
        if os.path.isdir(full) and not os.path.islink(full) and os.listdir(full):
            out.append(f"{d} is not empty in the image tree, yet the pin skips it")
    return out


def _pin_program_problems(tree: str, v15: bool = False) -> List[str]:
    """What ir_pin.py is written to do, read off its AST (row D4 pin): walk the root on one st_dev, keep regular
    non-empty files, mlockall(MCL_CURRENT), refuse when VmLck is short of the total, and notify READY only after.
    v15=True: exactly the v15-era checks (dcb384a), without v16's refusal of an unlisted filesystem boundary, of an
    unreadable directory, and of a non-empty skipped mountpoint."""
    p = os.path.join(tree, APP_DIR, "ir_pin.py")
    if not os.path.isfile(p):
        return ["ir_pin.py missing"]
    text = _text(p)
    mod = _ast_parse(text)
    out = []
    rf = _src(text, mod, "regular_files")
    walk = "os.walk(root)" if v15 else "os.walk(root, onerror=_refuse_unreadable)"
    if rf.count("st_dev == dev") < 2 or walk not in rf:   # prune AND file filter
        out.append("ir_pin.regular_files does not walk the root on one st_dev (both the directories it descends and the files it keeps)")
    if not v15:
        out += _pin_v16_problems(tree, text, mod, rf)
    if "S_ISREG(st.st_mode)" not in rf or "st.st_size > 0" not in rf:
        out.append("ir_pin.regular_files does not keep regular non-empty files only")
    la_fn = _function(mod, "lock_all")
    la_calls = [n for n in ast.walk(la_fn) if isinstance(n, ast.Call) and _call_name(n) == "mlockall"] if la_fn else []
    if not any(c.args and isinstance(c.args[0], ast.Name) and c.args[0].id == "MCL_CURRENT" for c in la_calls) \
            or "VmLck" not in (ast.get_source_segment(text, la_fn) or "").split('"""')[-1]:
        out.append("ir_pin.lock_all does not call mlockall(MCL_CURRENT) and read VmLck back")
    main = _function(mod, "main")
    if main is None:
        out.append("ir_pin.main not found")
    else:
        i_map = _stmt_index_calling(main.body, "map_all")
        i_lock = _stmt_index_calling(main.body, "lock_all")
        i_refuse = next((i for i, s in enumerate(main.body) if isinstance(s, ast.If) and "locked < total" in (ast.get_source_segment(text, s.test) or "")
                         and any(isinstance(n, ast.Raise) for n in ast.walk(s))), None)
        i_ready = _stmt_index_calling(main.body, "notify_ready")
        if None in (i_map, i_lock, i_refuse, i_ready) or not (i_map < i_lock < i_refuse < i_ready):
            out.append(f"ir_pin.main order map_all={i_map} lock_all={i_lock} refuse-if-short={i_refuse} notify_ready={i_ready}; "
                       "want map, lock, refuse when VmLck < total, then READY")
    return out


def _sysctl(tree: str) -> Dict[str, str]:
    p = os.path.join(tree, SYSCTL_FILE)
    out: Dict[str, str] = {}
    if os.path.isfile(p):
        for line in _text(p).splitlines():
            line = line.strip()
            if line and not line.startswith(("#", ";")) and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def check_dropins(rep: ImageReport, tree: str, src: Optional[Source]) -> None:
    """D4: for every unit of the closed box, every drop-in in every layer is one the source stages (and the unit
    exists in no other layer); the type-wide and prefix drop-in directories are empty; no administrator
    generators; no manager configuration beyond the stock file; the sysctl file says what it must."""
    problems = []
    for unit in DROPIN_GUARDED:
        _u, unit_path, dropins = effective_unit(tree, unit)
        for d in dropins:
            rel = os.path.relpath(d, tree)
            want = src.read(f"{MKOSI_EXTRA}/{rel}") if src is not None else None
            if src is None:
                problems.append(f"{unit}: drop-in {rel} (no source to compare with)")
            elif want is None:
                problems.append(f"{unit}: drop-in {rel} is not in the source")
            elif open(d, "rb").read() != want:
                problems.append(f"{unit}: drop-in {rel} differs from the source")
        copies = [layer for layer in UNIT_LAYERS if os.path.lexists(os.path.join(tree, layer, unit))]
        if unit.startswith("ir-") and copies != ["etc/systemd/system"]:
            problems.append(f"{unit} present in {copies}, want /etc/systemd/system only")
        elif len(copies) > 1:
            problems.append(f"{unit} present in more than one layer: {copies}")
    for layer in UNIT_LAYERS:
        for d in ("service.d", "-.service.d", "socket.d", "-.socket.d", "ir-.service.d", "ir-.socket.d"):
            dp = os.path.join(tree, layer, d)
            if os.path.isdir(dp) and os.listdir(dp):
                problems.append(f"{layer}/{d} holds {sorted(os.listdir(dp))}")
    for d in GENERATOR_ADMIN_DIRS:
        dp = os.path.join(tree, d)
        if os.path.isdir(dp) and os.listdir(dp):
            problems.append(f"/{d} holds {sorted(os.listdir(dp))}")
    for rel in GENERATOR_FORBIDDEN:
        if os.path.lexists(os.path.join(tree, rel)):
            problems.append(f"/{rel} present")
    for d in MANAGER_CONF_DIRS:
        dp = os.path.join(tree, d)
        if os.path.isdir(dp) and os.listdir(dp):
            problems.append(f"/{d} holds {sorted(os.listdir(dp))}")
    for rel in ("etc/systemd/system.conf", "usr/lib/systemd/system.conf"):
        p = os.path.join(tree, rel)
        if os.path.isfile(p):
            directives = [l.strip() for l in _text(p).splitlines() if l.strip() and not l.strip().startswith(("#", ";", "["))]
            if directives:
                problems.append(f"/{rel} sets {directives[:3]}")
    sysctl = _sysctl(tree)
    for k, v in SYSCTL_REQUIRED.items():
        if sysctl.get(k) != v:
            problems.append(f"{SYSCTL_FILE}: {k} = {sysctl.get(k)} (want {v})")
    only_absence = bool(problems) and all("(no source to compare with)" in x for x in problems)
    rep.add(None if (src is None and only_absence) else not problems, "D4. drop-ins, generators and manager configuration", detail=
            f"{len(DROPIN_GUARDED)} units: only the source's drop-ins in any layer, each unit in one layer; no type-wide or "
            "prefix drop-in directory; no administrator generator, no getty generator; no system.conf directive or "
            f"system.conf.d, system.control, system.attached, transient; {SYSCTL_FILE} sets Yama scope 3 and the map count"
            if not problems else "; ".join(problems[:8]))


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
            if not ((wants.endswith(".wants") or wants.endswith(".requires")) and os.path.isdir(wd)):
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
                for k, vals in _parse_unit(_text(cand)).get("Socket", {}).items():
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
    hyg += _id_problems(tree, accounts)
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
            f"root locked; {', '.join(ACCOUNTS_REQUIRED)} present without shell or password, uids "
            f"{'/'.join(str(v) for v in ACCOUNT_UIDS.values())}; "
            + "; ".join(f"{g} gid {GROUP_GIDS[g]} with exactly {', '.join(sorted(GROUP_MEMBERS[g]))}" for g in GROUP_GIDS)
            + ", no account with a shared group as its primary group; no fstab entries, no cmdline file, "
            "no repart definitions, no ssh/agent binaries" if not hyg else "; ".join(hyg))


def _unresolved_app_imports(tree: str, rel: str) -> List[str]:
    """Imports of the app's own packages (enclave.*, sealedresearch.*) in /opt/ir/app/<rel> that do not resolve in the
    staged tree: the module path must be a package or module under the app, and each imported name a submodule file or
    a name the package's __init__ binds. (v14 rc5: tdx_child's `from enclave.azure import m2_entry` named a file the
    image stages elsewhere; every child raised ImportError, silenced, and the box never served.)"""
    app = os.path.join(tree, APP_DIR)
    path = os.path.join(app, rel)
    mod = _parse(path) if os.path.isfile(path) else None
    out: List[str] = []
    if mod is None:
        return out

    def where(dotted: str) -> Optional[str]:
        base = os.path.join(app, *dotted.split("."))
        if os.path.isfile(base + ".py"):
            return base + ".py"
        if os.path.isfile(os.path.join(base, "__init__.py")):
            return os.path.join(base, "__init__.py")
        return None
    for node in ast.walk(mod):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in ("enclave", "sealedresearch") and where(a.name) is None:
                    out.append(f"import {a.name} does not resolve under /opt/ir/app")
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module \
                and node.module.split(".")[0] in ("enclave", "sealedresearch"):
            target = where(node.module)
            if target is None:
                out.append(f"from {node.module} import ... : {node.module} does not resolve under /opt/ir/app")
                continue
            bound = set()
            if target.endswith("__init__.py"):
                init = _parse(target)
                for n in ast.walk(init) if init is not None else []:
                    if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                        bound.add(n.name)
                    elif isinstance(n, ast.Assign):
                        bound |= {t.id for t in n.targets if isinstance(t, ast.Name)}
                    elif isinstance(n, (ast.Import, ast.ImportFrom)):
                        bound |= {(a.asname or a.name).split(".")[0] for a in n.names}
            for a in node.names:
                if a.name == "*" or a.name in bound or where(f"{node.module}.{a.name}") is not None:
                    continue
                if not target.endswith("__init__.py"):
                    continue                              # a name from a module file: an attribute, not checked here
                out.append(f"from {node.module} import {a.name}: no {node.module}.{a.name} under /opt/ir/app")
    return out


def _warm_thread_problems(ptext: str, pmod: Optional[ast.Module]) -> List[str]:
    """engine_preload.warm runs preload AND the dummy pass (_dummy: the encode and the faiss probe) only inside a
    function it runs on a thread it starts and joins, and calls neither on its own thread: the engine forks every
    child from the thread that called warm, and a child forked from a thread that ran an OpenMP region hangs at its
    own first one (v14 rc4: LightGBM's model parse in preload, on the forking thread, hung every child)."""
    why = " (a child forked from a thread that ran an OpenMP region hangs)"
    warm = _function(pmod, "warm") if pmod is not None else None
    dummy = _function(pmod, "_dummy") if pmod is not None else None
    if warm is None or dummy is None:
        return ["engine_preload has no warm or no _dummy" + why]
    out = []
    dsrc = ast.get_source_segment(ptext, dummy) or ""
    if ".encode(" not in dsrc or ".search(" not in dsrc:
        out.append("engine_preload._dummy does not run the encode and the faiss probe")
    nested = [n for n in warm.body if isinstance(n, ast.FunctionDef)]
    inner = {_call_name(c) for f in nested for c in ast.walk(f) if isinstance(c, ast.Call)}
    outer = set()
    for stmt in warm.body:
        if isinstance(stmt, ast.FunctionDef):
            continue
        outer |= {_call_name(c) for c in ast.walk(stmt) if isinstance(c, ast.Call)}
    targets = {kw.value.id for c in ast.walk(warm) if isinstance(c, ast.Call) and _call_name(c) == "Thread"
               for kw in c.keywords if kw.arg == "target" and isinstance(kw.value, ast.Name)}
    if not ({"preload", "_dummy"} <= inner) or not (targets & {f.name for f in nested}) or "join" not in outer:
        out.append("engine_preload.warm does not run preload and the encode/faiss probe in a thread it joins" + why)
    if outer & {"preload", "_dummy", "encode", "search", "Booster", "read_index", "SentenceTransformer"}:
        out.append("engine_preload.warm loads or runs a library on the forking thread: "
                   f"{sorted(outer & {'preload', '_dummy', 'encode', 'search', 'Booster', 'read_index', 'SentenceTransformer'})}" + why)
    return out


def _id_problems(tree: str, accounts: Dict[str, List[str]]) -> List[str]:
    """The fixed uids and gids, and the exact membership of ir-quote and ir-index (row D5)."""
    out = []
    for name, uid in ACCOUNT_UIDS.items():
        if name in accounts and (len(accounts[name]) < 4 or accounts[name][2] != str(uid)):
            out.append(f"account {name} has uid {accounts[name][2] if len(accounts[name]) > 2 else '?'}, not {uid}")
    group = os.path.join(tree, "etc/group")
    if not os.path.isfile(group):
        return out + ["/etc/group missing"]
    groups = {}
    for line in open(group, errors="replace"):
        f = line.rstrip("\n").split(":")
        if len(f) >= 4:
            if f[0] in groups:
                out.append(f"group {f[0]} listed twice in /etc/group")
            groups[f[0]] = f
    for name, gid in GROUP_GIDS.items():
        if name not in groups:
            out.append(f"group {name} missing from /etc/group")
            continue
        if groups[name][2] != str(gid):
            out.append(f"group {name} has gid {groups[name][2]}, not {gid}")
        members = {m for m in groups[name][3].split(",") if m}
        if members != GROUP_MEMBERS[name]:
            out.append(f"group {name} members {sorted(members)}, not exactly {sorted(GROUP_MEMBERS[name])}")
    shared = {str(g) for g in GROUP_GIDS.values()} | {groups[n][2] for n in GROUP_GIDS if n in groups}
    for name, f in accounts.items():
        if len(f) > 3 and f[3] in shared:
            out.append(f"account {name} has primary gid {f[3]}, a shared group (an unlisted member)")
    return out


def _assigned_string(tree_file: str, name: str) -> Optional[str]:
    mod = _parse(tree_file)
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


def _ram_unit_problems(tree: str) -> List[str]:
    """ir-ram.service (v14 rc2): mounts /ram once, in the host's namespace, before the fetch; fatal if it fails."""
    out = []
    u, path, dropins = effective_unit(tree, RAM_UNIT)
    if path is None:
        return [f"{RAM_UNIT} missing from every unit directory"]
    if not path.startswith(os.path.join(tree, "etc/systemd/system")):
        out.append(f"{RAM_UNIT} loaded from {os.path.relpath(path, tree)}, not /etc/systemd/system")
    if dropins:
        out.append(f"{RAM_UNIT} drop-ins applied: {[os.path.relpath(d, tree) for d in dropins]}")
    out += [f"{RAM_UNIT}: {x}" for x in _unit_problems(u, RAM_UNIT_REQUIRED, ())]
    box = os.path.join(tree, APP_DIR, "ir_box.sh")
    body = " ".join(_shell_case_body(_text(box), "mount-ram")) if os.path.isfile(box) else ""
    out += [f"ir_box.sh mount-ram lacks {want!r}" for want in RAM_MOUNT_LINES if want not in body]
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
    text = _text(conf)
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
    if any("ir-engine" in l and "accept" in l for l in text.splitlines()):
        problems.append("a rule accepts packets from ir-engine")
    if not os.path.islink(os.path.join(tree, "etc/systemd/system/sysinit.target.wants/nftables.service")):
        problems.append("nftables.service not wanted by sysinit.target")
    nd, _np, _nd = effective_unit(tree, "systemd-networkd.service")
    d = nd.get("Unit", {})
    if "nftables.service" not in " ".join(d.get("Requires", [])).split() or "nftables.service" not in " ".join(d.get("After", [])).split():
        problems.append("systemd-networkd does not require and follow nftables.service")
    # What nftables.service RUNS, as systemd would load it (vendor unit plus every drop-in in every layer): a
    # drop-in that reset ExecStart= to /bin/true would leave the box with no ruleset at all.
    nf, nf_path, _nf_dropins = effective_unit(tree, "nftables.service")
    if nf_path is None:
        problems.append("nftables.service missing from every unit directory")
    elif nf.get("Service", {}).get("ExecStart") != [NFT_EXEC_START]:
        problems.append(f"nftables.service ExecStart is {nf.get('Service', {}).get('ExecStart')} after drop-ins, expected [{NFT_EXEC_START!r}]")
    # The close: the fetch unit's ExecStartPost runs ir_box.sh close-fetch, which flushes the chain, reads it back,
    # re-checks the policies and makes /ram read-only.
    fu, _fp, _fd = effective_unit(tree, "ir-fetch.service")
    u = fu.get("Service", {})
    if u.get("ExecStartPost") != [FETCH_CLOSE_STEP]:
        problems.append(f"ir-fetch.service ExecStartPost is {u.get('ExecStartPost')}, expected [{FETCH_CLOSE_STEP!r}]")
    box = os.path.join(tree, APP_DIR, "ir_box.sh")
    if not os.path.isfile(box):
        problems.append("/opt/ir/app/ir_box.sh missing")
    else:
        bt = _text(box)
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
            f"output: policy drop; ir-engine dropped first, loopback, DHCP from systemd-network only, replies from tcp port {port} by ir-search only, "
            "a fetch chain (ir-fetch, resolver DNS) that close-fetch empties and reads back before the search starts; "
            f"input: policy drop, loopback, established, DHCP, tcp port {port}; loaded before networkd by nftables.service "
            f"whose effective ExecStart is {NFT_EXEC_START!r}"
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


# Ways to import or run code that ast.Import/ImportFrom never show (round 5): a call to any of these in a checked
# closure is refused, with ONE sanctioned site: engine_link._child's importlib.import_module(child_module), whose
# argument is the name tdx_engine passes as the literal "tdx_child".
# Builtins that run or compile code: counted as a bare name or on `builtins` (re.compile is a method of another thing).
DYNAMIC_BUILTINS = ("__import__", "exec", "eval", "compile")
# Loader and importlib/runpy calls: counted on ANY base (spec.loader.exec_module, il.import_module, runpy.run_path).
DYNAMIC_CALLS = ("import_module", "spec_from_file_location", "module_from_spec", "exec_module", "run_module", "run_path",
                 "load_module", "find_spec", "create_module")
DYNAMIC_GETATTR_TARGETS = ("importlib", "builtins", "sys", "__builtins__")
DYNAMIC_MODULES = ("runpy", "builtins")
SANCTIONED_DYNAMIC_SITE = ("sealedresearch/engine_link.py", "_child", "import_module", "child_module")
# The second and last sanctioned site: the record verifier loads tdx_image.py from BESIDE ITSELF (a vendored copy has
# no package); the file is one of the published, byte-pinned staged files. Sanctioned by shape: that function only,
# the literal file name, the path built from __file__.
SANCTIONED_LOADER = ("sealedresearch/verify_record.py", "load_tdx_image_module", "tdx_image.py")


def _loader_is_sanctioned(rel: str, func_node: Optional[ast.AST], text: str) -> bool:
    if rel != SANCTIONED_LOADER[0] or not isinstance(func_node, ast.FunctionDef) or func_node.name != SANCTIONED_LOADER[1]:
        return False
    src = ast.get_source_segment(text, func_node) or ""
    calls = {_call_name(n) for n in ast.walk(func_node) if isinstance(n, ast.Call)}
    return (f'"{SANCTIONED_LOADER[2]}"' in src and "__file__" in src and "os.path.dirname(os.path.abspath(__file__))" in src
            and not (calls & {"import_module", "__import__", "exec", "eval", "compile", "run_module", "run_path"}))


def dynamic_import_sites(path: str, tree_app: str) -> List[str]:
    """Every call in `path` that imports or runs code by a route the static closure cannot see: importlib.import_module,
    __import__, exec/eval/compile, importlib.util.spec_from_file_location/module_from_spec/exec_module, runpy, getattr on
    importlib/builtins/sys, and an import of runpy or builtins. Each as "file -> function: construct". The one sanctioned
    site (SANCTIONED_DYNAMIC_SITE) is left out ONLY when its argument is the bare name child_module."""
    rel = os.path.relpath(path, tree_app)
    text = _text(path)
    mod = _ast_parse(text)
    out: List[str] = []
    parents: Dict[ast.AST, ast.AST] = {}
    for node in ast.walk(mod):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing_node(node: ast.AST) -> Optional[ast.AST]:
        n = parents.get(node)
        while n is not None and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            n = parents.get(n)
        return n

    def enclosing(node: ast.AST) -> str:
        n = enclosing_node(node)
        return n.name if n is not None else "<module>"

    for node in ast.walk(mod):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                if name.split(".")[0] in DYNAMIC_MODULES:
                    out.append(f"{rel} -> {enclosing(node)}: import {name}")
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        is_builtin_route = name in DYNAMIC_BUILTINS and (isinstance(node.func, ast.Name) or (
            isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ("builtins", "__builtins__")))
        if name in DYNAMIC_CALLS or is_builtin_route:
            func = enclosing(node)
            if name in ("spec_from_file_location", "module_from_spec", "exec_module") and _loader_is_sanctioned(rel, enclosing_node(node), text):
                continue
            arg = node.args[0] if node.args else None
            if (rel, func, name) == SANCTIONED_DYNAMIC_SITE[:3] and isinstance(arg, ast.Name) and arg.id == SANCTIONED_DYNAMIC_SITE[3] \
                    and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "importlib":
                continue
            out.append(f"{rel} -> {func}: {name}(...)")
        elif name == "getattr" and node.args:
            target = node.args[0]
            if isinstance(target, ast.Name) and target.id in DYNAMIC_GETATTR_TARGETS:
                out.append(f"{rel} -> {enclosing(node)}: getattr({target.id}, ...)")
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in DYNAMIC_GETATTR_TARGETS:
                out.append(f"{rel} -> {enclosing(node)}: getattr({target.value.id}.{target.attr}, ...)")
    return out


def _local_imports(path: str, tree_app: str) -> List[str]:
    """Every module a file imports (module level or inside any function), as dotted names; local ones resolved
    relative to /opt/ir/app so `from . import x` inside sealedresearch/ becomes sealedresearch.x."""
    rel = os.path.relpath(path, tree_app)
    pkg = os.path.dirname(rel).replace(os.sep, ".")
    out: List[str] = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = ".".join(pkg.split(".")[:len(pkg.split(".")) - node.level + 1]) if pkg else ""
                mod = ".".join(x for x in (base, node.module or "") if x)
                out += [f"{mod}.{a.name}" if mod else a.name for a in node.names]
                if mod:
                    out.append(mod)
            else:
                mod = node.module or ""
                out.append(mod)
                out += [f"{mod}.{a.name}" for a in node.names]
    return out


def _module_file(name: str, tree_app: str) -> Optional[str]:
    p = os.path.join(tree_app, *name.split("."))
    if os.path.isfile(p + ".py"):
        return p + ".py"
    if os.path.isfile(os.path.join(p, "__init__.py")):
        return os.path.join(p, "__init__.py")
    return None


def front_closure(tree: str, entry: str = FRONT_ENTRY, closed_set: Tuple[str, ...] = CLOSED_MODULES) -> Tuple[List[str], List[str]]:
    """(files `entry` can reach by import, starting at tdx_entry.py by default; closed module names it names), both
    over EVERY import statement in those files, inside functions included. v14 round 3: run over the fetch too;
    round 4: over the engine's warm parent, against CLOSED_PROPER. Round 5: a dynamic import or code-running call
    in any reached file (dynamic_import_sites) counts as a closed name — the static closure cannot follow it."""
    app = os.path.join(tree, APP_DIR)
    seen, queue, closed = [], [os.path.join(app, entry)], []
    while queue:
        f = queue.pop()
        if f in seen or not os.path.isfile(f):
            continue
        seen.append(f)
        for name in _local_imports(f, app):
            if any(name == m or name.startswith(m + ".") for m in closed_set):
                closed.append(f"{os.path.relpath(f, app)} -> {name}")
            local = _module_file(name, app)
            if local and local not in seen:
                queue.append(local)
        closed += [f"dynamic: {site}" for site in dynamic_import_sites(f, app)]
    return sorted(os.path.relpath(x, app) for x in seen), sorted(set(closed))


_KEY_ATTRS = ("_x_priv", "_signer")
_KEY_INIT = ("self._x_priv, x_pub = envelope.gen_keypair()", "self._signer = Ed25519PrivateKey.generate()")
_REFLECTION_CALLS = ("getattr", "setattr", "delattr", "vars", "globals", "locals", "eval", "exec", "compile")
_REFLECTION_MODULES = ("pickle", "copy", "copyreg", "marshal", "shelve", "inspect", "gc", "ctypes", "dill", "operator",
                       "importlib", "builtins")
_KEY_STRING = re.compile(r"_x_priv|private_bytes|(?<![A-Za-z0-9_])_signer(?![A-Za-z0-9_])")


def _private_key_problems(stext: str, smod: Any, svc: Any, init: Any, app: str) -> List[str]:
    """For "D7. the front names its private keys only to open and sign" (review 8 Nov: a first version passed 8 ways to leak a key). Syntactic:
    it reads the published source, so it says what that source does, not what a library under it might do."""
    kp: List[str] = []
    if svc is None or init is None:
        return ["no SearchService.__init__ to check"]
    want = {ast.dump(ast.parse(src).body[0]) for src in _KEY_INIT}
    have = [n for n in ast.walk(svc) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and any(isinstance(t, ast.Attribute) and t.attr in _KEY_ATTRS for tt in getattr(n, "targets", [getattr(n, "target", None)])
                    for t in ast.walk(tt) if tt is not None)]
    if len(have) != 2 or {ast.dump(n) for n in have} != want or not all(any(n is m for m in ast.walk(init)) for n in have):
        kp.append("the two keys are not made by exactly the published statements in SearchService.__init__ "
                  f"({' / '.join(_KEY_INIT)})")
    parents = {c: p for p in ast.walk(smod) for c in ast.iter_child_nodes(p)}
    for n in ast.walk(smod):
        if not (isinstance(n, ast.Attribute) and n.attr in _KEY_ATTRS and isinstance(n.ctx, ast.Load)):
            continue
        up = parents.get(n)
        if n.attr == "_x_priv":
            f = getattr(up, "func", None)
            if not (isinstance(up, ast.Call) and isinstance(f, ast.Attribute) and f.attr == "open_"
                    and isinstance(f.value, ast.Name) and f.value.id == "envelope" and up.args and up.args[0] is n):
                kp.append(f"search_service line {n.lineno}: the sealing key is used other than as envelope.open_'s key")
        elif not (isinstance(up, ast.Attribute) and up.attr in ("sign", "public_key") and isinstance(parents.get(up), ast.Call)
                  and getattr(parents.get(up), "func", None) is up):
            kp.append(f"search_service line {n.lineno}: the signing key is used other than to sign or give its public half")
    for n in ast.walk(smod):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _REFLECTION_CALLS:
            a0 = n.args[0] if n.args else None
            a1 = n.args[1] if len(n.args) > 1 else None
            harmless = (n.func.id == "getattr" and not (isinstance(a0, ast.Name) and a0.id == "self")
                        and isinstance(a1, ast.Constant) and isinstance(a1.value, str) and not _KEY_STRING.search(a1.value))
            if not harmless:
                kp.append(f"search_service line {n.lineno}: {n.func.id}() (reflection could reach a key)")
        elif isinstance(n, ast.Attribute) and n.attr.startswith("__"):
            kp.append(f"search_service line {n.lineno}: .{n.attr} (no dunder attribute is used by the published front)")
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)) and isinstance(n.value, ast.Name) \
                and n.value.id in ("envelope", "statement", "search", "builtins"):
            kp.append(f"search_service line {n.lineno}: assigns {n.value.id}.{n.attr} (patching a module the keys pass through)")
        elif isinstance(n, ast.Name) and n.id in ("builtins", "operator", "importlib", "__import__", "__builtins__"):
            kp.append(f"search_service line {n.lineno}: {n.id}")
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""]
            for m in mods:
                if m.split(".")[0] in _REFLECTION_MODULES:
                    kp.append(f"search_service line {n.lineno}: imports {m}")
    # The one name the sealing key may be handed to: envelope.open_, with `envelope` the package module imported once.
    binds = []
    for n in ast.walk(smod):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in ("envelope", "open_"):
            binds.append(n.lineno)
        elif isinstance(n, ast.Name) and n.id in ("envelope", "open_") and isinstance(n.ctx, (ast.Store, ast.Del)):
            binds.append(n.lineno)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if (a.asname or a.name.split(".")[0]) in ("envelope", "open_") and not (
                        isinstance(n, ast.ImportFrom) and a.name == "envelope" and a.asname is None
                        and ((n.module is None and n.level == 1) or (n.module == "sealedresearch" and n.level == 0))):
                    binds.append(n.lineno)
    if binds:
        kp.append(f"search_service binds envelope/open_ other than by importing the package's envelope module (line(s) {binds})")
    for dirpath, _dirs, names in os.walk(app):
        for name in sorted(names):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, app)
            try:
                mod = _ast_parse(_text(path))
            except Exception:                               # noqa: BLE001
                kp.append(f"{rel} does not parse")
                continue
            in_gen = set()
            if rel == "sealedresearch/envelope.py":
                for fn in mod.body:
                    if isinstance(fn, ast.FunctionDef) and fn.name == "gen_keypair":
                        in_gen = {id(x) for x in ast.walk(fn)}
            for n in ast.walk(mod):
                if isinstance(n, ast.Attribute) and n.attr == "private_bytes" and id(n) not in in_gen:
                    kp.append(f"{rel} line {n.lineno}: private_bytes outside envelope.gen_keypair")
                if rel == "sealedresearch/search_service.py":
                    continue
                if isinstance(n, ast.Attribute) and n.attr in _KEY_ATTRS:
                    kp.append(f"{rel} line {n.lineno}: reaches into the machine's private keys (.{n.attr})")
                elif isinstance(n, ast.Constant) and isinstance(n.value, str) and _KEY_STRING.search(n.value):
                    kp.append(f"{rel} line {n.lineno}: names a private key in a string")
            if rel == "sealedresearch/search_service.py":
                for n in ast.walk(mod):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and _KEY_STRING.search(n.value):
                        kp.append(f"{rel} line {n.lineno}: names a private key in a string")
    return kp


def check_seal_order(rep: ImageReport, tree: str) -> None:
    """D7: the seal (sealedresearch/confine.py: no-new-privs + seccomp over EVERY thread, TSYNC, read back per task)
    sits between binding and serving in the Azure entry, and in the TDX front between bind and the engine; the
    engine process seals BEFORE it imports the closed modules; the front reaches no closed module by import; the
    quote helper answers once per boot; the offer is served from bytes written once."""
    problems = []
    app = os.path.join(tree, APP_DIR)
    paths = {n: os.path.join(app, n) for n in ("m2_entry.py", "tdx_entry.py", "tdx_engine.py", "sealedresearch/confine.py",
                                               "ir_quote.py", "tdx_attest.py", "sealedresearch/search_service.py",
                                               "sealedresearch/engine_link.py", "sealedresearch/search.py",
                                               "sealedresearch/result_schema.py", "tdx_fetch.py", "ir_pin.py")}
    for n, p in paths.items():
        if not os.path.isfile(p):
            rep.add(False, "D7. seal before serve", f"/{APP_DIR}/{n} missing")
            return
    conf_text = _text(paths["sealedresearch/confine.py"])
    cmod = _ast_parse(conf_text)
    seal = _function(cmod, "seal_network")
    if seal is None:
        problems.append("confine.seal_network not found")
    else:
        calls = {_call_name(n) for n in ast.walk(seal) if isinstance(n, ast.Call)}
        if not {"prctl", "syscall"} <= calls:
            problems.append("seal_network does not call prctl and syscall")
        flag = next((n.value.value for n in cmod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                     and any(isinstance(t, ast.Name) and t.id == "SECCOMP_FILTER_FLAG_TSYNC" for t in n.targets)), None)
        if flag != 1 or not _syscall_passes_tsync(seal):
            problems.append("seal_network does not install the filter with SECCOMP_FILTER_FLAG_TSYNC (= 1): threads alive at the seal stay unsealed")
        src_seal = ast.get_source_segment(conf_text, seal) or ""
        if "/proc/self/task" not in src_seal or "Seccomp:" not in src_seal:
            problems.append("seal_network does not read the seccomp mode back for every thread (/proc/self/task/*/status)")
    mod = _parse(paths["m2_entry.py"])
    main = _function(mod, "main")
    if main is None:
        problems.append("m2_entry.main not found")
    else:
        i_bind = _stmt_index_calling(main.body, "make_server")
        i_seal = _stmt_index_calling(main.body, "seal_network")
        i_serve = _stmt_index_calling(main.body, "serve_forever")
        if None in (i_bind, i_seal, i_serve) or not (i_bind < i_seal < i_serve):
            problems.append(f"m2_entry.main order make_server={i_bind} seal_network={i_seal} serve_forever={i_serve}")
        if not any(isinstance(s, ast.Expr) and _call_name(s.value) == "seal_network" for s in main.body):
            problems.append("seal_network() is not an unconditional top-level statement of m2_entry.main")
    tmod = _parse(paths["tdx_entry.py"])
    tmain = _function(tmod, "main")
    if tmain is None:
        problems.append("tdx_entry.main not found")
    else:
        i_chan = _stmt_index_calling(tmain.body, "open_quote_channel")
        i_link = _stmt_index_calling(tmain.body, "connect_engine")
        i_bind = _stmt_index_calling(tmain.body, "bind_server")
        i_seal = _stmt_index_calling(tmain.body, "seal_network")
        i_engine = _stmt_index_calling(tmain.body, "EngineProxy")
        i_probe = _stmt_index_calling(tmain.body, "search")
        i_service = _stmt_index_calling(tmain.body, "SearchService")
        if i_probe is None or i_engine is None or i_service is None or not (i_engine < i_probe < i_service):
            problems.append(f"tdx_entry.main does not run one probe search through the engine (={i_probe}) between EngineProxy "
                            f"(={i_engine}) and SearchService (={i_service}): the box would serve an offer for an engine never seen to answer")
        i_close = _stmt_index_calling(tmain.body, "close_quote_channel")
        i_serve = _stmt_index_calling(tmain.body, "serve_forever")
        order = (i_chan, i_link, i_bind, i_seal, i_engine, i_service, i_close, i_serve)
        if None in order or not (i_chan < i_seal and i_link < i_seal and i_bind < i_seal < i_engine < i_service < i_close < i_serve):
            problems.append(f"tdx_entry.main order quote channel={i_chan} engine link={i_link} bind_server={i_bind} seal_network={i_seal} "
                            f"EngineProxy={i_engine} SearchService={i_service} close_quote_channel={i_close} serve_forever={i_serve}; "
                            "want channel, link and bind, then seal, then the engine proxy, the service (its one quote), the channel closed, then serve")
        if not any(isinstance(s, ast.Expr) and _call_name(s.value) == "seal_network" for s in tmain.body):
            problems.append("seal_network() is not an unconditional top-level statement of tdx_entry.main")
        if _stmt_index_calling(tmain.body, "make_server") is not None:
            problems.append("tdx_entry.main calls make_server (binding and the engine in one step)")
    emod = _parse(paths["tdx_engine.py"])
    emain = _function(emod, "main")
    if emain is None:
        problems.append("tdx_engine.main not found")
    else:
        if any(_imports_closed(stmt) for stmt in ast.walk(emod)):
            problems.append("tdx_engine imports a closed module (the warm parent must never)")
        i_deny = _stmt_index_calling(emain.body, "deny_ptrace")
        i_seal = _stmt_index_calling(emain.body, "seal_network")
        i_mem = _stmt_index_calling(emain.body, "seal_memory")
        i_warm = _stmt_index_calling(emain.body, "warm")
        i_accept = _stmt_index_calling(emain.body, "accept_control")
        i_serve = _stmt_index_calling(emain.body, "serve_forking")
        if None in (i_deny, i_seal, i_mem, i_warm, i_accept, i_serve) or not (i_deny < i_seal < i_mem < i_warm < i_accept < i_serve):
            problems.append(f"tdx_engine.main order deny_ptrace={i_deny} seal_network={i_seal} seal_memory={i_mem} warm={i_warm} "
                            f"accept_control={i_accept} serve_forking={i_serve}; want non-dumpable, the two seals, the published "
                            "warm, the one control connection, then one process per request")
        if _stmt_index_calling(emain.body, "socket") is not None and not any(
                isinstance(n, ast.Call) and _call_name(n) == "socket" and any(isinstance(k, ast.keyword) and k.arg == "fileno" for k in n.keywords)
                for n in ast.walk(emain)):
            problems.append("tdx_engine.main creates a socket instead of taking the one systemd passes in (fileno=)")
    rep.add(not problems, "D7. seal before serve",
            "confine.seal_network: no-new-privs + seccomp with TSYNC, mode read back for every thread; m2_entry.main: make_server, "
            "seal, serve; tdx_entry.main: quote channel, engine link and bind_server, then seal, then EngineProxy, SearchService "
            "(one quote), close_quote_channel, serve_forever; tdx_engine.main: inherited socket, non-dumpable, both seals, the "
            "published warm, the one control connection, then serve_forking (no closed import in the parent)"
            if not problems else "; ".join(problems))
    # The front's import graph, and the fetch's (it runs while egress is open), and the root helpers' (stdlib only).
    for entry, row, key in ((FRONT_ENTRY, "D7. front imports no closed module", "front_files"),
                            (FETCH_ENTRY, "D7. fetch imports no closed module", "fetch_files")):
        files, closed = front_closure(tree, entry)
        bad_files = [f for f in files if f in CLOSED_FILES or f == "m2_entry.py"]
        rep.values[key] = files
        ok = bool(files) and not closed and not bad_files
        detail = (f"{len(files)} files reachable by import from {entry} (every import statement, inside functions included): "
                  + ", ".join(files))
        if entry == FETCH_ENTRY:
            stdlib = set(sys.stdlib_module_names)
            non_std = []
            for n in STDLIB_ONLY:
                p = os.path.join(app, n)
                if not os.path.isfile(p):
                    non_std.append(f"{n} missing")
                    continue
                for name in _local_imports(p, app):
                    if name.split(".")[0] not in stdlib:
                        non_std.append(f"{n} -> {name}")
            ok = ok and not non_std
            detail += f"; {', '.join(STDLIB_ONLY)} import the standard library only"
            if non_std:
                problems_s = f"; not stdlib: {sorted(set(non_std))}"
            else:
                problems_s = ""
        else:
            problems_s = ""
        rep.add(ok, row, detail if ok else
                (f"closed modules named: {closed}; " if closed else "") + (f"closed files reached: {bad_files}" if bad_files else "")
                + ("" if files else "no files") + problems_s)
    # One quote per boot: the helper claims a root-only marker O_EXCL before it asks the module, and refuses after.
    qtext = _text(paths["ir_quote.py"])
    qmod = _ast_parse(qtext)
    serve_fn = _function(qmod, "serve_connection")
    claim = _function(qmod, "claim_once")
    qp = []
    if claim is None or "O_EXCL" not in (ast.get_source_segment(qtext, claim) or ""):
        qp.append("ir_quote.claim_once does not create its marker O_EXCL")
    if serve_fn is None:
        qp.append("ir_quote.serve_connection not found")
    else:
        body_src = ast.get_source_segment(qtext, serve_fn) or ""
        i_claim = _stmt_index_calling(serve_fn.body, "claim_once")
        i_quote = _stmt_index_calling(serve_fn.body, "quote_fn")
        if None in (i_claim, i_quote) or not (i_claim <= i_quote):
            qp.append("ir_quote.serve_connection does not claim the once-marker before asking the module")
        if "while" in body_src.split("def serve_connection", 1)[-1].replace("while len(buf)", ""):
            qp.append("ir_quote.serve_connection answers more than one request per connection")
        if "bytes(64)" not in qtext or '"ir-fetch": bytes(64)' not in qtext:
            qp.append("ir_quote does not force the fetch's REPORTDATA to zeros")
    uq = effective_unit(tree, "ir-quote.service")[0].get("Service", {})
    if uq.get("RuntimeDirectoryPreserve") != ["yes"] or uq.get("RuntimeDirectory") != ["ir-quote"]:
        qp.append("ir-quote.service does not keep /run/ir-quote across restarts (the markers would reset)")
    atext = _text(paths["tdx_attest.py"])
    if "def close_quote_channel" not in atext:
        qp.append("tdx_attest has no close_quote_channel")
    stext = _text(paths["sealedresearch/search_service.py"])
    smod = _ast_parse(stext)
    svc = next((n for n in ast.walk(smod) if isinstance(n, ast.ClassDef) and n.name == "SearchService"), None)
    attest_calls = [n for n in ast.walk(svc) if isinstance(n, ast.Call) and _call_name(n) == "attest"] if svc else []
    init = next((n for n in svc.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None) if svc else None
    init_calls = [n for n in ast.walk(init) if isinstance(n, ast.Call) and _call_name(n) == "attest"] if init else []
    if len(attest_calls) != 1 or len(init_calls) != 1:
        qp.append(f"SearchService calls attest {len(attest_calls)} times ({len(init_calls)} in __init__); want exactly one, at init")
    rep.add(not qp, "D7. one quote per boot",
            "ir_quote: one request per connection, a root-only O_EXCL marker per peer claimed before the module is asked, the fetch's "
            "REPORTDATA forced to zeros, markers kept across restarts; SearchService attests once at init; the front closes its channel"
            if not qp else "; ".join(qp))
    # The offer: bytes written once at init, served as such.
    op = []
    if "self.offer_bytes" not in stext or "json.dumps(self.offer).encode()" not in stext:
        op.append("SearchService does not serialise the offer to bytes at init")
    handler_src = stext[stext.index("def do_GET"):stext.index("def do_POST")] if "def do_GET" in stext and "def do_POST" in stext else ""
    if "self.server.offer_bytes" not in handler_src or ".offer)" in handler_src or "service" in handler_src.split("else")[0]:
        op.append("GET /offer is not served from the server's frozen offer_bytes")
    srv_cls = next((n for n in ast.walk(smod) if isinstance(n, ast.ClassDef) and n.name == "_Server"), None)
    setter = next((n for n in ast.walk(srv_cls) if isinstance(n, ast.FunctionDef) and n.name == "service"
                   and any(isinstance(d, ast.Attribute) and d.attr == "setter" for d in n.decorator_list)), None) if srv_cls else None
    if setter is None or "offer_bytes" not in (ast.get_source_segment(stext, setter) or "") or "_frozen" not in (ast.get_source_segment(stext, setter) or ""):
        op.append("the server does not freeze offer_bytes when the service is attached")
    if init:
        assigns = [n for n in ast.walk(init) if isinstance(n, ast.Attribute) and n.attr == "offer_bytes" and isinstance(n.ctx, ast.Store)]
        if len(assigns) != 1:
            op.append(f"offer_bytes assigned {len(assigns)} times in __init__")
    if "offer_bytes" in stext.replace("self.offer_bytes: bytes = json.dumps(self.offer).encode()", "").split("def do_GET")[0].split("class SearchService")[-1] \
            and stext.count("offer_bytes =") > 1:
        op.append("offer_bytes is reassigned")
    rep.add(not op, "D7. offer served from immutable bytes",
            "SearchService.offer_bytes written once at init (json of the offer), frozen into the server when the service is "
            "attached, GET /offer writes those bytes and reads no dictionary" if not op else "; ".join(op))
    # Who could open a query (verifier blocker TDX_KEYS_RETENTION, 8 Nov 2026). The machine's two private keys are made
    # in the front's memory at start-up and their public halves go into the hardware-signed report. This row checks the
    # published code only ever USES them: the X25519 key as the key argument of envelope.open_, the signing key to sign
    # or to give its public half; one assignment each, at init; no other published module touches either attribute;
    # nothing in the front serialises a private key. (What the hardware keeps from the host is the trusted base.)
    kp = _private_key_problems(stext, smod, svc, init, app)
    rep.add(not kp, "D7. the front names its private keys only to open and sign",
            "a syntactic check of the front's published code (reflection elsewhere and libraries underneath are not "
            "established): SearchService makes its X25519 key (envelope.gen_keypair) and its "
            "signing key (Ed25519PrivateKey.generate) in exactly the published statements at init; the sealing key appears "
            "only as envelope.open_'s key and the signing key only to sign or give its public half; the front uses no "
            "reflection (getattr/setattr/vars/__dict__ on itself, pickle, copy, inspect, gc); no other published module "
            "names either key; private_bytes appears only in envelope.gen_keypair" if not kp else "; ".join(kp))
    # The firewall passes a reply only while its socket is owned by the search account; a closed socket has no owner.
    # So every accepted connection must linger until the peer has acknowledged everything (v14 rc6: the /offer was cut).
    lp = []
    getreq = next((n for n in ast.walk(srv_cls) if isinstance(n, ast.FunctionDef) and n.name == "get_request"), None) if srv_cls else None
    gsrc = (ast.get_source_segment(stext, getreq) or "") if getreq else ""
    if "SO_LINGER" not in gsrc or 'struct.pack("ii", 1, self.LINGER_SECONDS)' not in gsrc:
        lp.append("_Server.get_request does not set SO_LINGER (on, LINGER_SECONDS) on every accepted connection")
    secs = next((n.value.value for n in (srv_cls.body if srv_cls else []) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "LINGER_SECONDS" for t in n.targets)
                 and isinstance(n.value, ast.Constant)), None)
    if not isinstance(secs, int) or secs < 10:
        lp.append(f"LINGER_SECONDS is {secs!r}; want an integer of at least 10")
    rep.add(not lp, "D7. a reply is delivered before its socket is let go",
            f"every accepted connection lingers up to {secs} s: close() returns once the peer has acknowledged the whole reply "
            "and the FIN, so nothing is left queued on a socket the firewall's owner rule (skuid ir-search) no longer matches"
            if not lp else "; ".join(lp))
    check_per_request(rep, tree, paths, stext, smod)


def _assigned_dict(mod: ast.Module, name: str) -> Dict[str, int]:
    for node in mod.body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == name for x in node.targets) and isinstance(node.value, ast.Dict):
            return {k.value: v.value for k, v in zip(node.value.keys, node.value.values)
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)}
    return {}


def _reference_confine_source() -> str:
    """The verifier's own copy of sealedresearch/confine.py (shipped beside this module, vendored in the client).
    The image's confine.py must match it to the AST; the programs the rows judge are built by THIS copy."""
    return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "confine.py"), encoding="utf-8").read()


def _reference_confine_module() -> Any:
    """The reference confine module whose programs the D7 rows execute. Imported from the package when this module
    is part of one; otherwise (verify_record.py loads this file by path, with no package, as an exported record and
    the client do) the same confine.py beside this file is loaded by path. `from . import confine` alone raises
    ImportError there, and verify_record --tdx-image then refused every v14 image whose root it could open."""
    if __package__:
        from . import confine
        return confine
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confine.py")
    spec = importlib.util.spec_from_file_location("ir_tdx_confine_reference", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path} is not beside this checker")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _same_ast(a_text: str, b_text: str) -> bool:
    try:
        return ast.dump(_ast_parse(a_text)) == ast.dump(_ast_parse(b_text))
    except SyntaxError:
        return False


def run_bpf(prog: bytes, nr: int, args: Tuple[int, ...] = (), arch: int = 0xC000003E) -> str:
    """Execute a classic-BPF seccomp program (the subset the seals use: ld abs, jeq, jset, ret) against one
    syscall: returns "allow", "eperm", "kill" or "other". The rows judge the verifier's own programs by what
    they DO; the image's confine.py is compared to the reference and never run."""
    data = struct.pack("<II", nr, arch) + struct.pack("<Q", 0) + b"".join(struct.pack("<Q", a & 0xFFFFFFFFFFFFFFFF) for a in (list(args) + [0] * 6)[:6])
    words = [struct.unpack("HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
    acc, pc = 0, 0
    for _ in range(4096):
        if pc >= len(words):
            return "other"
        code, jt, jf, k = words[pc]
        if code == 0x20:                                                    # ld w abs
            acc = struct.unpack("<I", data[k:k + 4])[0]; pc += 1
        elif code == 0x15:                                                  # jeq k
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x45:                                                  # jset k
            pc += 1 + (jt if acc & k else jf)
        elif code == 0x06:                                                  # ret k
            return {0x7FFF0000: "allow", 0x00050000 | 1: "eperm", 0x80000000: "kill"}.get(k, "other")
        else:
            return "other"
    return "other"


def check_memory_seal(rep: ImageReport, tree: str, paths: Dict[str, str], ltext: str, lmod: ast.Module, etext: str) -> None:
    """D7 (round 3, H1): before the closed import the engine installs confine.seal_memory, whose program refuses
    every call in MEMORY_SEAL_REQUIRED and mmap with MAP_SHARED when anonymous or writable (read off the assembled
    BPF, not the comments); the engine unit keeps /dev/zero and /dev/hugepages read-only; before every fork the
    parent checks for shared writable mappings and new IPC objects and ends rather than forks; the child closes
    every inherited descriptor and refuses setsid/setpgid; the front refuses a reply the parent itself wrote."""
    pr = []
    ctext = _text(paths["sealedresearch/confine.py"])
    cmod = _ast_parse(ctext)
    table = _assigned_dict(cmod, "NR_DENIED_MEMORY")
    missing = {n: nr for n, nr in MEMORY_SEAL_REQUIRED.items() if table.get(n) != nr}
    if missing:
        pr.append(f"confine.NR_DENIED_MEMORY lacks {sorted(missing)}")
    if _function(cmod, "seal_memory") is None or "memory_seal_program()" not in _src(ctext, cmod, "seal_memory"):
        pr.append("confine.seal_memory does not install memory_seal_program")
    # The image's confine.py is never executed: it must equal the verifier's reference to the AST, and the program
    # judged below is the reference's own.
    reference = _reference_confine_module()
    if not _same_ast(ctext, _reference_confine_source()):
        pr.append("the image's sealedresearch/confine.py differs from the verifier's reference confine.py (AST): a seal that "
                  "could answer the checker one way and the kernel another is not accepted")
    prog = reference.memory_seal_program()
    if len(prog) % 8:
        pr.append("the reference seal program is malformed")
    else:
        # Executed, not pattern-matched: each refused call must come back EPERM, the mmap rule must refuse the
        # shared-anonymous and shared-writable cases and allow private and read-only-shared ones, an ordinary
        # call must pass, and a foreign architecture must be killed.
        not_refused = sorted(n for n, nr in MEMORY_SEAL_REQUIRED.items() if run_bpf(prog, nr, (0, 0, 0, 0, 0, 0)) != "eperm")
        if not_refused:
            pr.append(f"the assembled seal does not refuse {not_refused}")
        PROT_RW, PROT_R, SHARED, PRIVATE, ANON = 0x3, 0x1, 0x01, 0x02, 0x20
        mmap_cases = {("shared anonymous", (0, 4096, PROT_RW, SHARED | ANON, -1 & 0xFFFFFFFF, 0)): "eperm",
                      ("shared anonymous read-only", (0, 4096, PROT_R, SHARED | ANON, -1 & 0xFFFFFFFF, 0)): "eperm",
                      ("shared writable file", (0, 4096, PROT_RW, SHARED, 5, 0)): "eperm",
                      ("shared_validate writable file", (0, 4096, PROT_RW, 0x03, 5, 0)): "eperm",
                      ("private anonymous", (0, 4096, PROT_RW, PRIVATE | ANON, -1 & 0xFFFFFFFF, 0)): "allow",
                      ("shared read-only file", (0, 4096, PROT_R, SHARED, 5, 0)): "allow"}
        wrong = [f"mmap {name} -> {run_bpf(prog, 9, args)}" for (name, args), want in mmap_cases.items() if run_bpf(prog, 9, args) != want]
        if wrong:
            pr.append("the assembled seal's mmap rule is wrong: " + ", ".join(wrong))
        if run_bpf(prog, 0, (3, 0, 0)) != "allow" or run_bpf(prog, 1, (1, 0, 0)) != "allow":
            pr.append("the assembled seal does not allow read and write")
        if run_bpf(prog, 0, (3, 0, 0), arch=0x40000003) != "kill":
            pr.append("the assembled seal does not kill on a foreign architecture")
        if run_bpf(prog, 0x40000000 | 0, (3, 0, 0)) != "kill":
            pr.append("the assembled seal does not kill an x32 syscall number")
        # The child's program (confine.child_program(pid)): signals, limits, priorities and scheduling only on itself.
        cp = reference.child_program(4242)
        child_cases = {("kill self", 62, (4242, 9)): "allow", ("kill other", 62, (4241, 9)): "eperm", ("kill group", 62, (-4242 & 0xFFFFFFFF, 9)): "eperm",
                       ("tgkill other", 234, (4241, 4241, 9)): "eperm", ("rt_sigqueueinfo other", 129, (1, 9, 0)): "eperm",
                       ("pidfd_send_signal", 424, (5, 9, 0, 0)): "eperm", ("prlimit64 self (0)", 302, (0, 7, 0, 0)): "allow",
                       ("prlimit64 other", 302, (1, 7, 0, 0)): "eperm", ("sched_setaffinity self", 203, (0, 8, 0)): "allow",
                       ("sched_setaffinity other", 203, (4241, 8, 0)): "eperm", ("setpriority other", 141, (0, 4241, 0)): "eperm",
                       ("setsid", 112, ()): "eperm", ("setpgid", 109, (0, 0)): "eperm", ("read", 0, (3, 0, 0)): "allow",
                       ("fork", 57, ()): "allow", ("clone", 56, (0,)): "allow"}
        wrong = [f"{name} -> {run_bpf(cp, nr, args)}" for (name, nr, args), want in child_cases.items() if run_bpf(cp, nr, args) != want]
        if wrong:
            pr.append("the child's program is wrong: " + ", ".join(wrong))
        if run_bpf(cp, 0x40000000, (3, 0, 0)) != "kill":
            pr.append("the child's program does not kill an x32 syscall number")
    emain = _function(_ast_parse(etext), "main")
    if emain is not None:
        i_mem = _stmt_index_calling(emain.body, "seal_memory")
        i_warm = _stmt_index_calling(emain.body, "warm")
        i_base = _stmt_index_calling(emain.body, "ipc_snapshot")
        if None in (i_mem, i_warm, i_base) or not (i_mem < i_base < i_warm):
            pr.append(f"tdx_engine.main: seal_memory={i_mem} ipc_snapshot={i_base} warm={i_warm}; want the seal, the baseline, then the published warm")
        i_maps = _stmt_index_calling(emain.body, "shared_writable_maps")
        if i_maps is None or i_warm is None or not (i_maps < i_warm):
            pr.append("tdx_engine does not refuse a shared writable mapping before the warm")
        if "confine_child=confine.confine_child" not in etext or "baseline=baseline" not in etext:
            pr.append("tdx_engine.main does not pass the baseline and confine_child to serve_forking")
    sf = _src(ltext, lmod, "serve_forking")
    if "if not fork_is_safe(baseline):" not in sf or "control.close()" not in sf.split("fork_is_safe(baseline)", 1)[-1].split("socketpair", 1)[0]:
        pr.append("serve_forking does not check fork_is_safe before every fork and end with the control link closed")
    fs = _src(ltext, lmod, "fork_is_safe")
    if "shared_writable_maps()" not in fs or "ipc_snapshot()" not in fs:
        pr.append("fork_is_safe does not read /proc/self/maps and the IPC snapshot")
    sw = _src(ltext, lmod, "shared_writable_maps")
    if "/proc/self/maps" not in sw or '[1] == "w"' not in sw or '[3] == "s"' not in sw:
        pr.append("shared_writable_maps does not select writable shared mappings")
    snap = _src(ltext, lmod, "ipc_snapshot")
    if "/proc/sysvipc/" not in snap or "/proc/keys" not in snap:
        pr.append("ipc_snapshot does not read /proc/sysvipc and /proc/keys")
    ch = _src(ltext, lmod, "_child")
    if "_close_inherited(" not in ch or "confine_child()" not in ch:
        pr.append("_child does not close inherited descriptors and seal its process group")
    cc = _src(ctext, cmod, "confine_child")
    if "child_program(os.getpid())" not in cc:
        pr.append("confine.confine_child does not install child_program for the child's own pid")
    call = _method_src(ltext, lmod, "EngineProxy", "_call")
    if "pid == self.engine_pid" not in call or "recv_reply(" not in call:
        pr.append("EngineProxy._call does not refuse a reply whose kernel-stamped sender is the engine parent's pid (SCM_CREDENTIALS)")
    eu, _p, _d = effective_unit(tree, "ir-engine.service")
    svc = eu.get("Service", {})
    allow = [a.split() for a in svc.get("DeviceAllow", [])]
    writable = [a[0] for a in allow if len(a) > 1 and "w" in a[1]]
    if svc.get("DevicePolicy") != ["strict"] or ["/dev/zero", "r"] not in allow or writable != ["/dev/null"]:
        pr.append("ir-engine.service does not confine devices to /dev/zero read-only and /dev/null read-write (DevicePolicy=strict; "
                  "a read-only mount does not stop open(O_RDWR) on a device node, so a shared mapping of /dev/zero could gain write)")
    ro = " ".join(svc.get("ReadOnlyPaths", [])).split()
    if not any(x in ("/dev/hugepages", "-/dev/hugepages") for x in ro) or "/dev/shm" not in ro:
        pr.append("ir-engine.service does not keep /dev/hugepages and /dev/shm read-only")
    rep.add(not pr, "D7. no memory outlives a request",
            f"confine.seal_memory before the closed import: {len(MEMORY_SEAL_REQUIRED)} calls refused (SysV and POSIX IPC, keys, "
            "userfaultfd, process_madvise, mremap, remap_file_pages, memfd, io_uring, creat, openat2, mknod, ptrace, process_vm, "
            "pidfd_getfd, kcmp) and mmap refused when MAP_SHARED with MAP_ANONYMOUS or PROT_WRITE — read off the assembled BPF; "
            "/dev/zero read-only by the device cgroup, /dev/hugepages and /dev/shm by mount; the parent checks shared writable mappings and the IPC baseline before "
            "every fork and ends rather than forks; the child closes inherited descriptors and cannot leave its group, signal or "
            "re-limit another process; the front refuses a reply whose kernel-stamped sender pid is the parent's (this tells the "
            "parent from any OTHER process, not a helper the parent forked: that the parent forks none rests on its import "
            "closure, the next row)" if not pr else "; ".join(pr))
    check_parent_closure(rep, tree, paths, ltext, lmod, etext)
    check_fixed_shape(rep, tree)
    check_kernel_objects(rep, tree)
    check_data_not_code(rep, tree)


def _encoder_allowlist_problems(text: str, mod: ast.Module, cm: str) -> List[str]:
    """The v16 addition to row D7 parses-data (00de8be): the encoder directory is an exact allowlist."""
    pr: List[str] = []
    # v16: the encoder directory is an exact allowlist (files pinned by sha256, weights pinned by structure).
    ef = next((n.value for n in mod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict)
               and any(isinstance(x, ast.Name) and x.id == "ENCODER_FILES" for x in n.targets)), None)
    pins = {k.value: v.value for k, v in zip(ef.keys, ef.values) if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)} if ef is not None else {}
    if not ({"modules.json", "config.json", "tokenizer.json", "tokenizer_config.json", "config_sentence_transformers.json"} <= set(pins)
            and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values())):
        pr.append("ENCODER_FILES does not pin the encoder's configuration files by sha256")
    msha = next((n.value.value for n in mod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                 and any(isinstance(x, ast.Name) and x.id == "ENCODER_TENSOR_MANIFEST_SHA256" for x in n.targets)), None)
    if not (isinstance(msha, str) and re.fullmatch(r"[0-9a-f]{64}", msha)):
        pr.append("ENCODER_TENSOR_MANIFEST_SHA256 is not a pinned sha256")
    cmf = _function(mod, "check_model_dir")
    calls = {_call_name(n) for n in ast.walk(cmf) if isinstance(n, ast.Call)} if cmf else set()
    if not {"safetensors_manifest", "sha256", "islink"} <= calls or "found != want" not in cm or "followlinks=False" not in cm:
        pr.append("check_model_dir does not refuse anything but the pinned set (exact file set, sha256 per file, weights structure, no links)")
    return pr


def check_data_not_code(rep: ImageReport, tree: str) -> None:
    """D7 (round 5): the files the warm parent reads from the index provider cannot be code to the readers:
    SentenceTransformer(..., trust_remote_code=False) explicitly; TORCH_FORCE_WEIGHTS_ONLY_LOAD=1 set before torch is
    imported; the encoder directory checked (safetensors only, sentence_transformers modules only) before it is read;
    faiss's index and LightGBM's text model are typed structures by format."""
    pr = []
    p = os.path.join(tree, APP_DIR, "sealedresearch/engine_preload.py")
    if not os.path.isfile(p):
        rep.add(False, "D7. the warm parent parses data, not code", "engine_preload.py missing")
        return
    text = _text(p)
    mod = _ast_parse(text)
    st_calls = [n for n in ast.walk(mod) if isinstance(n, ast.Call) and _call_name(n) == "SentenceTransformer"]
    if not st_calls or not all(any(k.arg == "trust_remote_code" and isinstance(k.value, ast.Constant) and k.value.value is False for k in c.keywords) for c in st_calls):
        pr.append("SentenceTransformer is not called with trust_remote_code=False")
    imp = _function(mod, "import_libraries")
    body = [s for s in imp.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))] if imp else []
    if not body or not (isinstance(body[0], ast.Assign) and "TORCH_FORCE_WEIGHTS_ONLY_LOAD" in ast.dump(body[0])
                        and isinstance(body[0].value, ast.Constant) and body[0].value.value == "1"):
        pr.append("import_libraries does not set TORCH_FORCE_WEIGHTS_ONLY_LOAD=1 before anything is imported")
    pre = _function(mod, "preload")
    if pre is None:
        pr.append("preload not found")
    else:
        i_check = _stmt_index_calling(pre.body, "check_model_dir")
        i_st = _stmt_index_calling(pre.body, "SentenceTransformer")
        if None in (i_check, i_st) or not (i_check < i_st):
            pr.append("preload does not check the encoder directory before reading it")
    suffixes = next((n.value for n in mod.body if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "FORBIDDEN_MODEL_SUFFIXES" for x in n.targets)), None)
    have = {e.value for e in suffixes.elts} if isinstance(suffixes, ast.Tuple) else set()
    if not {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".py", ".so"} <= have:
        pr.append(f"FORBIDDEN_MODEL_SUFFIXES lacks a code-bearing suffix: have {sorted(have)}")
    cm = _src(text, mod, "check_model_dir")
    if "safetensors" not in cm or "modules.json" not in cm or "ALLOWED_MODULE_PREFIX" not in cm:
        pr.append("check_model_dir does not require safetensors weights and sentence_transformers modules")
    v15 = rules_for(rep) == "v15"            # a v14/v15 image: the v15-era rules (no encoder allowlist)
    if not v15:
        pr += _encoder_allowlist_problems(text, mod, cm)
    # preload opens exactly PRELOAD_PATHS, through faiss.read_index / SentenceTransformer / lgb.Booster, and nothing else.
    pp = next((n.value for n in mod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict)
               and any(isinstance(x, ast.Name) and x.id == "PRELOAD_PATHS" for x in n.targets)), None)
    keys = {k.value for k in pp.keys if isinstance(k, ast.Constant)} if pp is not None else set()
    if keys != {"index", "model", "stage1", "stage2"}:
        pr.append(f"PRELOAD_PATHS names {sorted(keys)}, want index, model, stage1, stage2")
    if pre is not None:
        readers = {"read_index": set(), "SentenceTransformer": set(), "Booster": set()}
        others = []
        for n in ast.walk(pre):
            if not isinstance(n, ast.Call):
                continue
            name = _call_name(n)
            args = list(n.args) + [k.value for k in n.keywords]
            subs = {a.slice.value for a in args if isinstance(a, ast.Subscript) and isinstance(a.value, ast.Name) and a.value.id == "paths"
                    and isinstance(a.slice, ast.Constant)}
            if name in readers:
                readers[name] |= subs
            elif name in ("open", "load", "read_parquet", "loads", "read", "connect", "read_csv", "fromfile", "memmap", "mmap"):
                others.append(name)
        opened = readers["read_index"] | readers["SentenceTransformer"] | readers["Booster"]
        if readers["read_index"] != {"index"} or readers["SentenceTransformer"] != {"model"} or readers["Booster"] != {"stage1", "stage2"} or opened != keys:
            pr.append(f"preload does not open exactly PRELOAD_PATHS through read_index/SentenceTransformer/Booster: {readers}")
        if others:
            pr.append(f"preload reads through other calls: {others}")
        # v17: preload may also BUILD the two fixed-shape evaluators, each from one of the Boosters it just read and
        # from nothing else (arrays, no file of their own); sealedresearch/oblivious_gbdt.py imports numpy only.
        ob = [n for n in ast.walk(pre) if isinstance(n, ast.Call) and _call_name(n) == "ObliviousGBDT"]
        if ob:
            boosters_of: Dict[str, str] = {}
            for n in ast.walk(pre):
                if isinstance(n, ast.Assign):
                    tg = n.targets[0]
                    names = [tg] if isinstance(tg, ast.Name) else list(tg.elts) if isinstance(tg, ast.Tuple) else []
                    vals = [n.value] if isinstance(tg, ast.Name) else list(n.value.elts) if isinstance(n.value, ast.Tuple) else []
                    for t, v in zip(names, vals):
                        if isinstance(t, ast.Name) and isinstance(v, ast.Call) and _call_name(v) == "Booster":
                            sub = [a.slice.value for a in list(v.args) + [k.value for k in v.keywords]
                                   if isinstance(a, ast.Subscript) and isinstance(a.value, ast.Name) and a.value.id == "paths"
                                   and isinstance(a.slice, ast.Constant)]
                            if len(sub) == 1:
                                boosters_of[t.id] = sub[0]
            built = sorted(boosters_of.get(c.args[0].id, "?") if (len(c.args) == 1 and not c.keywords and isinstance(c.args[0], ast.Name))
                           else "?" for c in ob)
            if built != ["stage1", "stage2"]:
                pr.append(f"preload builds ObliviousGBDT other than once from each Booster it read: {built}")
            og = os.path.join(tree, APP_DIR, "sealedresearch/oblivious_gbdt.py")
            if not os.path.isfile(og):
                pr.append("sealedresearch/oblivious_gbdt.py missing")
            else:
                top = sorted({n.split(".")[0] for n in _local_imports(og, os.path.join(tree, APP_DIR))} - {"__future__", "typing", "numpy"})
                if top:
                    pr.append(f"sealedresearch/oblivious_gbdt.py imports more than numpy: {top}")
                pr += [f"oblivious_gbdt: dynamic: {x}" for x in dynamic_import_sites(og, os.path.join(tree, APP_DIR))]
        # ... and nowhere else in the warm parent: no other ObliviousGBDT call in engine_preload.py, and no other file the
        # parent reaches by import names ObliviousGBDT or imports sealedresearch.oblivious_gbdt (pi-attested review)
        pre_ids = {id(n) for n in ast.walk(pre)}
        stray = [n.lineno for n in ast.walk(mod) if isinstance(n, ast.Call) and _call_name(n) == "ObliviousGBDT" and id(n) not in pre_ids]
        stray_imp = [n.lineno for n in ast.walk(mod) if isinstance(n, (ast.Import, ast.ImportFrom)) and id(n) not in pre_ids
                     and "oblivious_gbdt" in ast.dump(n)]
        if stray or stray_imp:
            pr.append(f"engine_preload.py builds or imports ObliviousGBDT outside preload (lines {sorted(stray + stray_imp)})")
        app = os.path.join(tree, APP_DIR)
        pfiles, _ = front_closure(tree, ENGINE_ENTRY, ENGINE_PROPER)
        for f in pfiles:
            if f in ("sealedresearch/engine_preload.py", "sealedresearch/oblivious_gbdt.py"):
                continue
            fp = os.path.join(app, f)
            names = _local_imports(fp, app)
            if any(n == "sealedresearch.oblivious_gbdt" or n.startswith("sealedresearch.oblivious_gbdt.") for n in names) \
                    or any(isinstance(n, ast.Call) and _call_name(n) == "ObliviousGBDT" for n in ast.walk(_parse(fp))):
                pr.append(f"{f} (in the warm parent) imports or builds ObliviousGBDT")
    ob_words = ("; from the two Boosters preload builds the fixed-shape evaluators (ObliviousGBDT, sealedresearch/oblivious_gbdt.py, "
                "numpy only): arrays, no file of their own" if pre is not None and any(
                    isinstance(n, ast.Call) and _call_name(n) == "ObliviousGBDT" for n in ast.walk(pre)) else "")
    if v15:
        rep.add(not pr, "D7. the warm parent parses data, not code", V15_RULES_PREFIX + (
                "engine_preload: preload opens exactly PRELOAD_PATHS (index, model, stage1, stage2) through faiss.read_index, "
                "SentenceTransformer and lgb.Booster and nothing else; TORCH_FORCE_WEIGHTS_ONLY_LOAD=1 before torch; SentenceTransformer(trust_remote_code=False) after "
                "check_model_dir (safetensors only, no .bin/.pt/.pth/.pkl/.pickle/.ckpt/.py/.so, modules.json entries all "
                "sentence_transformers.*); faiss.read_index and lgb.Booster(model_file) parse typed structures, never code"
                if not pr else "; ".join(pr)))
        return
    rep.add(not pr, "D7. the warm parent parses data, not code",
            "engine_preload: preload opens exactly PRELOAD_PATHS (index, model, stage1, stage2) through faiss.read_index, "
            "SentenceTransformer and lgb.Booster and nothing else; TORCH_FORCE_WEIGHTS_ONLY_LOAD=1 before torch; SentenceTransformer(trust_remote_code=False) after "
            "check_model_dir (exactly the files ENCODER_FILES pins by sha256 plus model.safetensors of the pinned tensor structure, "
            "no link, no other file; no .bin/.pt/.pth/.pkl/.pickle/.ckpt/.py/.so; modules.json entries all sentence_transformers.*); faiss.read_index and lgb.Booster(model_file) parse typed structures, never code"
            + ob_words if not pr else "; ".join(pr))


FIXED_SHAPE_ROW = "D7b. the engine's fixed-shape switch is on and its budgets are fixed in code"
SHAPE_USERS = ("sealedresearch/open_rank/ann.py", "sealedresearch/open_rank/ranker.py",
               "sealedresearch/open_rank/searcher.py", "sealedresearch/open_rank/survey_run.py")
SHAPE_FILE = "sealedresearch/open_rank/shape.py"
SHAPE_BUDGETS = ("PPR_EDGE_BUDGET", "CITER_GATHER_BUDGET")


def check_fixed_shape(rep: ImageReport, tree: str) -> None:
    """v17: the published engine pads each stage to a fixed amount of work (open_rank/shape.py). Not a required row:
    an image without it (v16) is not failed for it, and the record names the fixed shape only when it PASSED.
    Read off the code: ENABLED is the literal True at module level and nothing reassigns it; each budget is an integer
    literal; shape.py reads no file and no environment, and has no dynamic import site; the engine modules import it."""
    app = os.path.join(tree, APP_DIR)
    p = os.path.join(app, SHAPE_FILE)
    if not os.path.isfile(p):
        rep.add(None, FIXED_SHAPE_ROW, f"{SHAPE_FILE} not in the image (no fixed-shape engine)")
        return
    text = _text(p)
    mod = _ast_parse(text)
    pr: List[str] = []
    consts: Dict[str, Any] = {}
    for n in mod.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant):
            consts[n.targets[0].id] = n.value.value
    if consts.get("ENABLED") is not True:
        pr.append("shape.ENABLED is not the literal True at module level")
    for b in SHAPE_BUDGETS:
        if not (isinstance(consts.get(b), int) and not isinstance(consts.get(b), bool) and consts[b] > 0):
            pr.append(f"shape.{b} is not a positive integer literal")
    names = {_call_name(n) for n in ast.walk(mod) if isinstance(n, ast.Call)}
    if names & {"open", "getenv", "load", "loads"} or "environ" in text:
        pr.append("shape.py reads a file or the environment")
    pr += [f"shape.py: dynamic: {x}" for x in dynamic_import_sites(p, app)]
    def _imports_shape(m: ast.Module) -> Set[str]:
        """The names a module binds to the shape module, read off its import statements (AST, not text)."""
        out: Set[str] = set()
        for n in ast.walk(m):
            if isinstance(n, ast.ImportFrom) and any(a.name == "shape" for a in n.names) and (
                    n.module in ("sealedresearch.open_rank", None) or (n.level and n.module is None)):
                out |= {a.asname or a.name for a in n.names if a.name == "shape"}
        return out
    users = 0
    for dp, _dn, fs in os.walk(app):
        for name in fs:
            if not name.endswith(".py"):
                continue
            f = os.path.join(dp, name)
            rel = os.path.relpath(f, app)
            m = _ast_parse(_text(f))
            aliases = _imports_shape(m) | ({"shape"} if rel != SHAPE_FILE else set())
            for n in ast.walk(m):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, (ast.AugAssign, ast.AnnAssign)) else []
                for tg in tgts:
                    if isinstance(tg, ast.Attribute) and tg.attr == "ENABLED":
                        pr.append(f"{rel} assigns .ENABLED")
                    if isinstance(tg, ast.Name) and tg.id in _imports_shape(m):
                        pr.append(f"{rel} rebinds its shape module name {tg.id}")
                if isinstance(n, ast.Call) and _call_name(n) in ("setattr", "delattr", "vars") and n.args and \
                        isinstance(n.args[0], ast.Name) and n.args[0].id in aliases:
                    pr.append(f"{rel} calls {_call_name(n)} on the shape module")
            if rel in SHAPE_USERS and _imports_shape(m):
                users += 1
    missing = [u for u in SHAPE_USERS if not os.path.isfile(os.path.join(app, u))]
    if users < len(SHAPE_USERS) or missing:
        pr.append(f"{users} of the {len(SHAPE_USERS)} engine modules import shape (ANN, ranker, searcher, survey)")
    rep.values["fixed_shape_budgets"] = {b: consts.get(b) for b in SHAPE_BUDGETS}
    rep.add(not pr, FIXED_SHAPE_ROW,
            f"{SHAPE_FILE}: ENABLED = True (published code, not a data file; nothing reassigns it), "
            f"PPR_EDGE_BUDGET = {consts.get('PPR_EDGE_BUDGET')}, CITER_GATHER_BUDGET = {consts.get('CITER_GATHER_BUDGET')}; "
            f"read off the code, not observed running; all {users} engine modules (ANN, ranker, searcher, survey) import it; that "
            f"each stage pads is in the published source, not checked by this row" if not pr else "; ".join(pr))


def check_parent_closure(rep: ImageReport, tree: str, paths: Dict[str, str], ltext: str, lmod: ast.Module, etext: str) -> None:
    """D7 (round 4): the engine's warm parent reaches no closed module by import (static closure over tdx_engine.py,
    engine_preload and everything they import, every import statement, functions included); the closed modules are
    imported by the child only, by name, after the fork and the marker; the front runs a probe search."""
    pr = []
    files, closed = front_closure(tree, ENGINE_ENTRY, ENGINE_PROPER)
    bad_files = [f for f in files if f in CLOSED_FILES or f in ("m2_entry.py", "tdx_child.py")
                 or f.startswith("sealedresearch/open_rank/")]
    rep.values["engine_parent_files"] = files
    if not files:
        pr.append("tdx_engine.py missing")
    if closed:
        pr.append(f"the warm parent names closed modules: {closed}")
    if bad_files:
        pr.append(f"the warm parent reaches closed files: {bad_files}")
    if "sealedresearch/engine_preload.py" not in files:
        pr.append("the warm parent does not use the published warm (engine_preload)")
    child = os.path.join(tree, APP_DIR, "tdx_child.py")
    open_engine = False
    if not os.path.isfile(child):
        pr.append("tdx_child.py missing")
    else:
        cfiles, cclosed = front_closure(tree, "tdx_child.py", ENGINE_PROPER)
        if not cclosed:
            pr.append("tdx_child.py imports no engine module (closed, or v16's sealedresearch.open_rank): the child would answer with nothing")
        # "the engine is open_rank" only for a child that reaches open_rank and NO closed module besides tdx_child itself
        # (a mixed child is described as importing the closed modules; D1 also refuses it in a v16 image)
        reached = [c.split(" -> ", 1)[1] for c in cclosed if " -> " in c]
        # a dynamic import site in the child's closure ("dynamic: ...") loads what the static closure cannot see
        open_engine = (not any(c.startswith("dynamic:") for c in cclosed)
                       and any(n == "sealedresearch.open_rank" or n.startswith("sealedresearch.open_rank.") for n in reached)
                       and not any(n == m or n.startswith(m + ".") for n in reached for m in CLOSED_PROPER if m != "tdx_child"))
        ctext = _text(child)
        if "preloaded=preloaded" not in ctext or "def build(" not in ctext:
            pr.append("tdx_child.build does not build the engine over the parent's preloaded objects")
        pr += [f"tdx_child.py: {x}" for x in _unresolved_app_imports(tree, "tdx_child.py")]
    if 'CHILD_MODULE = "tdx_child"' not in etext or "child_module=CHILD_MODULE" not in etext:
        pr.append("tdx_engine does not name tdx_child as the child's module (by name, for the child only)")
    if "import tdx_child" in etext or "from tdx_child" in etext:
        pr.append("tdx_engine imports tdx_child")
    ch = _src(ltext, lmod, "_child")
    _mark = 'os.write(marker_w, SURVEY_MARKER if req.get("op") == "survey" else MARKER)'
    after_marker = ch.split(_mark, 1)[-1] if _mark in ch else ""
    if "importlib.import_module(child_module).build(preloaded)" not in after_marker:
        pr.append("engine_link._child does not import the child module by name AFTER the request and the marker")
    sf = _src(ltext, lmod, "serve_forking")
    if "import_module" in sf:
        pr.append("serve_forking (the parent) imports the child module")
    # The one sanctioned dynamic import: its argument is the name child_module, and the only binding of that name
    # that reaches _child is tdx_engine's CHILD_MODULE = "tdx_child" (checked above); nothing else may pass one.
    sites = dynamic_import_sites(os.path.join(tree, APP_DIR, "sealedresearch/engine_link.py"), os.path.join(tree, APP_DIR))
    if sites:
        pr.append(f"engine_link has a dynamic import or code-running call outside the sanctioned site: {sites}")
    for other in files:
        if other != "sealedresearch/engine_link.py" and "child_module=" in _text(os.path.join(tree, APP_DIR, other)) and other != ENGINE_ENTRY:
            pr.append(f"{other} passes a child_module")
    if etext.count("child_module=") != 1 or etext.count('CHILD_MODULE = "tdx_child"') != 1:
        pr.append("tdx_engine must pass child_module exactly once, from the one literal CHILD_MODULE")
    engine_words = ("the engine (sealedresearch.open_rank, published) is imported by tdx_child" if not pr and open_engine
                    else "the closed modules are imported by tdx_child")
    rep.add(not pr, "D7. the warm parent imports no closed module",
            f"{len(files)} files reachable by import from {ENGINE_ENTRY} (every import statement, functions included), none closed: "
            + ", ".join(files) + f"; {engine_words}, in the child, by name, after the request and the "
            "marker; the engine is built over the parent's preloaded objects (faiss index, encoder, boosters)" if not pr else "; ".join(pr))


# Every class of kernel-backed object a process can create or write, and the unit line that closes it for the engine.
KERNEL_OBJECT_CLOSURES = (
    ("POSIX message queues (/dev/mqueue: named, persistent, open(O_CREAT) is not mq_open)",
     lambda s: "-/dev/mqueue" in " ".join(s.get("InaccessiblePaths", [])).split() and "-/dev/mqueue" in " ".join(s.get("ReadOnlyPaths", [])).split()
     and s.get("LimitMSGQUEUE") == ["0"]),
    ("POSIX shared memory (/dev/shm)", lambda s: "/dev/shm" in " ".join(s.get("ReadOnlyPaths", [])).split()),
    ("hugetlbfs (/dev/hugepages)", lambda s: any(x in ("/dev/hugepages", "-/dev/hugepages") for x in " ".join(s.get("ReadOnlyPaths", [])).split())),
    ("device nodes that map as memory (/dev/zero) and ptys (/dev/ptmx, /dev/tty)",
     lambda s: s.get("DevicePolicy") == ["strict"] and all("w" not in a.split()[1] for a in s.get("DeviceAllow", []) if a.split()[0] != "/dev/null")),
    ("tmpfs scratch (/tmp, /var/tmp)", lambda s: all(":ro" in x for x in " ".join(s.get("TemporaryFileSystem", [])).split()) and s.get("PrivateTmp") is None),
    ("/run (no RuntimeDirectory, read-only under ProtectSystem=strict)", lambda s: s.get("RuntimeDirectory") is None and s.get("ProtectSystem") == ["strict"]),
    ("/proc/sys, /sys, debugfs, tracefs, bpffs, pstore, configfs, binfmt_misc, efivars (ProtectKernelTunables)", lambda s: s.get("ProtectKernelTunables") == ["yes"]),
    ("cgroupfs (ProtectControlGroups)", lambda s: s.get("ProtectControlGroups") == ["yes"]),
    ("SysV IPC, POSIX mq calls, keys, memfd, io_uring, shared mappings (confine.seal_memory, the row above)", lambda s: True),
    ("sockets (seccomp socket()/connect(); PrivateNetwork; AF_UNIX only)", lambda s: s.get("PrivateNetwork") == ["yes"] and s.get("RestrictAddressFamilies") == ["AF_UNIX"]),
)


def check_kernel_objects(rep: ImageReport, tree: str) -> None:
    """D7 (round 4): for each class of kernel-backed object a process could create or write — named or not,
    persistent or not — the engine unit line that closes it is present (effective unit, drop-ins merged). The
    classes were swept under the unit on 2 Nov: with these lines only per-process /proc/self entries remain."""
    eu, path, _d = effective_unit(tree, "ir-engine.service")
    s = eu.get("Service", {})
    pr = [] if path else ["ir-engine.service missing"]
    for name, ok in KERNEL_OBJECT_CLOSURES:
        if path and not ok(s):
            pr.append(f"not closed: {name}")
    fu, _fp, _fd = effective_unit(tree, "ir-search.service")
    fs = fu.get("Service", {})
    if not ("-/dev/mqueue" in " ".join(fs.get("InaccessiblePaths", [])).split() and fs.get("LimitMSGQUEUE") == ["0"]):
        pr.append("ir-search.service leaves /dev/mqueue reachable")
    rep.add(not pr, "D7. no writable kernel object",
            f"{len(KERNEL_OBJECT_CLOSURES)} classes closed for the engine (mqueue hidden, read-only and LimitMSGQUEUE=0; /dev/shm and "
            "hugetlbfs read-only; devices by cgroup; scratch tmpfs read-only; no runtime directory; kernel tunables, cgroups read-only; "
            "IPC, keys, memfd, io_uring and shared mappings by seccomp; no socket); the front keeps /dev/mqueue hidden too. "
            "What remains writable is per-process: /proc/self/comm and attr, gone with the child" if not pr else "; ".join(pr))


def _src(text: str, mod: ast.Module, name: str) -> str:
    fn = _function(mod, name)
    return (ast.get_source_segment(text, fn) or "") if fn else ""


def _method_src(text: str, mod: ast.Module, cls: str, name: str) -> str:
    c = next((n for n in ast.walk(mod) if isinstance(n, ast.ClassDef) and n.name == cls), None)
    fn = next((n for n in c.body if isinstance(n, ast.FunctionDef) and n.name == name), None) if c else None
    return (ast.get_source_segment(text, fn) or "") if fn else ""


def check_per_request(rep: ImageReport, tree: str, paths: Dict[str, str], stext: str, smod: ast.Module) -> None:
    """D7 (v14 round 3): one engine process per request; one reply size and one reply slot (two slots since rc9); results reduced to
    the published shape. Read off the published sources in the tree (which D1 says are the source's)."""
    ltext = _text(paths["sealedresearch/engine_link.py"])
    lmod = _ast_parse(ltext)
    pr = []
    sf = _src(ltext, lmod, "serve_forking")
    if not sf:
        pr.append("engine_link.serve_forking not found")
    else:
        if "fork()" not in sf and not any(_call_name(n) == "fork" for n in ast.walk(_function(lmod, "serve_forking"))):
            pr.append("serve_forking does not fork a child per request")
        if "send_fd(" not in sf or "socketpair(" not in sf:
            pr.append("serve_forking does not hand the front a fresh socketpair end per request (send_fd)")
        child_branch = sf.split("if pid == 0:", 1)[-1].split("_child(", 1)[0] if "if pid == 0:" in sf else ""
        if "control.close()" not in child_branch:
            pr.append("the child does not close the control link before the closed code runs")
        if "_kill(pid)" not in sf or "budget" not in sf:
            pr.append("serve_forking does not kill a child that outlives the budget")
        if "recv_message(" in sf:
            pr.append("serve_forking reads a request in the parent")
    ch = _src(ltext, lmod, "_child")
    if "_exit(" not in ch or "recv_message(" not in ch:
        pr.append("engine_link._child does not read one request and _exit")
    call = _method_src(ltext, lmod, "EngineProxy", "_call")
    if "recv_fd(" not in call and "_channel(" not in call:
        pr.append("EngineProxy._call does not take a fresh channel per request")
    if "finally:" not in call or "ch.close()" not in call.split("finally:", 1)[-1]:
        pr.append("EngineProxy._call does not close the channel after its one reply")
    if "deadline" not in call or "self.budget" not in call:
        pr.append("EngineProxy._call has no wall-clock budget")
    etext = _text(paths["tdx_engine.py"])
    if "fork_headroom_ok(" not in etext or "RssAnon" not in etext:
        pr.append("tdx_engine does not check the fork headroom (RssAnon against MemAvailable) at warm")
    ppath = os.path.join(tree, APP_DIR, "sealedresearch/engine_preload.py")
    ptext = _text(ppath) if os.path.isfile(ppath) else ""
    pmod = _ast_parse(ptext) if ptext else None
    pr += _warm_thread_problems(ptext, pmod)
    if pmod is not None:
        emain2 = _function(_ast_parse(etext), "main")
        main_calls = {_call_name(n) for n in ast.walk(emain2) if isinstance(n, ast.Call)} if emain2 else set()
        if main_calls & {"encode", "search", "dummy_pass", "PatentSearcher"}:
            pr.append("tdx_engine.main runs a library pass on the forking thread")
    check_memory_seal(rep, tree, paths, ltext, lmod, etext)
    rep.add(not pr, "D7. one engine process per request",
            "engine_link.serve_forking: a socketpair and a forked child per request, the front's end sent over the control "
            "link, the child closes the control link, reads one request, answers, _exit()s, killed at the budget; the parent "
            "reads no request; EngineProxy._call: one channel per request, closed after one reply, a wall-clock budget; "
            "tdx_engine checks the fork headroom at warm" if not pr else "; ".join(pr))
    # One reply size, one reply slot.
    sp = []
    if "REPLY_BYTES" not in stext or re.search(r"\btarget \*= 2\b|while target <", stext):
        sp.append("search_service pads replies into size buckets, not one size")
    if 'inner_obj["pad"] = "0" * (REPLY_BYTES - size)' not in stext or "assert len(inner) == REPLY_BYTES" not in stext:
        sp.append("search_service does not pad every reply to REPLY_BYTES exactly")
    if "RESULT_MAX_BYTES" not in stext or 'RefusedPayload("result_oversize")' not in stext:
        sp.append("search_service does not refuse a result that would not fit the one reply size")
    hs = _method_src(stext, smod, "SearchService", "handle")
    if "taken_up + slot - time.monotonic()" not in hs or "ceil" in hs:
        sp.append("SearchService.handle does not sleep to exactly one slot after the request was taken up")
    # rc9, two slots: the slot is chosen from the opened payload's DECLARED kind, before the request is taken up, and
    # by nothing else (not the outcome, not the engine's time): survey -> the survey slot, anything else -> the reply slot.
    if "slot = self._slot_for(plain)" not in hs or hs.index("slot = self._slot_for(plain)") > hs.index("taken_up = "):
        sp.append("SearchService.handle does not choose the slot from the opened payload before the request is taken up")
    slot_for = _method_src(stext, smod, "SearchService", "_slot_for")
    if ('return self._survey_slot if declared == SURVEY_KIND else self._slot' not in slot_for
            or 'declared = json.loads(plain).get("kind")' not in slot_for or 'SURVEY_KIND = "survey"' not in stext):
        sp.append("SearchService._slot_for does not pick the survey slot for a declared survey and the reply slot otherwise")
    init = _method_src(stext, smod, "SearchService", "__init__")
    if "budget" not in init or "< self._slot" not in init:
        sp.append("SearchService.__init__ does not check the engine budget below the slot")
    if "< self._survey_slot" not in init or "self._slot <= self._survey_slot <= 300" not in init:
        sp.append("SearchService.__init__ does not check the survey budget below the survey slot, and that slot against the reply slot")
    # Plain refusals (unreadable bytes, a full queue): padded to a sealed reply's wire length, measured once at init.
    if "self.wire_bytes" not in init or "envelope.seal(probe_pub, b\"0\" * REPLY_BYTES" not in init:
        sp.append("SearchService.__init__ does not measure a sealed reply's wire length (wire_bytes)")
    refusal = _method_src(stext, smod, "SearchService", "_refusal")
    if 'body["pad"] = "0" * (self.wire_bytes - size)' not in refusal:
        sp.append("SearchService._refusal does not pad a plain refusal to the sealed reply's wire length")
    if 'self._refusal("unreadable")' not in hs or 'self._refusal("busy")' not in hs:
        sp.append("SearchService.handle does not route unreadable and queue-full refusals through _refusal")
    waiting = next((n.value.value for n in smod.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                    and any(isinstance(x, ast.Name) and x.id == "MAX_WAITING" for x in n.targets)), None)
    if not isinstance(waiting, int) or waiting < 1:
        sp.append("search_service.MAX_WAITING is not a positive integer constant")
    rep.values["max_waiting"] = waiting if isinstance(waiting, int) else None
    if "self._waiting >= MAX_WAITING" not in hs:
        sp.append("SearchService.handle does not turn a request away at MAX_WAITING")
    post = stext[stext.index("def do_POST"):] if "def do_POST" in stext else ""
    if "if not 0 < n <= MAX_REQUEST:" not in post or 'self._json(413, {"refused": "size"})' not in post.split("MAX_REQUEST", 1)[-1][:200]:
        sp.append("the HTTP layer does not answer an empty or over-length request with an unpadded 413 before the service sees it")
    if 'if self.path != "/search":' not in post or 'self._json(404, {"refused": "not-found"})' not in post.split('"/search"', 1)[-1][:200]:
        sp.append("the HTTP layer does not answer a POST to another path with an unpadded 404 before the service sees it")
    # ONE deadline per request on the front's side: the wait for the engine's channel and the reply both spend from
    # it (two fresh waits of `budget` could spend twice the budget inside one slot).
    lpath = os.path.join(tree, APP_DIR, "sealedresearch/engine_link.py")
    ltext2 = _text(lpath) if os.path.isfile(lpath) else ""
    lmod2 = _ast_parse(ltext2) if ltext2 else None
    call_fn = None
    if lmod2 is not None:
        cls = next((n for n in ast.walk(lmod2) if isinstance(n, ast.ClassDef) and n.name == "EngineProxy"), None)
        call_fn = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_call"), None) if cls else None
    if call_fn is None:
        sp.append("engine_link.EngineProxy._call not found")
    else:
        assigns = [n for n in ast.walk(call_fn) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "deadline" for t in n.targets)]
        chan_calls = [n for n in ast.walk(call_fn) if isinstance(n, ast.Call) and _call_name(n) == "_channel"]
        reply_calls = [n for n in ast.walk(call_fn) if isinstance(n, ast.Call) and _call_name(n) == "recv_reply"]
        csrc = ast.get_source_segment(ltext2, call_fn) or ""
        seg = lambda n: ast.get_source_segment(ltext2, n) or ""              # noqa: E731
        if len(assigns) != 1 or seg(assigns[0].value) != 'time.monotonic() + (self.survey_budget if req.get("op") == "survey" else self.budget)':
            sp.append(f"EngineProxy._call takes {len(assigns)} deadlines; want exactly one, from take-up, the survey budget for a survey and the budget otherwise")
        if not chan_calls or any("deadline" not in seg(c) or "self.budget" in seg(c) for c in chan_calls):
            sp.append("EngineProxy._call waits for the engine's channel with a fresh budget instead of what remains of the one deadline")
        if not reply_calls or any(not (c.args and isinstance(c.args[-1], ast.Name) and c.args[-1].id == "deadline") for c in reply_calls):
            sp.append("EngineProxy._call does not read the reply against the one deadline")
        if csrc.index("deadline = ") > csrc.index("_channel(") if "_channel(" in csrc and "deadline = " in csrc else True:
            sp.append("EngineProxy._call takes its deadline after the channel wait")
        timeouts = [n for n in ast.walk(call_fn) if isinstance(n, ast.Call) and _call_name(n) == "settimeout"]
        if any("deadline" not in seg(c) for c in timeouts):
            sp.append("EngineProxy._call sets a socket timeout that is not drawn from the one deadline")
        # The bound is per _call: the published entry must configure ONE call per request (no canaries, which
        # search.run would run first, each a _call of its own).
        tpath = os.path.join(tree, APP_DIR, FRONT_ENTRY)
        if os.path.isfile(tpath):
            tmod3 = _parse(tpath)
            svc_calls = [n for n in ast.walk(tmod3) if isinstance(n, ast.Call) and _call_name(n) == "SearchService"]
            if not svc_calls or any(any(k.arg == "canaries" for k in c.keywords) for c in svc_calls):
                sp.append("tdx_entry configures canaries (each a call of its own before the request's): the budget would not bound a request")
    # rc9: the survey budget reaches both ends. The front passes it to its proxy; the engine passes it to the loop; the
    # loop kills each child at ITS kind's budget, read from the marker the child's published code wrote.
    # Each check is scoped to its call site (a string elsewhere in the file, a comment or dead code, does not count).
    def _calls_in(text: str, fn_name: str, callee: str) -> List[ast.Call]:
        mod = _ast_parse(text) if text else None
        fn = _function(mod, fn_name) if mod is not None else None
        return [n for n in ast.walk(fn) if isinstance(n, ast.Call) and _call_name(n) == callee] if fn else []

    def _kw(text: str, call: ast.Call, name: str) -> str:
        k = next((k for k in call.keywords if k.arg == name), None)
        return (ast.get_source_segment(text, k.value) or "") if k is not None else ""
    reaps = _calls_in(ltext2, "serve_forking", "_reap")
    if not any(len(c.args) == 3 and (ast.get_source_segment(ltext2, c.args[2]) or "")
               == "survey_budget if (mark == SURVEY_MARKER and survey_budget is not None) else budget" for c in reaps):
        sp.append("engine_link.serve_forking does not hold a child to its own kind's budget (survey marker)")
    child_writes = _calls_in(ltext2, "_child", "write")
    if not any((ast.get_source_segment(ltext2, c) or "") == 'os.write(marker_w, SURVEY_MARKER if req.get("op") == "survey" else MARKER)'
               for c in child_writes):
        sp.append("engine_link._child does not write the survey marker from the request it read")
    epath2 = os.path.join(tree, APP_DIR, "tdx_engine.py")
    etext2 = _text(epath2) if os.path.isfile(epath2) else ""
    loops = _calls_in(etext2, "main", "serve_forking")
    bfn = _function(_ast_parse(etext2), "budget_seconds") if etext2 else None
    returns = [ast.get_source_segment(etext2, n.value) for n in ast.walk(bfn) if isinstance(n, ast.Return)] if bfn else []
    if len(loops) != 1 or _kw(etext2, loops[0], "survey_budget") != "survey_budget" or returns != ["b, sb"]:
        sp.append("tdx_engine does not pass the survey budget to the forking loop")
    tpath2 = os.path.join(tree, APP_DIR, FRONT_ENTRY)
    ttext2 = _text(tpath2) if os.path.isfile(tpath2) else ""
    proxies = _calls_in(ttext2, "main", "EngineProxy")
    if len(proxies) != 1 or _kw(ttext2, proxies[0], "survey_budget") != 'float(os.environ.get("IR_SURVEY_BUDGET_SECONDS") or 0) or None':
        sp.append("tdx_entry does not give the proxy the survey budget")
    _slot, _fb, _eb, _ss, _sfb, env_problems = _slots_and_budgets(tree)
    sp += env_problems
    rep.add(not sp, "D7. one reply size and two reply slots",
            f"every readable request is answered in exactly REPLY_BYTES of sealed plaintext (a larger result is a signed "
            f"result_oversize refusal of the same size) and leaves exactly one slot after it was taken up: "
            f"{ENV_SURVEY_SLOT}={_ss} s when its opened payload declares kind \"survey\", {ENV_SLOT}={_slot} s otherwise, "
            f"chosen before take-up from the declared kind alone; the engine's budgets {ENV_BUDGET}={_fb} s and "
            f"{ENV_SURVEY_BUDGET}={_sfb} s lie below their slots and are the engine unit's too, and the front spends the "
            f"request's as ONE deadline (channel wait and reply together); a plain refusal "
            f"(unreadable bytes, or a request arriving with MAX_WAITING={waiting} already waiting) is padded to a sealed "
            "reply's wire length and leaves at once"
            if not sp else "; ".join(sp))
    # Results reduced to the published shape.
    rs = []
    xtext = _text(paths["sealedresearch/search.py"])
    xmod = _ast_parse(xtext)
    for fn, cleaner in (("run", "clean_search"), ("_run_document", "clean_document"), ("_run_survey", "clean_survey")):
        body = _src(xtext, xmod, fn)
        if f"_shaped(result_schema.{cleaner}, res)" not in body:
            rs.append(f"search.{fn} does not pass the engine's result through result_schema.{cleaner}")
    shaped = _src(xtext, xmod, "_shaped")
    if "SchemaError" not in shaped or 'RefusedPayload("searcher_failed")' not in shaped:
        rs.append("search._shaped does not turn a schema error into a searcher_failed refusal")
    rtext = _text(paths["sealedresearch/result_schema.py"])
    rmod = _ast_parse(rtext)
    sh = _src(rtext, rmod, "shape")
    if "for k, s in spec[1].items() if k in value" not in sh:
        rs.append("result_schema.shape does not drop unknown keys (it must build the dict from the SPEC's keys)")
    for name in ("HIT", "SEARCH", "DOCUMENT", "SURVEY"):
        if not any(isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == name for x in n.targets) for n in rmod.body):
            rs.append(f"result_schema has no {name} spec")
    hit = next((n.value for n in rmod.body if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "HIT" for x in n.targets)), None)
    hit_keys = sorted(k.value for k in hit.elts[1].keys) if isinstance(hit, ast.Tuple) and isinstance(hit.elts[1], ast.Dict) else []
    rep.values["hit_keys"] = hit_keys
    if not hit_keys or "key" not in hit_keys:
        rs.append("result_schema.HIT names no keys")
    rep.add(not rs, "D7. results reduced to the published shape",
            f"search.run, _run_document and _run_survey pass the engine's result through result_schema (known keys only, "
            f"unknown keys dropped, types and lengths bounded; a wrong shape is a signed searcher_failed); a hit may carry "
            f"exactly {hit_keys}" if not rs else "; ".join(rs))


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
        rep.add(None, "D8. initrd", f"could not decompress ({exc})", reason="malformed")
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
        rep.add(None, "D9. published ESP", "mtools (mdir, mcopy) not available to read the FAT partition", reason="tool")
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

def _guarded(rep: ImageReport, tree: str, row: str, fn: Any) -> None:
    """One group of D rows. Content of the image the group could not read as what it should be (ImageContent: an
    irregular entry, bytes that are not UTF-8, a .py that is not Python), or that broke the group any other way,
    is a FAIL on the group's first row naming it, with no reason given: it is in the image, so it is a difference,
    never a tool fault. The groups after it still run, and the rows gathered before it stand."""
    try:
        fn()
    except ImageContent as exc:
        rep.add(False, row, f"{exc.path.replace(tree, '', 1)}: {exc.why} — the rest of this group was not assessed")
    except Exception as exc:                                # noqa: BLE001
        rep.add(False, row, f"the image's content stopped this group ({type(exc).__name__}: {str(exc).replace(tree, '')}) "
                "— the rest of this group was not assessed")


def verify_image(artefacts: str, *, source: Optional[str] = None, root_tree: Optional[str] = None,
                 expect_image_sha384: Optional[str] = None, expect_loads: Optional[List[str]] = None,
                 keep_tree: Optional[str] = None, stated_commit: Optional[str] = None) -> ImageReport:
    """Every row for one published image. `root_tree` is an already-opened root (skips fsck.erofs); `keep_tree`
    names where to extract to (else a temporary directory, removed afterwards). Whatever stops the check, the rows
    gathered before it are returned: an unexpected exception becomes the last row, not a lost report."""
    rep = ImageReport()
    try:
        _verify_image(rep, artefacts, source=source, root_tree=root_tree, expect_image_sha384=expect_image_sha384,
                      expect_loads=expect_loads, keep_tree=keep_tree, stated_commit=stated_commit)
    except Exception as exc:                                # noqa: BLE001
        rep.add(False, "checker stopped", f"an unexpected exception ended the check after the rows above "
                f"({type(exc).__name__}: {exc}); rows not printed were not assessed", reason="malformed")
    return rep


def _verify_image(rep: ImageReport, artefacts: str, *, source: Optional[str], root_tree: Optional[str],
                  expect_image_sha384: Optional[str], expect_loads: Optional[List[str]],
                  keep_tree: Optional[str], stated_commit: Optional[str]) -> None:
    uki_path, root_path = os.path.join(artefacts, "uki.efi"), os.path.join(artefacts, "root.img")
    verity_path, esp_path = os.path.join(artefacts, "verity.img"), os.path.join(artefacts, "esp.img")
    src = Source(source) if source else None
    # A/B: the UKI
    if not os.path.isfile(uki_path):
        rep.add(False, "A. published UKI is the measured image", f"{uki_path} missing", reason="missing")
        return
    uki = open(uki_path, "rb").read()
    rep.values["uki_sha256"] = hashlib.sha256(uki).hexdigest()
    try:
        sections = pe_sections(uki)
        image_sha384 = authenticode_sha384(uki)
    except Exception as exc:                                # noqa: BLE001
        rep.add(False, "A. published UKI is the measured image", f"uki.efi is not a PE image ({type(exc).__name__})", reason="malformed")
        return
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
    rep.values["kernel_unhashable"] = kernel_sha384 is None   # no .linux section, or one that could not be hashed
    if kernel_sha384 is None:
        rep.add(False, "A. published UKI loads the named kernel", "the published UKI's kernel section could not be hashed", reason="malformed")
    elif expect_loads is not None:
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
        rep.add(False, "C. root bytes hash to the roothash", f"{root_path} missing", reason="missing")
    elif not roothash:
        rep.add(False, "C. root bytes hash to the roothash", "no roothash= on the command line")
    elif not os.path.isfile(verity_path):
        rep.add(False, "C. root bytes hash to the roothash", f"{verity_path} missing (it carries the salt and block sizes)", reason="missing")
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
            rep.add(False, "C. root bytes hash to the roothash", f"could not recompute ({type(exc).__name__}: {exc})", reason="malformed")
    # D: inside the root
    tmp = None
    tree = root_tree
    try:
        if tree is None and os.path.isfile(root_path):
            dest = keep_tree or (tmp := tempfile.mkdtemp(prefix="ir-root-"))
            try:
                tree = extract_erofs(root_path, dest)
            except Exception as exc:                        # noqa: BLE001
                rep.add(False, "D. root opened", str(exc), reason="tool")
                tree = None
            if tree is not None:
                rep.add(True, "D. root tree is root.img's contents", "the tree the D rows read was opened from root.img by this run (fsck.erofs)")
        elif tree is not None:
            # A pre-extracted tree: nothing ties it to root.img, so the D rows below are information, not the verdict.
            rep.add(None, "D. root tree is root.img's contents", "not opened from root.img by this run (a pre-extracted tree was "
                    "supplied with --root-tree); fsck.erofs needed", reason="tool")
        if tree is None:
            rep.add(None if os.path.isfile(root_path) else False, "D. root opened", reason="tool" if os.path.isfile(root_path) else "missing", detail=
                    "fsck.erofs not available to open root.img — rows D1-D7 not assessed (pass --root-tree with an extracted root)"
                    if os.path.isfile(root_path) else "no root.img")
        else:
            rep.add(True, "D. root opened", f"{sum(len(f) for _d, _s, f in os.walk(tree))} files" + (" (pre-extracted tree supplied)" if root_tree else ""))
            for row, fn in (("D1. published files equal the source", lambda: check_sources(rep, tree, src, stated_commit)),
                            ("D2. bytecode names its sources", lambda: check_bytecode(rep, tree)),
                            ("D3. installed packages match their RECORDs", lambda: check_records(rep, tree, src)),
                            ("D4. units and firewall files equal the source", lambda: check_unit(rep, tree, src)),
                            ("D5. unit census", lambda: check_units(rep, tree)),
                            ("D6. firewall rules", lambda: check_egress(rep, tree)),
                            ("D7. seal before serve", lambda: check_seal_order(rep, tree))):
                _guarded(rep, tree, row, fn)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    check_initrd(rep, sections.get(".initrd", b""))
    check_esp(rep, esp_path if os.path.isfile(esp_path) else None, rep.values["uki_sha256"])


def rows_for_measured(report: ImageReport, image_sha384: Optional[str], boot_apps: Optional[List[str]]) -> Tuple[List[Tuple[str, str, str]], bool]:
    out = rows_for_measured_report(report, image_sha384, boot_apps)
    return out.rows, out.posture_verified


def rows_for_measured_report(report: ImageReport, image_sha384: Optional[str], boot_apps: Optional[List[str]]) -> ImageReport:
    """The report's rows re-anchored to ONE measured boot: row A compares the published UKI with the image the quote
    names and the applications it then loaded. Returns (rows, posture_verified) — verified only if every required
    row, these two included, passed and nothing failed. Lets a record verifier compute the image once and judge it
    against each search's own quote."""
    out = ImageReport()
    out.reasons = dict(report.reasons)
    pub, kern = report.values.get("image_sha384"), report.values.get("kernel_sha384")
    unreadable = report.reasons.get("A. published UKI is the measured image", "missing")   # uki.efi missing, or not a PE (tool)
    if pub is None:
        out.add(False, "A. published UKI is the measured image", "no published UKI to compare with (uki.efi missing or unreadable)", reason=unreadable)
    elif not image_sha384:
        out.add(False, "A. published UKI is the measured image", "this search's quote names no measured image", reason="missing")
    else:
        same = pub == image_sha384.lower()
        out.add(same, "A. published UKI is the measured image",
                f"Authenticode SHA-384 of the published uki.efi {pub[:16]}… {'==' if same else '!='} the image this quote measured {image_sha384[:16]}…")
    later = [x.lower() for x in (boot_apps or [])[1:]]
    same_k = kern is not None and later == [kern]
    if kern is None:
        out.add(False, "A. published UKI loads the named kernel", reason=(unreadable if pub is None else "malformed"),
                detail="the published UKI's kernel section could not be hashed" if pub is not None else "no published UKI to compare with (uki.efi missing or unreadable)")
        for row in report.rows:
            if not row[1].startswith("A. "):
                out.rows.append(row)
        return out
    out.add(same_k, "A. published UKI loads the named kernel",
            reason=("missing" if not boot_apps else None), detail=
            f"after the image the firmware measured {len(later)} application(s); the published UKI's embedded kernel is {str(kern)[:16]}… "
            + ("and that is the one" if same_k else "and that is NOT what was loaded"))
    for row in report.rows:
        if not row[1].startswith("A. "):
            out.rows.append(row)
    return out


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
                         "NOT VERIFIED — " + ", ".join(f"{s} {n}" for s, n, _ in rep.rows if s == "FAIL" or (s != "PASS" and n in REQUIRED_ROWS))))
    if a.json:
        print(json.dumps({"rows": rep.rows, "values": rep.values, "posture_verified": rep.posture_verified}, indent=1, default=str))
    return 0 if rep.posture_verified else 1


if __name__ == "__main__":
    sys.exit(main())
