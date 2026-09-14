"""Confine a process and everything it spawns to two local TCP ports and nothing else — no privilege,
no admin step, inherited by children. This is the backstop that makes the agent's model lane and search
lane true even against a compromised or prompt-injected agent: the only addresses it can reach are the
two local verifying proxies.

Applied on Linux with two unprivileged kernel mechanisms, both after `PR_SET_NO_NEW_PRIVS`:

  Landlock (ABI >= 4): allow TCP connect to exactly the given ports; every other TCP connect is denied.
  seccomp: deny at the socket() call every socket family and type that is not an inet stream socket —
           UDP and other datagrams, raw and packet sockets, AF_UNIX (the local resolver and D-Bus,
           through which name resolution would otherwise leave), and io_uring.

What this closes, measured on this machine (kernel 7.0, Landlock ABI 8): remote TCP, TCP to other local
ports, UDP, DNS through glibc, DNS through systemd-resolved's unix socket, ICMP, raw and packet sockets.

What it does NOT close, stated so it is never assumed: Landlock matches PORT, not address, so a remote
server on the same port number as a local proxy is reachable. Closing that needs address-level control —
a network namespace after a one-time AppArmor profile, a connect()-inspecting supervisor, or (on macOS)
sandbox-exec. `apply()` returns a record naming this residual so a caller can show it.

Not Linux, or Landlock/seccomp unavailable: `apply()` refuses (raises Unavailable) rather than pretend.
The caller decides whether to run unconfined; it must never be silent.
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List

# syscall numbers by architecture (the three landlock numbers are shared)
_NR = {"x86_64": {"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446,
                  "seccomp": 317, "socket": 41, "io_uring_setup": 425, "AUDIT_ARCH": 0xC000003E},
       "aarch64": {"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446,
                   "seccomp": 277, "socket": 198, "io_uring_setup": 425, "AUDIT_ARCH": 0xC00000B7}}

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_NET_PORT = 2
LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

SECCOMP_SET_MODE_FILTER = 1
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000
EACCES = 13

AF_UNIX, AF_INET, AF_INET6, AF_PACKET = 1, 2, 10, 17
SOCK_DGRAM, SOCK_RAW = 2, 3
X32_MASK = 0x40000000

# classic-BPF opcodes (linux/bpf_common.h)
LD_W_ABS, JEQ_K, JGE_K, JA, AND_K, RET_K = 0x20, 0x15, 0x35, 0x05, 0x54, 0x06


class Unavailable(RuntimeError):
    """Confinement could not be established on this platform; the caller must decide, never assume."""


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class _NetPortAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


@dataclass
class Confinement:
    ports: List[int]
    landlock_abi: int
    residuals: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"mechanism": "landlock+seccomp", "allowed_tcp_ports": self.ports,
                "landlock_abi": self.landlock_abi, "residuals": self.residuals}


def _arch() -> str:
    m = os.uname().machine
    if m not in _NR:
        raise Unavailable(f"no confinement profile for architecture {m!r}")
    return m


def landlock_abi(libc: ctypes.CDLL) -> int:
    a = _NR[_arch()]
    return int(libc.syscall(a["landlock_create_ruleset"], None, ctypes.c_size_t(0),
                            ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION)))


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


def _seccomp_program(arch: str) -> bytes:
    """Allow everything except: wrong architecture or x32 (kill), io_uring_setup (EACCES), and socket()
    for AF_UNIX / AF_PACKET / any datagram or raw inet socket (EACCES). Inet stream sockets and
    socketpair() (a different syscall) stay allowed, so child pipes still work.

    seccomp_data: nr at offset 0, arch at 4, args at 16, 24, … Jumps name an absolute target index,
    converted to a relative offset here. Targets: 17 allow, 18 errno, 19 kill.
    """
    a = _NR[arch]
    IDX = {"allow": 17, "errno": 18, "kill": 19}

    def r(cur: int, target: str) -> int:
        return IDX[target] - cur - 1

    prog = [
        _stmt(LD_W_ABS, 4),                                    # 0  A = arch
        _jump(JEQ_K, a["AUDIT_ARCH"], 0, r(1, "kill")),        # 1  arch mismatch -> KILL
        _stmt(LD_W_ABS, 0),                                    # 2  A = nr
        _jump(JGE_K, X32_MASK, r(3, "kill"), 0),               # 3  x32 ABI -> KILL
        _jump(JEQ_K, a["io_uring_setup"], r(4, "errno"), 0),   # 4  io_uring_setup -> EACCES
        _jump(JEQ_K, a["socket"], 0, r(5, "allow")),           # 5  socket()? else ALLOW
        _stmt(LD_W_ABS, 16),                                   # 6  A = domain (args[0])
        _jump(JEQ_K, AF_UNIX, r(7, "errno"), 0),               # 7  AF_UNIX -> EACCES
        _jump(JEQ_K, AF_PACKET, r(8, "errno"), 0),             # 8  AF_PACKET -> EACCES
        _jump(JEQ_K, AF_INET, 12 - 9 - 1, 0),                  # 9  AF_INET -> type check (12)
        _jump(JEQ_K, AF_INET6, 12 - 10 - 1, 0),                # 10 AF_INET6 -> type check (12)
        _stmt(JA, r(11, "allow")),                             # 11 other family -> ALLOW
        _stmt(LD_W_ABS, 24),                                   # 12 A = type (args[1])
        _stmt(AND_K, 0xF),                                     # 13 A &= 0xF (strip SOCK_* flags)
        _jump(JEQ_K, SOCK_DGRAM, r(14, "errno"), 0),           # 14 SOCK_DGRAM -> EACCES
        _jump(JEQ_K, SOCK_RAW, r(15, "errno"), 0),             # 15 SOCK_RAW -> EACCES
        _stmt(JA, r(16, "allow")),                             # 16 SOCK_STREAM etc -> ALLOW
        _stmt(RET_K, SECCOMP_RET_ALLOW),                       # 17
        _stmt(RET_K, SECCOMP_RET_ERRNO | EACCES),              # 18
        _stmt(RET_K, SECCOMP_RET_KILL_PROCESS),                # 19
    ]
    return b"".join(prog)


def apply(ports: List[int], *, min_landlock_abi: int = 4) -> Confinement:
    """Confine THIS process and its children to TCP connect on `ports` only. Call in a child, after
    fork and before exec (a preexec_fn), or in a process about to become the agent.

    Raises Unavailable when the platform cannot do it; the caller must not proceed silently unconfined.
    """
    if sys.platform != "linux":
        raise Unavailable(f"confinement is implemented for Linux only, not {sys.platform!r} "
                          "(macOS sandbox-exec is the intended equivalent and is not built yet)")
    if not ports:
        raise Unavailable("no ports to allow — refusing to confine a process to nothing")
    arch = _arch()
    a = _NR[arch]
    libc = ctypes.CDLL(None, use_errno=True)

    abi = landlock_abi(libc)
    if abi < min_landlock_abi:
        raise Unavailable(f"Landlock ABI {abi} is below the required {min_landlock_abi} (TCP rules need ABI 4)")

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise Unavailable(f"PR_SET_NO_NEW_PRIVS failed (errno {ctypes.get_errno()})")

    attr = _RulesetAttr(0, LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP, 0)
    fd = libc.syscall(a["landlock_create_ruleset"], ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint32(0))
    if fd < 0:
        raise Unavailable(f"landlock_create_ruleset failed (errno {ctypes.get_errno()})")
    try:
        for port in ports:
            rule = _NetPortAttr(LANDLOCK_ACCESS_NET_CONNECT_TCP, int(port))
            if libc.syscall(a["landlock_add_rule"], fd, LANDLOCK_RULE_NET_PORT, ctypes.byref(rule), ctypes.c_uint32(0)) != 0:
                raise Unavailable(f"landlock_add_rule for port {port} failed (errno {ctypes.get_errno()})")
        if libc.syscall(a["landlock_restrict_self"], fd, ctypes.c_uint32(0)) != 0:
            raise Unavailable(f"landlock_restrict_self failed (errno {ctypes.get_errno()})")
    finally:
        os.close(fd)

    prog = _seccomp_program(arch)
    buf = ctypes.create_string_buffer(prog, len(prog))
    fprog = _SockFprog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))
    if libc.syscall(a["seccomp"], SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog)) != 0:
        raise Unavailable(f"seccomp filter install failed (errno {ctypes.get_errno()})")

    return Confinement(ports=sorted(set(int(p) for p in ports)), landlock_abi=abi,
                       residuals=["Landlock matches port, not address: a remote server on an allowed "
                                  "port number is reachable; close with a network namespace (one-time "
                                  "AppArmor profile), a connect-inspecting supervisor, or sandbox-exec on macOS."])


def preexec(ports: List[int], *, min_landlock_abi: int = 4):
    """A preexec_fn for subprocess/asyncio that confines the child before exec. On Unavailable it raises,
    so the parent's subprocess call fails loudly rather than launching an unconfined agent."""
    def _fn():
        apply(ports, min_landlock_abi=min_landlock_abi)
    return _fn


# ───────────────────────── address-level confinement availability ─────────────────────────
#
# Port-level (apply, above) confines by PORT: a remote host on an allowed port number is still
# reachable. Address-level confinement puts the agent in an empty network namespace with no route off
# the machine, so only the local proxies are reachable — but on Ubuntu-family systems that restrict
# unprivileged user namespaces it needs the one-time AppArmor profile (scripts/install-confine-profile.sh).
# This only reports whether that path is AVAILABLE; the netns wrapper that uses it is built separately
# and is exercised only once the profile is installed, since it cannot run without it.

def userns_restricted() -> bool:
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


def netns_available() -> bool:
    """True when an unprivileged empty network namespace can actually be created here (bubblewrap can
    bring up loopback in a fresh net namespace). Probed, not inferred, because the AppArmor profile,
    a reboot, or a policy reload all change the answer."""
    import shutil
    import subprocess
    bwrap = shutil.which("bwrap")
    if sys.platform != "linux" or not bwrap:
        return False
    try:
        r = subprocess.run([bwrap, "--unshare-net", "--dev-bind", "/", "/", "true"],
                           capture_output=True, timeout=20)
        return r.returncode == 0 and b"Operation not permitted" not in (r.stderr or b"")
    except (OSError, subprocess.SubprocessError):
        return False
