"""The process seal: outbound network made IMPOSSIBLE for the rest of a process's life, every thread (v14: moved here
from enclave/azure/m2_entry.py so the published front of the TDX image imports it without importing the Azure entry,
whose functions import the closed ranking modules). m2_entry re-exports it; both entry points call seal_network()
between binding their listener and serving."""
from __future__ import annotations

import os
import time


def say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── CONFINEMENT ───────────────────────────────────────────────────────────────────────────────────
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
SECCOMP_SET_MODE_FILTER = 1
# A seccomp filter is per THREAD. Without this flag, threads alive at install time keep an open door: the four
# OpenMP/torch workers warm() creates were never sealed (found by review, 2 Nov). TSYNC installs the filter on
# every thread of the process, or fails, and sets no-new-privs on all of them.
SECCOMP_FILTER_FLAG_TSYNC = 1
AUDIT_ARCH_X86_64 = 0xC000003E
NR_SECCOMP, NR_SOCKET, NR_CONNECT = 317, 41, 42
# ── the memory seal (v14 round 3) ─────────────────────────────────────────────────────────────────
# Every x86_64 syscall that makes memory, a message or a key that OUTLIVES a process and that a forked child could
# inherit or reach: the whole of SysV IPC (shared segments, semaphore values, message queues), POSIX queues, the
# kernel keyrings, userfaultfd and process_madvise (another process's pages), mremap/remap_file_pages (a shared
# map reshaped), memfd and io_uring (shareable buffers), creat/openat2 (write access the openat rule below could
# not see), mknod (a FIFO), and the cross-process reads and fd theft already refused by the unit.
NR_DENIED_MEMORY = {
    "shmget": 29, "shmat": 30, "shmctl": 31, "shmdt": 67,
    "semget": 64, "semop": 65, "semctl": 66, "semtimedop": 220,
    "msgget": 68, "msgsnd": 69, "msgrcv": 70, "msgctl": 71,
    "mq_open": 240, "mq_unlink": 241, "mq_timedsend": 242, "mq_timedreceive": 243, "mq_notify": 244, "mq_getsetattr": 245,
    "add_key": 248, "request_key": 249, "keyctl": 250,
    "userfaultfd": 323, "process_madvise": 440, "mremap": 25, "remap_file_pages": 216,
    "memfd_create": 319, "memfd_secret": 447, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "creat": 85, "openat2": 437, "mknod": 133, "mknodat": 259,
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "pidfd_getfd": 438, "kcmp": 312,
}
NR_MMAP = 9
MAP_SHARED, MAP_ANONYMOUS, PROT_WRITE = 0x01, 0x20, 0x02       # MAP_SHARED_VALIDATE (0x03) carries bit 0 too
NR_SETSID, NR_SETPGID = 112, 109
# The child seal's pid-gated calls (v14 round 4): a per-request child must not poke the warm parent or any other
# process. Allowed only when the target argument names the child itself (its own pid, or 0 = "self" where the
# call reads 0 that way); refused otherwise. (name, nr, index of the target argument, whether 0 means self)
CHILD_PID_GATED = (("kill", 62, 0, False), ("tkill", 200, 0, False), ("tgkill", 234, 0, False),
                   ("rt_sigqueueinfo", 129, 0, False), ("rt_tgsigqueueinfo", 297, 0, False),
                   ("prlimit64", 302, 0, True), ("setpriority", 141, 1, True), ("ioprio_set", 251, 1, True),
                   ("sched_setaffinity", 203, 0, True), ("sched_setscheduler", 144, 0, True),
                   ("sched_setparam", 142, 0, True), ("sched_setattr", 314, 0, True))
CHILD_DENIED = (("pidfd_send_signal", 424), ("setsid", NR_SETSID), ("setpgid", NR_SETPGID))
X32_BIT = 0x40000000                 # an x32 syscall number carries this bit: refuse the ABI outright
_JSET_K = 0x45
_LD_W_ABS, _JEQ_K, _RET_K = 0x20, 0x15, 0x06
_KILL_PROCESS, _ALLOW, _ERRNO_EPERM = 0x80000000, 0x7FFF0000, 0x00050000 | 1


def seal_network() -> None:
    """Make outbound network IMPOSSIBLE for the rest of this process's life, and its children's.

    WHY THIS EXISTS. "No code path sends your text anywhere" is a semantic property of a program.
    No static analysis decides it (Rice), no reviewer can certify it over 3,600 lines, and no model
    verdict — however attested — makes it true. But it does not need deciding. It can be made
    impossible, and then the claim rests on a mechanism instead of on anyone's judgment.

    WHY HERE, AND ONLY HERE. Measured 2026-09-29: this enclave touches the network in exactly two
    places, both before serving — obtain_root() fetches the index blob, and SearchService.__init__
    takes ONE attestation from the sidecar on localhost. Nothing outbound happens per query. So the
    last moment both are done is the first moment nothing is lost by closing the door.

    WHAT IT BLOCKS: socket() and connect(), with EPERM. New outbound connections become impossible
    for every line of code that runs afterwards, INCLUDING the compiled ranking modules whose source
    we do not publish — which is what stops "only these files touch your text" being an assertion
    nobody outside can check.

    WHAT IT DOES NOT BLOCK: accept() on the listening socket bound above, and reads and writes on
    connections already established. The service answers its client exactly as before. This was
    verified, not assumed: with the filter installed, socket() and connect() return EPERM while an
    established connection still carries data both ways and file I/O is untouched.

    EVERY THREAD. The filter is installed with SECCOMP_FILTER_FLAG_TSYNC, so threads that already exist
    get it too (a seccomp filter is per thread; threads created later inherit it). Measured 2 Nov in the
    m2 image: a thread started before the seal gets EPERM from socket() after it, and all 42 threads of
    a warmed engine read `Seccomp: 2`. The read-back below checks every task, not just the caller.

    EPERM rather than KILL deliberately: an attempted leak fails, and the enclave keeps serving the
    client it already has rather than dying mid-answer.

    Seccomp is one-way. Once installed, no later code can remove it — not a library, not a plugin,
    not a compromised dependency. PR_SET_NO_NEW_PRIVS is what makes that true across exec, and the
    filter is inherited by any child process.

    Verifiable by a reader without trusting us: these ~20 lines are the whole mechanism, they run
    unconditionally before serve_forever, and they are inside an image whose dm-verity hashes are in
    the CCE policy that HOST_DATA is the SHA-256 of. Reading them is a far smaller job than auditing
    dataflow through the rest.
    """
    import ctypes
    import struct

    def _f(code, jt, jf, k):
        return struct.pack("HBBI", code, jt, jf, k)

    prog = b"".join([
        _f(_LD_W_ABS, 0, 0, 4),                      # seccomp_data.arch
        _f(_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        _f(_RET_K, 0, 0, _KILL_PROCESS),             # unexpected arch: refuse to run at all
        _f(_LD_W_ABS, 0, 0, 0),                      # seccomp_data.nr
        _f(_JEQ_K, 2, 0, NR_SOCKET),
        _f(_JEQ_K, 1, 0, NR_CONNECT),
        _f(_RET_K, 0, 0, _ALLOW),
        _f(_RET_K, 0, 0, _ERRNO_EPERM),
    ])
    buf = ctypes.create_string_buffer(prog, len(prog))
    fprog = struct.pack("HxxxxxxQ", len(prog) // 8, ctypes.addressof(buf))
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    rc = libc.syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, fprog)
    if rc != 0:
        # A positive return names the thread that could not be synchronised; errno is set otherwise.
        raise OSError(ctypes.get_errno(), f"seccomp filter install failed (rc {rc})")
    # Read back what the kernel says, for EVERY thread, so the confinement is a checked fact and not a called function.
    for tid in os.listdir("/proc/self/task"):
        mode = next((l.split()[1] for l in open(f"/proc/self/task/{tid}/status") if l.startswith("Seccomp:")), "0")
        if mode != "2":
            raise OSError(f"refusing to serve: seccomp mode of thread {tid} is {mode!r}, expected '2' (filter)")
    say("network sealed: socket() and connect() now refused for the life of this process, every thread")


def deny_ptrace() -> None:
    """Make this process (and, by inheritance, every process it forks) non-dumpable: a same-uid process may then
    neither ptrace it nor take its descriptors (pidfd_getfd) nor read its /proc/<pid>/fd. v14: the engine's warm
    parent holds the control link to the front; a per-request child must have no way back to it."""
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")
    if libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:            # read back: a checked fact, not a called function
        raise OSError("PR_SET_DUMPABLE did not take")


def _assemble(insns):
    """A tiny BPF assembler: (code, jt, jf, k) with jt/jf a label name or None (fall through); labels are
    ("label", name) entries. Returns the packed program."""
    import struct
    index, out = {}, []
    for ins in insns:
        if ins[0] == "label":
            index[ins[1]] = len(out)
        else:
            out.append(ins)
    prog = []
    for i, (code, jt, jf, k) in enumerate(out):
        rj = lambda lab: 0 if lab is None else index[lab] - (i + 1)   # noqa: E731
        prog.append(struct.pack("HBBI", code, rj(jt), rj(jf), k))
    return b"".join(prog)


def memory_seal_program() -> bytes:
    """The BPF program of seal_memory (published, so a reader can check what it refuses): every NR_DENIED_MEMORY
    call -> EPERM; mmap with MAP_SHARED and (MAP_ANONYMOUS or PROT_WRITE) -> EPERM; everything else allowed (the
    network seal stacks beneath). No rule on open(): torch opens /dev/null O_RDWR at import (measured 2 Nov), so
    write-opens stay allowed and the file-backed route is closed by the unit instead (see seal_memory)."""
    insns = [(_LD_W_ABS, None, None, 4), (_JEQ_K, None, "kill", AUDIT_ARCH_X86_64), (_LD_W_ABS, None, None, 0),
             (_JSET_K, "kill", None, X32_BIT)]
    for nr in sorted(NR_DENIED_MEMORY.values()):
        insns.append((_JEQ_K, "deny", None, nr))
    insns += [(_JEQ_K, "mmap", None, NR_MMAP),
              (_RET_K, None, None, _ALLOW),
              # mmap(addr, len, prot=arg2, flags=arg3, ...): seccomp_data.args[i] low word sits at 16 + 8 i
              ("label", "mmap"), (_LD_W_ABS, None, None, 16 + 8 * 3), (_JSET_K, None, "allow", MAP_SHARED),
              (_JSET_K, "deny", None, MAP_ANONYMOUS), (_LD_W_ABS, None, None, 16 + 8 * 2), (_JSET_K, "deny", "allow", PROT_WRITE),
              # BPF jumps forward only: the shared targets come last
              ("label", "allow"), (_RET_K, None, None, _ALLOW),
              ("label", "kill"), (_RET_K, None, None, _KILL_PROCESS),
              ("label", "deny"), (_RET_K, None, None, _ERRNO_EPERM)]
    return _assemble(insns)


def _install(prog: bytes, tsync: bool) -> None:
    import ctypes
    import struct
    buf = ctypes.create_string_buffer(prog, len(prog))
    fprog = struct.pack("HxxxxxxQ", len(prog) // 8, ctypes.addressof(buf))
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    rc = libc.syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC if tsync else 0, fprog)
    if rc != 0:
        raise OSError(ctypes.get_errno(), f"seccomp filter install failed (rc {rc})")


def seal_memory() -> None:
    """Make memory that OUTLIVES a process impossible to create, for the rest of this process's life and its
    children's (v14 round 3).

    WHY. The engine answers each request in a child forked from one warm parent, so that nothing of a request
    survives it. But the closed modules are imported and warmed IN that parent, and a region made there with
    mmap(MAP_SHARED|MAP_ANONYMOUS), shmget/shmat, a SysV queue or semaphore, a POSIX queue or a kernel key is
    inherited by every child SHARED, not copied: child A writes, child B reads. Seccomp is the control here, not
    the published Python around the fork — closed code shares this process and could rebind any of that.

    WHAT IT REFUSES (memory_seal_program; EPERM, every thread, inherited by children): the calls in
    NR_DENIED_MEMORY; mmap with MAP_SHARED when anonymous or writable.

    THE FILE-BACKED ROUTE, and why mprotect needs no rule. A MAP_SHARED mapping made read-only can be made
    writable later with mprotect only if the kernel set VM_MAYWRITE on it, which for a file needs a descriptor
    opened for writing. So what matters is what the process can open for writing AND map: under
    ir-engine.service that is nothing — the system, /ram, /dev/shm, /dev/hugepages, /tmp and /var/tmp are
    read-only mounts, and /dev/zero (shared anonymous memory in effect) is read-only by the DEVICE CGROUP
    (DevicePolicy=strict, DeviceAllow=/dev/zero r): a read-only mount does not stop open(O_RDWR) on a device
    node, measured 2 Nov, and so was not the control. Opened read-only, a shared map of /dev/zero refuses
    mprotect(PROT_WRITE) with EACCES (measured). /dev/null, which torch opens O_RDWR at import, has no mmap.
    A seccomp rule on open() modes was measured and dropped for that reason.

    WHAT IT DOES NOT REFUSE: private mappings, read-only shared mappings of files (the index on /ram), pipes and
    socketpairs (the parent's own; a child closes every inherited descriptor but its channel), threads.
    Installed BEFORE the closed import, with TSYNC, and read back for every thread like seal_network."""
    _install(memory_seal_program(), tsync=True)
    for tid in os.listdir("/proc/self/task"):
        mode = next((l.split()[1] for l in open(f"/proc/self/task/{tid}/status") if l.startswith("Seccomp:")), "0")
        if mode != "2":
            raise OSError(f"refusing to serve: seccomp mode of thread {tid} is {mode!r}, expected '2' (filter)")
    say("memory sealed: no shared anonymous or writable mapping, no SysV or POSIX IPC, no key, for the life of this process and its children")


def child_program(pid: int) -> bytes:
    """The per-request child's BPF (published): CHILD_DENIED -> EPERM; each CHILD_PID_GATED call -> EPERM unless
    its target argument is `pid` (or 0 where that means self); x32 -> kill; everything else allowed."""
    insns = [(_LD_W_ABS, None, None, 4), (_JEQ_K, None, "kill", AUDIT_ARCH_X86_64), (_LD_W_ABS, None, None, 0),
             (_JSET_K, "kill", None, X32_BIT)]
    for _name, nr in CHILD_DENIED:
        insns.append((_JEQ_K, "deny", None, nr))
    for name, nr, _arg, _zero in CHILD_PID_GATED:
        insns.append((_JEQ_K, f"gate_{name}", None, nr))
    insns.append((_RET_K, None, None, _ALLOW))
    for name, _nr, arg, zero_is_self in CHILD_PID_GATED:
        insns += [("label", f"gate_{name}"), (_LD_W_ABS, None, None, 16 + 8 * arg), (_JEQ_K, "allow", None, pid & 0xFFFFFFFF)]
        if zero_is_self:
            insns.append((_JEQ_K, "allow", None, 0))
        insns.append((_RET_K, None, None, _ERRNO_EPERM))
    insns += [("label", "allow"), (_RET_K, None, None, _ALLOW),
              ("label", "kill"), (_RET_K, None, None, _KILL_PROCESS),
              ("label", "deny"), (_RET_K, None, None, _ERRNO_EPERM)]
    return _assemble(insns)


def confine_child() -> None:
    """In a per-request child, after its own setsid(): child_program(os.getpid()) for it and everything it makes.
    setsid/setpgid refused, so a grandchild cannot leave the process group the parent kills (chosen over denying
    fork — the libraries may spawn helpers; threads are untouched — and over a cgroup per child, which
    ProtectControlGroups= forbids); signals, limits, priorities and scheduling refused for any target but the
    child itself, so it cannot poke the parent or a neighbour (pidfd_send_signal refused outright: its target is
    a descriptor). What a child can still tell the parent: its exit status, its /proc comm, and when it exits.
    No TSYNC: a fresh child has one thread, and threads it starts inherit the filter."""
    _install(child_program(os.getpid()), tsync=False)
