"""VM-only extra socket-family guard; stacks with the Linux backend.

The trusted guest supervisor owns AF_VSOCK. Agents may create only AF_UNIX,
AF_INET or AF_INET6 sockets, further restricted by the existing Linux filter,
Landlock and empty netns. Missing/unsupported setup refuses before target exec.
"""

import ctypes, errno, os, platform, struct, sys


def apply():
    architectures = {"aarch64": (198, 277, 0xC00000B7), "x86_64": (41, 317, 0xC000003E)}
    if sys.platform != "linux" or platform.machine() not in architectures:
        raise RuntimeError("unsupported")
    socket_nr, seccomp_nr, audit = architectures[platform.machine()]
    # Wrong arch kills; only socket() is additionally fenced. Native socketpair
    # remains available for child IPC and cannot open a virtio host connection.
    instructions = [
        (0x20, 0, 0, 4),
        (0x15, 0, 7, audit),
        (0x20, 0, 0, 0),
        (0x15, 0, 6, socket_nr),
        (0x20, 0, 0, 16),
        (0x15, 4, 0, 1),
        (0x15, 3, 0, 2),
        (0x15, 2, 0, 10),
        (0x06, 0, 0, 0x00050000 | errno.EACCES),
        (0x06, 0, 0, 0x80000000),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    raw = b"".join(struct.pack("HBBI", *i) for i in instructions)

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(raw)
    program = Program(len(instructions), ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if (
        libc.prctl(38, 1, 0, 0, 0) != 0
        or libc.syscall(seccomp_nr, 1, 0, ctypes.byref(program)) != 0
    ):
        raise RuntimeError("filter unavailable")


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        return 78
    try:
        apply()
        os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
    except (OSError, RuntimeError):
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
