"""Egress confinement: the seccomp program is well-formed, and applied in a child it lets TCP reach the
allowed ports and nothing else — no remote TCP, no UDP, no DNS through glibc or systemd-resolved, no raw
or AF_UNIX sockets — while a real subprocess launched under it still runs. Linux-only; skipped elsewhere."""
import os
import socket
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from inferroute_local import confinement as C

linux = pytest.mark.skipif(sys.platform != "linux", reason="confinement is Linux-only")


def _abi():
    import ctypes
    return C.landlock_abi(ctypes.CDLL(None, use_errno=True))


needs_landlock = pytest.mark.skipif(sys.platform != "linux" or _abi() < 4 if sys.platform == "linux" else True,
                                    reason="needs Landlock ABI >= 4")


def test_seccomp_program_is_structurally_valid():
    prog = C._seccomp_program("x86_64")
    ins = [struct.unpack("HBBI", prog[i * 8:i * 8 + 8]) for i in range(len(prog) // 8)]
    assert len(ins) == 20
    assert ins[0][0] == 0x20 and ins[0][3] == 4                 # load arch at offset 4
    assert ins[17] == (0x06, 0, 0, C.SECCOMP_RET_ALLOW)
    assert ins[19] == (0x06, 0, 0, C.SECCOMP_RET_KILL_PROCESS)
    for code, jt, jf, _ in ins:                                  # every jump lands inside the program
        for off in (jt, jf):
            assert off < len(ins)


def test_apply_refuses_off_linux(monkeypatch):
    monkeypatch.setattr(C.sys, "platform", "darwin")
    with pytest.raises(C.Unavailable):
        C.apply([8000])


def test_apply_refuses_empty_ports():
    with pytest.raises(C.Unavailable):
        C.apply([])


# The real thing runs in a forked child, so a killed filter never takes the test process down.

def _child(ports, attempts, allowed_port):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            C.apply(ports)
            out = attempts(allowed_port)
            os.write(w, out.encode())
            os._exit(0)
        except BaseException as e:                              # noqa: BLE001
            try:
                os.write(w, f"SETUP-FAILED:{type(e).__name__}".encode())
            finally:
                os._exit(3)
    os.close(w)
    buf = b""
    while True:
        chunk = os.read(r, 4096)
        if not chunk:
            break
        buf += chunk
    _, status = os.waitpid(pid, 0)
    os.close(r)
    return buf.decode(), status


def _attempts(allowed):
    lines = []

    def a(label, fn):
        try:
            lines.append(f"{label}={fn()}")
        except Exception as e:                                  # noqa: BLE001
            lines.append(f"{label}=BLOCKED:{type(e).__name__}")

    a("proxy", lambda: (socket.create_connection(("127.0.0.1", allowed), timeout=4).close() or "OK"))
    a("other_local", lambda: (socket.create_connection(("127.0.0.1", 22), timeout=2).close() or "OK"))
    a("udp", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM) and "OK")
    a("afunix", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) and "OK")
    a("raw", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) and "OK")
    a("socketpair", lambda: socket.socketpair() and "OK")
    a("stream_flags", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) and "OK")
    a("glibc_dns", lambda: socket.getaddrinfo("example.org", 443)[0][4] and "RESOLVED")
    r = subprocess.run(["resolvectl", "query", "example.com"], capture_output=True, text=True, timeout=8)
    lines.append(f"resolved_dns={'RESOLVED' if r.returncode == 0 and 'example.com:' in r.stdout else 'BLOCKED'}")
    return "\n".join(lines)


@needs_landlock
def test_confined_child_reaches_only_the_allowed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        allowed = s.getsockname()[1]
    server = ThreadingHTTPServer(("127.0.0.1", allowed), _Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        out, status = _child([allowed], _attempts, allowed)
    finally:
        server.shutdown()
        server.server_close()
    assert "SETUP-FAILED" not in out, out
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (out, status)
    got = dict(line.split("=", 1) for line in out.splitlines())
    assert got["proxy"] == "OK"
    assert got["socketpair"] == "OK" and got["stream_flags"] == "OK"
    for key in ("other_local", "udp", "afunix", "raw", "glibc_dns"):
        assert got[key].startswith("BLOCKED"), (key, got[key])
    assert got["resolved_dns"] == "BLOCKED"                      # the systemd-resolved varlink hole is closed


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()


@needs_landlock
def test_a_subprocess_launched_under_preexec_still_runs():
    proc = subprocess.run([sys.executable, "-c", "print('ALIVE')"], preexec_fn=C.preexec([8000]),
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "ALIVE" in proc.stdout


@needs_landlock
def test_confined_child_cannot_reach_a_remote_host():
    out, status = _child([9], lambda _p: ("remote=" + (
        "OK" if _try_remote() else "BLOCKED")), 9)
    assert out == "remote=BLOCKED", out


def _try_remote():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=4).close()
        return True
    except Exception:                                           # noqa: BLE001
        return False


@needs_landlock
def test_write_scoping_confines_writes_but_not_reads():
    """Only the given trees are writable; the plant-and-run escape paths are denied; reads stay open."""
    import tempfile
    d = tempfile.mkdtemp()
    ws, cfg, deny = os.path.join(d, "ws"), os.path.join(d, "cfg"), os.path.join(d, "deny")
    for p in (ws, cfg, deny):
        os.makedirs(p)
    with open(os.path.join(deny, "search.json"), "w") as fh:
        fh.write("orig")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    def attempts(allowed):
        out = []

        def a(label, fn):
            try:
                fn(); out.append(f"{label}=OK")
            except Exception:                                          # noqa: BLE001
                out.append(f"{label}=DENIED")
        a("write_ws", lambda: open(os.path.join(ws, "e.txt"), "w").write("x"))
        a("mkdir_ws", lambda: os.mkdir(os.path.join(ws, "sub")))
        a("write_cfg", lambda: open(os.path.join(cfg, "s.jsonl"), "w").write("x"))
        a("write_devnull", lambda: open("/dev/null", "w").write("x"))
        a("escape_write_searchjson", lambda: open(os.path.join(deny, "search.json"), "w").write("PWNED"))
        a("read_etc_passwd", lambda: open("/etc/passwd").read())
        return "\n".join(out)

    def child(ports, _attempts, allowed_port):
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                C.apply(ports, write_paths=[ws, cfg, "/dev/null"])
                os.write(w, attempts(allowed_port).encode())
                os._exit(0)
            except BaseException as e:                                 # noqa: BLE001
                os.write(w, f"SETUP-FAILED:{type(e).__name__}".encode()); os._exit(3)
        os.close(w)
        buf = b""
        while True:
            c = os.read(r, 4096)
            if not c:
                break
            buf += c
        os.waitpid(pid, 0)
        return buf.decode()

    out = child([port], attempts, port)
    assert "SETUP-FAILED" not in out, out
    got = dict(line.split("=", 1) for line in out.splitlines())
    assert got["write_ws"] == "OK" and got["mkdir_ws"] == "OK" and got["write_cfg"] == "OK" and got["write_devnull"] == "OK"
    assert got["escape_write_searchjson"] == "DENIED"
    assert got["read_etc_passwd"] == "OK"                               # reads are NOT confined
    assert open(os.path.join(deny, "search.json")).read() == "orig"     # the escape file is untouched
