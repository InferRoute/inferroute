#!/usr/bin/python3
"""DEVELOPMENT ONLY — a Linux stand-in for native/macos/ProbantVM.swift.

It lets the whole host<->guest path be exercised on a Linux machine with no Mac: the real `Backend`,
the real `Broker`, the real guest supervisor, real AF_VSOCK, the real bubblewrap/Landlock/seccomp stack
and a real Pi — everything except Virtualization.framework and the Swift runner themselves.

The "VM" is a container started from the x86_64 build of the SAME guest recipe
(`build_guest.py --arch x86_64`, imported as `probant-guest-dev:x86`) with no network. It mirrors the
runner's contract exactly, so `Backend` cannot tell the difference:

    ProbantVM --owned-runtime <boot.json> --bridge-fd N --status-fd M

  * stdout/stdin are Pi's RPC stream and nothing else;
  * a `host.bind` frame carrying this run's session id is written to each host socket before any guest
    frame is relayed;
  * a terminal frame with `vm_complete` from the host is what later allows exit code 0;
  * the guest never stops itself — this process stops it, and only then reports.

It is never imported by the product and never shipped. It authenticates nothing: no signature, no
manifest. That is the point of keeping it in tests/dev — a production path must not be able to reach it.
"""
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import uuid
from pathlib import Path

BROKER, RPC, STATUS = 40501, 40504, 40505
IMAGE = "probant-guest-dev:x86"
QEMU_IMAGE = "probant-qemu-dev:arm64"       # alpine + qemu-system-aarch64; see run_linux_vm_e2e.py


def exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError
        data.extend(block)
    return bytes(data)


def main() -> int:
    a = sys.argv
    if len(a) != 7 or a[1] != "--owned-runtime" or a[3] != "--bridge-fd" or a[5] != "--status-fd":
        print("Probant VM refused: verified owned runtime and bridge required", file=sys.stderr)
        return 78
    host = {BROKER: socket.socket(fileno=int(a[4])), STATUS: socket.socket(fileno=int(a[6]))}
    session = str(uuid.uuid4())
    here = Path(__file__).resolve().parent
    listeners = {}
    for port in (BROKER, RPC, STATUS):
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((socket.VMADDR_CID_ANY, port))
        s.listen(1)
        listeners[port] = s

    name = "probant-vm-dev-" + session[:8]
    log = open(here / "guest.log", "wb")
    if (here / "kernel").exists() and (here / "initrd").exists():
        # QEMU mode: the REAL arm64 kernel and initrd, emulated. Nothing is shimmed — the guest's own
        # /init runs as PID 1, reads the session from the real kernel command line and reaches the host
        # at VMADDR_CID_HOST over a real virtio-vsock device, exactly as under Virtualization.framework.
        # The machine mirrors ProbantVM.swift: 2 CPUs, 1 GiB, no network device, no disk, no shared
        # folder, one virtio console (hvc0), one vsock device, one entropy device.
        cid = 3 + int(uuid.UUID(session)) % 60000
        guest = subprocess.Popen(
            ["docker", "run", "--rm", "--name", name, "--network", "none", "--device", "/dev/vhost-vsock",
             "-v", f"{here}:/rt:ro", QEMU_IMAGE,
             "qemu-system-aarch64", "-M", "virt", "-cpu", "max", "-smp", "2", "-m", "1024",
             "-display", "none", "-serial", "none", "-monitor", "none", "-no-reboot", "-nic", "none",
             "-kernel", "/rt/kernel", "-initrd", "/rt/initrd",
             "-append", f"console=hvc0 rdinit=/init panic=0 probant.session={session}",
             "-device", "virtio-serial-pci", "-chardev", "stdio,id=con,signal=off",
             "-device", "virtconsole,chardev=con",
             "-device", f"vhost-vsock-pci,guest-cid={cid}", "-device", "virtio-rng-pci"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    else:
        guest = subprocess.Popen(
            ["docker", "run", "--rm", "--name", name, "--network", "none", "--privileged",
             "-e", "PYTHONPATH=/opt/probant/client", "-e", "PYTHONDONTWRITEBYTECODE=1",
             "-e", "HOME=/root", "-e", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
             "-v", f"{here / 'guest_shim.py'}:/opt/dev/guest_shim.py:ro",
             IMAGE, "python3", "/opt/dev/guest_shim.py", session],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    print("PROBANT_VM_STARTED nic=none host_share=none (linux development stand-in)", file=sys.stderr, flush=True)

    done = threading.Event()
    state = {"success": False, "reason": "broker failure"}

    def finish(reason: str) -> None:
        if not done.is_set():
            state["reason"] = reason
            done.set()

    def pump(src: socket.socket, dst: socket.socket, from_host: bool) -> None:
        reason = "broker failure"
        try:
            while True:
                head = exact(src, 4)
                size = struct.unpack("!I", head)[0]
                if not 0 < size <= 65536:
                    raise ValueError("frame size")
                body = exact(src, size)
                if from_host:
                    obj = json.loads(body)
                    if obj.get("end") is True and obj.get("vm_complete") is True and obj.get("ok") is True:
                        state["success"] = True
                dst.sendall(head + body)
        except EOFError:
            reason = "broker EOF"
        except Exception:                                   # noqa: BLE001
            pass
        finish(reason)

    def serve_channel(port: int) -> None:
        try:
            conn, _ = listeners[port].accept()
        except OSError:
            return
        bind = json.dumps({"v": 1, "session": session, "op": "host.bind"}).encode()
        host[port].sendall(struct.pack("!I", len(bind)) + bind)
        threading.Thread(target=pump, args=(conn, host[port], False), daemon=True).start()
        threading.Thread(target=pump, args=(host[port], conn, True), daemon=True).start()

    def serve_rpc() -> None:
        try:
            conn, _ = listeners[RPC].accept()
        except OSError:
            return

        def out() -> None:
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    os.write(1, data)
            except OSError:
                pass

        def inp() -> None:
            try:
                while True:
                    data = os.read(0, 65536)
                    if not data:
                        conn.shutdown(socket.SHUT_WR)
                        break
                    conn.sendall(data)
            except OSError:
                pass

        threading.Thread(target=out, daemon=True).start()
        threading.Thread(target=inp, daemon=True).start()

    for port in (BROKER, STATUS):
        threading.Thread(target=serve_channel, args=(port,), daemon=True).start()
    threading.Thread(target=serve_rpc, daemon=True).start()

    parent = os.getppid()

    def watch_parent() -> None:
        while not done.wait(0.5):
            if os.getppid() != parent:
                finish("host parent exited")
            elif guest.poll() is not None:
                finish("guest stopped before host teardown proof")

    threading.Thread(target=watch_parent, daemon=True).start()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *_: finish("host signal"))

    done.wait()
    # The HOST stops the machine. A guest that had already gone is a failure, exactly as in the runner.
    already_gone = guest.poll() is not None
    subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    guest.wait()
    log.close()
    ok = state["success"] and state["reason"] == "broker EOF" and not already_gone
    print(f"PROBANT_VM_STOPPED state=stopped reason={state['reason']} completion_proved={int(state['success'])}",
          file=sys.stderr, flush=True)
    return 0 if ok else 78


if __name__ == "__main__":
    raise SystemExit(main())
