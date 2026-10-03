"""DEVELOPMENT ONLY — what the agent's sandbox inside the guest actually refuses.

Run INSIDE the guest image (the x86_64 build in a no-network container here; the arm64 one on a Mac):

    docker run --rm --network none --privileged -e PYTHONPATH=/opt/probant/client \
        -v $PWD/tests/dev/guest_confinement_probe.py:/opt/dev/probe.py:ro probant-guest-dev:x86 \
        python3 /opt/dev/probe.py

The outer process builds the SAME sandbox the supervisor builds for Pi — NetnsSandbox + the socket-family
guard + --unshare-pid — and runs this file again inside it with `--inside`. Every line is an attempt and
what the kernel said. A refusal is only evidence beside a control that succeeds, so each denied thing is
paired with the allowed thing next to it.
"""
import errno
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

MODEL, SEARCH = 40502, 40503


def attempt(label, fn):
    try:
        out = fn()
        return {"what": label, "result": "ALLOWED", "detail": str(out)[:60] if out is not None else ""}
    except OSError as e:
        return {"what": label, "result": "DENIED", "detail": errno.errorcode.get(e.errno, str(e.errno))}
    except Exception as e:                                  # noqa: BLE001
        return {"what": label, "result": "ERROR", "detail": type(e).__name__ + ": " + str(e)[:50]}


def inside():
    def connect(port, host="127.0.0.1"):
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        return "connected"

    def vsock():
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.close()
        return "socket created"

    def write(path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("x")
        return "written"

    rows = [
        attempt("write inside the matter folder", lambda: write("/matter/probe-ok.txt")),
        attempt("write inside the agent's config dir", lambda: write("/probe-config/tmp/ok.txt")),
        attempt("write to /etc", lambda: write("/etc/probe-denied")),
        attempt("write to /opt (the client's own code)", lambda: write("/opt/probe-denied")),
        attempt("write to the home directory", lambda: write(os.path.expanduser("~/probe.txt"))),
        attempt("connect to the model relay port", lambda: connect(MODEL)),
        attempt("connect to another local port", lambda: connect(40999)),
        attempt("connect to a public address", lambda: connect(443, "1.1.1.1")),
        attempt("open an AF_VSOCK socket (the host channel)", vsock),
        attempt("open a raw packet socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()),
        attempt("see a file outside the binds (/init2)", lambda: Path("/init2").read_text()[:10]),
        attempt("list network interfaces", lambda: sorted(os.listdir("/sys/class/net"))),
    ]
    print(json.dumps(rows))


def outside():
    from inferroute_local import netns
    for d in ("/matter", "/probe-config"):
        os.makedirs(d, exist_ok=True)
    # The controls: something listening where the relay points, and something listening where it must not reach.
    listeners = []
    for port in (MODEL, 40999):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        listeners.append(srv)
        threading.Thread(target=lambda s=srv: [c.close() for c, _ in iter(s.accept, None)], daemon=True).start()
    guard = [sys.executable, "/opt/probant/client/inferroute_local/macos_vm/guard.py", "--"]
    box = netns.NetnsSandbox(ports=[MODEL, SEARCH], cfg_dir="/probe-config", rw=["/matter"], binary="/usr/bin/node")
    try:
        argv = box.wrap(guard + [sys.executable, "/opt/dev/probe.py", "--inside"],
                        write_paths=["/matter", "/probe-config", "/probe-config/tmp", "/dev/null", "/dev/tty"])
        argv.insert(1, "--unshare-pid")
        # /opt/dev is where this file is mounted; the real sandbox binds /opt read-only, which covers it.
        r = subprocess.run(argv, env={"HOME": "/root", "PATH": "/usr/bin:/bin"}, capture_output=True, text=True,
                           timeout=60)
    finally:
        box.close()
    if r.returncode != 0 or not r.stdout.strip():
        print("SANDBOX DID NOT RUN:", r.returncode, (r.stderr or "")[-400:])
        return 1
    rows = json.loads(r.stdout.strip().splitlines()[-1])
    for row in rows:
        print(f"  {row['result']:8} {row['what']:44} {row['detail']}")
    print("outside the sandbox, the file it wrote exists:", Path("/matter/probe-ok.txt").exists())
    return 0


if __name__ == "__main__":
    raise SystemExit(inside() if "--inside" in sys.argv else outside())
