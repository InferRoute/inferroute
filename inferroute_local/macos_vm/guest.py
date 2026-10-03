"""Trusted immutable guest supervisor, invoked only by the packaged Linux PID 1.

Pi gets anonymous stdin/stdout pipes, not virtio socket descriptors. No credential
or host filesystem is mounted. Readiness precedes matter capability release.
"""

import base64, http.server, json, os, socket, subprocess, sys, threading
from pathlib import Path
from .wire import request, CHUNK_BYTES, MAX_REQUEST_BYTES
from .workspace import valid_path
from inferroute_local import confinement, netns

ROOT = Path("/matter")
CFG = Path("/config")
MODEL = 40502
SEARCH = 40503


class Channel:
    def __init__(self, stream, session):
        self.stream = stream
        self.session = session
        self.seq = 0
        self.lock = threading.Lock()

    def call(self, op, body=None):
        with self.lock:
            seq = self.seq
            self.seq += 1
            yield from request(self.stream, self.session, seq, op, body)

    def json(self, op, body=None):
        return json.loads(b"".join(self.call(op, body)))


MODEL_ROUTES = {
    ("POST", "/v1/chat/completions"): "model.chat",
    ("GET", "/confidential/receipt"): "model.receipt",
    ("POST", "/probant/intake/create-draft"): "intake.create",
}
SEARCH_ROUTES = {
    ("GET", "/enclave"): "search.verify",
    ("POST", "/search"): "search.query",
    ("POST", "/document"): "search.document",
    ("GET", "/matter/state"): "search.state",
    ("POST", "/matter/approve"): "search.approve",
    ("POST", "/matter/mark"): "search.mark",
    ("GET", "/record"): "search.record.get",
    ("POST", "/record"): "search.record.put",
    ("GET", "/lifecycle"): "search.lifecycle",
    ("POST", "/activity"): "search.activity",
    ("POST", "/keep-warm"): "search.keep_warm",
}


def proxy(channel, port, routes, status_channel=None):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def relay(self):
            op = routes.get((self.command, self.path))
            if op is None:
                self.send_error(403)
                return
            if (
                port == MODEL
                and self.headers.get("Authorization") != "Bearer vm-local-capability"
                and self.headers.get("x-api-key") != "vm-local-capability"
            ):
                self.send_error(403)
                return
            sent = False
            self.close_connection = True
            try:
                body = None
                if self.command == "POST":
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_REQUEST_BYTES:
                        self.send_error(413)
                        return
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict):
                        self.send_error(400)
                        return
                selected = status_channel if op == "model.receipt" else channel
                iterator = selected.call(op, body)
                meta = json.loads(next(iterator))
                self.send_response(meta["status"])
                self.send_header("Content-Type", meta["content_type"])
                self.send_header("Connection", "close")
                self.end_headers()
                sent = True
                disconnected = False
                for chunk in iterator:
                    if disconnected:
                        continue
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        disconnected = True
                # Drain the bounded response after a browser abort so the channel stays synchronized.
            except (OSError, ValueError, EOFError, StopIteration):
                if not sent:
                    self.send_error(503)
                # A failed channel cannot be reused after outstanding ACKs; fail whole guest.
                os._exit(78)

        do_GET = relay
        do_POST = relay

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def preflight():
    if (
        sys.platform != "linux"
        or set(os.listdir("/sys/class/net")) != {"lo"}
        or not confinement.netns_bind_available()
    ):
        raise RuntimeError("guest primitives unavailable")
    for path in (ROOT, CFG):
        path.mkdir(exist_ok=True)
    guard = [
        sys.executable,
        "/opt/probant/client/inferroute_local/macos_vm/guard.py",
        "--",
    ]
    # Exercise the exact filter stack, before importing documents or starting Pi.
    # Separate relay paths prevent a closing preflight listener from unlinking
    # a newly started session listener with the same name.
    preflight_config = Path("/preflight-config")
    preflight_config.mkdir(exist_ok=True)
    box = netns.NetnsSandbox(
        ports=[MODEL, SEARCH],
        cfg_dir=str(preflight_config),
        rw=[str(ROOT)],
        binary="/usr/bin/node",
    )
    try:
        argv = box.wrap(
            guard + ["/bin/true"],
            write_paths=[
                str(ROOT),
                str(preflight_config),
                str(preflight_config / "tmp"),
                "/dev/null",
                "/dev/tty",
            ],
        )
        argv.insert(1, "--unshare-pid")
        result = subprocess.run(
            argv,
            env={"HOME": "/root", "PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=10,
        )
    finally:
        box.close()
    if result.returncode != 0:
        raise RuntimeError("guest filter preflight failed")
    return guard


def main():
    words = Path("/proc/cmdline").read_text().split()
    session = next(
        (w.split("=", 1)[1] for w in words if w.startswith("probant.session=")), None
    )
    if not session:
        return 78
    guard = preflight()
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as stream:
        stream.connect((socket.VMADDR_CID_HOST, 40501))
        stream.settimeout(600)
        channel = Channel(stream, session)
        channel.json("guest.ready", {"netns": True, "guard": True, "protocol": 1})
        plan = channel.json("session.plan")
        launch = plan["launch"]
        for name in plan["files"]:
            relative = valid_path(name)
            target = ROOT / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                for chunk in channel.call(
                    "workspace.read", json.dumps(relative).encode()
                ):
                    output.write(chunk)
            target.chmod(0o600)
        for name, data in launch["files"].items():
            if not name.startswith("/config/"):
                raise RuntimeError("config capability refused")
            target = CFG / valid_path(name[8:])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(data, validate=True))
            target.chmod(0o600)
        for name in ("tmp", "attested-sessions", "sessions"):
            (CFG / name).mkdir(exist_ok=True)
        status_stream = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        status_stream.connect((socket.VMADDR_CID_HOST, 40505))
        status_stream.settimeout(600)
        status_channel = Channel(status_stream, session)

        def heartbeat(target):
            import time

            while True:
                time.sleep(30)
                try:
                    target.json("session.keep-alive")
                except (OSError, ValueError, EOFError):
                    os._exit(78)

        # One per channel. A keep-alive waits its turn behind whatever the channel is carrying, and a long
        # model answer can hold the main one for minutes; a single loop over both left the status channel
        # silent for as long, and the runner stops the machine when either goes ten minutes without a frame.
        for target in (channel, status_channel):
            threading.Thread(target=heartbeat, args=(target,), daemon=True).start()
        servers = [proxy(channel, MODEL, MODEL_ROUTES, status_channel)]
        ports = [MODEL]
        if launch["env"].get("IR_SEARCH_ENDPOINT"):
            servers.append(proxy(channel, SEARCH, SEARCH_ROUTES))
            ports.append(SEARCH)
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as rpc:
            rpc.connect((socket.VMADDR_CID_HOST, 40504))
            sandbox = netns.NetnsSandbox(
                ports=ports, cfg_dir=str(CFG), rw=[str(ROOT)], binary="/usr/bin/node"
            )
            argv = sandbox.wrap(
                guard + launch["argv"],
                write_paths=[
                    str(ROOT),
                    str(CFG),
                    str(CFG / "tmp"),
                    "/dev/null",
                    "/dev/tty",
                ],
            )
            # PID namespace termination kills detached descendants before reconciliation.
            argv.insert(1, "--unshare-pid")
            proc = subprocess.Popen(
                argv,
                cwd=ROOT,
                env=launch["env"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            def input_worker():
                try:
                    while True:
                        data = rpc.recv(65536)
                        if not data:
                            break
                        proc.stdin.write(data)
                        proc.stdin.flush()
                except (OSError, ValueError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass

            threading.Thread(target=input_worker, daemon=True).start()
            while True:
                data = proc.stdout.read1(65536)
                if not data:
                    break
                rpc.sendall(data)
            code = proc.wait()
            sandbox.close()
        # Reconcile only safe workspace outputs. Credentials/hidden config never exported.
        if code == 0:
            from .workspace import WorkspaceSnapshot

            snapshot = WorkspaceSnapshot(ROOT)
            try:
                for name, data in snapshot.files.items():
                    if name in plan["files"] and data == b"".join(
                        channel.call("workspace.read", json.dumps(name).encode())
                    ):
                        continue
                    channel.json("output.begin", {"name": name, "bytes": len(data)})
                    for start in range(0, len(data), CHUNK_BYTES):
                        channel.json(
                            "output.chunk",
                            json.dumps(
                                base64.b64encode(
                                    data[start : start + CHUNK_BYTES]
                                ).decode()
                            ).encode(),
                        )
                    channel.json("output.end")
            finally:
                snapshot.close()
        channel.json("session.finish", str(code if 0 <= code <= 255 else 78).encode())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(78)
