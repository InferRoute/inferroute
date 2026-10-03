#!/usr/bin/env python3
"""DEVELOPMENT ONLY — one synthetic Probant session through the VM path, end to end, on Linux.

    python3 tests/dev/run_linux_vm_e2e.py

Real: Backend, Broker, wire protocol, WorkspaceSnapshot, the guest supervisor, AF_VSOCK, bubblewrap +
Landlock + seccomp + the extra socket-family guard, Pi 0.84.1 and the ir-attested extension.
Synthetic: the model (a local server answering in OpenAI SSE), the receipt, the matter, the disclosure.
Stand-in: the runner (tests/dev/linux_vm_runner.py) and the VM (a no-network container built from the
x86_64 output of native/macos/guest/build_guest.py).

Needs: `docker import <out>/rootfs.tar probant-guest-dev:x86` done once after building the x86_64 guest.
"""
import asyncio
import json
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from inferroute_local.macos_vm.backend import Backend          # noqa: E402
from inferroute_local.macos_vm.plan import build_plan          # noqa: E402
from inferroute_local.macos_vm.runtime import Runtime          # noqa: E402

MODEL_KEY = "synthetic-host-key"
SEEN = []


class Model(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        SEEN.append(("GET", self.path, self.headers.get("Authorization"), b""))
        if self.path != "/confidential/receipt":
            self.send_error(404)
            return
        body = json.dumps({
            "verdict": "confidential", "model_short": "synthetic", "verified_at": "2026-10-03T00:00:00Z",
            "started_at": "2026-10-03T00:00:00Z", "transport": "development harness",
            "checks": {"synthetic": {"ok": True, "label": "Synthetic check", "why": "development harness"}},
            "instance": {"id": "00000000", "gpu_count": 0}, "limitations": [], "e2ee": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        SEEN.append(("POST", self.path, self.headers.get("Authorization"), body))
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()

        def chunk(delta, finish=None, usage=None):
            obj = {"id": "synthetic", "object": "chat.completion.chunk", "model": "synthetic",
                   "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            if usage:
                obj["usage"] = usage
            self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
            self.wfile.flush()

        chunk({"role": "assistant", "content": "SYNTHETIC "})
        chunk({"content": "ANSWER FROM THE HOST SIDE"})
        chunk({}, "stop", {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


async def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    model_url = f"http://127.0.0.1:{server.server_address[1]}"

    tmp = Path(tempfile.mkdtemp(prefix="probant-vm-e2e-"))
    workspace = tmp / "matter"
    workspace.mkdir()
    (workspace / "disclosure.md").write_text("# Disclosure\n\nA synthetic wrist device with a synthetic sensor.\n")
    runtime_dir = tmp / "runtime"
    runtime_dir.mkdir()
    shutil.copy2(HERE / "linux_vm_runner.py", runtime_dir / "ProbantVM")
    (runtime_dir / "ProbantVM").chmod(0o755)
    shutil.copy2(HERE / "guest_shim.py", runtime_dir / "guest_shim.py")
    (runtime_dir / "boot.json").write_text("{}")

    backend = Backend(Runtime(runtime_dir, {}), workspace)
    result = {"events": [], "answer": "", "ok": False}
    try:
        await backend.prepare()
        print(f"[1] guest ready — label: {backend.label}")
        plan = build_plan(alias="synthetic", passthrough=["--mode", "rpc"], mode="matter",
                          surface_browser_only=True, documents={})
        request = plan.request
        request["env"].pop("IR_SEARCH_ENDPOINT", None)          # no search verifier in this run
        backend.configure(request, model_url=model_url, model_key=MODEL_KEY)
        print("[2] plan configured; the guest now starts Pi")

        proc = backend.proc
        proc.stdin.write((json.dumps({"type": "prompt", "message": "Say the synthetic answer."}) + "\n").encode())
        await proc.stdin.drain()

        async def read_until_end():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    return False
                try:
                    ev = json.loads(line)
                except ValueError:
                    result["events"].append("<non-json>")
                    continue
                kind = ev.get("type")
                result["events"].append(kind)
                if kind == "message_update":
                    delta = (ev.get("assistantMessageEvent") or {})
                    if delta.get("type") == "text_delta":
                        result["answer"] += delta.get("delta", "")
                if kind == "agent_end":
                    return True

        ended = await asyncio.wait_for(read_until_end(), 180)
        print(f"[3] Pi events: {sorted(set(result['events']))}")
        print(f"    answer through the VM path: {result['answer']!r}  (agent_end: {ended})")
        proc.stdin.close()
        code = await asyncio.wait_for(backend.finish(), 120)
        print(f"[4] finish(): agent exit {code}; exported {backend.exported}")
        result["ok"] = ended and code == 0
    finally:
        err = b""
        if backend.proc is not None and backend.proc.stderr is not None:
            try:
                err = await asyncio.wait_for(backend.proc.stderr.read(), 5)
            except Exception:                                   # noqa: BLE001
                pass
        # Read the guest's log BEFORE close(): closing the backend removes the staged runtime directory.
        log = runtime_dir / "guest.log"
        guest_log = log.read_text(errors="replace")[-1500:] if log.exists() else "(none)"
        await backend.close()
        server.shutdown()
        print("--- runner stderr ---")
        print(err.decode(errors="replace").strip() or "(none)")
        print("--- guest log (tail) ---")
        print(guest_log.strip() or "(empty)")
        print("--- what the synthetic model saw ---")
        for method, path, auth, body in SEEN:
            print(f"  {method} {path}  auth={'host key' if auth == 'Bearer ' + MODEL_KEY else auth!r}  body={len(body)}B")
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
