#!/usr/bin/env python3
"""DEVELOPMENT ONLY — one synthetic Probant session through the VM path, end to end, on Linux.

    python3 tests/dev/run_linux_vm_e2e.py                          # Linux: stand-in runner, container guest
    python3 tests/dev/run_linux_vm_e2e.py --mac-runtime DIR        # macOS: the real runner, a real VM

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

        # A scripted model: read the disclosure, write a note beside it, then answer. Three turns, so the
        # run covers a tool that READS the matter (the snapshot really arrived in the guest), a tool that
        # WRITES it (the output really comes back, and only after the machine is stopped), and plain text.
        posts = sum(1 for m, pth, *_ in SEEN if m == "POST" and pth == "/v1/chat/completions")
        usage = {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}

        def call(name, arguments):
            chunk({"role": "assistant", "content": None, "tool_calls": [
                {"index": 0, "id": f"call_{posts}", "type": "function",
                 "function": {"name": name, "arguments": json.dumps(arguments)}}]})
            chunk({}, "tool_calls", usage)

        if posts == 1:
            call("read_matter_file", {})
        elif posts == 2:
            call("write", {"path": "notes.md", "content": "SYNTHETIC NOTE written inside the guest\n"})
        else:
            chunk({"role": "assistant", "content": "SYNTHETIC "})
            chunk({"content": "ANSWER FROM THE HOST SIDE"})
            chunk({}, "stop", usage)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


async def main() -> int:
    # --mac-runtime DIR: the REAL runner on a Mac. DIR holds ProbantVM (native/macos/build_runner.sh) and the
    # arm64 `kernel` and `initrd` (native/macos/guest/build_guest.py --arch aarch64). Still development: the
    # Runtime is constructed here directly, with no vendor signature and no Developer ID check, which is the
    # separate synthetic harness the runner's README allows and the product's own locate() never does.
    mac_runtime = None
    if "--mac-runtime" in sys.argv:
        mac_runtime = Path(sys.argv[sys.argv.index("--mac-runtime") + 1]).resolve()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    model_url = f"http://127.0.0.1:{server.server_address[1]}"

    tmp = Path(tempfile.mkdtemp(prefix="probant-vm-e2e-"))
    workspace = tmp / "matter"
    workspace.mkdir()
    (workspace / "disclosure.md").write_text("# Disclosure\n\nA synthetic wrist device with a synthetic sensor.\n")
    runtime_dir = tmp / "runtime"
    runtime_dir.mkdir()
    if mac_runtime is None:
        shutil.copy2(HERE / "linux_vm_runner.py", runtime_dir / "ProbantVM")
        (runtime_dir / "ProbantVM").chmod(0o755)
        shutil.copy2(HERE / "guest_shim.py", runtime_dir / "guest_shim.py")
        (runtime_dir / "boot.json").write_text("{}")
    else:
        # A private copy, exactly as the product's stage() makes one: close() removes the directory it ran from.
        import hashlib
        from inferroute_local.macos_vm.runtime import canonical
        artifacts = {}
        for name in ("ProbantVM", "kernel", "initrd"):
            shutil.copy2(mac_runtime / name, runtime_dir / name)
            if name != "ProbantVM":
                data = (runtime_dir / name).read_bytes()
                artifacts[name] = {"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (runtime_dir / "ProbantVM").chmod(0o500)
        (runtime_dir / "boot.json").write_bytes(canonical(
            {"schema": 1, "development_only": False, "architecture": "arm64", "artifacts": artifacts}))

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
        note = workspace / "notes.md"
        print(f"    before the machine is stopped, the host workspace has notes.md: {note.exists()}")
        early = note.exists()
        code = await asyncio.wait_for(backend.finish(), 120)
        print(f"[4] finish(): agent exit {code}; exported {backend.exported}")
        text = note.read_text() if note.exists() else None
        print(f"    after the stop is proved, notes.md on the host: {text!r}")

        posts = [json.loads(b) for m, pth, _a, b in SEEN if m == "POST" and pth == "/v1/chat/completions"]
        tools = sorted(t["function"]["name"] for t in posts[0].get("tools", []))
        print(f"[5] tools the model was offered: {tools}")
        read_result = next((m.get("content") for m in posts[1]["messages"] if m.get("role") == "tool"), "")
        if isinstance(read_result, list):
            read_result = " ".join(str(x.get("text", "")) for x in read_result)
        print(f"    read_matter_file returned the disclosure: {'synthetic wrist device' in read_result}; "
              f"footer: {read_result.strip().splitlines()[-1] if read_result else None!r}")
        result["ok"] = (ended and code == 0 and not early and backend.exported == ("notes.md",)
                        and text == "SYNTHETIC NOTE written inside the guest\n"
                        and "ls" not in tools and "find" not in tools and "read_matter_file" in tools
                        and "synthetic wrist device" in read_result
                        and "No other files in the matter folder." in read_result)
        print(f"[6] every check held: {result['ok']}")
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
