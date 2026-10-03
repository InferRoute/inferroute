#!/usr/bin/env python3
"""DEVELOPMENT ONLY — one REAL Probant session through the product's macOS VM path, on Linux.

    python3 tests/dev/run_product_vm.py                      # container guest
    python3 tests/dev/run_product_vm.py --qemu-guest DIR     # the real arm64 kernel + initrd, emulated
    python3 tests/dev/run_product_vm.py --home               # just start `ir probant home` that way, for a person

Unlike run_linux_vm_e2e.py nothing here is synthetic except the invention: the model is the sealed lane, the
search machine is the configured enclave, the page is the product's own, and it is driven over the same HTTP
API the browser uses. It spends a few cents. The matter lives in a throwaway IR_PROBANT_ROOT.

What it shows that the synthetic run cannot: that confidential.py's Mac branch, the search verifier behind
the broker's search route, the session page and the record all work together with a VM-held agent.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DISCLOSURE = """# Disclosure (synthetic — development harness)

A bicycle pedal with a strain gauge bonded inside the pedal spindle. The gauge measures how the spindle
bends as the rider pushes, and a small circuit in the pedal body turns that into pedalling power, which
is sent by radio to a handlebar display. The battery is a coin cell behind a screw cap on the pedal's
outer face. The novelty we believe we have: the gauge sits inside a bore along the spindle's axis rather
than on its surface, so it is sealed from water and can be replaced without removing the bearings.
"""


def main() -> int:
    argv = sys.argv[1:]
    standin = "container"
    if "--qemu-guest" in argv:
        standin = str(Path(argv[argv.index("--qemu-guest") + 1]).resolve())
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(HERE / "vm_product"), str(REPO)])
    env["PROBANT_DEV_VM_STANDIN"] = standin
    env["IR_ALLOW_NESTED"] = "1"
    env["IR_PROBANT_NO_BROWSER"] = "1"
    py = sys.executable
    if "--home" in argv:
        env.pop("IR_PROBANT_NO_BROWSER")
        return subprocess.call([py, "-m", "inferroute_cli", "probant", "home"], env=env)

    # BOTH stores are throwaway. IR_PROBANT_ROOT alone moves only the matter FOLDERS; the matter records,
    # approvals and session records live under INFERROUTE_HOME, and the first run of this harness wrote a
    # test matter into the real one. Only the search configuration is carried over, read-only by convention.
    root = Path(tempfile.mkdtemp(prefix="probant-product-vm-"))
    irhome = root / "inferroute-home"
    (irhome / "confidential").mkdir(parents=True)
    real = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential" / "search.json"
    if real.exists():
        shutil.copy2(real, irhome / "confidential" / "search.json")
    env["INFERROUTE_HOME"] = str(irhome)
    env["IR_PROBANT_ROOT"] = str(root / "Probant")
    (root / "Probant").mkdir()
    made = subprocess.run([py, "-m", "inferroute_cli", "probant", "new", "devclient", "pedal",
                           "--priority-date", "2026-01-15"], env=env, capture_output=True, text=True)
    print("[new]", (made.stdout + made.stderr).strip().splitlines()[-1] if (made.stdout + made.stderr).strip() else made.returncode)
    folders = [p for p in (root / "Probant").rglob("*") if p.is_dir() and p.name == "pedal"]
    if not folders:
        print("no matter folder under", root, [str(p) for p in root.rglob("*")][:20])
        return 1
    matter_dir = folders[0]
    (matter_dir / "disclosure.md").write_text(DISCLOSURE)
    listed = subprocess.run([py, "-m", "inferroute_cli", "probant", "list"], env=env, capture_output=True, text=True)
    print("[list]", listed.stdout.strip()[-300:])

    proc = subprocess.Popen([py, "-m", "inferroute_cli", "probant", "open", "devclient/pedal", "--web"], env=env,
                            cwd=str(REPO), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    lines, url = [], [None]

    def reader():
        for line in proc.stdout:
            lines.append(line.rstrip("\n"))
            m = re.search(r"(http://127\.0\.0\.1:\d+/#k=\S+)", line)
            if m:
                url[0] = m.group(1)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + (600 if standin != "container" else 240)
    while url[0] is None and proc.poll() is None and time.time() < deadline:
        time.sleep(0.5)
    if url[0] is None:
        print("the session never offered a page. Output:")
        print("\n".join(lines[-40:]))
        proc.kill()
        return 1
    base, token = url[0].split("/#k=")
    print("[page]", base)

    def api(path, data=None, timeout=60):
        req = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token,
                                                           "Content-Type": "application/json"},
                                     data=None if data is None else json.dumps(data).encode())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    ok = False
    try:
        session = api("/api/session")
        trust = session.get("trust") or {}
        print("[session] search tool:", session.get("search"), "| mode:", session.get("mode"))
        print("[trust]", json.dumps(trust)[:900])
        sent = api("/api/prompt", {"text": "Read the disclosure, run ONE prior-art search for its main idea, "
                                           "then write a three-line summary of what you found into notes.md "
                                           "in the matter folder. Keep it short."})
        print("[prompt]", sent)
        kinds, text, tools, end = {}, [], [], None
        req = urllib.request.Request(base + "/api/events?after=0", headers={"Authorization": "Bearer " + token})
        started = time.time()
        with urllib.request.urlopen(req, timeout=900) as stream:
            idle_since = None
            for raw in stream:
                e = json.loads(raw)
                k = e.get("kind")
                kinds[k] = kinds.get(k, 0) + 1
                if k == "dialog":
                    # The page asks the professional before a search leaves. Say yes, as they would.
                    print("[dialog]", str(e.get("title"))[:80], "|", str(e.get("message") or e.get("text") or "")[:160])
                    print("   ->", api("/api/dialog", {"id": e.get("id"), "confirmed": True, "value": ""}))
                if k in ("tool", "tool_start", "tool_end"):
                    tools.append(json.dumps(e)[:160])
                if k in ("text", "assistant", "delta"):
                    text.append(str(e.get("text") or e.get("delta") or ""))
                if k == "ping":
                    state = api("/api/session")
                    # "Not busy" only means finished once the assistant has been seen to START: an
                    # emulated guest takes a minute to bring Pi up, and the prompt waits in its input
                    # until then with the page quite truthfully reporting an idle agent.
                    if not state.get("busy") and kinds.get("assistant_end"):
                        idle_since = idle_since or time.time()
                        if time.time() - idle_since > 10:
                            break
                    else:
                        idle_since = None
                if k in ("idle", "turn_end", "done") and kinds.get("assistant_end"):
                    state = api("/api/session")
                    if not state.get("busy"):
                        break
                if time.time() - started > 840:
                    print("gave up waiting for the turn to end")
                    break
        print("[events]", kinds)
        for t in tools[:12]:
            print("   ", t)
        print("[answer]", "".join(text)[-700:])
        print("[faults]", json.dumps(api("/api/faults"))[:300])
        before = (matter_dir / "notes.md").exists()
        print("[notes.md on the host before the session ends]", before)
        print("[end]", api("/api/end", {}, timeout=120))
        for _ in range(240):
            if (api("/api/session").get("ended")):
                break
            time.sleep(0.5)
        end = api("/api/session").get("ended")
        print("[ended]", json.dumps(end)[:300])
        note = matter_dir / "notes.md"
        print("[notes.md on the host after]", note.read_text()[:400] if note.exists() else None)
        print("[matter folder]", sorted(p.name for p in matter_dir.iterdir()))
        ok = note.exists() and not before
        try:
            api("/api/close", {})
        except Exception:                                   # noqa: BLE001
            pass
    finally:
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except Exception:                                   # noqa: BLE001
            pass
        try:
            proc.wait(60)
        except subprocess.TimeoutExpired:
            proc.terminate()
        print("--- session output (tail) ---")
        print("\n".join(lines[-30:]))
        print("root kept at", root)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
