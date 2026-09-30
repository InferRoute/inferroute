"""A confidential session that outlives the command that started it.

Everything on the sealed lane so far has been bound to one foreground command: the local endpoint lives
exactly as long as the agent you launched. That is why `ir goose-cowork` cannot be confidential — it
starts the Goose desktop app detached, and the app outlives the command.

So: one detached process holding one verified session, serving the same authenticated local endpoint, with
a state file other commands can find it by.

TWO THINGS THIS MUST NOT BECOME.

  A port that outlives its evidence. The request path re-verifies on arrival, so nothing is ever SEALED to
  stale evidence — but a daemon can sit idle for hours, and while idle it would report itself verified on
  evidence that old. The watchdog here is timer-driven for that reason, and when a session stops being
  confidential the endpoint stops serving (the gate lives in the server, so foreground sessions get it
  too) and this process exits rather than sitting there answering errors for ever.

  A second credential. The token is minted by the serving process and written to a 0600 state file. It is
  never passed on a command line: `xdg-open` already puts one key of ours in the process table, and that
  is one too many.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "inferroute.confidential.daemon/1"
WATCH_EVERY_S = 60          # how often the watchdog asks; the session decides when to re-verify
GRACE_S = 20                # keep answering "stopped, because…" this long, so an agent shows a message
                            # rather than a socket error, then exit


def state_path() -> Path:
    base = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    d = base / "confidential"
    d.mkdir(parents=True, exist_ok=True)
    return d / "daemon.json"


def read_state() -> dict | None:
    try:
        d = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("schema") == SCHEMA else None


def write_state(d: dict) -> None:
    p = state_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=1) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def clear_state() -> None:
    try:
        state_path().unlink()
    except OSError:
        pass


def answers(state: dict, path: str = "/health") -> int | None:
    """Ask the endpoint itself rather than trusting the pid: pids are reused, and a stale file that
    happens to name a live unrelated process would otherwise read as a running session."""
    import urllib.error
    import urllib.request
    url = f"http://127.0.0.1:{state.get('port')}{path}"
    req = urllib.request.Request(url, headers={"authorization": f"Bearer {state.get('token', '')}"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return None


def running() -> dict | None:
    """The state of a daemon that is actually there, or None — clearing a file that answers nothing."""
    st = read_state()
    if st is None:
        return None
    code = answers(st)
    if code is None:
        clear_state()
        return None
    st["serving"] = code == 200
    return st


def log_path() -> Path:
    return state_path().with_name("daemon.log")


async def _watch(session, server, stop_reason: list) -> None:
    """Ask the session, on a timer, whether it may still be used; stop the endpoint when it may not."""
    while not server.should_exit:
        await asyncio.sleep(WATCH_EVERY_S)
        try:
            ok = await session.heartbeat()
        except Exception as e:                      # a heartbeat that cannot run is not a pass
            from inferroute_local.confidential.session import public_reason
            session.receipt.note("heartbeat-failed", public_reason(e))
            ok = session.receipt.is_confidential
        if not ok:
            stop_reason.append(session.receipt.refusal or session.receipt.verdict)
            # The endpoint is already refusing — the gate in the server keys off the same receipt — so
            # this grace is only so an agent mid-request sees a message instead of a closed socket.
            await asyncio.sleep(GRACE_S)
            server.should_exit = True
            return


def serve(model: str | None) -> int:
    """The daemon body. Runs in the FOREGROUND of a detached child, so it is testable without forking."""
    import secrets

    import httpx
    import uvicorn

    from inferroute_local.confidential.server import SEALED_KEEPALIVE_S, create_app
    from . import confidential as C
    from . import launch as launch_mod

    alias = C._resolve_model(model)
    console = C._console()
    session_id = launch_mod._new_session_id()

    async def _run() -> int:
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)) as http:
            session, receipt = await C._open_session(alias, session_id, http, console)
            if not receipt.is_confidential:
                # Never write a state file for a session that did not open: a later `status` would read
                # it as a running confidential session.
                clear_state()
                return 3
            port = C._free_port()
            token = "ir-" + secrets.token_urlsafe(32)
            # Loopback, one client, for the life of one session: uvicorn's 5s idle close buys nothing here
            # and costs a race — the server's FIN can cross the agent's next request on a pooled connection.
            server = uvicorn.Server(uvicorn.Config(create_app(session, token), host="127.0.0.1",
                                                   port=port, log_level="critical",
                                                   timeout_keep_alive=SEALED_KEEPALIVE_S))
            task = asyncio.create_task(server.serve())
            while not server.started:
                await asyncio.sleep(0.05)
            write_state({"schema": SCHEMA, "pid": os.getpid(), "port": port, "token": token,
                         "session_id": session_id, "model": alias.short,
                         "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            stop_reason: list = []
            watch = asyncio.create_task(_watch(session, server, stop_reason))
            try:
                await task
            finally:
                watch.cancel()
                session.close()
                clear_state()
            if stop_reason:
                sys.stderr.write(f"\n  confidential daemon stopped: {stop_reason[0]}\n")
                return 3
            return 0

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        clear_state()
        return 130


def start(model: str | None) -> int:
    """Spawn the daemon detached and wait for it to say it is up.

    The token is NOT passed here — the child mints it and writes the state file, so it never appears in
    an argument list. The parent's job is only to wait for that file and report honestly if it never came.
    """
    st = running()
    if st:
        print(f"\n  A confidential daemon is already running ({st['model']}, session {st['session_id'][:8]}).")
        print("  Stop it first with `ir confidential daemon stop`.\n")
        return 0
    clear_state()
    argv = [sys.executable, "-m", "inferroute_cli", "confidential", "daemon", "serve"]
    if model:
        argv += ["--model", model]
    log = open(log_path(), "ab", buffering=0)
    proc = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                            start_new_session=True, close_fds=True)
    deadline = time.time() + 120        # verification talks to Intel, NVIDIA and the operator
    while time.time() < deadline:
        if proc.poll() is not None:
            print(f"\n  The confidential daemon exited before it was ready (code {proc.returncode}).")
            print(f"  What it said: {log_path()}\n")
            return 1
        st = running()
        if st and st.get("serving"):
            print(f"\n  🔒 Confidential daemon up — {st['model']}, session {st['session_id'][:8]}")
            print(f"     127.0.0.1:{st['port']} · it re-checks the enclave and stops if that lapses")
            print("     `ir confidential daemon status` · `… stop`\n")
            return 0
        time.sleep(0.5)
    print("\n  The confidential daemon did not come up in time.")
    print(f"  What it said: {log_path()}\n")
    return 1


def status() -> int:
    st = running()
    if not st:
        print("\n  No confidential daemon is running.\n")
        return 1
    if not st.get("serving"):
        print(f"\n  ⛔ The daemon is present but no longer serving ({st['model']}).")
        print("     It stopped because the enclave could not be re-checked; it will exit shortly.")
        print(f"     Why, in its own words: {log_path()}\n")
        return 3
    print(f"\n  🔒 Confidential daemon — {st['model']}, session {st['session_id'][:8]}")
    print(f"     up since {st['started_at']} · 127.0.0.1:{st['port']}\n")
    return 0


def stop() -> int:
    st = read_state()
    if not st:
        print("\n  No confidential daemon is running.\n")
        return 1
    try:
        os.kill(int(st["pid"]), signal.SIGTERM)
    except (OSError, ValueError, KeyError):
        pass
    for _ in range(40):
        if running() is None:
            break
        time.sleep(0.1)
    clear_state()
    print("\n  Confidential daemon stopped.\n")
    return 0
