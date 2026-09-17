"""`ir surveyor open <matter> --web` — the same confined session, shown in a local browser page.

Nothing about the session changes: the AI machine is verified and pinned, the search verifier runs beside
Pi, and Pi runs in the same address-level sandbox. Only the screen differs. Pi runs in RPC mode, and this
bridge — a small web server on 127.0.0.1, in the launcher's process, OUTSIDE the sandbox — relays between
Pi's stdin/stdout and one browser tab.

What the bridge guarantees, and the tests pin:

- It listens on 127.0.0.1 only, and answers only requests whose Host is that address and port (a page on
  another site cannot reach it by rebinding a name to 127.0.0.1).
- Every /api call carries a per-launch secret. The page receives it in the URL fragment, which a browser
  never sends to any server, and removes it from the address bar at once.
- It forwards a FIXED set of commands to Pi: prompt, abort, and answers to dialogs Pi actually opened. The
  RPC protocol also carries direct shell execution, model and session switching; none are reachable.
- The page's policy (Content-Security-Policy) forbids loading anything from anywhere but this server, and
  the page's code builds text nodes only: nothing the assistant writes becomes a link, an image or markup.
  The agent's sandbox has no route to the internet; the browser does, so the page must not give it one.
- Marks are made here, by the person clicking, and go straight to the host-side search verifier. The agent
  has no route to this bridge (its sandbox has no network) and cannot make or change a mark.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# At module level, not inside app(): with postponed annotations FastAPI resolves `request: Request` by name
# in this module's globals. Imported locally, the name does not resolve, and every POST answers 422.
from fastapi import Request

STATIC = Path(__file__).resolve().parent / "surveyor_web"
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PUB_RE = re.compile(r"^[A-Z]{2}[-A-Z0-9]{2,}$")
MARKS = ("relevant", "not-relevant", "known")
HISTORY_CAP = 5000

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def install_guard(app: Any, port: Callable[[], int], token: Callable[[], str]) -> None:
    """The rules every local Surveyor page lives by, installed once per app so the session page and the home
    page cannot drift: answer only our own Host (a name rebound to 127.0.0.1 still sends its own Host), refuse
    another origin, require the per-launch key on every /api call, and send the strict page headers."""
    from fastapi.responses import JSONResponse, Response

    @app.middleware("http")
    async def guard(request: Request, call_next):
        p = port()
        host = request.headers.get("host", "")
        if host not in (f"127.0.0.1:{p}", f"localhost:{p}"):
            return Response("wrong host", status_code=421)
        origin = request.headers.get("origin")
        if origin is not None and origin not in (f"http://127.0.0.1:{p}", f"http://localhost:{p}"):
            return Response("cross-origin request refused", status_code=403)
        if request.url.path.startswith("/api/"):
            given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            if not given or not hmac.compare_digest(given, token()):
                return JSONResponse({"error": "this link has no session key; open the link printed in your terminal"}, status_code=401)
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp


def strip_ansi(text: Any) -> str:
    return ANSI.sub("", str(text or ""))


def normalize(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pi RPC event → the page's small event vocabulary. Unknown events are dropped, not passed through."""
    t = ev.get("type")
    if t == "agent_start":
        return [{"kind": "busy", "value": True}]
    if t == "agent_settled":
        return [{"kind": "busy", "value": False}]
    if t == "message_start" and (ev.get("message") or {}).get("role") == "assistant":
        return [{"kind": "assistant_start"}]
    if t == "message_update":
        d = ev.get("assistantMessageEvent") or {}
        if d.get("type") == "text_delta":
            return [{"kind": "assistant_delta", "text": str(d.get("delta", ""))}]
        return []
    if t == "message_end":
        msg = ev.get("message") or {}
        if msg.get("role") != "assistant":
            return []
        text = "".join(str(c.get("text", "")) for c in msg.get("content") or [] if isinstance(c, dict) and c.get("type") == "text")
        out: Dict[str, Any] = {"kind": "assistant_end", "text": text}
        if msg.get("stopReason") in ("error", "aborted"):
            out["stopped"] = msg.get("stopReason")
            if msg.get("errorMessage"):
                out["error"] = strip_ansi(msg.get("errorMessage"))
        return [out]
    if t == "tool_execution_start":
        return [{"kind": "tool_start", "call": ev.get("toolCallId"), "tool": ev.get("toolName"), "args": ev.get("args") or {}}]
    if t == "tool_execution_end":
        res = ev.get("result") or {}
        text = "".join(str(c.get("text", "")) for c in res.get("content") or [] if isinstance(c, dict) and c.get("type") == "text")
        details = res.get("details") if isinstance(res.get("details"), dict) else None
        return [{"kind": "tool_end", "call": ev.get("toolCallId"), "tool": ev.get("toolName"),
                 "ok": not ev.get("isError"), "text": text[:4000], "details": details}]
    if t == "extension_ui_request":
        m = ev.get("method")
        if m in ("confirm", "select", "input", "editor"):
            return [{"kind": "dialog", "id": ev.get("id"), "method": m, "title": strip_ansi(ev.get("title")),
                     "message": strip_ansi(ev.get("message")), "options": ev.get("options") or []}]
        if m == "notify":
            return [{"kind": "notify", "level": ev.get("notifyType") or "info", "message": strip_ansi(ev.get("message"))}]
        if m == "setStatus":
            return [{"kind": "status", "key": ev.get("statusKey"), "text": strip_ansi(ev.get("statusText")) if ev.get("statusText") else ""}]
        return []
    if t == "extension_error":
        return [{"kind": "notify", "level": "error", "message": f"extension error: {strip_ansi(ev.get('error'))}"}]
    if t == "auto_retry_start":
        return [{"kind": "notify", "level": "warning", "message": "The AI machine didn't answer; retrying…"}]
    if t == "response" and ev.get("success") is False:
        return [{"kind": "notify", "level": "error", "message": strip_ansi(ev.get("error") or "the request was refused")}]
    return []


def _search_call(endpoint: Optional[str], path: str, body: Optional[dict] = None, timeout: float = 60.0) -> dict:
    import urllib.request
    if not endpoint:
        return {"ok": False, "refusal": "no search in this session"}
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"{endpoint}{path}", data=data, method="GET" if body is None else "POST",
                                 headers={} if body is None else {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:                      # loopback only
        return json.loads(r.read())


def disclosure_info(workspace: Path) -> Dict[str, Any]:
    """File names, sizes and the disclosure's word count: enough for the page to say what the folder holds,
    without sending any of the invention's text to the page."""
    files = []
    try:
        for p in sorted(workspace.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                files.append({"name": p.name, "bytes": p.stat().st_size})
    except OSError:
        pass
    words = 0
    d = workspace / "disclosure.md"
    try:
        body = [ln for ln in d.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]
        template = "Describe the invention here"
        words = 0 if any(template in ln for ln in body) else sum(len(ln.split()) for ln in body)
    except OSError:
        pass
    return {"folder": str(workspace), "files": files, "disclosure_words": words}


class Bridge:
    def __init__(self, *, matter: str, date_bound: str, workspace: Path, summary: Dict[str, Any],
                 search_endpoint: Optional[str], receipt: Callable[[], Any],
                 rebuild_summary: Callable[[], Dict[str, Any]], export: Callable[[], Path],
                 conversation_file: Optional[Path] = None):
        self.matter, self.date_bound, self.workspace = matter, date_bound, workspace
        self.summary = summary
        self.search_endpoint = search_endpoint
        self._receipt, self._rebuild, self._export = receipt, rebuild_summary, export
        self.token = secrets.token_urlsafe(32)
        self.port = 0
        self.history: List[Dict[str, Any]] = []
        self.subscribers: List[asyncio.Queue] = []
        self.dialogs: Dict[str, Dict[str, Any]] = {}
        self.busy = False
        self.ended: Optional[Dict[str, Any]] = None
        self.proc: Any = None
        self._seq = 0
        self.closed = asyncio.Event()
        # The conversation, kept with the matter's records (under confidential/, outside the agent's reach,
        # owner-only) so the home page can show it later. Announced on the page; None keeps nothing.
        self.conversation_file = conversation_file

    # ── events ──
    def publish(self, event: Dict[str, Any]) -> None:
        self._seq += 1
        event = {"seq": self._seq, **event}
        if event["kind"] == "busy":
            self.busy = bool(event["value"])
        if event["kind"] == "dialog":
            self.dialogs[str(event["id"])] = event
        self.history.append(event)
        self._keep(event)
        if len(self.history) > HISTORY_CAP:
            del self.history[: len(self.history) - HISTORY_CAP]
        for q in list(self.subscribers):
            q.put_nowait(event)

    def _keep(self, event: Dict[str, Any]) -> None:
        """What the home page needs to show a past conversation: the professional's messages, the assistant's
        answers, each search in one line, reading the marks, the approval. Not streaming deltas, statuses or
        documents (those are in the search records already)."""
        if self.conversation_file is None:
            return
        kind, at = event.get("kind"), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        row: Optional[Dict[str, Any]] = None
        if kind == "user":
            row = {"kind": "user", "text": event.get("text", "")}
        elif kind == "assistant_end" and (event.get("text") or "").strip():
            row = {"kind": "assistant", "text": event.get("text", "")}
        elif kind == "tool_end" and event.get("tool") == "prior_art_search":
            d = event.get("details") or {}
            row = {"kind": "search", "ok": bool(event.get("ok") and d.get("ok")), "search_no": d.get("searchNo"),
                   "feature": d.get("feature"), "like": d.get("like"), "k": d.get("k"), "documents": len(d.get("docs") or []),
                   "refusal": "" if event.get("ok") else str(event.get("text") or "")[:300]}
        elif kind == "tool_end" and event.get("tool") == "matter_marks":
            row = {"kind": "marks_read"}
        elif kind == "dialog_closed":
            row = {"kind": "approval", "answer": event.get("answer")}
        if row is None:
            return
        try:
            fd = os.open(self.conversation_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": at, **row}, ensure_ascii=False) + "\n")
        except OSError:
            pass

    async def send(self, obj: Dict[str, Any]) -> None:
        if self.proc is None or self.proc.stdin is None or self.proc.stdin.is_closing():
            raise RuntimeError("the session has ended")
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        await self.proc.stdin.drain()

    async def pump(self, proc: Any) -> int:
        """Read Pi's stdout (strict JSONL: split on LF only) until it exits; return its exit code."""
        self.proc = proc
        buf = b""
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.rstrip(b"\r")
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                for out in normalize(ev):
                    self.publish(out)
        rc = await proc.wait()
        self.busy = False
        self.ended = self.session_end()
        self.publish({"kind": "ended", "summary": self.ended})
        return rc

    def session_end(self) -> Dict[str, Any]:
        r = self._receipt()
        c = dict(getattr(r, "counters", None) or {})
        return {"requests": c.get("requests", 0), "sealed_bytes": c.get("plaintext_bytes_sealed_here", 0),
                "opened_bytes": c.get("response_bytes_opened_here", 0), "plaintext_left": 0,
                "export_command": f"ir surveyor export {self.matter}"}

    # ── the app ──
    def app(self):
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse, Response, StreamingResponse

        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        bridge = self

        install_guard(app, lambda: bridge.port, lambda: bridge.token)

        def static(name: str, media: str):
            async def handler():
                return Response((STATIC / name).read_bytes(), media_type=media)
            return handler

        app.get("/")(static("index.html", "text/html; charset=utf-8"))
        app.get("/common.js")(static("common.js", "text/javascript; charset=utf-8"))
        app.get("/app.js")(static("app.js", "text/javascript; charset=utf-8"))
        app.get("/app.css")(static("app.css", "text/css; charset=utf-8"))

        @app.get("/api/session")
        async def session():
            return {"matter": bridge.matter, "date_bound": bridge.date_bound, "trust": bridge.summary,
                    "disclosure": disclosure_info(bridge.workspace), "busy": bridge.busy, "ended": bridge.ended,
                    "search": bool(bridge.search_endpoint)}

        @app.get("/api/events")
        async def events(request: Request, after: int = 0):
            q: asyncio.Queue = asyncio.Queue()
            backlog = [e for e in bridge.history if e["seq"] > after]
            bridge.subscribers.append(q)

            async def stream():
                try:
                    for e in backlog:
                        yield json.dumps(e) + "\n"
                    last = backlog[-1]["seq"] if backlog else after
                    while True:
                        if await request.is_disconnected():
                            break
                        try:
                            e = await asyncio.wait_for(q.get(), timeout=15)
                        except asyncio.TimeoutError:
                            yield json.dumps({"kind": "ping"}) + "\n"
                            continue
                        if e["seq"] <= last:
                            continue
                        last = e["seq"]
                        yield json.dumps(e) + "\n"
                finally:
                    if q in bridge.subscribers:
                        bridge.subscribers.remove(q)
            return StreamingResponse(stream(), media_type="application/x-ndjson")

        async def body(request: Request) -> dict:
            try:
                data = await request.json()
            except ValueError:
                return {}
            return data if isinstance(data, dict) else {}

        @app.post("/api/prompt")
        async def prompt(request: Request):
            data = await body(request)
            text = str(data.get("text") or "").strip()
            if not text:
                return JSONResponse({"error": "empty message"}, status_code=400)
            if len(text) > 20000:
                return JSONResponse({"error": "message too long"}, status_code=400)
            cmd: Dict[str, Any] = {"type": "prompt", "message": text}
            if bridge.busy:
                cmd["streamingBehavior"] = "followUp"
            try:
                await bridge.send(cmd)
            except RuntimeError as e:
                return JSONResponse({"error": str(e)}, status_code=409)
            bridge.publish({"kind": "user", "text": text})
            return {"ok": True}

        @app.post("/api/abort")
        async def abort():
            try:
                await bridge.send({"type": "abort"})
            except RuntimeError as e:
                return JSONResponse({"error": str(e)}, status_code=409)
            return {"ok": True}

        @app.post("/api/dialog")
        async def dialog(request: Request):
            data = await body(request)
            did = str(data.get("id") or "")
            pending = bridge.dialogs.pop(did, None)
            if pending is None:
                return JSONResponse({"error": "no such dialog"}, status_code=404)
            answer: Dict[str, Any] = {"type": "extension_ui_response", "id": did}
            if data.get("cancelled"):
                answer["cancelled"] = True
            elif pending["method"] == "confirm":
                answer["confirmed"] = data.get("confirmed") is True
            else:
                answer["value"] = str(data.get("value") or "")
            try:
                await bridge.send(answer)
            except RuntimeError as e:
                return JSONResponse({"error": str(e)}, status_code=409)
            bridge.publish({"kind": "dialog_closed", "id": did,
                            "answer": "allowed" if answer.get("confirmed") else "declined" if pending["method"] == "confirm" else "answered"})
            return {"ok": True}

        @app.get("/api/marks")
        async def marks():
            try:
                state = await asyncio.to_thread(_search_call, bridge.search_endpoint, "/matter/state")
            except Exception:                                   # noqa: BLE001
                return {"marks": {}}
            return {"marks": {k: (v.get("latest") or {}).get("value") for k, v in (state.get("marks") or {}).items()}}

        @app.post("/api/mark")
        async def mark(request: Request):
            data = await body(request)
            key, value = str(data.get("key") or "").strip().upper(), str(data.get("mark") or "")
            if not PUB_RE.match(key) or value not in MARKS:
                return JSONResponse({"error": "not a publication number or mark"}, status_code=400)
            try:
                await asyncio.to_thread(_search_call, bridge.search_endpoint, "/matter/mark", {"key": key, "mark": value})
            except Exception:                                   # noqa: BLE001
                return JSONResponse({"error": "the search verifier did not record the mark"}, status_code=502)
            return {"ok": True, "key": key, "mark": value}

        @app.post("/api/recheck")
        async def recheck():
            bridge.summary = await asyncio.to_thread(bridge._rebuild)
            bridge.publish({"kind": "trust", "trust": bridge.summary})
            return {"trust": bridge.summary}

        @app.post("/api/export")
        async def export():
            try:
                path = await asyncio.to_thread(bridge._export)
            except Exception as e:                              # noqa: BLE001
                return JSONResponse({"error": f"export failed: {e}"}, status_code=500)
            return {"ok": True, "path": str(path), "verify_here": f"ir surveyor verify-export {path}",
                    "verify_anyone": "python3 verify_record.py ."}

        @app.post("/api/close")
        async def close_page():
            bridge.closed.set()
            return {"ok": True}

        @app.post("/api/end")
        async def end():
            if bridge.proc is not None and bridge.proc.returncode is None:
                try:
                    bridge.proc.stdin.close()
                except Exception:                               # noqa: BLE001
                    pass
            return {"ok": True}

        return app


class Page:
    """The running page: its bridge and web server. `linger` keeps it up after the agent exits, so the
    record can still be exported from the page, until the person closes it or the time runs out."""

    def __init__(self, bridge: Bridge, server: Any, task: "asyncio.Task") -> None:
        self.bridge, self.server, self.task = bridge, server, task

    async def linger(self, console: Any, seconds: float | None = None) -> None:
        import select
        import sys
        seconds = float(os.environ.get("IR_SURVEYOR_WEB_LINGER", "1800")) if seconds is None else seconds
        mins = max(1, int(seconds // 60))
        console.print(f"[grey58]The page stays open so you can export the record. Press Enter here to close it "
                      f"(it closes by itself after {mins} minute{'s' if mins != 1 else ''}).[/]")
        loop = asyncio.get_running_loop()

        def _stdin() -> None:
            if not sys.stdin.isatty():
                return
            r, _, _ = select.select([sys.stdin], [], [], seconds)
            if r:
                sys.stdin.readline()
        waiters = [asyncio.ensure_future(self.bridge.closed.wait()), asyncio.ensure_future(asyncio.sleep(seconds))]
        if sys.stdin.isatty():
            waiters.append(asyncio.ensure_future(loop.run_in_executor(None, _stdin)))
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        for w in waiters:
            w.cancel()
        self.server.should_exit = True
        await self.task


async def start(*, surveyor: Dict[str, Any], session: Any, search_endpoint: Optional[str], workspace: Path,
                console: Any) -> Page:
    """Start the bridge's web server and open the page. The agent is started by the launcher right after,
    with its stdin/stdout handed to `page.bridge.pump`."""
    import socket
    import uvicorn
    from . import pi_attested, surveyor_export, surveyor_trust
    from .surveyor import _split_matter
    matter = surveyor.get("matter", "")
    client, name = _split_matter(matter)

    def rebuild() -> Dict[str, Any]:
        found = pi_attested.search_verification(search_endpoint)
        return surveyor_trust.build(session.receipt, found, pi_attested.confinement_label(), matter=matter,
                                    date_bound=surveyor.get("date_bound", ""), surface="browser")

    from .surveyor import records_dir
    kept = (records_dir(client, name) / f"{pi_attested.LAST_SESSION_ID}.conversation.jsonl"
            if search_endpoint and pi_attested.LAST_SESSION_ID else None)
    bridge = Bridge(matter=matter, date_bound=surveyor.get("date_bound", ""), workspace=workspace,
                    summary=surveyor.get("summary") or {}, search_endpoint=search_endpoint,
                    receipt=lambda: session.receipt, rebuild_summary=rebuild,
                    export=lambda: surveyor_export.write_bundle(client, name, None), conversation_file=kept)
    if kept is not None:
        bridge.publish({"kind": "conversation_kept"})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        bridge.port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(bridge.app(), host="127.0.0.1", port=bridge.port, log_level="critical"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.05)
    url = open_url(bridge)
    opened = launch_browser(url)
    console.print(f"\n[bold]Open this session in your browser:[/]  {url}")
    console.print("[grey58]" + ("Opened it for you. " if opened else "") +
                  "The link works on this computer only and belongs to this session alone; don't share it.[/]\n")
    return Page(bridge, server, task)


def open_url(bridge: Bridge) -> str:
    return f"http://127.0.0.1:{bridge.port}/#k={bridge.token}"


def launch_browser(url: str) -> bool:
    if os.environ.get("IR_SURVEYOR_NO_BROWSER") == "1":
        return False
    import webbrowser
    try:
        return webbrowser.open(url, new=2)
    except Exception:                                           # noqa: BLE001
        return False
