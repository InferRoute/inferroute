"""`ir probant home` — the Probant home page: every matter and its past sessions, a new matter, a new session,
and a plain guide.

It is a small web server on 127.0.0.1 with the same rules as a session's page (probant_web.install_guard):
our own Host only, same origin only, a per-launch key on every /api call, strict page headers, pages that
build text nodes only. It reads what Probant already keeps host-side — the matter records, each session's
record and searches, the marks, the exported records — and writes only three things, each on the
professional's click: a new matter, the disclosure text, an export.

Starting a session runs exactly `ir probant open <matter> --web` as a child process: the same verification,
the same sandbox, its own page and key. The home page shows progress while the sealed machines are checked,
then offers the session's link. Sessions end with the home page's process (PR_SET_PDEATHSIG), because the
child is started from the server's main thread.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Request

from . import probant as S
from .probant_web import STATIC, disclosure_info, install_guard, launch_browser, strip_ansi

SESSION_URL = re.compile(r"(http://127\.0\.0\.1:\d+/#k=[A-Za-z0-9_-]+)")
SESSION_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RECORD_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src 'self'; base-uri 'none'; "
              "form-action 'none'; frame-ancestors 'none'; sandbox")
MAX_DISCLOSURE = 200_000
BOX_LINE = re.compile(r"[│╭╮╰╯─━┃┏┓┗┛]+")


# ───────────────────────── reading what Probant keeps ─────────────────────────

def _json(p: Path) -> Optional[dict]:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _jsonl(p: Path) -> List[dict]:
    out: List[dict] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
    except OSError:
        pass
    return out


def matter_marks(client: str, matter: str) -> Dict[str, str]:
    state = _json(S.state_path(client, matter)) or {}
    return {k: str(((v or {}).get("latest") or {}).get("value") or "")
            for k, v in (state.get("marks") or {}).items()}


def _stamp_of(session_id: str) -> str:
    """20260917T163734Z-… → 2026-09-17T16:37:34Z (the fallback start time)."""
    s = session_id[:16]
    return f"{s[:4]}-{s[4:6]}-{s[6:8]}T{s[9:11]}:{s[11:13]}:{s[13:15]}Z" if len(s) == 16 else ""


def _signed_searches(rows: List[dict]) -> List[dict]:
    return [r for r in rows if (r.get("statement") or {}).get("sig")]


def list_sessions(client: str, matter: str) -> List[Dict[str, Any]]:
    rdir = S.records_dir(client, matter)
    out = []
    for f in (rdir.glob("*.json") if rdir.is_dir() else []):
        sid = f.stem
        if not SESSION_ID_RE.match(sid):
            continue
        rec = _json(f) or {}
        searches = _signed_searches(_jsonl(rdir / f"{sid}.searches.jsonl"))
        keys = {str(h.get("key")) for x in searches for h in ((x.get("result") or {}).get("hits") or [])}
        model = rec.get("model_lane") or {}
        kept = (rdir / f"{sid}.conversation.jsonl").exists()
        out.append({"id": sid, "started_at": _stamp_of(sid), "surface": rec.get("surface") or ("browser" if kept else ""),
                    "searches": len(searches), "documents": len(keys), "ai_verified": bool(model.get("verified")),
                    "boxed": str(rec.get("confinement") or "").startswith("require, address-level"),
                    "conversation": kept})
    out.sort(key=lambda s: s["id"], reverse=True)
    return out


def list_exports(client: str, matter: str) -> List[Dict[str, Any]]:
    root = S.probant_root() / client / "exports"
    pattern = re.compile(rf"^{re.escape(matter)}-prior-art-record-(\d{{8}}T\d{{6}}Z)$")
    out = []
    for d in (root.iterdir() if root.is_dir() else []):
        m = pattern.match(d.name)
        if d.is_dir() and m and (d / "record.html").is_file():
            out.append({"name": d.name, "made_at": _stamp_of(m.group(1) + "-00000000"), "folder": str(d)})
    out.sort(key=lambda e: e["name"], reverse=True)
    return out


def list_matters() -> List[Dict[str, Any]]:
    out = []
    root = S.matters_dir()
    for cdir in (sorted(root.iterdir()) if root.is_dir() else []):
        if not cdir.is_dir():
            continue
        for f in sorted(cdir.glob("*.json")):
            if f.name.endswith(".state.json"):
                continue
            rec = _json(f)
            if not rec or not rec.get("client") or not rec.get("matter"):
                continue
            client, matter = str(rec["client"]), str(rec["matter"])
            sessions = list_sessions(client, matter)
            marks = matter_marks(client, matter)
            ws = Path(str(rec.get("workspace") or ""))
            out.append({"id": f"{client}/{matter}", "client": client, "matter": matter,
                        "date_bound": rec.get("date_bound"), "created_at": rec.get("created_at"),
                        "sessions": len(sessions), "searches": sum(s["searches"] for s in sessions),
                        "marks": len(marks), "last_activity": sessions[0]["started_at"] if sessions else rec.get("created_at"),
                        "disclosure_words": disclosure_info(ws)["disclosure_words"] if ws.is_dir() else 0})
    out.sort(key=lambda m: str(m.get("last_activity") or ""), reverse=True)
    return out


def session_detail(client: str, matter: str, sid: str) -> Optional[Dict[str, Any]]:
    if not SESSION_ID_RE.match(sid):
        return None
    rdir = S.records_dir(client, matter)
    rec = _json(rdir / f"{sid}.json")
    if rec is None:
        return None
    rows = _jsonl(rdir / f"{sid}.searches.jsonl")
    searches = []
    for n, x in enumerate(_signed_searches(rows), 1):
        hits = (x.get("result") or {}).get("hits") or []
        searches.append({"n": n, "at": x.get("at"), "query": x.get("query_text") or "",
                         "date_bound": (x.get("statement") or {}).get("cutoff_date"),
                         "documents": [{"key": str(h.get("key")), "year": h.get("year"), "title": str(h.get("title") or "")}
                                       for h in hits]})
    model = rec.get("model_lane") or {}
    conv_file = rdir / f"{sid}.conversation.jsonl"
    summary = next((s for s in list_sessions(client, matter) if s["id"] == sid), {})
    return {"id": sid, "matter": f"{client}/{matter}", **summary,
            "model": {"verified": bool(model.get("verified")), "checks": model.get("checks"), "name": model.get("model")},
            "unanswered": sum(1 for r in rows if r.get("kind") == "unanswered"),
            "conversation": _jsonl(conv_file) if conv_file.exists() else None,
            "searches": searches, "marks": matter_marks(client, matter)}


# ───────────────────────── starting sessions ─────────────────────────

class Launches:
    """Sessions started from the home page: the child's state, its link once it prints one, and a plain
    reason if it stops before that."""

    def __init__(self, home_url: str = "") -> None:
        self.items: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.home_url = home_url

    def view(self, it: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": it["id"], "matter": it["matter"], "state": it["state"], "url": it["url"],
                "elapsed": int(time.time() - it["started"]), "message": it["message"]}

    def running_for(self, matter_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for it in self.items.values():
                if it["matter"] == matter_id and it["state"] in ("starting", "ready") and it["proc"].poll() is None:
                    return it
        return None

    def start(self, matter_id: str) -> Dict[str, Any]:
        existing = self.running_for(matter_id)
        if existing:
            return existing
        from . import pi_attested
        # The child's page shows a way back here, so a finished session is not a dead end.
        env = dict(os.environ, IR_PROBANT_NO_BROWSER="1", IR_PROBANT_HOME_URL=self.home_url)
        argv = [sys.executable, "-m", "inferroute_cli", "probant", "open", matter_id, "--web"]
        # Started from the event loop's (main) thread: PR_SET_PDEATHSIG fires when the THREAD that started the
        # child exits, so starting it from a worker thread would end the session when that worker is recycled.
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, preexec_fn=pi_attested._die_with_parent)
        it = {"id": secrets.token_hex(6), "matter": matter_id, "started": time.time(), "state": "starting",
              "url": None, "message": "", "tail": deque(maxlen=60), "proc": proc}
        with self.lock:
            self.items[it["id"]] = it
        threading.Thread(target=self._follow, args=(it,), daemon=True).start()
        return it

    def _follow(self, it: Dict[str, Any]) -> None:
        proc = it["proc"]
        for raw in proc.stdout:
            line = BOX_LINE.sub(" ", strip_ansi(raw)).strip()
            if line:
                it["tail"].append(line)
            m = SESSION_URL.search(raw)
            if m and it["state"] == "starting":
                it["url"], it["state"] = m.group(1), "ready"
        proc.wait()
        if it["state"] == "ready":
            it["state"], it["message"] = "ended", "The session has ended."
        else:
            it["state"], it["message"] = "failed", failure_message(list(it["tail"]))


def failure_message(tail: List[str]) -> str:
    text = " ".join(tail)
    low = text.lower()
    if "nested agent session" in low:
        return "This was started from inside another assistant session. Start Probant home from a normal terminal."
    if "not opened" in low or "refused" in low or "could not open the confidential session" in low:
        return "The AI machine could not be verified, so the session was not opened and nothing was sent. Try again in a minute."
    if "cannot reach the carrier" in low or "key was refused" in low:
        return "Couldn't reach InferRoute to open the session. Check the connection (or `ir login`) and try again."
    if "workspace is missing" in low:
        return "This matter's folder is missing, so the session was not opened."
    reasons = [ln for ln in tail if re.search(r"refus|error|could not|cannot|missing|invalid", ln, re.I)]
    return "The session did not start. " + (reasons[-1] if reasons else "See the terminal where Probant home runs.")


# ───────────────────────── the app ─────────────────────────

class Home:
    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.port = 0
        self.launches = Launches()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/#k={self.token}"

    def record_cap(self, matter_id: str, name: str) -> str:
        return hmac.new(self.token.encode(), f"{matter_id}|{name}".encode(), hashlib.sha256).hexdigest()[:32]

    def record_link(self, matter_id: str, name: str) -> str:
        from urllib.parse import urlencode
        return "/record?" + urlencode({"id": matter_id, "name": name, "v": self.record_cap(matter_id, name)})

    def app(self):
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse, Response
        home = self
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        install_guard(app, lambda: home.port, lambda: home.token)

        def static(name: str, media: str):
            async def handler():
                return Response((STATIC / name).read_bytes(), media_type=media)
            return handler

        app.get("/")(static("home.html", "text/html; charset=utf-8"))
        app.get("/home.js")(static("home.js", "text/javascript; charset=utf-8"))
        app.get("/common.js")(static("common.js", "text/javascript; charset=utf-8"))
        app.get("/app.css")(static("app.css", "text/css; charset=utf-8"))

        def problem(msg: str, code: int = 400):
            return JSONResponse({"error": msg}, status_code=code)

        def matter_of(matter_id: str):
            client, matter = S._split_matter(str(matter_id or ""))
            return client, matter, S.load_record(client, matter)

        async def body(request: Request) -> dict:
            try:
                d = await request.json()
            except ValueError:
                return {}
            return d if isinstance(d, dict) else {}

        @app.get("/api/overview")
        async def overview():
            matters = list_matters()
            recent = []
            for m in matters:
                for s in list_sessions(m["client"], m["matter"])[:5]:
                    recent.append({**s, "matter": m["id"]})
            recent.sort(key=lambda s: s["id"], reverse=True)
            running = [home.launches.view(it) for it in home.launches.items.values() if it["state"] in ("starting", "ready")]
            return {"matters": matters, "recent": recent[:12], "running": running}

        @app.post("/api/matters")
        async def create(request: Request):
            d = await body(request)
            date = str(d.get("priority_date") or "").strip()
            if date and not DATE_RE.match(date):
                return problem("the priority date must be a date (YYYY-MM-DD)")
            try:
                client, matter = S.sanitize(str(d.get("client") or ""), "client"), S.sanitize(str(d.get("matter") or ""), "matter")
                import contextlib
                import io
                with contextlib.redirect_stdout(io.StringIO()):
                    S.cmd_new(client, matter, date or None)
            except S.ProbantError as e:
                return problem(str(e))
            text = str(d.get("disclosure") or "")
            if text.strip():
                if len(text) > MAX_DISCLOSURE:
                    return problem("the disclosure is too long for one matter")
                (S.workspace_path(client, matter) / "disclosure.md").write_text(f"# Disclosure\n\n{text.strip()}\n", encoding="utf-8")
            return {"ok": True, "id": f"{client}/{matter}"}

        @app.get("/api/matter")
        async def matter_view(id: str = ""):
            try:
                client, matter, rec = matter_of(id)
            except S.ProbantError as e:
                return problem(str(e), 404)
            mid = f"{client}/{matter}"
            ws = Path(str(rec.get("workspace") or ""))
            exports = [{**e, "view": home.record_link(mid, e["name"])}
                       for e in list_exports(client, matter)]
            running = home.launches.running_for(mid)
            return {"id": mid, "client": client, "matter": matter, "date_bound": rec.get("date_bound"),
                    "pre_filing_default": bool(rec.get("pre_filing_default")), "created_at": rec.get("created_at"),
                    "disclosure": disclosure_info(ws) if ws.is_dir() else {"folder": str(ws), "files": [], "disclosure_words": 0},
                    "sessions": list_sessions(client, matter), "exports": exports, "marks": matter_marks(client, matter),
                    "running": home.launches.view(running) if running else None}

        @app.get("/api/disclosure")
        async def get_disclosure(id: str = ""):
            try:
                client, matter, rec = matter_of(id)
            except S.ProbantError as e:
                return problem(str(e), 404)
            try:
                text = (Path(str(rec["workspace"])) / "disclosure.md").read_text(encoding="utf-8")
            except OSError:
                text = ""
            body_lines = text.splitlines()
            if body_lines and body_lines[0].strip() == "# Disclosure":
                text = "\n".join(body_lines[1:]).strip()
            if "Describe the invention here" in text:
                text = ""
            return {"text": text}

        @app.post("/api/disclosure")
        async def put_disclosure(request: Request):
            d = await body(request)
            try:
                client, matter, rec = matter_of(str(d.get("id") or ""))
            except S.ProbantError as e:
                return problem(str(e), 404)
            text = str(d.get("text") or "")
            if len(text) > MAX_DISCLOSURE:
                return problem("the disclosure is too long for one matter")
            ws = Path(str(rec["workspace"]))
            if not ws.is_dir():
                return problem("this matter's folder is missing", 409)
            (ws / "disclosure.md").write_text(f"# Disclosure\n\n{text.strip()}\n", encoding="utf-8")
            return {"ok": True, "words": disclosure_info(ws)["disclosure_words"]}

        @app.post("/api/sessions")
        async def start_session(request: Request):
            d = await body(request)
            try:
                client, matter, _ = matter_of(str(d.get("id") or ""))
            except S.ProbantError as e:
                return problem(str(e), 404)
            return home.launches.view(home.launches.start(f"{client}/{matter}"))

        @app.get("/api/launch")
        async def launch_view(id: str = ""):
            it = home.launches.items.get(id)
            return home.launches.view(it) if it else problem("no such session start", 404)

        @app.get("/api/session")
        async def session_view(id: str = "", sid: str = ""):
            try:
                client, matter, _ = matter_of(id)
            except S.ProbantError as e:
                return problem(str(e), 404)
            detail = session_detail(client, matter, sid)
            return detail if detail else problem("no such session", 404)

        @app.post("/api/export")
        async def export(request: Request):
            d = await body(request)
            try:
                client, matter, _ = matter_of(str(d.get("id") or ""))
            except S.ProbantError as e:
                return problem(str(e), 404)
            import asyncio
            import contextlib
            import io
            from . import probant_export

            def run() -> Path:
                with contextlib.redirect_stdout(io.StringIO()):
                    return probant_export.write_bundle(client, matter, None)
            try:
                path = await asyncio.to_thread(run)
            except Exception as e:                              # noqa: BLE001
                return problem(f"export failed: {e}", 500)
            mid = f"{client}/{matter}"
            return {"ok": True, "folder": str(path), "view": home.record_link(mid, path.name),
                    "verify_here": f"ir probant verify-export {path}", "verify_anyone": "python3 verify_record.py ."}

        @app.post("/api/check")
        async def check(request: Request):
            """Check one exported record, here, and say what it means. The verifier that runs is the
            bundle's own — the same file a stranger would run — so this is convenience, not a second
            opinion: its exit code is the verdict this answers with."""
            import asyncio
            from . import probant_check
            d = await body(request)
            try:
                client, matter, _ = matter_of(str(d.get("id") or ""))
            except S.ProbantError as e:
                return problem(str(e), 404)
            name = str(d.get("name") or "")
            match = next((e for e in list_exports(client, matter) if e["name"] == name), None)
            if not match:
                return problem("no such record", 404)
            try:
                out = await asyncio.to_thread(probant_check.check, match["folder"])
            except Exception as e:                              # noqa: BLE001
                return problem(f"the check could not be run: {type(e).__name__}", 500)
            out["folder"] = match["folder"]
            return out

        @app.get("/record")
        async def record(id: str = "", name: str = "", v: str = ""):
            # A capability link for ONE exported record (a new tab cannot send the key header). The record is
            # our own escaped HTML; it is still served sandboxed: no scripts, no forms, no navigation of the tab.
            if not hmac.compare_digest(v, home.record_cap(id, name)):
                return Response("this record link is not valid for this home page", status_code=403)
            try:
                client, matter, _ = matter_of(id)
            except S.ProbantError:
                return Response("no such matter", status_code=404)
            match = next((e for e in list_exports(client, matter) if e["name"] == name), None)
            if not match:
                return Response("no such record", status_code=404)
            resp = Response((Path(match["folder"]) / "record.html").read_bytes(), media_type="text/html; charset=utf-8")
            resp.headers["Content-Security-Policy"] = RECORD_CSP
            return resp

        return app


def run(open_browser: bool = True) -> int:
    import socket
    import uvicorn
    home = Home()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        home.port = sock.getsockname()[1]
    url = home.url
    home.launches.home_url = url
    # flush: a terminal shows these at once, but anything reading this output through a pipe would wait for a
    # full buffer, and the link is the one thing it needs.
    print(f"\n  Probant home:  {url}", flush=True)
    print("  The link works on this computer only; don't share it. Keep this terminal open while you work:", flush=True)
    print("  closing it (Ctrl+C) also ends any session started from the page.\n", flush=True)
    if open_browser:
        launch_browser(url)
    # timeout_graceful_shutdown: Ctrl-C and `kill` must end this, not wait on whatever request a
    # browser tab happens to be holding open.
    uvicorn.run(home.app(), host="127.0.0.1", port=home.port, log_level="warning",
                timeout_graceful_shutdown=5)
    return 0
