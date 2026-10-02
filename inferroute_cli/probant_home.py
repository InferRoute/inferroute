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
import datetime as dt
import asyncio
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
from .probant_web import ENDED_MARK, STATIC, PageFiles, disclosure_info, install_guard, launch_browser, strip_ansi

# ── when the search machine is meant to be up ──────────────────────────────────────────────────────────
# The search enclave is a sealed machine that costs money to keep running, so it is scheduled rather than
# permanent: 13:00-15:00 Europe/Paris, every day. That is the ONE place the window is written; the page is
# told the opening and closing instants and never re-derives them, so a page and a server cannot come to
# different views of when search is open (and the page never has to get Paris's daylight saving right).
SEARCH_WINDOW_TZ = "Europe/Paris"
SEARCH_WINDOW = (13, 15)          # [open, close) in that timezone, daily — used ONLY in scheduled mode

# WHICH OF THE TWO THIS INSTALLATION IS, and it is not a detail: on 2026-10-01 the search enclave was
# deployed to run continuously, and this file still said 13:00-15:00 — so the home page would have told a
# client "closed until 13:00" about a machine that was up. A timetable for a machine that does not keep one
# is the failure where a confident answer is worse than none, because nobody questions a timetable.
#
# `always`    — the machine runs continuously; the page says nothing about openings at all.
# `scheduled` — the machine opens for a window each day, and the page says when.
#
# Read from the host config (search.json) so it is set per installation rather than compiled in, and so a
# future backend-served value has one place to land. ABSENT MEANS ALWAYS: a schedule is the special case,
# and claiming one that does not exist is the error this constant was changed to prevent.
def search_availability(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """{"mode": "always"} or {"mode": "scheduled", "from_hour", "to_hour", "tz"}."""
    conf = (cfg or {}).get("availability")
    if isinstance(conf, dict) and str(conf.get("mode")) == "scheduled":
        w = conf.get("window") or SEARCH_WINDOW
        try:
            frm, to = int(w[0]), int(w[1])
        except (TypeError, ValueError, IndexError):
            frm, to = SEARCH_WINDOW
        return {"mode": "scheduled", "from_hour": frm, "to_hour": to,
                "tz": str(conf.get("tz") or SEARCH_WINDOW_TZ)}
    return {"mode": "always"}
SEARCH_PROBE_TIMEOUT = 2.5        # a page must not hang on a machine that is deliberately switched off
SEARCH_PROBE_TTL = 30.0           # seconds a probe result stands for, so refreshing does not hammer it
_search_probe: Dict[str, Any] = {"at": 0.0, "state": "unreachable"}
_search_probe_lock = threading.Lock()


def _search_window(now: Optional[dt.datetime] = None, avail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The current or next opening, as instants. Returns UTC ISO stamps: the page formats them in whatever
    timezone the reader is actually in, which is the only way a window named in Paris time is safe to show
    to someone who is not in Paris."""
    from zoneinfo import ZoneInfo
    a = avail or {"mode": "always"}
    # ALWAYS-ON HAS NO WINDOW TO DESCRIBE. open_now is true and there are no instants, so the page has
    # nothing to format and says nothing — rather than being handed a timetable it is asked not to show.
    if a.get("mode") != "scheduled":
        return {"mode": "always", "open_now": True}
    tz = ZoneInfo(a.get("tz") or SEARCH_WINDOW_TZ)
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(tz)
    opens = now.replace(hour=int(a["from_hour"]), minute=0, second=0, microsecond=0)
    closes = now.replace(hour=int(a["to_hour"]), minute=0, second=0, microsecond=0)
    if now >= closes:                                   # today's window is over; the next one is tomorrow
        opens, closes = opens + dt.timedelta(days=1), closes + dt.timedelta(days=1)
    open_now = opens <= now < closes
    iso = lambda d: d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"mode": "scheduled", "open_now": open_now, "opens_at": iso(opens), "closes_at": iso(closes),
            "tz": a.get("tz") or SEARCH_WINDOW_TZ, "from_hour": int(a["from_hour"]), "to_hour": int(a["to_hour"])}


def _search_probe_state(enclave: str) -> str:
    """"up", "unreachable", or "unknown-host".

    This is LIVENESS ONLY and deliberately not a verification: /offer is the first step of the attested
    handshake, and an answer to it says a server is listening, not that it is the sealed machine running
    the software we expect. That verdict is reached per session, against the signed reference, before any
    text is sent. The page must not blur the two.

    The third state is the one that matters. A scheduled machine that is switched off REFUSES the
    connection: its name still resolves, and "closed until 13:00" is then a true account of it. A machine
    that has been taken away does not resolve at all — and on 24 Sep that is exactly what the configured
    address did, the container having been deleted rather than stopped. Collapsing the two would have the
    page promise an opening time for a machine that is not coming back, which is the failure where a
    reassuring answer is worse than none: nobody investigates a timetable."""
    import socket
    import urllib.error
    import urllib.request
    with _search_probe_lock:
        if (time.monotonic() - _search_probe["at"]) < SEARCH_PROBE_TTL:
            return str(_search_probe["state"])
    try:
        with urllib.request.urlopen(enclave.rstrip("/") + "/offer", timeout=SEARCH_PROBE_TIMEOUT) as fh:
            state = "up" if fh.status == 200 else "unreachable"
    except urllib.error.HTTPError:
        state = "unreachable"          # it answered, just not with an offer: something IS listening
    except (urllib.error.URLError, OSError, ValueError) as e:
        cause = getattr(e, "reason", e)
        state = "unknown-host" if isinstance(cause, socket.gaierror) else "unreachable"
    with _search_probe_lock:
        _search_probe.update({"at": time.monotonic(), "state": state})
    return state


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


def _sealed_once(prompt: str, *, timeout: float = 240.0) -> str:
    """One sealed request for a drafting pass, over the SAME lane a session uses.

    A context file is the client's material, so it must not travel any other way than their searches do:
    the enclave is verified against the signed reference and the text sealed to it, exactly as in a matter
    session. This borrows the confidential DAEMON — a detached process holding one verified session and
    serving an authenticated local endpoint — rather than opening a session of its own, because a draft is
    one short request and attestation is the expensive part.

    If no daemon is running, that is what the caller is told, in those words: silently falling back to an
    unsealed path would be the one failure this product cannot have.
    """
    import urllib.error
    import urllib.request
    from . import confidential_daemon as D

    st = D.read_state() or {}
    base, token = str(st.get("endpoint") or ""), str(st.get("token") or "")
    if not base or not token:
        raise RuntimeError("the sealed lane is not running on this computer. Start it with "
                           "`ir confidential daemon start`, then try again — nothing is sent any other way.")
    body = json.dumps({"model": st.get("model") or "", "max_tokens": 1200,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(f"{base.rstrip('/')}/v1/chat/completions", data=body, method="POST",
                                 headers={"authorization": f"Bearer {token}",
                                          "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            d = json.loads(fh.read().decode())
    except urllib.error.URLError as e:
        raise RuntimeError(f"the sealed endpoint did not answer ({e})") from None
    text = ((d.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    if not str(text).strip():
        raise RuntimeError("the sealed machine returned nothing")
    return str(text).strip()


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

    def stop_running(self, matter_id: str) -> bool:
        """End a session this page started, from this page. Returns whether one was ended.

        Without this a running session could only be ended from its own tab, so a session whose page is
        unreachable — a closed tab, a crashed browser, a link to 127.0.0.1 opened from another machine —
        made its matter permanently undeletable, and the refusal named a remedy the person could not reach.
        A refusal has to name something the reader can actually do.
        """
        with self.lock:
            live = [it for it in self.items.values()
                    if it["matter"] == matter_id and it["proc"].poll() is None]
        for it in live:
            it["proc"].terminate()
            try:
                it["proc"].wait(timeout=10)
            except subprocess.TimeoutExpired:
                it["proc"].kill()
            it["state"] = "ended"
        return bool(live)

    def stop_ended(self, matter_id: str) -> None:
        """End the lingering process of a FINISHED session on this matter (its page stays up for exporting).
        Deleting the matter is the person saying they are done with it."""
        with self.lock:
            done = [it for it in self.items.values() if it["matter"] == matter_id and it["proc"].poll() is None
                    and it["state"] in ("ended", "failed")]
        for it in done:
            it["proc"].terminate()
            try:
                it["proc"].wait(timeout=10)
            except subprocess.TimeoutExpired:
                it["proc"].kill()

    def start(self, matter_id: str, *, intake_dir: str = "") -> Dict[str, Any]:
        """A session on a matter, or — with `intake_dir` — a session that reads one staged document and
        proposes matters from it. Both are the same child, the same page and the same sealed lane; only
        the command differs, so a reading session cannot drift into a second kind of session."""
        existing = self.running_for(matter_id)
        if existing:
            return existing
        from . import pi_attested
        # The child's page shows a way back here, so a finished session is not a dead end.
        env = dict(os.environ, IR_PROBANT_NO_BROWSER="1", IR_PROBANT_HOME_URL=self.home_url)
        argv = ([sys.executable, "-m", "inferroute_cli", "probant", "intake", intake_dir, "--web"] if intake_dir
                else [sys.executable, "-m", "inferroute_cli", "probant", "open", matter_id, "--web"])
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
            # The session is OVER although its process lives on for a while, keeping the page up for exporting.
            # Counting it as running offered "Open the session" onto a closed session — and made "Start a session"
            # on that matter return the ended one until the window closed (19 Sep).
            if ENDED_MARK in line and it["state"] == "ready":
                it["state"], it["message"] = "ended", "The session has ended."
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
    if ("not found on path" in low or "is not installed on this computer" in low) and "pi" in low:
        # A page started as a service or from a desktop shortcut has a PATH a terminal does not, and every
        # start failed in a second (19-20 Sep). The launcher now looks where these programs install, so
        # reaching this means it really is absent — and the answer is an install, never "use a terminal".
        return ("The assistant program (Pi) is not installed on this computer, so no session can start. "
                "Install it with: npm install -g @earendil-works/pi-coding-agent — then try again. "
                "Nothing was sent.")
    reasons = [ln for ln in tail if re.search(r"refus|error|could not|cannot|missing|invalid|not found", ln, re.I)]
    if reasons:
        return reasons[-1]
    # No recognisable reason: show what it DID say. "See the terminal where Probant home runs" pointed at a
    # terminal that often does not exist (a service, a shortcut) — a message that sends you nowhere.
    last = [ln for ln in tail if not ln.lower().startswith(("opening ", "traceback"))][-2:]
    return ("It stopped with: " + " / ".join(last)) if last else "It stopped before printing anything. Nothing was sent."


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

        files = PageFiles(("home.html", "home.js", "common.js", "app.css"))
        static = files.handler

        app.get("/")(static("home.html", "text/html; charset=utf-8"))
        app.get("/home.js")(static("home.js", "text/javascript; charset=utf-8"))
        app.get("/common.js")(static("common.js", "text/javascript; charset=utf-8"))
        app.get("/app.css")(static("app.css", "text/css; charset=utf-8"))

        def problem(msg: str, code: int = 400, extra: Optional[Dict[str, Any]] = None):
            return JSONResponse({"error": msg, **(extra or {})}, status_code=code)

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
            return {"matters": matters, "recent": recent[:12], "running": running, "update_waiting": files.stale()}

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

        @app.post("/api/sessions/end")
        async def end_session(request: Request):
            """End a running session this page started. The remedy the delete refusal names.

            Deliberate, never automatic: a session holds the person's work, so deleting a matter does not
            quietly kill one. This is the button they press having been told why.
            """
            d = await body(request)
            mid = str(d.get("id") or "")
            try:
                matter_of(mid)
            except S.ProbantError as e:
                return problem(str(e), 404)
            ended = home.launches.stop_running(mid)
            return {"ok": True, "ended": ended}

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

        # ── deleting a matter: restorable for probant_delete.RETENTION_DAYS, then erased ──
        @app.post("/api/matter/delete")
        async def delete_matter(request: Request):
            """The page must send the matter's name typed by the person, not only its id: one misplaced click
            on the wrong matter must not be enough."""
            from . import probant_delete as D
            d = await body(request)
            mid = str(d.get("id") or "")
            try:
                client, matter, _ = matter_of(mid)
            except S.ProbantError as e:
                return problem(str(e), 404)
            if str(d.get("confirm") or "").strip() != matter:
                return problem("type the matter's name exactly to delete it", 400)
            # The refusal NAMES WHAT TO DO and the page can do it — see /api/sessions/end. It used to say
            # "End it first" about a session whose only control was inside its own tab, which is no remedy
            # at all when that tab is gone or the link points at a loopback port on another machine.
            live = home.launches.running_for(mid)
            if live:
                return problem("a session is still open on this matter. End it from here, or close its page, "
                               "then delete.", 409, extra={"running_session": live.get("id"), "can_end": True})
            home.launches.stop_ended(mid)          # a finished session whose page is still up
            try:
                out = D.delete(client, matter)
            except S.ProbantError as e:
                return problem(str(e), 409)
            return {"ok": True, "id": out["id"], "left_in_place": out["left_in_place"], "days": D.RETENTION_DAYS}

        @app.get("/api/deleted")
        async def deleted():
            from . import probant_delete as D
            return {"deleted": D.list_deleted(), "days": D.RETENTION_DAYS}

        @app.post("/api/deleted/restore")
        async def restore_deleted(request: Request):
            from . import probant_delete as D
            d = await body(request)
            try:
                return {"ok": True, "id": D.restore(str(d.get("id") or ""))}
            except S.ProbantError as e:
                return problem(str(e), 409)

        @app.post("/api/deleted/erase")
        async def erase_deleted(request: Request):
            from . import probant_delete as D
            d = await body(request)
            try:
                D.erase(str(d.get("id") or ""))
            except S.ProbantError as e:
                return problem(str(e), 404)
            return {"ok": True}

        # ── reading a document: staged here, read by a sealed session, proposals created by the professional ──
        @app.post("/api/intake")
        async def intake(request: Request):
            """Stage a document the person gave the page, and start a session that reads it."""
            import asyncio
            from . import probant_intake as I
            d = await body(request)
            try:
                meta = await asyncio.to_thread(I.stage, str(d.get("text") or ""), str(d.get("name") or ""))
            except S.ProbantError as e:
                return problem(str(e), 400)
            it = home.launches.start(f"document · {meta['source_name']}", intake_dir=str(I.path_of(meta["id"])))
            return {"ok": True, "id": meta["id"], "chars": meta["chars"], "launch": home.launches.view(it)}

        @app.get("/api/intake")
        async def intake_view(id: str = ""):
            from . import probant_intake as I
            try:
                meta = I.meta_of(id)
                proposals = I.read_proposals(id)
            except S.ProbantError as e:
                return problem(str(e), 404)
            running = home.launches.running_for(f"document · {meta['source_name']}")
            return {"meta": meta, "proposals": proposals, "dropped": I.dropped_count(id),
                    "running": home.launches.view(running) if running else None}

        @app.get("/api/intakes")
        async def intakes():
            """Documents read on this computer, newest first — so a reading is not lost when the page moves."""
            from . import probant_intake as I
            out = []
            root = I.intake_root()
            for d in (sorted(root.iterdir(), reverse=True) if root.is_dir() else [])[:20]:
                try:
                    meta = json.loads((d / "meta.json").read_text())
                    out.append({**meta, "proposals": len(I.read_proposals(meta["id"]))})
                except (OSError, ValueError, S.ProbantError):
                    continue
            return {"documents": out}

        @app.post("/api/intake/create")
        async def intake_create(request: Request):
            import asyncio
            from . import probant_intake as I
            d = await body(request)
            try:
                made = await asyncio.to_thread(I.create_matter, str(d.get("id") or ""), str(d.get("client") or ""),
                                               str(d.get("matter") or ""), int(d.get("index") or 0),
                                               str(d.get("priority_date") or "") or None)
            except S.ProbantError as e:
                return problem(str(e), 400)
            except (TypeError, ValueError):
                return problem("that proposal is not one this document has", 400)
            return {"ok": True, "id": made}

        def corpus_documents() -> List[Dict[str, Any]]:
            """The documents this installation can send WITH a corpus: what a cluster run wrote about the
            whole cluster (its matter list, its reading guide).

            The page chooses by ID from this list and never sends a path. A path from a browser page is a
            path someone can edit, and "seal this file to a stranger" is the last place to accept one.
            """
            from . import probant_cluster as PF
            out: List[Dict[str, Any]] = []
            root = PF.cluster_root()
            if not root.is_dir():
                return out
            for run in sorted(root.iterdir(), reverse=True):
                for name in ("MATTERS.txt", "READING-GUIDE.txt"):
                    f = run / name
                    if f.is_file():
                        out.append({"id": f"{run.name}/{name}", "name": name, "run": run.name,
                                    "bytes": f.stat().st_size, "path": str(f)})
            return out

        # ── sharing a corpus of matters with another Probant user ──
        @app.get("/api/sharing")
        async def sharing():
            """This installation's identity and the people it can share with. Public material only."""
            from . import probant_share as SH
            me = SH.identity()
            return {"fingerprint": me["fingerprint"], "card": SH.public_card(me),
                    "contacts": [{"name": n, **c} for n, c in SH.contacts().items()],
                    # Offered by id; the page never sends a path back (see corpus_documents).
                    "documents": [{k: v for k, v in x.items() if k != "path"} for x in corpus_documents()],
                    # The deliveries themselves. The page could send one and open one and never show you
                    # that any existed — which is what "I don't see the corpus integration" was about.
                    "corpora": SH.corpora()}

        @app.post("/api/sharing/contact")
        async def add_contact(request: Request):
            from . import probant_share as SH
            d = await body(request)
            card = d.get("card")
            if isinstance(card, str):
                try:
                    card = json.loads(card)
                except ValueError:
                    return problem("that is not a public key: paste the whole block they sent you", 400)
            try:
                got = SH.add_contact(str(d.get("name") or ""), card or {})
            except S.ProbantError as e:
                return problem(str(e), 400)
            return {"ok": True, "name": d.get("name"), "fingerprint": got["fingerprint"]}

        @app.post("/api/sharing/contact/preview")
        async def preview_contact(request: Request):
            """The fingerprint a pasted card gives, without recording anything. This exists so the box a
            person pastes into answers them — a blank textarea that stays blank is the part of this page
            people do not finish. It adds no contact and writes no file."""
            from . import probant_share as SH
            d = await body(request)
            card = d.get("card")
            if isinstance(card, str):
                if not card.strip():
                    return {"ok": False, "reason": ""}
                try:
                    card = json.loads(card)
                except ValueError:
                    return {"ok": False, "reason": "that is not the whole key yet — paste the whole block, "
                                                   "from the first { to the last }"}
            try:
                return {"ok": True, "fingerprint": SH.read_card(card or {})}
            except S.ProbantError as e:
                return {"ok": False, "reason": str(e)}

        @app.get("/api/search-status")
        async def search_status():
            """Whether the search machine is up, and when it is meant to be. Never names the machine."""
            import asyncio
            from . import pi_attested
            # The config is read FIRST: the availability mode comes out of it, and building `out` before
            # loading it used `cfg` a line before it existed.
            try:
                cfg = json.loads(pi_attested.search_config_path().read_text())
            except (OSError, ValueError):
                cfg = {}
            out: Dict[str, Any] = {"configured": False, **_search_window(avail=search_availability(cfg))}
            if not cfg:
                return out
            enclave = str(cfg.get("enclave") or "")
            if not enclave:
                return out
            out["configured"] = True
            state = await asyncio.to_thread(_search_probe_state, enclave)
            out["reachable"] = state == "up"
            out["found"] = state != "unknown-host"
            return out

        @app.post("/api/sharing/share")
        async def share(request: Request):
            """Seal the chosen matters to a contact. The file lands beside the matters, for the person to
            send however they like — the channel cannot read it."""
            import asyncio
            from . import probant_share as SH
            d = await body(request)
            to = str(d.get("to") or "")
            known = SH.contacts()
            if to not in known:
                return problem("no such contact", 404)
            ids = [str(x) for x in (d.get("matters") or [])]
            if not ids:
                return problem("choose at least one matter to share", 400)
            # Resolve the chosen documents against OUR list, by id — never against a path from the page.
            offered = {x["id"]: x for x in corpus_documents()}
            chosen = [offered[str(x)] for x in (d.get("documents") or []) if str(x) in offered]

            def build() -> Dict[str, Any]:
                me = SH.identity()
                entries = []
                for mid in ids:
                    client, matter, _ = matter_of(mid)
                    entries.append(SH.matter_payload(client, matter))
                files = SH.corpus_files([Path(x["path"]) for x in chosen])
                payload = SH.build_share(entries, note=str(d.get("note") or ""), files=files,
                                         corpus_name=str(d.get("corpus_name") or ""))
                cards = [known[to]] + ([SH.public_card(me)] if d.get("keep_copy", True) else [])
                blob = SH.seal_to(cards, payload, me)
                stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                dest = S.probant_root() / f"probant-corpus-for-{to}-{stamp}{SH.SUFFIX}"
                dest.write_bytes(blob)
                os.chmod(dest, 0o600)
                # The SENDER's own trace of an outbound disclosure: what went, to whom, when, with which
                # documents. Only the CLI wrote one (probant.py), so a corpus sealed from this page left no
                # record at all and the page's own Deliveries list stayed empty after sealing it.
                SH.record_sent(payload, to, known[to]["fingerprint"], dest)
                return {"path": str(dest), "matters": len(entries), "bytes": len(blob),
                        "documents": [x["name"] for x in chosen], "corpus": payload["corpus"]["id"],
                        "to_fingerprint": known[to]["fingerprint"], "from_fingerprint": me["fingerprint"]}

            try:
                return {"ok": True, **await asyncio.to_thread(build)}
            except S.ProbantError as e:
                return problem(str(e), 400)

        @app.post("/api/sharing/open")
        async def open_share(request: Request):
            """Open a share sealed to this installation: every matter in it becomes one of the reader's own."""
            import asyncio
            from . import probant_share as SH
            d = await body(request)
            path = Path(str(d.get("path") or "")).expanduser()
            try:
                blob = await asyncio.to_thread(path.read_bytes)
            except OSError:
                return problem("could not read that file on this computer", 400)
            try:
                payload = SH.open_sealed(blob)
            except S.ProbantError as e:
                return problem(str(e), 400)
            if not d.get("client"):
                # A look before the leap: who signed it, whether we know them, and what is inside.
                return {"ok": True, "preview": True, "from": payload.get("from_fingerprint"),
                        "from_name": payload.get("from_name"), "known": payload.get("from_known"),
                        "made_at": payload.get("made_at"), "note": payload.get("note"),
                        "corpus": (payload.get("corpus") or {}).get("name", ""),
                        "documents": [{"name": f.get("name"), "bytes": f.get("bytes")}
                                      for f in ((payload.get("corpus") or {}).get("files") or [])],
                        "matters": [{"matter": m.get("matter"), "date_bound": m.get("date_bound"),
                                     "claims": len(m.get("claims") or []),
                                     "marks": len(m.get("marks") or {})} for m in payload.get("matters") or []]}
            try:
                made = await asyncio.to_thread(SH.create_matters_from_share, payload, str(d["client"]))
                # The corpus documents describe the WHOLE delivery. Opening the matters and not writing them
                # loses, in silence, the material the delivery was made for.
                wrote = await asyncio.to_thread(SH.write_corpus, payload, str(d["client"]))
            except S.ProbantError as e:
                return problem(str(e), 409)
            return {"ok": True, "opened": made, "documents": wrote.get("written") or [],
                    "corpus": wrote.get("id") or "", "corpus_dir": wrote.get("dir") or ""}

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
    from . import probant_delete
    for gone in probant_delete.erase_expired():           # deleted more than RETENTION_DAYS ago: erased now
        print(f"  Erased a matter deleted more than {probant_delete.RETENTION_DAYS} days ago ({gone}).", flush=True)
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
    # SAY IT HERE, NOT AT THE CLICK. Started from inside a coding assistant, the page comes up, hands out a
    # working link and looks healthy — and then refuses the one action it exists for, because every session it
    # launches inherits CLAUDECODE=1 and `ir` will not nest agent sessions. Henry hit exactly that on 1 Oct
    # after I started it from my own tool: the failure arrived at "Start a session", several minutes and one
    # browser round-trip after the decision that caused it. The page is still worth having for reading records,
    # so this warns rather than refuses — but it warns where the mistake is still cheap to undo.
    if os.environ.get("CLAUDECODE") == "1" and os.environ.get("IR_ALLOW_NESTED") != "1":
        print("  ⚠ Started from inside a coding assistant (CLAUDECODE=1). You can read matters and records,", flush=True)
        print("    but STARTING A SESSION FROM THIS PAGE WILL BE REFUSED: sessions must not nest. Stop this", flush=True)
        print("    and run `ir probant home` in an ordinary terminal window instead.\n", flush=True)
    class HomeServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            # Uvicorn sets started only after binding the listening socket. Opening the browser
            # before this point gives Firefox a connection refusal on its first request.
            if self.started and open_browser:
                await asyncio.to_thread(launch_browser, url)

    # timeout_graceful_shutdown: Ctrl-C and `kill` must end this, not wait on whatever request a
    # browser tab happens to be holding open.
    server = HomeServer(uvicorn.Config(home.app(), host="127.0.0.1", port=home.port,
                                      log_level="warning", timeout_graceful_shutdown=5))
    server.run()
    return 0
