"""`ir probant open <matter> --web` — the same confined session, shown in a local browser page.

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
import datetime as dt
import hmac
import json
import shlex
import os
import re
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# At module level, not inside app(): with postponed annotations FastAPI resolves `request: Request` by name
# in this module's globals. Imported locally, the name does not resolve, and every POST answers 422.
from fastapi import Request

from . import pi_attested

STATIC = Path(__file__).resolve().parent / "probant_web"
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PUB_RE = re.compile(r"^[A-Z]{2}[-A-Z0-9]{2,}$")
# The three judgements, and taking one back off. "cleared" is NOT a delete: the store is append-only
# because a changed mind is signal, so clearing a mark appends a new human row whose latest value says the
# professional no longer wants an opinion on this document. Every consumer here tests the value POSITIVELY
# (== "relevant", `in MARK_LABEL`), so a cleared document falls out of relevance, out of the model's marks
# note and out of the deep search's outward-walk by construction rather than by a rule someone must
# remember. Henry, 25 Sep: "there is no way to just remove the selection".
MARKS = ("relevant", "not-relevant", "known", "cleared")
CLEARED = "cleared"
HISTORY_CAP = 5000
# Printed by a session once its assistant has ended and only its page stays up (for exporting). The home page
# reads it to stop offering "Open the session" for a session that is over — one line, one definition.
ENDED_MARK = "The page stays open so you can export the record."
# Pi event types this page knows: the ones normalize() handles (some deliberately ignored in part — the
# professional's own messages, the marks note) and routine bookkeeping it has no use for. Only a type OUTSIDE
# this set is reported at the end of a session as one "the page has no word for": that line exists to catch
# something new — a Pi upgrade, an event that might explain a hang — and listing routine events every time
# would bury it (it did, from 18 Sep until this list: every session's own messages were "unrecognised").
KNOWN_EVENTS = frozenset({
    "agent_start", "agent_settled", "message_start", "message_update", "message_end",
    "tool_execution_start", "tool_execution_update", "tool_execution_end",
    "extension_ui_request", "extension_error", "auto_retry_start", "response",
    "agent_end", "turn_start", "turn_end", "auto_retry_end", "queue_update",
    "session_info", "session_info_changed", "compaction_start", "compaction_end", "extension_ui_response",
})
# The steps a sealed search reports, in order (ir-attested.ts). Anything else is dropped.
TOOL_PHASES = ("verifying", "approval", "searching")


def env(name: str, default: str = "") -> str:
    """A Probant setting, under its own name or the name it had while the product was called Surveyor.
    The old spelling is not decoration: a home page already running passes IR_SURVEYOR_HOME_URL to the
    session it starts, and a session that loses its way back home is how a rename breaks someone's day."""
    return os.environ.get(f"IR_PROBANT_{name}") or os.environ.get(f"IR_SURVEYOR_{name}") or default


# How long the assistant may say nothing at all, mid-turn, before the page stops claiming it is working.
# Measured against real turns: a sealed search takes 20-60 s and streams status lines throughout, so two
# minutes of COMPLETE silence is not slowness. A turn that goes quiet forever has happened (17 Sep: the
# model stream ended mid-answer, Pi never learned, and the page said "The assistant is working…" until the
# session was killed from a shell) and the page must never again present that as work in progress.
STALL_SECONDS = float(env("STALL_SECONDS", "120"))
# How long `abort` and `end` wait for the agent to do as it is told before saying it did not.
ABORT_GRACE = float(os.environ.get("IR_PROBANT_ABORT_GRACE", "6"))
END_GRACE = float(os.environ.get("IR_PROBANT_END_GRACE", "5"))
KILL_GRACE = float(os.environ.get("IR_PROBANT_KILL_GRACE", "3"))
# When the agent runs in a virtual machine, ending politely is not one process exiting: Pi exits, the guest
# compares its folder with what it was given and sends back what changed, the host accepts it, and only then
# is the machine stopped. Stopping the runner before that is over DISCARDS every file the session wrote —
# and five seconds was not always enough even for a session that had written nothing (ADE, 3 Oct). A wedged
# session still ends; it takes this long to be sure it was wedged.
VM_END_GRACE = 60.0

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


class PageFiles:
    """The page's files as they were when this server started, and whether the installed code has changed since.

    A server that read its page fresh from disk on every request showed a page NEWER than the code answering it:
    on 19 Sep the home page offered "Delete matter" to a server started before the delete route existed, and
    the button failed with a bare 404. Serving the snapshot keeps page and server the same version; `stale()`
    lets the page say that a newer version is installed and a restart will bring it in."""

    def __init__(self, names) -> None:
        self.files = {n: (STATIC / n).read_bytes() for n in names}
        self.stamp = self._stamp()

    @staticmethod
    def _stamp() -> tuple:
        # Size and modification time of every file of the package that a running server would be missing:
        # cheap enough for every overview request, and changed by any install, checkout or edit.
        root = Path(__file__).resolve().parent
        out = []
        for p in sorted([*root.glob("*.py"), *STATIC.iterdir()]):
            try:
                st = p.stat()
            except OSError:
                continue
            out.append((p.name, st.st_size, st.st_mtime_ns))
        return tuple(out)

    def stale(self) -> bool:
        return self._stamp() != self.stamp

    def handler(self, name: str, media: str):
        from fastapi.responses import Response
        data = self.files[name]

        async def serve():
            return Response(data, media_type=media)
        return serve


def install_guard(app: Any, port: Callable[[], int], token: Callable[[], str]) -> None:
    """The rules every local Probant page lives by, installed once per app so the session page and the home
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
    if t == "tool_execution_update":
        # Which step a search is on. Only a name from a fixed list crosses to the page — never the partial
        # result itself, which for another tool could carry anything.
        details = (ev.get("partialResult") or {}).get("details") if isinstance(ev.get("partialResult"), dict) else None
        phase = (details or {}).get("phase") if isinstance(details, dict) else None
        if phase in TOOL_PHASES:
            out = {"kind": "tool_progress", "call": ev.get("toolCallId"), "phase": phase}
            # A fan-out is several sealed searches and takes minutes; with only a phase name the card
            # repeats the same three words and looks stalled. Position crosses as two INTEGERS and nothing
            # else — the page composes the words — so this stays a channel that cannot carry content, which
            # is what the rule above is protecting.
            for k in ("step", "steps"):
                v = (details or {}).get(k)
                if isinstance(v, bool) or not isinstance(v, int):
                    continue
                if 0 <= v <= 99:
                    out[k] = v
            return [out]
        return []
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


# ── opening a terminal for the audit ───────────────────────────────────────────────────────────────────
#
# The audit runs an interactive agent, which needs a terminal; a browser page cannot open one, so the
# server does it. That makes this the one endpoint here that starts a program, and it is built so the page
# cannot say WHICH: it sends a choice from a fixed set, and the command is composed here from the same
# constants the copyable text is made from. A page that could hand over a command string would be a way to
# run anything on this computer, reachable by anything that reached the page.
#
# The terminal is NOT tied to this server's lifetime. An audit takes ten to fifteen minutes and the person
# may well close Probant while it runs; killing their agent because they closed a window it did not belong
# to would lose the work and look like a crash.
_TERMINALS = (
    ("x-terminal-emulator", ["-e"]), ("gnome-terminal", ["--"]), ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]), ("alacritty", ["-e"]), ("wezterm", ["start", "--"]),
    ("kitty", []), ("foot", []), ("xterm", ["-e"]),
)


def terminal_argv(script: Path) -> Optional[List[str]]:
    """How to open a terminal running `script`, or None when there is no terminal to open.

    Each entry carries its OWN separator because they disagree: gnome-terminal wants `--`, xfce4-terminal
    wants `-x` (its `-e` takes one string and would mangle an argv), kitty and foot take the command with
    no flag at all. Getting this wrong opens a terminal that flashes and closes, which reads as the feature
    being broken rather than the flag being wrong."""
    import shutil
    if sys.platform == "darwin":
        return ["open", "-a", "Terminal", str(script)]
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None                                     # no desktop: nothing to open a window on
    for name, sep in _TERMINALS:
        found = shutil.which(name)
        if found:
            return [found, *sep, "/bin/bash", str(script)]
    return None


# Where the agent programs an audit may use are really installed. A new Terminal window (and the page's own
# server) often has none of these on its PATH: Claude Code installs to ~/.local/bin, Homebrew to /opt/homebrew/bin.
# `ir --plain` itself needs `claude` and says "`claude` not found on PATH" without it (ADE, 3 Oct).
AGENT_DIRS = ("~/.local/bin", "/opt/homebrew/bin", "/usr/local/bin")


def agent_search_path() -> str:
    extra = [os.path.expanduser(d) for d in AGENT_DIRS]
    return os.pathsep.join([*os.environ.get("PATH", "").split(os.pathsep), *[d for d in extra if os.path.isdir(d)]])


def audit_agent_on_path(agent: str) -> bool:
    import shutil
    return shutil.which(agent, path=agent_search_path()) is not None


def audit_ir_path() -> Optional[str]:
    """The `ir` a NEW terminal window should run for the audit: the one that belongs to the install running
    this page, by absolute path; failing that whatever the shell finds; failing that None.

    Two failures made this order matter, both on ADE on 3 Oct. Asking only whether `ir` was on this server's
    PATH said "InferRoute isn't available on this computer" to a person who had just installed it (a venv
    install keeps `ir` in ~/probant/bin, on nobody's PATH). And a PATH lookup alone can find a DIFFERENT, older
    install first (ADE had one in ~/.local/bin) — an audit run by the wrong version of the program."""
    import shutil
    mine = Path(sys.executable).parent / "ir"
    if mine.is_file() and os.access(mine, os.X_OK):
        return str(mine)
    return "ir" if shutil.which("ir", path=agent_search_path()) else None


def can_open_terminal() -> bool:
    """Whether this computer has a terminal to open. The page asks before offering the button, for the same
    reason the deep-search button asks about the search machine: an action that cannot work should not be
    offered, and the copyable command is a perfectly good answer where it cannot."""
    return terminal_argv(Path(os.devnull)) is not None


def audit_launch_script(pack: Path, command: str) -> Path:
    """A one-line script in a private temp dir, so every terminal needs the same shape: run bash on one
    file. Not written into the audit pack — that folder is evidence a third party will hash, and a script
    we dropped in it afterwards is one more thing they have to account for."""
    import stat
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="probant-audit-"))
    sh = d / "run-audit.sh"
    # EVERY AUDIT GETS ITS OWN COPY OF THE PACK, and never the pack itself. Two reasons, both of them
    # things that happened on 25 Sep when two audits were launched on one folder:
    #   * one auditor filled the report template in where it lay, and the other — running concurrently in
    #     the same directory — found the record failing its own integrity check and was one step from
    #     filing evidence tampering that was really a colleague's scratch edit;
    #   * anything an auditor writes in there is one more file the NEXT reader has to account for.
    # The copy sits beside the original as `audit-run-<pack>-<pid>`, so a report written "one directory
    # up" lands in the exports folder where every other report already is, and the original is never
    # opened for writing by anyone.
    # One server can launch several auditors: its pid alone is not a unique run id.
    run = pack.parent / f"audit-run-{pack.name}-{os.getpid()}-{d.name}"
    sh.write_text("#!/bin/bash\n"
                  # The places the agents install, appended AFTER the shell's own PATH: nothing the person has
                  # is shadowed, and `claude` is found by the program (`ir`) that needs it.
                  'export PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin"\n'
                  f"cp -r {shlex.quote(str(pack))} {shlex.quote(str(run))} || exit 1\n"
                  f"chmod -R u+w {shlex.quote(str(run))}\n"
                  f"cd {shlex.quote(str(run))} || exit 1\n"
                  f"printf 'Working on a copy: %s\\n(the original pack is untouched; write your report one directory up)\\n\\n' {shlex.quote(str(run))}\n"
                  # The model behind the default audit sometimes ends a turn having only SAID what it will do next
                  # ("Let me read the key files…") — a tool-less turn, so the session simply waits. It is not stuck
                  # and nothing is wrong with the evidence; one word restarts it. Said before it can happen.
                  "printf 'If the assistant stops after saying what it will do next, type:  continue\\n\\n'\n"
                  f"{command}\n"
                  'printf "\\n[the audit session has ended — this window can be closed]\\n"\n'
                  "exec bash\n")
    sh.chmod(sh.stat().st_mode | stat.S_IXUSR)
    return sh


_PUBNO_RE = re.compile(r"\b([A-Z]{2}-[0-9A-Z]{3,}-[A-Z0-9]{1,3})\b")


def _first_pubno(text: str) -> str:
    """The first publication number a passage names, upper-cased, or "".

    Used to decide whether an assistant turn is a READING OF a document: the first publication number the reply names must BE this document. A reading opens with its
                    # subject ("Opened US-5553613-A…", "Here is what the index holds for US-…"), so the first
                    # number named is the one it is about. "Mentions the key somewhere" was too weak and let
                    # through a survey report that listed US-12446781-B2 among its results, and a reading of
                    # US-6445938-B1 that happened to cite US-6421548-B1 later on.
    """
    m = _PUBNO_RE.search(str(text or "").upper())
    return m.group(1) if m else ""


class Bridge:
    def __init__(self, *, matter: str, date_bound: str, workspace: Path, summary: Dict[str, Any],
                 search_endpoint: Optional[str], receipt: Callable[[], Any],
                 rebuild_summary: Callable[[], Dict[str, Any]], export: Callable[[], Path],
                 conversation_file: Optional[Path] = None, records_dir: Optional[Path] = None,
                 mode: str = "matter", intake_id: str = ""):
        self.matter, self.date_bound, self.workspace = matter, date_bound, workspace
        self.summary = summary
        self.mode, self.intake_id = mode, intake_id
        self.search_endpoint = search_endpoint
        self._receipt, self._rebuild, self._export = receipt, rebuild_summary, export
        self.token = secrets.token_urlsafe(32)
        self.end_grace = 0.0                # raised by the launcher for a VM-held agent; see VM_END_GRACE
        self.port = 0
        self.history: List[Dict[str, Any]] = []
        self.subscribers: List[asyncio.Queue] = []
        self.dialogs: Dict[str, Dict[str, Any]] = {}
        self.busy = False
        self.ended: Optional[Dict[str, Any]] = None
        self.proc: Any = None
        self._seq = 0
        self.closed = asyncio.Event()
        # Set when this page is going away. The event stream never ends on its own — it is a long poll that
        # pings for ever — and uvicorn's graceful shutdown waits for open requests, so without this a launcher
        # asked to stop waits for the browser tab to be closed first. That is how `kill` on a wedged session
        # looked like a signal being ignored, and it needed SIGKILL.
        self.shutdown = asyncio.Event()
        # Liveness. `last_agent` moves only when PI says something; our own events (a mark, a trust
        # recheck, the stall notice itself) must not make a dead turn look alive.
        self.last_agent = time.monotonic()
        self.stalled = False
        self._watchdog: Any = None
        # toolCallId → tool name, for calls that started and have not ended.
        self.running_tools: Dict[str, str] = {}
        self.opening = ""                   # a reading session's first instruction; empty for a matter session
        self.oneshot = False                # a round of a cluster run: end the session when its work is done
        self.recorded = 0                   # findings this session has actually written
        self.turns = 0                      # assistant turns, so "barely started" is distinguishable
        self.tool_counts: Dict[str, int] = {}
        self.last_assistant = ""            # its own last words: usually why a round produced nothing
        self.last_error = ""                # a turn that stopped on an error says so here, not in silence
        # EVERY failed turn, not only the last, and readable WHILE the session is live. On 2026-09-30 a
        # session showed "Connection error." at the start of every answer; the only way to see that string
        # was to tap the page's own event stream, because last_error above reaches disk only at round end
        # and only under IR_ROUND_LOG. The relay fault behind it was two hops below the lane, so the
        # session's receipt read 7 requests and 0 errors throughout — correctly. Diagnosing a fault
        # outside the lane needs a place that records faults outside the lane.
        self.faults: List[Dict[str, Any]] = []
        # WHAT THE ASSISTANT SAID ABOUT A DOCUMENT, so reopening it does not have to buy the reading again.
        # Keyed by publication number, captured from the turn in which that document was read — an attribution
        # by turn, which is why the page labels it "what the assistant said in this session" and never "the
        # summary of the document". The document TEXT is the archive's; only this is ours.
        # PERSISTED, per matter, beside the record the document text itself comes from. It was in memory
        # only, so the readings died with the session that made them and a document opened tomorrow said
        # "the assistant has not written about this document yet" about one it had already read — Henry,
        # 2026-10-01. The whole point of keeping these is that reopening costs nothing, and a cache that
        # does not outlive the process is not a cache.
        # QUESTIONS WE HOLD, not ones Pi holds. Sending with streamingBehavior "followUp" handed the queue
        # to Pi, which delivered it at the START of the next turn — so a question sent while the assistant
        # was working sat there after it went idle and only moved when the person sent ANOTHER message, at
        # which point both arrived. Henry, 2026-10-01. Holding it here makes the page's "waiting" and the
        # real queue the same thing, and the delivery a decision this process makes at a moment it can see.
        self.pending_prompts: List[str] = []
        self._draining = False
        self.readings: Dict[str, str] = {}
        self._readings_meta: Dict[str, Dict[str, Any]] = {}
        self._read_this_turn: List[str] = []
        self._turn_began = 0                # server ms when the agent last went busy
        self._quiet_since = 0               # server ms of the previous event: how long it had been silent
        self.nudged = False                 # a round gets ONE reminder, never a loop
        self._timings: Dict[str, Dict[str, Any]] = {}      # toolCallId → a search being timed
        self._search_stats: Optional[Dict[str, Any]] = None
        # Event types Pi sent that the page has no vocabulary for. Counted by name only — never content —
        # so that a turn that ends in an event we don't understand leaves a trail instead of a mystery.
        self.dropped: Dict[str, int] = {}
        # The conversation, kept with the matter's records (under confidential/, outside the agent's reach,
        # owner-only) so the home page can show it later. Announced on the page; None keeps nothing.
        self.conversation_file = conversation_file
        self.records_dir = records_dir                      # the matter's search records, for mark titles
        # Last, because it needs records_dir: every reading from every earlier session on this matter,
        # so a document opened today shows what was already written about it rather than claiming none.
        self._load_readings()

    # ── events ──
    def publish(self, event: Dict[str, Any], *, agent: bool = False) -> None:
        if agent:
            self.last_agent = time.monotonic()
            if self.stalled:                       # it spoke again: withdraw the notice, don't leave it standing
                self.stalled = False
                self.publish({"kind": "stall", "value": False})
        self._seq += 1
        # Every event carries the moment the SERVER saw it. The page used to time searches with its own clock at
        # the moment it received each event — and a reload replays the whole session at once, so every timer
        # restarted from zero and a finished search claimed "0.0 s". Durations come from these stamps now.
        event = {"seq": self._seq, "at": round(time.time() * 1000), **event}
        if event["kind"] == "busy":
            was, self.busy = self.busy, bool(event["value"])
            if not was and self.busy:
                self._turn_began = event["at"]
            # WENT IDLE: deliver the next question we are holding. This is the moment the old path missed —
            # Pi had the message and was not going to act on it until something else woke it.
            if was and not self.busy and self.pending_prompts:
                asyncio.ensure_future(self._drain_pending())
            if self.oneshot and was and not self.busy and not self.dialogs:
                asyncio.ensure_future(self._end_round())
        if event["kind"] == "tool_start":
            name = str(event.get("tool") or "")
            self.tool_counts[name] = self.tool_counts.get(name, 0) + 1
            if name == "read_patent":
                key = str(((event.get("args") or {}) if isinstance(event.get("args"), dict) else {}).get("key") or "").upper()
                if key:
                    self._read_this_turn.append(key)
        if event["kind"] == "assistant_end":
            self.turns += 1
            if str(event.get("text") or "").strip():
                self.last_assistant = str(event.get("text"))
                # The FIRST words after a read are the reading; a later turn in the same round is talking
                # about something else, so it does not overwrite one already captured.
                for key in self._read_this_turn:
                    # IT MUST BE ABOUT THAT DOCUMENT. The turn in which a document was read is not always a
                    # turn ABOUT it — the assistant may finish an earlier answer first, or (measured
                    # 2026-09-30) answer a read request by running a search. Attaching those words to the
                    # document anyway puts a confident paragraph under the wrong publication number, which
                    # in a prior-art tool is worse than showing nothing. Naming the document is a weak test,
                    # but it is the difference between "possibly about it" and "demonstrably not".
                    if _first_pubno(str(event.get("text") or "")) != key.upper():
                        continue
                    if key not in self.readings:
                        self.readings[key] = str(event.get("text"))[:6000]
                        self._readings_meta[key] = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
                        self._save_readings()
                self._read_this_turn = []
            # A turn that stopped on an error is the commonest reason a round records nothing, and it is
            # invisible in the text: 62 of 76 empty rounds made no tool call and said nothing at all.
            if event.get("error") or event.get("stopped"):
                self.last_error = f"{event.get('stopped') or 'error'}: {str(event.get('error') or '')[:300]}"
                self.faults.append({"at": event["at"], "turn": self.turns,
                                    "stopped": str(event.get("stopped") or ""),
                                    "raw": str(event.get("error") or "")[:300],
                                    # How far into the turn it failed. A fault at a round 30 s is a timer
                                    # somewhere, not a busy provider, and that distinction is the whole
                                    # diagnosis — it is what identified the relay's 30 s idle teardown.
                                    "ms_into_turn": (event["at"] - self._turn_began) if self._turn_began else None,
                                    # And how long it had been SILENT when it gave up, which is the sharper
                                    # fingerprint: a timer shows up as the same number every time.
                                    "ms_quiet": (event["at"] - self._quiet_since) if self._quiet_since else None})
                del self.faults[:-40]
        if event["kind"] == "tool_end" and str(event.get("tool") or "").startswith(("record_", "propose_")):
            self.recorded += 1
        if event["kind"] == "dialog":
            self.dialogs[str(event["id"])] = event
        # A tool call the agent started and never finished. The page shows "checking the search machine…"
        # for one of these, and that card is NOT covered by `busy`: an agent can go silent with a tool
        # outstanding while busy is false, and then nothing on the page ever says so. Henry hit exactly
        # that on 18 Sep and had to ask a human why it was stuck.
        if event["kind"] == "tool_start":
            self.running_tools[str(event.get("call"))] = str(event.get("tool") or "")
        if event["kind"] == "tool_end":
            self.running_tools.pop(str(event.get("call")), None)
        self._quiet_since = event["at"]
        self.history.append(event)
        self._keep(event)
        if len(self.history) > HISTORY_CAP:
            del self.history[: len(self.history) - HISTORY_CAP]
        for q in list(self.subscribers):
            q.put_nowait(event)
        # AFTER the event is delivered: timing a finished search publishes the new statistics, and that event
        # must be numbered after the result it follows. Numbered before it, the page — which skips anything at
        # or below the last number it saw — would drop the search result itself.
        self._time_search(event)

    def _time_search(self, event: Dict[str, Any]) -> None:
        """Record how long each step of a completed search took, from this bridge's own clock, for the
        progress view's expectations (probant_timing). The approval prompt's time is the person's, not the
        machine's, and is left out."""
        from . import probant_timing as T
        kind, call, at = event.get("kind"), str(event.get("call")), event["at"]
        # A deep search's legs are ordinary sealed searches and take ordinary sealed-search time, so the
        # progress view's expectations are built from both. Filtering on one tool name left a press with no
        # timings at all, which is how "checking the search machine…" sits still with nothing behind it.
        if kind == "tool_start" and event.get("tool") in ("prior_art_search", "deep_prior_art_search"):
            self._timings[call] = {"k": T.k_of(event.get("args") or {}), "phase": "verifying", "since": at, "ms": {}}
            return
        t = self._timings.get(call)
        if t is None:
            return
        if kind == "tool_progress":
            t["ms"][t["phase"]] = t["ms"].get(t["phase"], 0) + (at - t["since"])
            t["phase"], t["since"] = event.get("phase"), at
        elif kind == "tool_end":
            self._timings.pop(call, None)
            t["ms"][t["phase"]] = t["ms"].get(t["phase"], 0) + (at - t["since"])
            # Only a search that completed says anything about the machine; a refusal measured nothing.
            if event.get("ok") and (event.get("details") or {}).get("ok"):
                T.record_wait(k=t["k"], verifying_ms=t["ms"].get("verifying"), searching_ms=t["ms"].get("searching"))
                self._search_stats = None                   # recompute on next read
                self.publish({"kind": "search_timing", "stats": self.search_stats()})

    def search_stats(self) -> Dict[str, Any]:
        if self._search_stats is None:
            from . import probant_timing as T
            self._search_stats = T.stats()
        return self._search_stats

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
        elif kind == "queue_cancel":
            # The question was asked of THIS page and is already on record above; say it never went.
            row = {"kind": "withdrawn", "text": event.get("text", "")}
        elif kind == "assistant_end" and (event.get("text") or "").strip():
            row = {"kind": "assistant", "text": event.get("text", "")}
        elif kind == "tool_end" and event.get("tool") == "prior_art_search":
            d = event.get("details") or {}
            row = {"kind": "search", "ok": bool(event.get("ok") and d.get("ok")), "search_no": d.get("searchNo"),
                   "feature": d.get("feature"), "like": d.get("like"), "k": d.get("k"), "documents": len(d.get("docs") or []),
                   "refusal": "" if event.get("ok") else str(event.get("text") or "")[:300]}
        elif kind == "tool_end" and event.get("tool") == "deep_prior_art_search":
            # A press is several sealed searches, and each is a search the professional is entitled to see
            # the way they see any other — the aggregate alone told them a number and nothing else. One row
            # opens the press and says why it is the size it is; then one row per leg, in the order run.
            d = event.get("details") or {}
            legs = d.get("legs") or []
            rows = [{"kind": "deep_search", "ok": bool(event.get("ok")), "planned": d.get("planned"),
                     "cap": d.get("cap"), "sent": d.get("sent"), "documents": d.get("documents"),
                     "notes": d.get("notes") or [],
                     "refusal": "" if event.get("ok") else str(event.get("text") or "")[:300]}]
            for leg in legs:
                rows.append({"kind": "search", "ok": leg.get("status") == "ok", "search_no": leg.get("searchNo"),
                             "feature": leg.get("feature"), "like": None, "k": None,
                             "documents": leg.get("hits") or 0, "of_deep": True,
                             "refusal": str(leg.get("why") or "")[:300] if leg.get("status") == "failed" else ""})
            for r in rows:
                self._append_row(r, at)
            return

        elif kind == "tool_end" and event.get("tool") == "matter_marks":
            row = {"kind": "marks_read"}
        elif kind == "dialog_closed":
            row = {"kind": "approval", "answer": event.get("answer")}
        if row is None:
            return
        self._append_row(row, at)

    def _append_row(self, row: dict, at: Any) -> None:
        """One line of the conversation record. Extracted because a deep search appends SEVERAL rows for one
        tool_end, and a second copy of this write would be a second way for the record to be written."""
        try:
            fd = os.open(self.conversation_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": at, **row}, ensure_ascii=False) + "\n")
        except OSError:
            pass

    # ── the assistant's readings, kept with the matter ────────────────────────────────────────────
    #
    # Beside the searches archive and the conversation, in the matter's own records directory, which is
    # outside the sandbox and already where this session's material lives. Not a new location and not a
    # global cache: these are the client's work product about one matter.
    def _readings_path(self) -> Optional[Path]:
        return (self.records_dir / "readings.json") if self.records_dir else None

    def _load_readings(self) -> None:
        """Readings from every earlier session on this matter. A missing or unreadable file is simply no
        readings — it must never stop a session opening, because the readings are a convenience and the
        record is the thing that matters."""
        path = self._readings_path()
        if not path or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for key, row in (data.get("readings") or {}).items():
            if not isinstance(row, dict):
                continue
            text = str(row.get("text") or "")
            if text:
                self.readings.setdefault(str(key), text)
                self._readings_meta.setdefault(str(key), {"at": row.get("at")})

    def _save_readings(self) -> None:
        """Written on capture, not at round end: a session that is killed mid-work — which is how most of
        them end — would otherwise save nothing. Atomic, so a kill during the write cannot leave a
        half-written file that reads as no readings at all."""
        path = self._readings_path()
        if not path:
            return
        payload = {"schema": "inferroute.probant-readings/1", "matter": self.matter,
                   "readings": {k: {"text": v, "at": (self._readings_meta.get(k) or {}).get("at")}
                                for k, v in self.readings.items()}}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            pass

    def _write_round_log(self, why: str) -> None:
        """Why a round ended, beside what it produced — written to the run directory, never to a console.

        A job that records nothing gave me a stopwatch reading and no reason (three of seven, 20 Sep). The
        session's own last words usually say it outright. Kept out of stdout because whoever runs this may
        be an agent whose transcript leaves the machine, and a session's words are the client's material.
        """
        path = os.environ.get("IR_ROUND_LOG")
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                     # Which job this round was, so a log of 195 rounds says WHICH document
                                     # went quiet. Without these two, reading progress out of a run means
                                     # reconstructing it from process start times and file mtimes — which is
                                     # what a resumed run cost me on 20 Sep, and the artefact should not need
                                     # an outside witness to be read.
                                     "label": os.environ.get("IR_ROUND_LABEL", ""),
                                     "ended": why, "recorded": self.recorded, "nudged": self.nudged,
                                     "turns": self.turns, "tools": dict(self.tool_counts),
                                     "error": self.last_error,
                                     # No tool call at all is a FAILED round, not a document with nothing in
                                     # it: the session never got a usable answer to work from.
                                     "worked": bool(self.tool_counts),
                                     "last_words": (self.last_assistant or "")[:1500]}) + "\n")
            os.chmod(path, 0o600)
        except OSError:
            pass

    async def _end_round(self) -> None:
        """Close a one-shot round — but a turn ending is NOT the work being done.

        Measured 20 Sep: reading three documents takes several turns, and the model ends a turn to say "now
        the next one". Ending the session there killed two jobs of seven mid-read, and both reported zero
        findings, which is indistinguishable from documents that assert nothing. So: if nothing has been
        recorded yet, say so once and let it finish; end on the next turn's end either way.
        """
        await asyncio.sleep(1.0)
        if self.busy:                        # a follow-up turn began: not the end of the round after all
            return
        if not self.recorded and not self.nudged:
            self.nudged = True
            try:
                await self.send({"type": "prompt", "message":
                                 "You have recorded nothing yet. If you have finished reading, record your "
                                 "findings now with record_findings. If there is genuinely nothing to record "
                                 "in what you read, say so in one line and stop."})
            except RuntimeError:
                pass
            return
        self._write_round_log("nothing recorded after a reminder" if not self.recorded else "work done")
        try:
            await self.stop_agent()
        finally:
            self.closed.set()

    def cancel_queued(self, index: int, text: str) -> bool:
        """Withdraw a held question, if and only if it is still held.

        The page names it by position AND by its text, so a question that was delivered a moment ago — the
        queue shifted under the click — is never confused with the one that took its place, and the answer
        to "was it cancelled" is the truth: False means it has already been sent and cannot be recalled.
        """
        if type(index) is not int or not 0 <= index < len(self.pending_prompts) or self.pending_prompts[index] != text:
            return False
        self.pending_prompts.pop(index)
        self.publish({"kind": "queue_cancel", "index": index, "text": text})
        self.publish({"kind": "queue_update", "waiting": len(self.pending_prompts)})
        return True

    async def _drain_pending(self) -> None:
        """Send the oldest held question, once, now that the assistant is free.

        One at a time and guarded: the next question is delivered when the turn it starts finishes, so two
        can never be in flight at once and the transcript keeps its Q A Q A shape. A send that fails puts
        the question back at the FRONT — losing it silently would be worse than the bug this replaced.
        """
        if self._draining:
            return
        self._draining = True
        try:
            while self.pending_prompts and not self.busy and not self.ended:
                text = self.pending_prompts.pop(0)
                try:
                    await self.send({"type": "prompt", "message": text})
                except RuntimeError:
                    self.pending_prompts.insert(0, text)
                    return
                self.publish({"kind": "queue_update", "waiting": len(self.pending_prompts)})
                # One per idle moment: the agent is about to go busy on this one, and the next goes when
                # that turn ends. Waiting for that is the whole point.
                return
        finally:
            self._draining = False

    async def open_with(self) -> None:
        """Send the opening instruction, once, when the agent is ready for one."""
        text, self.opening = self.opening, ""
        if not text:
            return
        self.publish({"kind": "user", "text": text})
        try:
            await self.send({"type": "prompt", "message": text})
        except RuntimeError:
            pass

    async def send(self, obj: Dict[str, Any]) -> None:
        if self.proc is None or self.proc.stdin is None or self.proc.stdin.is_closing():
            raise RuntimeError("the session has ended")
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        await self.proc.stdin.drain()

    async def pump(self, proc: Any) -> int:
        """Read Pi's stdout (strict JSONL: split on LF only) until it exits; return its exit code."""
        self.proc = proc
        self.last_agent = time.monotonic()
        self._watchdog = asyncio.ensure_future(self._watch())
        await self.open_with()                 # a reading session starts itself; a matter session does not
        buf = b""
        try:
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                # The guest is untrusted. Bound complete events and unfinished JSONL
                # before parsing; continuous newline-free output must not grow RAM.
                if len(buf) > 8 * 1024 * 1024 and any(
                        len(part) > 8 * 1024 * 1024 for part in buf.split(b"\n")):
                    await self.stop_agent()
                    raise ValueError("agent RPC event exceeded the session limit")
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.rstrip(b"\r")
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    outs = normalize(ev)
                    name = str(ev.get("type") or "?")[:60]
                    if not outs and name not in KNOWN_EVENTS:
                        self.dropped[name] = self.dropped.get(name, 0) + 1
                    # Anything Pi says is a sign of life, including an event the page does not render:
                    # a turn is stalled when NOTHING arrives, not when nothing is shown.
                    self.last_agent = time.monotonic()
                    for out in outs:
                        self.publish(out, agent=True)
        finally:
            if self._watchdog is not None:
                self._watchdog.cancel()
                self._watchdog = None
        rc = await proc.wait()
        self.busy = False
        self.stalled = False
        self.ended = self.session_end()
        self.publish({"kind": "ended", "summary": self.ended})
        return rc

    async def _watch(self) -> None:
        """Say so when the assistant goes silent mid-turn. This makes no judgement about why — the page's
        job is only to stop claiming work is happening when nothing has arrived for two minutes."""
        try:
            while True:
                await asyncio.sleep(min(2.0, max(0.02, STALL_SECONDS / 4)))
                quiet = time.monotonic() - self.last_agent
                working = self.busy or bool(self.running_tools)
                # Waiting for the PERSON is not a stall. With an approval prompt open the assistant is silent
                # by design, and "the assistant has stopped answering" would be telling someone reading the
                # prompt that we broke.
                waiting_on_you = bool(self.dialogs)
                if working and not waiting_on_you and not self.stalled and quiet >= STALL_SECONDS:
                    self.stalled = True
                    self.publish({"kind": "stall", "value": True, "seconds": int(quiet)})
        except asyncio.CancelledError:
            pass

    def stop_streams(self) -> None:
        """End the page's long-poll streams so the server can actually shut down. Waking each subscriber
        matters: a stream parked in a 15-second wait would otherwise hold the shutdown for that long."""
        self.shutdown.set()
        for q in list(self.subscribers):
            q.put_nowait({"seq": -1, "kind": "ping"})

    async def settle(self, timeout: float) -> bool:
        """Wait for the agent to finish its turn. False means it did not, and the caller must say so."""
        deadline = time.monotonic() + timeout
        while self.busy and self.proc is not None and self.proc.returncode is None:
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.1)
        return True

    async def stop_agent(self) -> str:
        """End the agent process for good, however wedged it is. Returns what it took, for the page to
        report honestly: a session that cannot be ended is worse than one that ends abruptly."""
        proc = self.proc
        if proc is None or proc.returncode is not None:
            return "already-ended"
        try:
            if proc.stdin is not None and not proc.stdin.is_closing():
                proc.stdin.close()                      # the polite end: Pi exits when its input closes
        except Exception:                               # noqa: BLE001
            pass
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), max(END_GRACE, self.end_grace))
            return "closed"
        except Exception:                               # noqa: BLE001
            pass
        for how, act in (("terminated", proc.terminate), ("killed", proc.kill)):
            try:
                act()
            except Exception:                           # noqa: BLE001
                continue
            try:
                await asyncio.wait_for(asyncio.shield(proc.wait()), KILL_GRACE)
                return how
            except Exception:                           # noqa: BLE001
                continue
        return "would-not-end"

    def session_end(self) -> Dict[str, Any]:
        r = self._receipt()
        c = dict(getattr(r, "counters", None) or {})
        end = {"requests": c.get("requests", 0), "sealed_bytes": c.get("plaintext_bytes_sealed_here", 0),
               "opened_bytes": c.get("response_bytes_opened_here", 0), "plaintext_left": 0,
               "export_command": f"ir probant export {self.matter}"}
        if self.dropped:
            # Names of event types only, never their content. A turn that ends in an event the page has no
            # word for is exactly the shape of the 17 Sep hang; this is the trail that names it next time.
            end["unrecognised"] = dict(sorted(self.dropped.items()))
        return end

    # ── the app ──
    def app(self):
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse, Response, StreamingResponse

        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        bridge = self

        install_guard(app, lambda: bridge.port, lambda: bridge.token)
        files = PageFiles(("index.html", "common.js", "app.js", "app.css"))
        static = files.handler

        app.get("/")(static("index.html", "text/html; charset=utf-8"))
        app.get("/common.js")(static("common.js", "text/javascript; charset=utf-8"))
        app.get("/app.js")(static("app.js", "text/javascript; charset=utf-8"))
        app.get("/app.css")(static("app.css", "text/css; charset=utf-8"))

        @app.get("/api/session")
        async def session():
            return {"matter": bridge.matter, "date_bound": bridge.date_bound, "trust": bridge.summary,
                    "mode": bridge.mode, "intake_id": bridge.intake_id,
                    "disclosure": disclosure_info(bridge.workspace), "busy": bridge.busy, "ended": bridge.ended,
                    "stalled": bridge.stalled, "search": bool(bridge.search_endpoint),
                    "search_timing": bridge.search_stats(), "now": round(time.time() * 1000),
                    # Where this session came from, so a finished session is not a dead end. Only what the
                    # launcher was told; a session started from a terminal has none and the page shows no link.
                    "home": os.environ.get("IR_PROBANT_HOME_URL", "")}

        @app.get("/api/intake/drafts")
        async def intake_drafts():
            if bridge.mode != "intake" or not bridge.intake_id:
                return JSONResponse({"error": "this is not a document reading"}, status_code=404)
            from . import probant_intake as I
            try:
                return {"drafts": await asyncio.to_thread(I.created_drafts, bridge.intake_id)}
            except (OSError, ValueError):
                return JSONResponse({"error": "the saved draft list could not be loaded; reopen this reading from home"}, status_code=500)

        @app.get("/api/documents")
        async def documents():
            """Every document this matter has opened, newest first, with the text as it was read.

            Served from the recorded archive, so it survives a restart and costs no sealed request to reopen —
            which is the whole point: Henry, 2026-10-01, "im not seeing any popup or list of opened patents we
            can come back to". Read-only, and the client's own material, so it is behind the session key like
            every other /api call.
            """
            docs = await asyncio.to_thread(pi_attested.matter_documents, bridge.records_dir)
            return {"documents": docs, "readings": bridge.readings}

        @app.get("/api/faults")
        async def faults():
            """Every turn this session lost, while it is still running. Token-gated like the rest.

            Not a user surface — the page never fetches this. It exists because the one thing missing when a
            live session kept failing was the failure itself: the raw string, and how long it had been quiet
            when it gave up. The lane's own receipt cannot answer it, and correctly so: a fault between the
            agent and this machine's verifying proxy never reaches the lane, so the receipt reads 0 errors
            while the page shows a failure on every turn. `ms_quiet` landing on the same number twice is a
            timer; scattered numbers are a busy provider.
            """
            return {"faults": bridge.faults, "turns": bridge.turns,
                    "now": round(time.time() * 1000), "busy": bridge.busy}

        @app.get("/api/disclosure")
        async def get_disclosure():
            try:
                text = (bridge.workspace / "disclosure.md").read_text(encoding="utf-8")
            except OSError:
                text = ""
            lines = text.splitlines()
            if lines and lines[0].strip() == "# Disclosure":
                text = "\n".join(lines[1:]).strip()
            return {"text": "" if "Describe the invention here" in text else text}

        @app.post("/api/disclosure")
        async def put_disclosure(request: Request):
            data = await body(request)
            text = str(data.get("text") or "")
            if len(text) > 200_000:
                return JSONResponse({"error": "that is too long for one disclosure"}, status_code=400)
            try:
                (bridge.workspace / "disclosure.md").write_text(f"# Disclosure\n\n{text.strip()}\n", encoding="utf-8")
            except OSError as e:
                return JSONResponse({"error": f"could not write the disclosure ({e.__class__.__name__})"}, status_code=500)
            return {"ok": True, "words": disclosure_info(bridge.workspace)["disclosure_words"]}

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
                    while not bridge.shutdown.is_set():
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
            if bridge.stalled:
                # A follow-up is delivered when the current turn finishes. A stalled turn never finishes, so
                # accepting one here is how "sending a new message doesn't work" looked from the page.
                return JSONResponse({"error": "The assistant is not responding, so this would not be delivered. "
                                              "Stop the current attempt first."}, status_code=409)
            # BUSY: hold it here rather than handing it to Pi as a followUp. Pi delivered a followUp at the
            # start of the NEXT turn, so a question sent while the assistant was working stayed undelivered
            # after it went idle and only moved when another message arrived — then both ran. The page
            # already shows these as waiting; now the thing it shows and the thing that is queued are the
            # same object, and this process decides when to deliver.
            if bridge.busy:
                bridge.pending_prompts.append(text)
                bridge.publish({"kind": "user", "text": text})
                return {"ok": True, "waiting": len(bridge.pending_prompts)}
            try:
                await bridge.send({"type": "prompt", "message": text})
            except RuntimeError as e:
                return JSONResponse({"error": str(e)}, status_code=409)
            bridge.publish({"kind": "user", "text": text})
            return {"ok": True}

        @app.post("/api/prompt/cancel")
        async def prompt_cancel(request: Request):
            """Take back a question that is still waiting for the assistant to finish."""
            data = await body(request)
            index, text = data.get("index"), data.get("text")
            if type(index) is not int or not isinstance(text, str):
                return JSONResponse({"error": "which question?"}, status_code=400)
            if not bridge.cancel_queued(index, text):
                return JSONResponse({"error": "It was already sent: the assistant has taken it up, so it cannot be taken back."},
                                    status_code=409)
            return {"ok": True, "waiting": len(bridge.pending_prompts)}

        @app.post("/api/abort")
        async def abort():
            """Stop the current turn — and say whether it actually stopped. Writing `abort` into the agent's
            input always succeeds; an agent that is wedged never acts on it, and answering {"ok": true}
            regardless is how the page came to show a stopped session as a working one."""
            try:
                await bridge.send({"type": "abort"})
            except RuntimeError as e:
                return JSONResponse({"error": str(e)}, status_code=409)
            return {"ok": True, "settled": await bridge.settle(ABORT_GRACE)}

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
            # A cleared mark is a row in the store's history and NOT a mark on the page: the professional
            # asked for no opinion on that document, so it must not appear in any count, chip or group.
            marks_now = {k: val for k, v in (state.get("marks") or {}).items()
                         if (val := ((v.get("latest") or {}).get("value"))) and val != CLEARED}
            # What each marked document is about, from every search recorded on this matter — so a mark made in
            # an EARLIER session still says what it marks, although its results are not on this page.
            titles = await asyncio.to_thread(pi_attested.matter_titles, bridge.records_dir, set(marks_now))
            return {"marks": marks_now, "titles": titles}

        @app.post("/api/mark")
        async def mark(request: Request):
            data = await body(request)
            key, value = str(data.get("key") or "").strip().upper(), str(data.get("mark") or "")
            if not PUB_RE.match(key) or value not in MARKS:
                return JSONResponse({"error": "not a publication number or mark"}, status_code=400)
            try:
                state = await asyncio.to_thread(_search_call, bridge.search_endpoint, "/matter/mark",
                                                {"key": key, "mark": value})
            except Exception:                                   # noqa: BLE001
                return JSONResponse({"error": "the search verifier did not record the mark"}, status_code=502)
            # READ BACK WHAT THE STORE NOW SAYS. The verifier ignores a value it does not recognise and
            # still answers 200 with the unchanged state, so a version of it that predates a mark value
            # would leave this page reporting a judgement the store never took — the page lying about a
            # human judgement, which is the one thing it must never do. Cheap, because the endpoint
            # already returns the whole state.
            landed = ((state.get("marks") or {}).get(key) or {}).get("latest") or {}
            if not isinstance(state, dict) or landed.get("value") != value:
                return JSONResponse(
                    {"error": f"this matter's search verifier did not accept '{value}'; the mark is "
                              f"unchanged" + (f" (still '{landed.get('value')}')" if landed.get("value") else "")},
                    status_code=409)
            return {"ok": True, "key": key, "mark": value, "cleared": value == CLEARED}

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
            return {"ok": True, "path": str(path), "verify_here": f"ir probant verify-export {path}",
                    "verify_anyone": ("python3 verify_record.py . --reference <InferRoute's reference> "
                                      "--reference-key <its key>")}

        from . import probant_audit_results
        proved: dict = probant_audit_results.restore(bridge.records_dir, bridge.matter)

        @app.post("/api/prove")
        async def prove():
            """Export the record and check it with its OWN verifier — the file a stranger would run — so the
            panel's claims come with proof the professional can see, not only our word. The verdict is the
            verifier's exit code (probant_check); this adds nothing to it."""
            from . import probant_check
            try:
                path = await asyncio.to_thread(bridge._export)
            except Exception as e:                              # noqa: BLE001
                return JSONResponse({"error": f"export failed: {e}"}, status_code=500)
            try:
                result = await asyncio.to_thread(probant_check.check, path)
            except Exception as e:                              # noqa: BLE001
                result = {"verdict": "refused", "headline": "The check could not be run.",
                          "explainer": type(e).__name__, "groups": [], "checks": 0}
            result.pop("output", None)
            proved["path"] = path
            proved.pop("pack", None)
            proved.pop("pack_identity", None)
            proved.pop("restore_error", None)
            probant_audit_results.remember(bridge.records_dir, None)
            return {"ok": True, "path": str(path), "check": result, "verify_anyone": ("python3 verify_record.py . --reference <InferRoute's reference> "
                                      "--reference-key <its key>")}

        @app.post("/api/audit-pack")
        async def audit_pack():
            """An evidence-only copy of the record just proven, for the professional's OWN AI to audit: no query,
            result or document text. The record is the one this page exported, never a path the page sends."""
            from . import probant_export
            from . import probant_audit_results
            # Offered in the panel from the start, so it exports and checks the record first when nothing has
            # been exported yet: a second opinion should be one click, not a sequence the professional has to
            # know. The record is always the one THIS page wrote — never a path the page sends.
            if not proved.get("path"):
                try:
                    proved["path"] = await asyncio.to_thread(bridge._export)
                except Exception as e:                          # noqa: BLE001
                    return JSONResponse({"error": f"export failed: {e}"}, status_code=500)
            try:
                pack = await asyncio.to_thread(probant_export.write_audit_pack, proved["path"])
                pack_identity = probant_audit_results.identity(pack)
            except Exception as e:                              # noqa: BLE001
                return JSONResponse({"error": f"the audit pack could not be written: {e}"}, status_code=500)
            prompt = probant_export.AUDIT_PROMPT
            proved["pack"] = str(pack)              # the folder a launch opens, so it never prepares a second
            proved["pack_identity"] = pack_identity
            proved.pop("restore_error", None)
            probant_audit_results.remember(bridge.records_dir, pack, Path(proved["path"]))
            return {"ok": True, "path": str(pack), "prompt": prompt, "pack_identity": pack_identity,
                    "can_launch": can_open_terminal(),
                    "claude": probant_export.audit_command("claude"),
                    "codex": probant_export.audit_command("codex"),
                    "ir": probant_export.audit_command("ir", ir_path=audit_ir_path() or "ir")}

        @app.get("/api/audit-results")
        async def audit_results():
            from . import probant_audit_results
            if not proved.get("pack"):
                rejected = ([{"file": "Saved audit", "reason": proved["restore_error"]}]
                            if proved.get("restore_error") else [])
                return {"results": [], "rejected": rejected, "prepared": False}
            # A new export may be prepared while the file reader is running. Return the identity
            # we actually read, so the page cannot attach yesterday's conclusions to the new pack.
            pack = Path(proved["pack"])
            expected = dict(proved["pack_identity"])
            got = await asyncio.to_thread(probant_audit_results.collect, pack, expected)
            return {**got, "prepared": True,
                    "pack": expected, "record": pack.name,
                    "attribution": "The auditor's report, not a new hardware verification."}

        @app.post("/api/audit-launch")
        async def audit_launch(request: Request):
            """Open a terminal on the prepared audit pack, running the chosen agent.

            The page sends WHICH agent, from three, and never a command. The command is built here from the
            same constants the copyable text uses, so the two can never say different things, and there is
            no string from the page anywhere in what gets run."""
            import subprocess
            from . import probant_export
            d = await body(request)
            agent = str(d.get("agent") or "")
            if agent not in ("claude", "codex", "ir"):
                return JSONResponse({"error": "unknown agent"}, status_code=400)
            pack = proved.get("pack")
            if not pack or not Path(pack).is_dir():
                return JSONResponse({"error": "prepare the audit pack first"}, status_code=409)
            import shutil
            ir_path = audit_ir_path() if agent == "ir" else None
            if (ir_path is None) if agent == "ir" else (not audit_agent_on_path(agent)):
                label = {"claude": "Claude", "codex": "Codex", "ir": "InferRoute"}[agent]
                return JSONResponse({"error": f"{label} isn't available on this computer. Install it, then try again."},
                                    status_code=409)
            command = probant_export.audit_command(agent, ir_path=ir_path or "ir")
            argv = terminal_argv(audit_launch_script(Path(pack), command))
            if argv is None:
                return JSONResponse({"error": "no terminal to open on this computer"}, status_code=501)
            try:
                # Detached on purpose: the audit outlives this page (see terminal_argv).
                subprocess.Popen(argv, start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as e:
                return JSONResponse({"error": f"the terminal did not open: {e}"}, status_code=500)
            return {"ok": True, "terminal": Path(argv[0]).name, "agent": agent}

        @app.post("/api/close")
        async def close_page():
            bridge.closed.set()
            return {"ok": True}

        @app.post("/api/end")
        async def end():
            """End the session. Closing the agent's input is the polite way and is usually enough; when it
            is not, this escalates rather than leaving the person with a page they cannot leave and a
            process only a shell can kill. The matter keeps everything either way."""
            return {"ok": True, "how": await bridge.stop_agent()}

        return app


OPENING_INSTRUCTION = ("Read document.txt in this directory, all of it, and propose each invention you find "
                       "with propose_matter. Then write your short answer for the professional.")
DRAFT_OPENING_INSTRUCTION = ("Read document.txt in this directory, all of it. Create a draft matter for each distinct "
                             "invention with create_draft_matter, preserving its full technical description and "
                             "supporting it with a passage from the source. Then give the professional a short summary "
                             "of the drafts actually created and anything that needs review.")


class Page:
    """The running page: its bridge and web server. `linger` keeps it up after the agent exits, so the
    record can still be exported from the page, until the person closes it or the time runs out."""

    def __init__(self, bridge: Bridge, server: Any, task: "asyncio.Task") -> None:
        self.bridge, self.server, self.task = bridge, server, task

    async def linger(self, console: Any, seconds: float | None = None) -> None:
        import select
        import sys
        seconds = float(os.environ.get("IR_PROBANT_WEB_LINGER", "1800")) if seconds is None else seconds
        mins = max(1, int(seconds // 60))
        console.print(f"[grey58]{ENDED_MARK} Press Enter here to close it "
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
        self.bridge.stop_streams()                     # or the graceful shutdown waits for the open tab
        self.server.should_exit = True
        await self.task


async def start(*, probant: Dict[str, Any], session: Any, search_endpoint: Optional[str], workspace: Path,
                console: Any) -> Page:
    """Start the bridge's web server and open the page. The agent is started by the launcher right after,
    with its stdin/stdout handed to `page.bridge.pump`."""
    import socket
    import uvicorn
    from . import pi_attested, probant_export, probant_trust
    from .probant import ProbantError, _split_matter, records_dir
    matter = probant.get("matter", "")
    mode = probant.get("mode", "matter")
    # A reading session has no matter: its label names the document. Nothing that belongs to a matter —
    # records, marks, an export — exists for it, so those are absent rather than pointed at a made-up name.
    client, name = ("", "")
    if mode != "intake":
        client, name = _split_matter(matter)

    def rebuild() -> Dict[str, Any]:
        found = pi_attested.search_verification(search_endpoint)
        return probant_trust.build(session.receipt, found, pi_attested.confinement_label(), matter=matter,
                                    date_bound=probant.get("date_bound", ""), surface="browser", mode=mode)

    def no_export() -> Path:
        raise ProbantError("this session is reading a document, not working a matter: open a matter from what "
                            "it proposes, and export that matter's record.")

    kept = (records_dir(client, name) / f"{pi_attested.LAST_SESSION_ID}.conversation.jsonl"
            if client and search_endpoint and pi_attested.LAST_SESSION_ID else None)
    bridge = Bridge(matter=matter, date_bound=probant.get("date_bound", ""), workspace=workspace,
                    summary=probant.get("summary") or {}, search_endpoint=search_endpoint,
                    receipt=lambda: session.receipt, rebuild_summary=rebuild,
                    export=(no_export if mode == "intake" else lambda: probant_export.write_bundle(client, name, None)),
                    conversation_file=kept,
                    records_dir=records_dir(client, name) if client else None,
                    mode=mode, intake_id=str(probant.get("intake") or ""))
    if kept is not None:
        bridge.publish({"kind": "conversation_kept"})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        bridge.port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(bridge.app(), host="127.0.0.1", port=bridge.port,
                                       log_level="critical", timeout_graceful_shutdown=5))
    task = asyncio.create_task(server.serve())
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.05)
    # A reading session opens itself: the professional handed over a document, not a conversation, and an
    # agent sitting at an empty prompt waiting to be told to read it is a page that looks broken.
    if mode == "intake":
        bridge.opening = str(probant.get("instruction") or
                             (DRAFT_OPENING_INSTRUCTION if probant.get("draft_client") else OPENING_INSTRUCTION))
        # A round of a cluster run has nobody at the keyboard: when its turn ends, the round is over, and
        # a session left open would hold the next round behind it.
        bridge.oneshot = bool(probant.get("oneshot"))
    url = open_url(bridge)
    opened = launch_browser(url)
    console.print(f"\n[bold]Open this session in your browser:[/]  {url}")
    console.print("[grey58]" + ("Opened it for you. " if opened else "") +
                  "The link works on this computer only and belongs to this session alone; don't share it.[/]\n")
    return Page(bridge, server, task)


def open_url(bridge: Bridge) -> str:
    return f"http://127.0.0.1:{bridge.port}/#k={bridge.token}"


def launch_browser(url: str) -> bool:
    if os.environ.get("IR_PROBANT_NO_BROWSER") == "1":
        return False
    import webbrowser
    try:
        return webbrowser.open(url, new=2)
    except Exception:                                           # noqa: BLE001
        return False
