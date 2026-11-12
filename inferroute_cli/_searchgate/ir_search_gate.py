"""The sealed search verifier, launched through InferRoute's search gate.

    python -m ir_search_gate serve --enclave https://<gate host> ...      (the same arguments as
                                                                            sealedresearch.search_verifier)

WHY A WRAPPER. The verifier (sealedresearch.search_verifier) is vendored byte for byte from sealed-research and a test
holds it to the canonical copy, so it is not edited here. It reaches the search machine through one method,
Verifier._call. When the search address is the gate, this module replaces that one method before handing the command
line to the verifier's own main(); everything else, the attestation above all, runs unchanged.

WHAT THE GATE GETS, AND WHERE IT GOES. A POST /search to the gate carries the user's Anteriora key (x-api-key) and,
when billing is on, the permit of the search unit the session took (x-inferroute-permit). Only to the gate: the host
must be exactly one of GATE_HOSTS, over https, on the default port, and no redirect is followed (a 3xx is an error,
never a second request with the key on it). A direct address (the machine's own http://<ip>:8000) gets neither,
whatever this module is told: a key sent there would go to whoever answers at that address. The credentials come from
the launcher on stdin, one JSON line, so they are in no command line and no environment variable.

NOTHING ABOUT THE GATE IS TRUSTED. GET /offer through the gate is the machine's evidence unchanged, and the verifier
checks it exactly as it checks a direct one; the request body is sealed to the attested key before the gate sees it,
and the answer is opened and its signature checked here. A gate that lied would fail those checks, never pass them.

ITS REFUSALS ARE NOT VERIFICATION FAILURES. A refusal from the gate (inferroute_local.confidential.billing_refusal,
parse_search) is about the account, the permit or the service: 402/401/413 are final, 429/503 are asked once more after
Retry-After (capped at 30 s; 160 s for a search waiting for another one to finish on the machine). The verdict then
says what the gate said, under a step of its own (GATE_STEP), and carries `gate_refusal`, so no page reads it as "the
machine could not be verified". The one exception is search_unavailable on /offer: the machine is not answering, and
the verdict says so in the verifier's own words for that ("nothing answered"), which every page shows as offline.
"""
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

# The gate's exact hosts. Not "anything under run.app": a lookalike, a subdomain or a suffix is a direct address and
# gets no key. probant_search_setup imports this list; it is not repeated anywhere.
GATE_HOSTS = ("ir-search-gate-851040540464.europe-west4.run.app",)
KEY_HEADER = "x-api-key"
PERMIT_HEADER = "x-inferroute-permit"
GATE_STEP = "search service let the search through"
REACHABLE_STEP = "search enclave reachable"         # the verifier's own first step (probant_trust.REACHABLE_STEP)
SLOT_WAIT_CAP_S = 160.0                             # the machine's survey slot is 150 s; the gate says what is left
MAX_CRED = 512


def gate_base(url: Any) -> Optional[str]:
    """https://<gate host> when `url` is exactly the gate, None for anything else (a direct address included)."""
    if not isinstance(url, str):
        return None
    try:
        s = urlsplit(url.strip())
        host, port = s.hostname or "", s.port
    except ValueError:
        return None
    if (s.scheme != "https" or s.username or s.password or port is not None or s.path not in ("", "/")
            or s.query or s.fragment or host not in GATE_HOSTS or s.netloc.lower() != host):
        return None
    return f"https://{host}"


def _billing_refusal():
    """inferroute_local.confidential.billing_refusal: imported when this interpreter has the package, otherwise
    loaded from the file beside this one (a development config runs the verifier under sealed-research's own
    interpreter, which does not have inferroute installed)."""
    try:
        from inferroute_local.confidential import billing_refusal
        return billing_refusal
    except ImportError:
        path = Path(__file__).resolve().parents[2] / "inferroute_local" / "confidential" / "billing_refusal.py"
        spec = importlib.util.spec_from_file_location("_ir_billing_refusal", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        return mod


BR = _billing_refusal()


class GateRefused(Exception):
    """The gate refused (after the one retry, where there is one). Carries the parsed refusal and the route."""

    def __init__(self, refusal: Any, path: str):
        super().__init__(refusal.sentence)
        self.refusal, self.path = refusal, path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):              # the key never follows a redirect: a 3xx is an error here
        return None


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _may_have_reached_the_machine(code: str) -> bool:
    """The gate counts a search AFTER the machine answered, and withholds the answer when the count is refused
    (permit used up) or cannot be made (billing unavailable). The code does not say which side of the machine it
    came from, so a permit or billing refusal on /search may follow an answer the machine made and this computer
    never received."""
    return code.startswith("permit_") or code.startswith("billing_") or code == "out_of_credits"


class Gate:
    """The transport to the gate, for one verifier process. Per-thread state, because the verifier serves several
    requests at once (ThreadingHTTPServer)."""

    def __init__(self, base: str, key: str = "", permit: str = "", *, sleep: Callable[[float], None] = time.sleep,
                 say: Optional[Callable[[str], None]] = None, opener: Any = None, used_up_file: str = ""):
        if gate_base(base) != base:
            raise ValueError("not the search gate")
        self.base = base
        self.key = str(key or "").strip()[:MAX_CRED]
        self.permit = str(permit or "").strip()[:64]
        self.sleep = sleep
        self.say = say or (lambda s: sys.stderr.write(f"ir-search-gate: {s}\n"))
        self.opener = opener or urllib.request.build_opener(_NoRedirect)
        self._tl = threading.local()
        # Where to tell the launcher the permit is used up (it settles it delivered, then takes a new unit next time).
        self.used_up_file = str(used_up_file or "")

    # ---- per-request state
    def begin(self) -> None:
        self._tl.refused, self._tl.notes, self._tl.withheld, self._tl.slot = None, [], None, False

    def _state(self):
        if not hasattr(self._tl, "notes"):
            self.begin()
        return self._tl

    def headers(self, method: str, path: str) -> Dict[str, str]:
        """The key and permit go on POST /search and on nothing else (GET /offer is public)."""
        if method != "POST" or path != "/search":
            return {}
        out: Dict[str, str] = {}
        if self.key:
            out[KEY_HEADER] = self.key
        if self.permit:
            out[PERMIT_HEADER] = self.permit
        return out

    def call(self, url: str, method: str, path: str, body: Optional[bytes], timeout: float) -> bytes:
        if gate_base(url) != self.base:                 # belt and braces: never the key to another address
            raise ValueError("not the search gate")
        st = self._state()
        for attempt in (0, 1):
            hdrs = {"content-type": "application/octet-stream"} if body is not None else {}
            hdrs.update(self.headers(method, path))
            req = urllib.request.Request(self.base + path, data=body, method=method, headers=hdrs)
            try:
                with self.opener.open(req, timeout=timeout) as fh:
                    return fh.read()
            except urllib.error.HTTPError as e:
                try:
                    raw = e.read(65536)
                except Exception:                       # noqa: BLE001
                    raw = b""
                r = BR.parse_search(e.code, e.headers, raw)
                if r is None:
                    raise                               # the machine's own answer, passed through: as if direct
                # The gate says whether the machine answered: x-inferroute-forwarded 1 = it did and the reply is
                # withheld (a search happened), 0 = refused before forwarding. A gate that predates the header is
                # read by the code, as before (_may_have_reached_the_machine).
                fwd = BR._headers_lower(e.headers).get("x-inferroute-forwarded", "").strip()
                answered = path == "/search" and (fwd == "1" if fwd in ("0", "1")
                                                  else _may_have_reached_the_machine(r.code))
                if answered:
                    st.withheld = r.code
                # Never replay a sealed request the machine already answered: forwarded=1 is final.
                if attempt == 0 and r.retryable and fwd != "1":
                    self.sleep(self._wait(r, path, st))
                    continue
                if attempt == 1 and r.code == "rate_limited" and path == "/search" and getattr(st, "slot", False):
                    r.fixed = BR.SEARCH_STILL_RUNNING   # "yours will start when it finishes" is no longer true
                if r.final and r.code in BR.PERMIT_REFUSAL_CODES:
                    self._signal_permit_refusal(r.code)
                st.refused = GateRefused(r, path)
                raise st.refused
        raise AssertionError("unreachable")            # pragma: no cover

    def _signal_permit_refusal(self, code: str) -> None:
        """Tell the launcher which permit the gate refused, and how (used up, or dead: invalid, expired, ...). The
        permit is the one THIS process sent, so the launcher acts on that permit and on no other."""
        if not (self.used_up_file and self.permit):
            return
        try:
            Path(self.used_up_file).write_text(json.dumps({"permit": self.permit, "code": code}), encoding="utf-8")
        except OSError:
            pass

    def _wait(self, r: Any, path: str, st: Any) -> float:
        slot = r.code == "rate_limited" and path == "/search"
        st.slot = slot and ("another search" in r.server_message.lower()
                            or (r.retry_after or 0) > BR.RETRY_AFTER_CAP_S)
        if r.retry_after is None:
            secs = BR.RETRY_AFTER_DEFAULT_S
        else:
            secs = min(max(0.0, float(r.retry_after)), SLOT_WAIT_CAP_S if slot else BR.RETRY_AFTER_CAP_S)
        if slot and secs > BR.RETRY_AFTER_CAP_S:
            note = f"another search is running, waiting {int(round(secs))} s"
        else:
            note = f"{r.sentence} Waiting {int(round(secs))} s, then asking once more."
        st.notes.append(note)
        self.say(note)
        return secs

    # ---- the verdict
    def finish(self, out: Dict[str, Any]) -> Dict[str, Any]:
        st = self._state()
        refused, notes, withheld = st.refused, list(st.notes), st.withheld
        self.begin()
        if not isinstance(out, dict):
            return out
        if refused is None:
            if notes:
                out["gate_notes"] = notes
            if withheld and "_unanswered" not in out:
                s = out.get("statement") if isinstance(out.get("statement"), dict) else {}
                out["_unanswered"] = {"request_id": s.get("request_id"), "lifetime_id": s.get("lifetime_id"),
                                      "reason": self._withheld_reason(withheld), "at": _utcnow()}
            return out
        r = refused.refusal
        steps: List[Dict[str, Any]] = [s for s in (out.get("steps") or []) if isinstance(s, dict) and s.get("ok")]
        if refused.path == "/offer" and r.code == "search_unavailable":
            detail = ("nothing answered — InferRoute's search service says the search machine is not answering "
                      "(it may be starting). This is a connection failure, NOT a failed verification")
            steps = [{"ok": False, "step": REACHABLE_STEP, "detail": detail}]
            refusal = f"{REACHABLE_STEP}: {detail}"
        else:
            steps.append({"ok": False, "step": GATE_STEP, "detail": r.sentence})
            refusal = r.sentence
        new = {k: v for k, v in out.items() if k not in ("_unanswered", "_evidence", "_reply_to", "result")}
        new.update(ok=False, steps=steps, refusal=refusal,
                   gate_refusal={"status": r.status, "code": r.code, "final": r.final, "path": refused.path})
        if notes:
            new["gate_notes"] = notes
        un = out.get("_unanswered")
        if withheld and isinstance(un, dict):
            new["_unanswered"] = {**un, "reason": self._withheld_reason(withheld)}
        return new

    @staticmethod
    def _withheld_reason(code: str) -> str:
        return (f"InferRoute's search service refused or withheld the answer ({code}); the search machine may have "
                "answered before the refusal")


def install(verifier_cls: Any, gate: Gate) -> None:
    """Route verifier_cls's transport through `gate` for the gate's own address, and only for it."""
    original = verifier_cls._call

    def _call(self, method: str, path: str, body: Optional[bytes] = None) -> bytes:
        if gate_base(self.url) != gate.base:
            return original(self, method, path, body)
        return gate.call(self.url, method, path, body, self.timeout)

    verifier_cls._call = _call
    for name in ("verify", "search", "document"):
        inner = getattr(verifier_cls, name)

        def wrapped(self, *a, _inner=inner, **k):
            if gate_base(self.url) != gate.base:
                return _inner(self, *a, **k)
            gate.begin()
            return gate.finish(_inner(self, *a, **k))

        wrapped.__name__ = name
        setattr(verifier_cls, name, wrapped)


def read_credentials(stream: Any) -> Dict[str, str]:
    """One JSON line {"key", "permit"} from the launcher. Nothing (a terminal, an empty pipe) means none."""
    try:
        if stream is None or stream.isatty():
            return {}
        line = stream.readline(4096)
        doc = json.loads(line) if line and line.strip() else {}
    except (OSError, ValueError, AttributeError):
        return {}
    if not isinstance(doc, dict) or not doc:
        return {}
    return {k: str(doc.get(k) or "") for k in ("key", "permit", "used_up_file")}


def enclave_arg(argv: List[str]) -> str:
    for i, a in enumerate(argv):
        if a == "--enclave" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--enclave="):
            return a.split("=", 1)[1]
    return ""


def main(argv: Optional[List[str]] = None, stdin: Any = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    from sealedresearch import search_verifier as SV
    base = gate_base(enclave_arg(argv))
    if base:
        creds = read_credentials(sys.stdin if stdin is None else stdin)
        install(SV.Verifier, Gate(base, creds.get("key", ""), creds.get("permit", ""),
                                  used_up_file=creds.get("used_up_file", "")))
    return SV.main(argv)


if __name__ == "__main__":
    sys.exit(main())
