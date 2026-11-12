"""Anteriora units on the client: a permit before a matter's first sealed session, settled when it ends.

ON when the account service says so: its balance answers `billing: "units"`. It is asked once per launch and
the answer kept for BALANCE_TTL seconds. No answer (offline, no key, an older service) means OFF, which is what
every release before this one did. IR_ANTERIORA_BILLING=1 or =0 overrides the answer, for tests only.

The unit is a MATTER, not a session: the first session on an invention matter (or a name matter) takes one
unit, and every later session on that matter for PERMIT_DAYS reuses the same permit. That first session
settles the permit:

* delivered — something the founder paid for came out of it: a search ran (invention matter) or
  name-check.md was written (name matter). The unit stays spent.
* failed — the session ended without either. The unit is given back, and the next session on the matter asks
  for a new permit.

A READING (a document or a repository read for proposals) has no matter: each reading takes one search unit,
keyed by its intake id, and its permit is kept in the host-side intake record. It is delivered when the reading
produced proposals or draft matters.

A CLUSTER run (`anteriora cluster`, many sealed sessions over one folder) is billed as one reading, keyed by its
cluster id: every session of the run, workers and synthesis included, uses the run's permit while that permit is
live (current_permit), and otherwise takes one search unit. Its record is kept host-side under
confidential/cluster-permits/, never in the cluster folder, which the sessions work in.

The permit id also goes with the sealed session: a header on the relay's gated routes (candidates, nonces,
invoke) and nowhere else, so the gateway can see the session is covered by a unit and charge no AI credit for it.
It is not in usage reports: the relay logs it on invoke rows only.

What goes to the site: the unit type, the permit and the session id. Never the matter's name, title,
disclosure or anything the founder wrote. The permit is kept in the host-side matter record, which the
assistant cannot write.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

PERMIT_DAYS = 30
ISSUED_HOURS = 6                # the service refunds a permit left unsettled this long; never reuse one past it
TIMEOUT = 15.0
BALANCE_TTL = 300.0             # seconds an answer about billing is kept: "once per launch, briefly"
BALANCE_TIMEOUT = 5.0           # a slow answer must not hold a launch up; no answer means OFF
GONE = (404, 410)               # settle answers meaning "this permit is not yours, or no longer exists"


class BillingError(Exception):
    def __init__(self, message: str = "", status: int = 0):
        super().__init__(message)
        self.status = status


NO_UNITS_WORDS = ("You have no checks or searches left on this account. Buy more at inferroute.ai/anteriora, "
                  "then start again.")
DEVICE_LIMIT_WORDS = ("This account is already used on its maximum number of computers. Write to "
                      "support@inferroute.ai to move it to this one.")


_answer: Optional[tuple] = None          # (monotonic time, on?) — the account service's last word on billing


def enabled() -> bool:
    """Whether sessions need a unit permit: what the account service says, cached for BALANCE_TTL."""
    global _answer
    override = os.environ.get("IR_ANTERIORA_BILLING")
    if override in ("0", "1"):
        return override == "1"
    now = time.monotonic()
    if _answer is not None and now - _answer[0] < BALANCE_TTL:
        return _answer[1]
    try:
        on = _get("/api/anteriora/balance").get("billing") == "units"
    except BillingError:
        on = False
    _answer = (now, on)
    return on


def _key() -> str:
    from . import config
    return config.load().api_key or ""


def _account_tag() -> str:
    """Which key took a permit, so a permit taken under one account is never reused under another. A short
    hash of the key, kept on this computer only."""
    key = _key()
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else ""


def _get(path: str) -> Dict[str, Any]:
    key = _key()
    if not key:
        raise BillingError("no key")
    req = urllib.request.Request(_site() + path, method="GET", headers={"authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=BALANCE_TIMEOUT) as r:
            got = json.loads(r.read() or b"{}")
    except (urllib.error.URLError, OSError, ValueError) as e:     # HTTPError is a URLError
        raise BillingError(str(e), getattr(e, "code", 0) or 0)
    return got if isinstance(got, dict) else {}


def _site() -> str:
    return os.environ.get("IR_SITE_BASE", "https://inferroute.ai").rstrip("/")


def _post(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    key = _key()
    if not key:
        raise BillingError("Add your InferRoute key first.")
    req = urllib.request.Request(_site() + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", "authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}")
        except ValueError:
            detail = {}
        # The app's own words for the two answers a founder can act on, not the site's (22 Oct). The site's
        # 403 sent people to "your account page", which does not exist yet; and the home page recognises
        # these two sentences (probant_home.failure_message) to show them in place of "Something went wrong".
        if e.code == 402 or detail.get("needsPurchase"):
            raise BillingError(NO_UNITS_WORDS)
        if e.code == 403 and detail.get("deviceLimit"):
            raise BillingError(DEVICE_LIMIT_WORDS)
        raise BillingError(detail.get("error") or f"the account service answered {e.code}", e.code)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise BillingError(f"could not reach the account service ({getattr(e, 'reason', e)}); try again")


def device_id() -> str:
    """A random id for this installation, made once and kept owner-only. It identifies nothing about the
    machine; it only lets a subscription count its devices."""
    import secrets
    from . import probant as S
    path = S._irhome() / "device-id"
    try:
        value = path.read_text().strip()
        if len(value) == 32:
            return value
    except OSError:
        pass
    value = secrets.token_hex(16)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(value)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return value


def unit_for(rec: Dict[str, Any]) -> str:
    return "name_check" if rec.get("kind") == "name" else "search"


def _request_for(rec: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    body = {"unit": unit_for(rec), "sessionId": session_id, "deviceId": device_id()}
    if rec.get("kind") == "reading":
        body.update(kind="reading", intake_id=str(rec["intake"]))
    return body


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def current_permit(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The matter's permit if it still covers new sessions: delivered and under PERMIT_DAYS old, or issued and
    under ISSUED_HOURS old (past that the service has given the unit back, and the permit covers nothing)."""
    p = rec.get("permit")
    if not isinstance(p, dict) or p.get("state") not in ("issued", "delivered"):
        return None
    try:
        at = dt.datetime.fromisoformat(str(p["at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    limit = dt.timedelta(hours=ISSUED_HOURS) if p.get("state") == "issued" else dt.timedelta(days=PERMIT_DAYS)
    return p if _now() - at < limit else None


def before_session(rec: Dict[str, Any], session_id: str) -> Optional[Dict[str, Any]]:
    """Make sure the matter is covered; returns the permit, or None when billing is off. Raises BillingError
    (with the words to show) when the account has no unit left. Updates `rec` in place; the caller writes it."""
    if not enabled():
        return None
    account = _account_tag()
    held = current_permit(rec)
    if held and held.get("account", account) == account:
        return held
    got = _post("/api/anteriora/permit", _request_for(rec, session_id))
    permit = {"id": str(got["permit"]), "unit": unit_for(rec), "state": "issued",
              "at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"), "first_session": session_id, "account": account}
    rec["permit"] = permit
    return permit


def delivered(rec: Dict[str, Any], workspace: Path, searches_before: set, searches_after: set,
              started: float) -> bool:
    if rec.get("kind") == "name":
        out = workspace / "name-check.md"
        return out.is_file() and out.stat().st_mtime >= started and out.stat().st_size > 0
    return bool(searches_after - searches_before)


def after_session(rec: Dict[str, Any], session_id: str, was_delivered: bool) -> Optional[str]:
    """Settle the permit the FIRST session took. Later sessions on a matter settle nothing. Returns the
    permit's new state, or None if there was nothing to settle. A failure to reach the service leaves the
    permit issued; the next session tries again.

    Not gated on enabled(): an issued permit means billing was on when the session began, and a session can
    outlast the cached answer. Leaving it unsettled would let the service refund a unit that was used.

    A settle that fails for good — the permit is not this account's, or no longer exists — drops it, so the
    next session asks for a new one instead of reusing a permit the service will not honour. So does an answer
    that the permit was already refunded (the service refunds permits left unsettled for hours)."""
    p = rec.get("permit")
    if not isinstance(p, dict) or p.get("state") != "issued":
        return None
    if p.get("first_session") != session_id and not was_delivered:
        return None
    try:
        got = _post("/api/anteriora/settle", {"permit": p["id"], "outcome": "delivered" if was_delivered else "failed",
                                              "sessionId": session_id})
    except BillingError as e:
        if e.status in GONE:
            rec.pop("permit", None)
            return "gone"
        return None
    p["state"] = got.get("state") or p["state"]
    if p["state"] == "refunded":
        rec.pop("permit", None)                 # the next session asks for a new one
    return p["state"]


# ───────────────────────── readings ─────────────────────────
# A reading has no matter record, so its permit lives in the host-side intake record (outside the reading
# session's write scope), one file per intake.

def _reading_path(intake_id: str, cluster: bool = False) -> Path:
    if cluster:
        import re
        from . import probant as S
        if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", intake_id or ""):
            raise S.ProbantError("no such cluster")
        return S._irhome() / "confidential" / "cluster-permits" / f"{intake_id}.json"
    from . import probant_intake as I
    return I.authority_dir(intake_id) / "permit.json"


def load_reading(intake_id: str, cluster: bool = False) -> Dict[str, Any]:
    """The reading's record: an intake's, or with `cluster` a cluster run's (one reading of a whole folder)."""
    rec: Dict[str, Any] = {"kind": "reading", "intake": intake_id}
    if cluster:
        rec["cluster"] = True
    try:
        p = json.loads(_reading_path(intake_id, cluster).read_text(encoding="utf-8")).get("permit")
        if isinstance(p, dict):
            rec["permit"] = p
    except (OSError, ValueError, AttributeError):
        pass
    return rec


def save_reading(rec: Dict[str, Any]) -> None:
    path = _reading_path(str(rec["intake"]), bool(rec.get("cluster")))
    if "permit" not in rec:
        try:
            path.unlink()
        except OSError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"permit": rec["permit"]}), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def reading_delivered(intake_id: str) -> bool:
    """A reading delivered something when it left proposals that check against the document, or created
    draft matters. A reading that produced neither gives its unit back."""
    from . import probant_intake as I
    try:
        return bool(I.created_drafts(intake_id) or I.read_proposals(intake_id))
    except Exception:
        return False
