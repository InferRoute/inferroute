"""Anteriora units on the client: a permit before a matter's first sealed session, settled when it ends.

OFF unless IR_ANTERIORA_BILLING=1 (a release turns it on once checkout is live), so nothing changes for
anyone until there is something to buy.

The unit is a MATTER, not a session: the first session on an invention matter (or a name matter) takes one
unit, and every later session on that matter for PERMIT_DAYS reuses the same permit. That first session
settles the permit:

* delivered — something the founder paid for came out of it: a search ran (invention matter) or
  name-check.md was written (name matter). The unit stays spent.
* failed — the session ended without either. The unit is given back, and the next session on the matter asks
  for a new permit.

What goes to the site: the unit type, the permit and the session id. Never the matter's name, title,
disclosure or anything the founder wrote. The permit is kept in the host-side matter record, which the
assistant cannot write.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

PERMIT_DAYS = 30
TIMEOUT = 15.0


class BillingError(Exception):
    pass


NO_UNITS_WORDS = ("You have no checks or searches left on this account. Buy more at inferroute.ai/anteriora, "
                  "then start again.")
DEVICE_LIMIT_WORDS = ("This account is already used on its maximum number of computers. Write to "
                      "support@inferroute.ai to move it to this one.")


def enabled() -> bool:
    return os.environ.get("IR_ANTERIORA_BILLING") == "1"


def _site() -> str:
    return os.environ.get("IR_SITE_BASE", "https://inferroute.ai").rstrip("/")


def _post(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    from . import config
    key = config.load().api_key
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
        raise BillingError(detail.get("error") or f"the account service answered {e.code}")
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


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def current_permit(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The matter's permit if it still covers new sessions: issued or delivered, and under PERMIT_DAYS old."""
    p = rec.get("permit")
    if not isinstance(p, dict) or p.get("state") not in ("issued", "delivered"):
        return None
    try:
        at = dt.datetime.fromisoformat(str(p["at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    return p if _now() - at < dt.timedelta(days=PERMIT_DAYS) else None


def before_session(rec: Dict[str, Any], session_id: str) -> Optional[Dict[str, Any]]:
    """Make sure the matter is covered; returns the permit, or None when billing is off. Raises BillingError
    (with the words to show) when the account has no unit left. Updates `rec` in place; the caller writes it."""
    if not enabled():
        return None
    held = current_permit(rec)
    if held:
        return held
    got = _post("/api/anteriora/permit", {"unit": unit_for(rec), "sessionId": session_id, "deviceId": device_id()})
    permit = {"id": str(got["permit"]), "unit": unit_for(rec), "state": "issued",
              "at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"), "first_session": session_id}
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
    permit issued; the next session tries again."""
    p = rec.get("permit")
    if not enabled() or not isinstance(p, dict) or p.get("state") != "issued":
        return None
    if p.get("first_session") != session_id and not was_delivered:
        return None
    try:
        got = _post("/api/anteriora/settle", {"permit": p["id"], "outcome": "delivered" if was_delivered else "failed",
                                              "sessionId": session_id})
    except BillingError:
        return None
    p["state"] = got.get("state") or p["state"]
    if p["state"] == "refunded":
        rec.pop("permit", None)                 # the next session asks for a new one
    return p["state"]
