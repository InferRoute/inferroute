"""Choose a repository from GitHub (Henry, 19 Oct: "could we have them also select the repo that way and have that
be the primary option?").

Through the Anteriora GitHub App, not an OAuth app: an OAuth app that reads private code needs the `repo` scope,
which also grants WRITE to every repository the person has. The App has repository contents READ and metadata
READ, nothing else, and on github.com the person chooses which repositories it may see.

Sign-in is GitHub's device flow: GitHub shows the person a page where they type a short code, so no secret is
shipped in this program and nothing listens for a redirect. The token is kept in ~/.inferroute/github.json (0600)
and used for two things only: listing the repositories the App was given, and copying the one chosen. It reaches
git through the environment, never a command line or the copy's own config, so the copy on disk holds no token.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import probant as S

# Public identifiers of the Anteriora GitHub App, registered 20 Oct 2026 under the InferRoute organization (app id
# 5388584). A client id is not a secret: the device flow is built for apps that cannot keep one. The environment
# may override both for testing; an empty client id means the option is not offered.
CLIENT_ID = os.environ.get("IR_GITHUB_APP_CLIENT_ID", "Iv23likDCihz10aAgxka")
SLUG = os.environ.get("IR_GITHUB_APP_SLUG", "anteriora")
DEVICE_PAGE = "https://github.com/login/device"
API = "https://api.github.com"
UA = "Anteriora"

_pending: Dict[str, Any] = {}          # the one device-flow sign-in in progress (device_code stays here, not the page)


def configured() -> bool:
    return bool(CLIENT_ID)


def install_page() -> str:
    return f"https://github.com/apps/{SLUG}/installations/new" if SLUG else ""


def _store() -> Path:
    return S._irhome() / "github.json"


def _post(url: str, data: Dict[str, str]) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                 headers={"accept": "application/json", "user-agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b"{}")
        except ValueError:
            raise S.ProbantError(f"GitHub answered {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise S.ProbantError(f"Could not reach GitHub: {getattr(e, 'reason', e)}")


def _get(path: str, token: str) -> Any:
    req = urllib.request.Request(API + path, headers={"accept": "application/vnd.github+json", "user-agent": UA,
                                                      "authorization": f"Bearer {token}",
                                                      "x-github-api-version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            _forget()
            raise S.ProbantError("GitHub no longer accepts this sign-in. Connect GitHub again.")
        raise S.ProbantError(f"GitHub answered {e.code} for {path}")
    except (urllib.error.URLError, OSError) as e:
        raise S.ProbantError(f"Could not reach GitHub: {getattr(e, 'reason', e)}")


def _save(tok: Dict[str, Any], login: str) -> None:
    now = time.time()
    rec = {"access_token": tok["access_token"], "login": login,
           "expires_at": now + int(tok["expires_in"]) if tok.get("expires_in") else None}
    path = _store()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f)


def _forget() -> None:
    try:
        _store().unlink()
    except FileNotFoundError:
        pass


def _token() -> Optional[Dict[str, Any]]:
    try:
        rec = json.loads(_store().read_text())
    except (FileNotFoundError, ValueError):
        return None
    if rec.get("expires_at") and rec["expires_at"] < time.time() + 60:
        # Refreshing needs the App's secret, which a program on the person's computer must not hold; a new
        # device sign-in is one short code away.
        _forget()
        return None
    return rec


def status() -> Dict[str, Any]:
    rec = _token() if configured() else None
    return {"configured": configured(), "connected": bool(rec), "login": (rec or {}).get("login", ""),
            "pending": bool(_pending), "install_page": install_page(), "device_page": DEVICE_PAGE}


def connect() -> Dict[str, Any]:
    """Start a sign-in: GitHub gives a short code the person types at github.com/login/device."""
    if not configured():
        raise S.ProbantError("GitHub is not set up in this version of Anteriora.")
    r = _post("https://github.com/login/device/code", {"client_id": CLIENT_ID})
    if "device_code" not in r:
        raise S.ProbantError(f"GitHub did not start the sign-in: {r.get('error_description') or r.get('error') or r}")
    _pending.clear()
    _pending.update(device_code=r["device_code"], interval=int(r.get("interval", 5)),
                    expires=time.time() + int(r.get("expires_in", 900)), next=0.0)
    return {"user_code": r["user_code"], "device_page": r.get("verification_uri") or DEVICE_PAGE,
            "interval": _pending["interval"]}


def poll() -> Dict[str, Any]:
    """Whether the person has typed the code yet. The page calls this every few seconds; GitHub is asked no
    more often than it allows."""
    if not _pending:
        return {"status": "connected" if _token() else "none", "login": (_token() or {}).get("login", "")}
    now = time.time()
    if now > _pending["expires"]:
        _pending.clear()
        return {"status": "expired"}
    if now < _pending["next"]:
        return {"status": "pending"}
    r = _post("https://github.com/login/oauth/access_token",
              {"client_id": CLIENT_ID, "device_code": _pending["device_code"],
               "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
    err = r.get("error")
    if err == "slow_down":
        _pending["interval"] = int(r.get("interval", _pending["interval"] + 5))
    if err in ("authorization_pending", "slow_down"):
        _pending["next"] = now + _pending["interval"]
        return {"status": "pending"}
    if err:
        _pending.clear()
        return {"status": "denied" if err == "access_denied" else "expired", "message": r.get("error_description", err)}
    _pending.clear()
    login = _get("/user", r["access_token"]).get("login", "")
    _save(r, login)
    return {"status": "connected", "login": login}


def disconnect() -> None:
    """Forget the sign-in on this computer. (Revoking it at GitHub is under Settings → Applications.)"""
    _pending.clear()
    _forget()


def repos() -> Dict[str, Any]:
    """The repositories the person gave the App, newest push first."""
    rec = _token()
    if not rec:
        raise S.ProbantError("Connect GitHub first.")
    out: List[Dict[str, Any]] = []
    for inst in _get("/user/installations?per_page=100", rec["access_token"]).get("installations", []):
        page = 1
        while page <= 10:
            got = _get(f"/user/installations/{inst['id']}/repositories?per_page=100&page={page}", rec["access_token"])
            for r in got.get("repositories", []):
                out.append({"full_name": r["full_name"], "private": bool(r.get("private")),
                            "pushed_at": r.get("pushed_at") or "", "description": (r.get("description") or "")[:140]})
            if len(got.get("repositories", [])) < 100:
                break
            page += 1
    out.sort(key=lambda r: r["pushed_at"], reverse=True)
    return {"repos": out, "login": rec.get("login", ""), "install_page": install_page()}


def clone_url(full_name: str) -> str:
    parts = full_name.split("/")
    if len(parts) != 2 or not all(p and p.strip(".") and not p.startswith("-")
                                  and all(c.isalnum() or c in "-_." for c in p) for p in parts):
        raise S.ProbantError("Choose a repository from the list.")
    return f"https://github.com/{full_name}.git"


def git_env() -> Dict[str, str]:
    """The token for git, as configuration in the ENVIRONMENT (git reads GIT_CONFIG_* there): not on a command
    line other programs can list, and not written into the copy's .git/config."""
    rec = _token()
    if not rec:
        raise S.ProbantError("Connect GitHub first.")
    basic = base64.b64encode(f"x-access-token:{rec['access_token']}".encode()).decode()
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}
