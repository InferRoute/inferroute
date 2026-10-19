"""Choosing a repository from GitHub through the read-only Anteriora App (19 Oct). GitHub's answers are
simulated; what is checked is what this program does with them: the device flow waits as GitHub asks, the
token is kept 0600 and reaches git only through the environment, and a refused or revoked sign-in is forgotten."""
import json
import os
import stat
import subprocess

import pytest

from inferroute_cli import github_link as G
from inferroute_cli import probant as S
from inferroute_cli import probant_repo as R


@pytest.fixture
def gh(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setattr(G, "CLIENT_ID", "Iv1.test")
    monkeypatch.setattr(G, "SLUG", "anteriora")
    G._pending.clear()
    answers = []
    monkeypatch.setattr(G, "_post", lambda url, data: answers.pop(0))
    monkeypatch.setattr(G, "_get", lambda path, token: {"login": "ada"} if path == "/user" else {})
    return answers


def test_not_offered_until_the_app_is_registered(monkeypatch):
    monkeypatch.setattr(G, "CLIENT_ID", "")
    assert G.status()["configured"] is False
    with pytest.raises(S.ProbantError):
        G.connect()


def test_device_flow_waits_then_keeps_the_token_private(gh, tmp_path, monkeypatch):
    gh += [{"device_code": "dev", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device",
            "interval": 5, "expires_in": 900},
           {"error": "authorization_pending"},
           {"access_token": "ghu_secret", "expires_in": 28800}]
    assert G.connect()["user_code"] == "ABCD-1234"
    assert G.poll()["status"] == "pending"
    assert G.poll()["status"] == "pending" and len(gh) == 1          # not asked again before the interval
    G._pending["next"] = 0
    assert G.poll() == {"status": "connected", "login": "ada"}
    f = tmp_path / "ir" / "github.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and json.loads(f.read_text())["access_token"] == "ghu_secret"
    assert G.status()["connected"] and G.status()["login"] == "ada"


def test_a_declined_sign_in_keeps_nothing(gh, tmp_path):
    gh += [{"device_code": "dev", "user_code": "X", "interval": 5, "expires_in": 900}, {"error": "access_denied"}]
    G.connect(); G._pending["next"] = 0
    assert G.poll()["status"] == "denied" and not (tmp_path / "ir" / "github.json").exists()


def test_an_expired_token_is_forgotten_rather_than_refreshed_with_a_secret(gh, tmp_path):
    G._save({"access_token": "old", "expires_in": 1}, "ada")
    assert G.status()["connected"] is False and not (tmp_path / "ir" / "github.json").exists()


def test_only_a_listed_repository_name_becomes_a_clone_address():
    assert G.clone_url("ada/engine") == "https://github.com/ada/engine.git"
    for bad in ["ada", "ada/engine/x", "../x", "ada/eng ine", "ada/$(id)", "ada/..", "-x/engine", "ada/engine/"]:
        with pytest.raises(S.ProbantError):
            G.clone_url(bad)


def test_the_token_reaches_git_by_environment_and_never_lands_in_the_copy(gh, tmp_path, monkeypatch):
    G._save({"access_token": "ghu_secret"}, "ada")
    env = G.git_env()
    assert "ghu_secret" not in json.dumps(env)                       # base64 inside an auth header, not the bare token
    seen = {}
    real = subprocess.run
    def spy(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw.get("env", {})
        os.makedirs(R.clone_dir(cmd[-2]) / ".git", exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(R.subprocess, "run", spy)
    R.fetch(G.clone_url("ada/engine"), True, env)
    assert not any("ghu_" in part or "extraheader" in part or "AUTHORIZATION" in part for part in seen["cmd"])
    assert seen["env"]["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
