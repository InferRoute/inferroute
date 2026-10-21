"""A git repository as an intake source (Anteriora, 19 Oct).

What a founder cannot check by eye, and so what is checked here: that nothing outside the chosen commit is
read (the working tree, untracked files, ignored files), that keys and credential files never reach the
staged text, that a repository's own config cannot make git run a program, and that the dates on a draft
come from git on this computer, at the quoted lines, not from the model.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_intake as I
from inferroute_cli import probant_repo as R

ENGINE = '''"""Adaptive debounce for sensor bursts."""


def debounce(samples, window):
    # INVENTION-MARKER: widen the window while the variance of the last burst is above threshold,
    # so a vibrating contact settles without a fixed delay.
    out = []
    for s in samples:
        out.append(s)
    return out
'''


def git(repo, *args, env_extra=None, date="2024-03-01T10:00:00Z"):
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", **(env_extra or {})}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    return tmp_path


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "gadget"
    (r / "src").mkdir(parents=True)
    git(r.parent, "init", "-q", str(r))
    (r / "README.md").write_text("# Gadget\nA sensor hub.\n")
    (r / "src" / "engine.py").write_text("def debounce(samples, window):\n    return samples\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "first", date="2024-03-01T10:00:00Z")
    (r / "src" / "engine.py").write_text(ENGINE)
    (r / ".env").write_text("DATABASE_URL=postgres://u:hunter2hunter2@db/x\n")
    (r / "config.py").write_text('API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz012345"\n')
    (r / "node_modules" / "left").mkdir(parents=True)
    (r / "node_modules" / "left" / "index.js").write_text("module.exports = 1\n")
    (r / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\0\0\0")
    (r / "package-lock.json").write_text("{}\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "second", date="2025-06-15T09:00:00Z")
    # After the commit: neither of these may be read.
    (r / "src" / "engine.py").write_text(ENGINE + "\n# WORKTREE-ONLY change\n")
    (r / "untracked.py").write_text("UNTRACKED = True\n")
    return r


def test_only_the_commit_is_read_and_everything_left_out_is_named(repo):
    text, info = R.snapshot(str(repo))
    assert text.startswith(R.HEADER)
    assert "INVENTION-MARKER" in text and "WORKTREE-ONLY" not in text and "UNTRACKED" not in text
    assert "hunter2" not in text and "sk-live" not in text and "module.exports" not in text
    read = {f["path"] for f in info["files"]}
    assert read == {"README.md", "src/engine.py"}
    left = {row["path"]: row["reason"] for row in info["excluded"]}
    assert left[".env"] == "environment file"
    assert left["config.py"].startswith("contains what looks like a")
    assert left["node_modules/left/index.js"] == "dependency or build folder"
    assert left["logo.png"] == "binary file" and left["package-lock.json"] == "lock file"
    # The listing names the rule, never the secret.
    assert "sk-live" not in json.dumps(info) and "hunter2" not in json.dumps(info)
    # Offsets map back to each file exactly.
    for f in info["files"]:
        body = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{f['path']}"], capture_output=True,
                              text=True).stdout
        assert text[f["start"]:f["end"]] == body


def test_an_earlier_commit_can_be_chosen(repo):
    text, info = R.snapshot(str(repo), "HEAD~1")
    assert "INVENTION-MARKER" not in text and info["commit"] == git(repo, "rev-parse", "HEAD~1").strip()


def test_a_repository_config_cannot_make_git_run_a_program(repo, tmp_path):
    flag = tmp_path / "ran"
    hook = tmp_path / "evil.sh"
    hook.write_text(f"#!/bin/sh\ntouch {flag}\n")
    hook.chmod(0o755)
    git(repo, "config", "core.fsmonitor", str(hook))
    git(repo, "config", "core.pager", str(hook))
    R.snapshot(str(repo))
    assert not flag.exists()


def test_secret_shapes_are_caught_and_ordinary_code_is_not():
    assert R.secret_kind("-----BEGIN OPENSSH PRIVATE KEY-----\nabc") == "private key"
    assert R.secret_kind("key = AKIAABCDEFGHIJKLMNOP") == "AWS access key"
    assert R.secret_kind("token: ghp_" + "a" * 36) == "GitHub token"
    assert R.secret_kind('password = "Zq8vB2nX4mP7rT1wK9yL"') == "assigned secret"
    assert R.secret_kind("url = postgres://admin:s3cretpass@db.internal/app") == "connection string with password"
    assert R.secret_kind("def password_strength(pw):\n    return len(pw) > 12\n") is None
    assert R.secret_kind("API_KEY = os.environ['API_KEY']") is None


def test_a_remote_url_never_keeps_embedded_credentials(repo):
    git(repo, "remote", "add", "origin", "https://user:tok3n@github.com/acme/gadget.git")
    _, info = R.snapshot(str(repo))
    assert info["remotes"] == ["https://github.com/acme/gadget.git"]
    assert any("public disclosure" in line for line in R.public_notice(info))


def test_a_folder_that_is_not_a_repository_is_refused(tmp_path):
    with pytest.raises(S.ProbantError, match="is not a git repository.*git init"):
        R.snapshot(str(tmp_path))


def test_a_draft_from_a_repository_is_located_and_dated_by_git_not_by_the_model(home, repo):
    text, info = R.snapshot(str(repo))
    meta = I.stage(text, "gadget", extra=info)
    assert meta["kind"] == "repo" and meta["commit"] == info["commit"]
    assert meta["sha256"] and meta["chars"] == len(text)          # computed keys are never replaced by extra
    creator = I.DraftCreator(meta["id"], "Personal")
    row = creator.create({"title": "Variance-adaptive debounce",
                          "summary": "A debounce window that widens while the burst variance is high.",
                          "quote": "INVENTION-MARKER: widen the window while the variance of the last burst is above threshold,"})
    c, m = S._split_matter(row["id"])
    rec = S.load_record(c, m)
    where = rec["intake_origin"]["repo"]
    assert where["file"] == "src/engine.py" and where["commit"] == info["commit"]
    assert where["lines"][0] == where["lines"][1] == 5
    assert where["file_added"].startswith("2024-03-01")             # the file existed from the first commit
    assert where["lines_dated"] == ["2025-06-15", "2025-06-15"]     # these lines took their form in the second
    disclosure = (S.workspace_path(c, m) / "disclosure.md").read_text()
    assert "src/engine.py, lines 5–5" in disclosure
    assert "not proof of an invention date" in disclosure


def test_a_staged_snapshot_cannot_be_overwritten_by_extra_keys(home):
    meta = I.stage("REPOSITORY SNAPSHOT\nbody\n", "x", extra={"sha256": "forged", "id": "forged", "kind": "repo"})
    assert meta["sha256"] != "forged" and meta["id"] != "forged" and meta["kind"] == "repo"


def test_only_reads_the_chosen_folders(repo):
    text, info = R.snapshot(str(repo), only=["src/"])
    assert {f["path"] for f in info["files"]} == {"src/engine.py"} and info["only"] == ["src"]
    assert "A sensor hub" not in text


def test_the_home_page_previews_before_it_stages_and_refuses_a_moved_commit(home, repo, monkeypatch):
    from fastapi.testclient import TestClient
    from inferroute_cli import probant_home as H
    monkeypatch.setenv("INFERROUTE_API_KEY", "inf_SYNTHETIC")
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    started = []
    monkeypatch.setattr(h.launches, "start", lambda *a, **k: started.append((a, k)) or {"id": "x"})
    monkeypatch.setattr(h.launches, "view", lambda it: it)
    r = c.post("/api/intake/repo", json={"path": str(repo)}).json()
    assert r["files"] == 2 and any(".env" in line for line in r["preview"])
    assert not I.intake_root().exists() or not any(I.intake_root().iterdir())     # the preview staged nothing
    assert not started
    moved = c.post("/api/intake/repo", json={"path": str(repo), "confirm": True, "commit_seen": "0" * 40})
    assert moved.status_code == 409 and not started
    ok = c.post("/api/intake/repo", json={"path": str(repo), "confirm": True, "commit_seen": r["commit"]}).json()
    assert ok["ok"] and len(started) == 1 and I.meta_of(ok["id"])["kind"] == "repo"


# ── choosing the repository: a folder picker and a git link (Henry, 19 Oct) ──

def test_the_folder_picker_lists_folder_names_and_marks_repositories(repo, tmp_path):
    (tmp_path / "plain").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "a-file.txt").write_text("x")
    r = R.list_dirs(str(tmp_path))
    names = {d["name"]: d["git"] for d in r["dirs"]}
    assert names.get("gadget") is True and names.get("plain") is False
    assert ".hidden" not in names and "a-file.txt" not in names
    assert r["parent"] == str(tmp_path.parent)
    assert R.list_dirs(str(repo))["git"] is True
    with pytest.raises(S.ProbantError):
        R.list_dirs(str(tmp_path / "a-file.txt"))


@pytest.mark.parametrize("bad", ["file:///etc", "/home/me/repo", "ext::sh -c touch% /tmp/pwned",
                                 "--upload-pack=touch /tmp/pwned", "https://", "ftp://example.com/r.git"])
def test_a_git_link_that_is_not_https_or_ssh_is_refused_before_git_runs(home, bad):
    with pytest.raises(S.ProbantError, match="git link"):
        R.fetch(bad)
    assert not (home / "ir" / "repos").exists()


def test_a_git_link_is_copied_once_refreshed_on_preview_and_read_like_a_folder(home, repo, monkeypatch):
    # The real fetch allows only https and ssh; a local clone stands in for the server here.
    monkeypatch.setattr(R, "_URL", __import__("re").compile(r".+"))
    monkeypatch.setattr(R, "CLONE_SAFE", ["-c", "protocol.file.allow=always"])
    url = f"file://{repo}"
    dest = R.fetch(url)
    assert dest.name == "gadget" and str(dest).startswith(str(home / "ir" / "repos"))
    text, info = R.snapshot(str(dest))
    assert "INVENTION-MARKER" in text and "WORKTREE-ONLY" not in text and info["repo_name"] == "gadget"
    first = info["commit"]
    (repo / "src" / "more.py").write_text("NEW = 1\n")
    git(repo, "add", "src/more.py")
    git(repo, "commit", "-q", "-m", "third", date="2025-07-01T09:00:00Z")
    assert R.snapshot(str(R.fetch(url, refresh=False)))[1]["commit"] == first     # confirm reads what was previewed
    assert R.snapshot(str(R.fetch(url)))[1]["commit"] != first                    # a new preview sees the new commit


def test_a_git_link_git_cannot_reach_says_how_to_sign_in(home, monkeypatch):
    monkeypatch.setenv("GIT_SSH_COMMAND", "false")
    with pytest.raises(S.ProbantError, match="signed in"):
        R.fetch("git@example.invalid:me/private.git")


def test_test_code_is_left_out_unless_its_folder_is_named(repo):
    (repo / "tests").mkdir()
    (repo / "tests" / "test_engine.py").write_text("def test_x():\n    assert True\n")
    (repo / "src" / "engine_test.py").write_text("X = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "tests", date="2025-07-01T09:00:00Z")
    _, info = R.snapshot(str(repo))
    taken = {f["path"] for f in info["files"]}
    left = {row["path"]: row["reason"] for row in info["excluded"]}
    assert "src/engine.py" in taken
    assert left["tests/test_engine.py"] == "test code" and left["src/engine_test.py"] == "test code"
    _, named = R.snapshot(str(repo), only=["tests"])
    assert {f["path"] for f in named["files"]} == {"tests/test_engine.py"}


def test_a_repository_too_large_offers_its_folders_and_splits_one_too_large_alone(repo):
    _, info = R.snapshot(str(repo))
    whole = R.folder_choices(info, 10_000_000)
    assert [c["label"] for c in whole][:1] == ["src"] and whole[-1]["label"] == "files at the top level"
    assert whole[-1]["paths"] == ["README.md"]
    (repo / "src" / "deep").mkdir()
    (repo / "src" / "deep" / "a.py").write_text("A = 1\n" * 50)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "deep", date="2025-07-02T09:00:00Z")
    _, info = R.snapshot(str(repo))
    split = {c["label"]: c["paths"] for c in R.folder_choices(info, 100)}
    assert split["src/deep"] == ["src/deep"] and split["src (files directly in it)"] == ["src/engine.py"]
    text = "x" * 4_000_001
    assert "Tick the folders" in R.describe(info, text, "page")[1] and "--only" in R.describe(info, text)[1]
