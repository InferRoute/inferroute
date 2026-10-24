"""Anteriora's private, pinned Pi on its own Node (inferroute_cli/pi_runtime.py), and two launch defects found
with it on a fresh Linux install (23 Oct): relay socket paths too long for AF_UNIX under a long home, and
sessions started with the current folder on sys.path.

Offline: the "Node tarball" here is a stand-in whose `node` is a shell script playing npm and Pi."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from inferroute_cli import agents, pi_runtime

REPO = Path(__file__).resolve().parents[1]
GUEST_PI = REPO / "native" / "macos" / "guest" / "pi"


# ───────────────────────── the pins ─────────────────────────

def test_linux_pins_the_same_pi_as_the_mac_guest_and_the_lock_resolves_to_it():
    text = (REPO / "native" / "macos" / "guest" / "build_guest.py").read_text()
    assert re.search(r'^PI_VERSION = "([^"]+)"', text, re.M).group(1) == pi_runtime.PI_VERSION
    lock = json.loads((GUEST_PI / "package-lock.json").read_text())
    pkg = lock["packages"][f"node_modules/{pi_runtime.PI_PACKAGE}"]
    assert pkg["version"] == pi_runtime.PI_VERSION and pkg["integrity"].startswith("sha512-")
    assert json.loads((GUEST_PI / "package.json").read_text())["dependencies"] == {
        pi_runtime.PI_PACKAGE: pi_runtime.PI_VERSION}


def test_the_pinned_node_is_new_enough_for_the_pinned_pi():
    lock = json.loads((GUEST_PI / "package-lock.json").read_text())
    need = lock["packages"][f"node_modules/{pi_runtime.PI_PACKAGE}"]["engines"]["node"]
    floor = tuple(int(x) for x in need.lstrip(">=").split("."))
    assert tuple(int(x) for x in pi_runtime.NODE_VERSION.split(".")) >= floor
    assert set(pi_runtime.NODE_SHA256) == {"x64", "arm64"}
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in pi_runtime.NODE_SHA256.values())


def test_the_wheel_ships_the_lock_it_installs_from():
    text = (REPO / "pyproject.toml").read_text()
    assert '"native/macos/guest/pi/package-lock.json" = "inferroute_cli/pi_lock/package-lock.json"' in text
    assert '"native/macos/guest/pi/package.json" = "inferroute_cli/pi_lock/package.json"' in text
    pkg, lock = pi_runtime._lock_files()                    # found in the source tree too
    assert lock.read_bytes() == (GUEST_PI / "package-lock.json").read_bytes()


# ───────────────────────── the install, offline ─────────────────────────

FAKE_NODE = r"""#!/bin/sh
# Stands in for node. As `node npm-cli.js ci ...` it lays out Pi the way npm ci would; as `node cli.js --version`
# it is Pi answering. FAKE_NPM_FAIL / FAKE_PI_VERSION make it misbehave.
case "$1" in
  *npm-cli.js)
    [ -n "$FAKE_NPM_FAIL" ] && { echo "npm ERR! network" >&2; exit 1; }
    d=node_modules/@earendil-works/pi-coding-agent
    mkdir -p "$d/dist"
    printf '{"name":"@earendil-works/pi-coding-agent","version":"%s","bin":{"pi":"dist/cli.js"}}' "${FAKE_PI_VERSION:-0.84.1}" > "$d/package.json"
    echo "// pi" > "$d/dist/cli.js"
    pwd > "$HOME_MARK"
    ;;
  *cli.js) [ "$2" = "--version" ] && echo "${FAKE_PI_VERSION:-0.84.1}" ;;
esac
"""


def _fake_node_tarball(dest_dir: Path) -> Path:
    top = f"node-v{pi_runtime.NODE_VERSION}-linux-{pi_runtime.node_arch()}"
    out = dest_dir / f"v{pi_runtime.NODE_VERSION}" / f"{top}.tar.xz"
    out.parent.mkdir(parents=True)
    files = {"bin/node": (FAKE_NODE.encode(), 0o755), "lib/node_modules/npm/bin/npm-cli.js": (b"//", 0o644),
             "include/node/node.h": (b"", 0o644), "share/doc/node/x": (b"", 0o644)}
    with tarfile.open(out, "w:xz") as t:
        for rel, (data, mode) in files.items():
            info = tarfile.TarInfo(f"{top}/{rel}")
            info.size, info.mode = len(data), mode
            t.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo(f"{top}/bin/npm")
        link.type, link.linkname = tarfile.SYMTYPE, "../lib/node_modules/npm/bin/npm-cli.js"
        t.addfile(link)
    return out


@pytest.fixture
def offline(monkeypatch, tmp_path):
    if not pi_runtime.supported():
        pytest.skip("the private runtime is installed on Linux x64/arm64 only")
    dist = tmp_path / "dist"
    tarball = _fake_node_tarball(dist)
    monkeypatch.setenv("IR_NODE_DIST", dist.as_uri())
    monkeypatch.setenv("IR_PI_RUNTIME_DIR", str(tmp_path / "rt"))
    monkeypatch.setenv("HOME_MARK", str(tmp_path / "npm-ran-in"))
    monkeypatch.setitem(pi_runtime.NODE_SHA256, pi_runtime.node_arch(),
                        hashlib.sha256(tarball.read_bytes()).hexdigest())
    monkeypatch.setattr(pi_runtime.time, "sleep", lambda s: None)
    return tmp_path


def test_install_lays_out_a_complete_pinned_runtime_and_keeps_only_what_runs(offline):
    said = []
    pi = pi_runtime.install(said.append)
    d = pi_runtime.install_dir()
    assert pi == str(d / "bin" / "pi") == pi_runtime.installed_binary()
    assert subprocess.run([pi, "--version"], capture_output=True, text=True).stdout.strip() == pi_runtime.PI_VERSION
    assert os.readlink(d / "bin" / "node") == "../node/bin/node"      # Pi's children get this node first
    assert json.loads((d / pi_runtime.STAMP).read_text())["pi"] == pi_runtime.PI_VERSION
    # npm ran in the runtime's own folder, from the shipped lock — never a global install.
    assert (offline / "npm-ran-in").read_text().strip().endswith("/lib")
    assert (d / "lib" / "package-lock.json").read_bytes() == (GUEST_PI / "package-lock.json").read_bytes()
    for gone in ("node/include", "node/share", "node/lib/node_modules/npm", "node/bin/npm"):
        assert not os.path.lexists(d / gone), gone
    assert [p.name for p in Path(os.environ["IR_PI_RUNTIME_DIR"]).iterdir()] == [pi_runtime.DIR_NAME]
    assert any("Pi 0.84.1" in s for s in said) and not any("npm" in s for s in said)
    assert pi_runtime.install(said.append) == pi                      # idempotent: nothing downloaded again


def test_a_tarball_that_does_not_match_its_fingerprint_is_refused_and_leaves_nothing(offline, monkeypatch):
    monkeypatch.setitem(pi_runtime.NODE_SHA256, pi_runtime.node_arch(), "0" * 64)
    with pytest.raises(pi_runtime.SetupFailed) as e:
        pi_runtime.install(lambda s: None)
    assert "fingerprint" in str(e.value) and "npm" not in str(e.value)
    assert pi_runtime.installed_binary() is None
    assert list(Path(os.environ["IR_PI_RUNTIME_DIR"]).iterdir()) == []


@pytest.mark.parametrize("env", [{"FAKE_NPM_FAIL": "1"}, {"FAKE_PI_VERSION": "1.4.0"}])
def test_a_failed_or_drifted_pi_install_is_never_used(offline, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(pi_runtime.SetupFailed) as e:
        pi_runtime.install(lambda s: None)
    assert str(e.value) == pi_runtime.NEEDS_CONNECTION_WORDS
    assert pi_runtime.installed_binary() is None
    assert list(Path(os.environ["IR_PI_RUNTIME_DIR"]).iterdir()) == []


def test_an_unreachable_download_says_check_the_connection(offline, monkeypatch, tmp_path):
    monkeypatch.setenv("IR_NODE_DIST", (tmp_path / "nowhere").as_uri())
    with pytest.raises(pi_runtime.SetupFailed) as e:
        pi_runtime.install(lambda s: None)
    assert "internet connection" in str(e.value) and "nowhere" in e.value.detail


def test_the_runtime_lives_in_the_apps_own_folder_by_default(monkeypatch):
    monkeypatch.delenv("IR_PI_RUNTIME_DIR", raising=False)
    r = pi_runtime.root()
    if sys.prefix != sys.base_prefix and os.access(sys.prefix, os.W_OK):
        assert r == Path(sys.prefix) / "assistant"
    else:
        assert r.parts[-2:] == ("inferroute", "assistant")


# ───────────────────────── repair at session start ─────────────────────────

def test_an_anteriora_session_installs_a_missing_pi_instead_of_naming_npm(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(agents, "find_agent", lambda a: None)
    monkeypatch.setattr(agents, "warn_clipboard_once", lambda: None)
    monkeypatch.setattr(pi_runtime, "supported", lambda: True)
    monkeypatch.setattr(pi_runtime, "install", lambda say: str(tmp_path / "pi"))
    assert agents.binary_for("pi", repair=True) == str(tmp_path / "pi")
    assert "Setting up the assistant program" in capsys.readouterr().out


def test_a_repair_that_fails_exits_with_plain_words_the_page_can_show(monkeypatch, capsys):
    from inferroute_cli import probant_home as H

    def boom(say):
        raise pi_runtime.SetupFailed(pi_runtime.NEEDS_CONNECTION_WORDS, "timed out")
    monkeypatch.setattr(agents, "find_agent", lambda a: None)
    monkeypatch.setattr(agents, "warn_clipboard_once", lambda: None)
    monkeypatch.setattr(pi_runtime, "supported", lambda: True)
    monkeypatch.setattr(pi_runtime, "install", boom)
    with pytest.raises(SystemExit) as e:
        agents.binary_for("pi", repair=True)
    assert e.value.code == 127
    out = capsys.readouterr()
    msg = H.failure_message((out.out + out.err).splitlines())
    assert msg.startswith(pi_runtime.NEEDS_CONNECTION_WORDS) and "npm" not in msg


def test_plain_ir_pi_does_not_install_anything_by_itself(monkeypatch):
    monkeypatch.setattr(agents, "find_agent", lambda a: None)
    monkeypatch.setattr(agents, "warn_clipboard_once", lambda: None)
    monkeypatch.setattr(pi_runtime, "install", lambda say: pytest.fail("installed without being asked"))
    with pytest.raises(SystemExit):
        agents.binary_for("pi")


# ───────────────────────── the two launch defects ─────────────────────────

def test_relay_sockets_fit_af_unix_under_a_long_home(monkeypatch, tmp_path):
    """A home path of ~65 characters made <cfg>/tmp/netns/<port>.sock longer than sun_path allows."""
    from inferroute_local import confinement, netns
    monkeypatch.setattr(confinement, "netns_bind_available", lambda: True)
    cfg = tmp_path / ("a-rather-long-home-directory-name-" * 3) / ".config" / "inferroute" / "pi-session"
    cfg.mkdir(parents=True)
    assert len(str(cfg / "tmp" / "netns" / "65535.sock")) > netns.UNIX_PATH_MAX
    box = netns.NetnsSandbox(ports=[65535], cfg_dir=str(cfg), rw=[str(cfg)])
    try:
        sock = box._maps[65535]
        assert len(sock) <= netns.UNIX_PATH_MAX and stat.S_ISSOCK(os.stat(sock).st_mode)
        assert stat.S_IMODE(os.stat(box.relay_dir).st_mode) == 0o700
        cmd = box.wrap(["true"])
        i = cmd.index(box.relay_dir)
        assert cmd[i - 1] == "--ro-bind" and cmd[i + 1] == box.relay_dir   # the sandbox can reach it
    finally:
        box.close()
    assert not os.path.exists(box.relay_dir)


def test_short_socket_dir_skips_a_runtime_dir_that_is_itself_too_long(monkeypatch, tmp_path):
    from inferroute_local import netns
    long_dir = tmp_path / ("x" * 100)
    long_dir.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(long_dir))
    d = netns.short_socket_dir()
    try:
        assert d.startswith("/tmp/ir-") and stat.S_IMODE(os.stat(d).st_mode) == 0o700
    finally:
        os.rmdir(d)


def test_isolated_mode_keeps_a_folder_named_like_the_package_from_shadowing_it(tmp_path):
    shadow = tmp_path / "inferroute_cli"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("")
    (shadow / "__main__.py").write_text("print('THE WRONG COPY')\n")
    plain = subprocess.run([sys.executable, "-m", "inferroute_cli", "--version"], cwd=tmp_path,
                           capture_output=True, text=True)
    isolated = subprocess.run([sys.executable, "-I", "-m", "inferroute_cli", "--version"], cwd=tmp_path,
                              capture_output=True, text=True)
    assert "THE WRONG COPY" in plain.stdout                          # the defect, as it was
    assert "THE WRONG COPY" not in isolated.stdout and isolated.returncode == 0
