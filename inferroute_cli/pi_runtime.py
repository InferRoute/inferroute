"""Anteriora's own copy of the assistant program (Pi) and the Node runtime it runs on, on Linux.

A fresh Linux computer has no Pi, often no npm, and the Node its package manager offers can be too old for
Pi (Ubuntu 22.04/24.04 ship Node 18; Pi 0.84.1 needs 22.19 or later). An unpinned `npm install -g` would
also pull whatever Pi is newest, not the release this client was tested with. So the app keeps its own:

  * Node, the official release tarball from nodejs.org, pinned by version AND sha256 per architecture,
    refused unless the downloaded bytes match;
  * Pi, installed with `npm ci` from the committed lock (the same one the Mac's virtual machine is built
    from), so every package is checked against the lock's integrity hash; install scripts and optional
    native modules are skipped, exactly as in that build.

Everything goes in one versioned folder under the app's own data directory (the installed environment, or
~/.local/share/inferroute when that is not writable). No sudo, no change to system Node, global npm or the
person's shell. A half-finished install is never used: the folder is assembled under a temporary name and
renamed into place only after `pi --version` answers with the pinned version.

The installer runs `anteriora setup-assistant` once; a session that finds Pi missing runs the same install
(agents.binary_for(..., repair=True)). On a Mac nothing here is used: Pi runs inside the virtual machine,
which carries its own pinned Pi and Node.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

# The Pi release this client is tested with. It must equal the Mac guest's pin (native/macos/guest), and
# the lock below must resolve to it; tests/test_pi_runtime.py holds the three together.
PI_VERSION = "0.84.1"
PI_PACKAGE = "@earendil-works/pi-coding-agent"

# Node.js 24 "Krypton", the active LTS line (Pi needs >= 22.19). 24.22.1 is the 20 Oct 2026 security release.
# The hashes are nodejs.org's own SHASUMS256.txt for that release.
NODE_VERSION = "24.22.1"
NODE_SHA256 = {
    "x64": "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6",
    "arm64": "dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e",
}
NODE_DIST = "https://nodejs.org/dist"
DOWNLOAD_MB = 56                       # Node's tarball (32 MB) and Pi's libraries (24 MB); about 300 MB unpacked

DIR_NAME = f"pi-{PI_VERSION}-node-{NODE_VERSION}"
STAMP = "installed.json"

# What a person reads when this cannot be done. No npm, no command: the app runs the install itself.
NEEDS_CONNECTION_WORDS = ("Anteriora could not set up its assistant program on this computer, so no session "
                          "can start. Check the internet connection and try again. Nothing was sent.")
REINSTALL_WORDS = ("Part of Anteriora is missing on this computer, so no session can start. Run the Anteriora "
                   "installer again. Nothing was sent.")
NO_ROOM_WORDS = ("Anteriora could not write its assistant program to this computer's disk (it needs about 300 MB), "
                 "so no session can start. Nothing was sent.")


class SetupFailed(RuntimeError):
    """The private Pi could not be installed. str() is safe to show; .detail is for "Technical details"."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


def node_arch() -> Optional[str]:
    m = platform.machine().lower()
    return {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(m)


def supported() -> bool:
    return sys.platform.startswith("linux") and node_arch() in NODE_SHA256


def root() -> Path:
    """Where the app keeps its runtime. The installed environment first, so `rm -rf ~/anteriora` removes it
    with everything else; a read-only environment (a system-wide install) falls back to the user's data dir."""
    override = os.environ.get("IR_PI_RUNTIME_DIR")
    if override:
        return Path(override)
    prefix = Path(sys.prefix)
    if sys.prefix != sys.base_prefix and os.access(prefix, os.W_OK):
        return prefix / "assistant"
    data = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return data / "inferroute" / "assistant"


def install_dir() -> Path:
    return root() / DIR_NAME


def installed_binary() -> Optional[str]:
    """The private Pi, only if a COMPLETE install of the pinned versions is there."""
    d = install_dir()
    pi = d / "bin" / "pi"
    try:
        stamp = json.loads((d / STAMP).read_text())
    except (OSError, ValueError):
        return None
    if stamp.get("pi") != PI_VERSION or stamp.get("node") != NODE_VERSION:
        return None
    if pi.is_file() and os.access(pi, os.X_OK) and (d / "node" / "bin" / "node").is_file():
        return str(pi)
    return None


def _lock_files() -> tuple[Path, Path]:
    """package.json + package-lock.json: shipped in the wheel, or read from the source tree in development."""
    for d in (Path(__file__).resolve().parent / "pi_lock",
              Path(__file__).resolve().parents[1] / "native" / "macos" / "guest" / "pi"):
        if (d / "package.json").is_file() and (d / "package-lock.json").is_file():
            return d / "package.json", d / "package-lock.json"
    raise SetupFailed(REINSTALL_WORDS, "the pinned Pi lock file is missing from this installation")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _download(url: str, dest: Path, say: Callable[[str], None]) -> None:
    last: Exception | None = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "anteriora-setup"})
            with urllib.request.urlopen(req, timeout=60) as r, dest.open("wb") as out:
                shutil.copyfileobj(r, out, 1 << 20)
            return
        except OSError as e:          # URLError and socket timeouts are OSErrors
            last = e
            if attempt < 3:
                say("  the connection dropped; trying again ...")
                time.sleep(2 * (attempt + 1))
    raise SetupFailed(NEEDS_CONNECTION_WORDS, f"download of {url} failed: {last}")


def _extract_node(tarball: Path, into: Path) -> None:
    """Unpack the Node tarball, its top folder stripped, refusing any member that would land outside."""
    into.mkdir(parents=True)
    with tarfile.open(tarball, "r:xz") as t:
        members = []
        for m in t.getmembers():
            parts = Path(m.name).parts
            if len(parts) < 2:
                continue
            m.name = str(Path(*parts[1:]))
            members.append(m)
        if hasattr(tarfile, "data_filter"):
            t.extractall(into, members=members, filter="data")
        else:                                                  # Python without extraction filters
            base = into.resolve()
            for m in members:
                target = (into / m.name).resolve()
                if not str(target).startswith(str(base) + os.sep) or m.isdev():
                    raise SetupFailed(NEEDS_CONNECTION_WORDS, f"unsafe member in the Node tarball: {m.name}")
                if m.issym() and os.path.isabs(m.linkname):
                    raise SetupFailed(NEEDS_CONNECTION_WORDS, f"absolute link in the Node tarball: {m.name}")
            t.extractall(into, members=members)


def _clean_env(node_bin: Path, cache: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
    env.update(PATH=os.pathsep.join([str(node_bin), "/usr/bin", "/bin"]),
               npm_config_cache=str(cache), npm_config_update_notifier="false",
               npm_config_fund="false", npm_config_audit="false")
    for k in ("NODE_OPTIONS", "NODE_PATH"):
        env.pop(k, None)
    return env


def _wrapper(final: Path, cli: str) -> str:
    return ("#!/bin/sh\n"
            "# Anteriora's pinned Pi, on Anteriora's own Node. Written by inferroute_cli.pi_runtime.\n"
            f'exec "{final}/node/bin/node" "{final}/lib/node_modules/{PI_PACKAGE}/{cli}" "$@"\n')


def install(say: Callable[[str], None] = print, *, force: bool = False) -> str:
    """Install the pinned Node and Pi; return the path of the private `pi`. Idempotent."""
    if not supported():
        raise SetupFailed("Anteriora cannot set up its assistant program on this kind of computer.",
                          f"unsupported platform {sys.platform}/{platform.machine()}")
    have = installed_binary()
    if have and not force:
        return have
    arch = node_arch()
    assert arch is not None
    pkg_json, lock_json = _lock_files()
    base = root()
    final = base / DIR_NAME
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise SetupFailed(NO_ROOM_WORDS, str(e)) from e
    stage = Path(tempfile.mkdtemp(prefix=".setup-", dir=base))
    try:
        name = f"node-v{NODE_VERSION}-linux-{arch}.tar.xz"
        tarball = stage / name
        say(f"Downloading the Node runtime for the assistant (Node {NODE_VERSION}, about 32 MB) ...")
        _download(f"{os.environ.get('IR_NODE_DIST', NODE_DIST)}/v{NODE_VERSION}/{name}", tarball, say)
        got = _sha256(tarball)
        if got != NODE_SHA256[arch]:
            raise SetupFailed("The downloaded Node runtime did not match its fingerprint, so it was not used. "
                              "Try again; if it happens again, tell InferRoute. Nothing was sent.",
                              f"{name}: sha256 {got}, expected {NODE_SHA256[arch]}")
        _extract_node(tarball, stage / "node")
        tarball.unlink()
        node = stage / "node" / "bin" / "node"
        npm_cli = stage / "node" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
        lib = stage / "lib"
        lib.mkdir()
        shutil.copyfile(pkg_json, lib / "package.json")
        shutil.copyfile(lock_json, lib / "package-lock.json")
        say(f"Installing the assistant program (Pi {PI_VERSION}) from its pinned list ...")
        env = _clean_env(node.parent, stage / "npm-cache")
        r = subprocess.run([str(node), str(npm_cli), "ci", "--omit=optional", "--ignore-scripts", "--no-audit",
                            "--no-fund", "--loglevel=error"], cwd=lib, env=env, capture_output=True, text=True,
                           timeout=900)
        if r.returncode != 0:
            raise SetupFailed(NEEDS_CONNECTION_WORDS, "npm ci failed: " + (r.stdout + r.stderr)[-1500:])
        meta = json.loads((lib / "node_modules" / PI_PACKAGE / "package.json").read_text())
        if meta.get("version") != PI_VERSION:
            raise SetupFailed(NEEDS_CONNECTION_WORDS, f"Pi resolved to {meta.get('version')}, not {PI_VERSION}")
        bin_field = meta.get("bin")
        cli = bin_field.get("pi") if isinstance(bin_field, dict) else bin_field
        if not cli:
            raise SetupFailed(NEEDS_CONNECTION_WORDS, "the Pi package names no `pi` program")
        # Only what runs is kept: npm was needed for the install alone (a repair downloads it again), and the
        # headers and manual pages are never used. About a third of the unpacked size.
        shutil.rmtree(stage / "npm-cache", ignore_errors=True)
        for rel in ("include", "share", "lib/node_modules/npm", "lib/node_modules/corepack",
                    "bin/npm", "bin/npx", "bin/corepack"):
            p = stage / "node" / rel
            if p.is_symlink() or p.is_file():
                p.unlink()
            elif p.is_dir():
                shutil.rmtree(p)
        (stage / "bin").mkdir()
        wrapper = stage / "bin" / "pi"
        wrapper.write_text(_wrapper(final, str(cli).lstrip("./")))
        wrapper.chmod(0o755)
        os.symlink("../node/bin/node", stage / "bin" / "node")   # Pi's own children find this node first
        if final.exists():
            shutil.rmtree(final)
        os.rename(stage, final)
        stage = final
        v = subprocess.run([str(final / "bin" / "pi"), "--version"], capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, PATH=os.pathsep.join([str(final / "bin"), os.environ.get("PATH", "")])))
        if v.stdout.strip() != PI_VERSION:
            shutil.rmtree(final, ignore_errors=True)
            raise SetupFailed(NEEDS_CONNECTION_WORDS,
                              f"pi --version answered {v.stdout.strip()!r} {v.stderr.strip()[-300:]!r}")
        (final / STAMP).write_text(json.dumps({"pi": PI_VERSION, "node": NODE_VERSION, "arch": arch,
                                               "node_sha256": NODE_SHA256[arch]}, indent=1) + "\n")
        # Earlier pinned versions are ours and no longer used.
        for old in base.glob("pi-*-node-*"):
            if old.name != DIR_NAME and old.is_dir():
                shutil.rmtree(old, ignore_errors=True)
        say(f"The assistant program is ready (Pi {PI_VERSION}, Node {NODE_VERSION}).")
        return str(final / "bin" / "pi")
    except SetupFailed:
        raise
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as e:
        raise SetupFailed(NEEDS_CONNECTION_WORDS, f"{type(e).__name__}: {e}") from e
    finally:
        if stage != final:
            shutil.rmtree(stage, ignore_errors=True)


def main_setup(force: bool = False) -> int:
    """`anteriora setup-assistant`: what the installer runs, and what a person can run to repair."""
    if not supported():
        print("  Nothing to set up here: on this computer the assistant program is not installed by Anteriora.")
        return 0
    try:
        install(lambda s: print("  " + s, flush=True), force=force)
    except SetupFailed as e:
        sys.stderr.write(f"\n  {e}\n")
        if e.detail:
            sys.stderr.write(f"  ({e.detail})\n")
        sys.stderr.write("\n")
        return 1
    return 0
