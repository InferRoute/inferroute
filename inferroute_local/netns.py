"""Address-level confinement: run the agent in an EMPTY network namespace with only the matter tree bound in.

Port-level confinement (confinement.apply) matches a port number, so a remote host on an allowed port is
still reachable, and it leaves file READS unbounded — an agent can read ~/.ssh into model context even though
it cannot write there. This closes both, by topology rather than by rule:

    host netns                          │  sandbox netns (empty: loopback only)
      verifying proxy  127.0.0.1:PORT   │    agent connects to  127.0.0.1:PORT
            ▲                           │            │
            │  relay thread             │            ▼  forwarder (binds first, then confines)
      unix socket  <cfg>/tmp/netns/…    │──bind-mount──┘

There is no route off the machine from inside — not a filtered one, an absent one. The only channel is a unix
socket the launcher created, whose other end is a proxy that verifies the enclave before anything is sealed.
And the filesystem is built up from nothing: $HOME is a tmpfs, and only the matter workspace, the agent's own
config dir and the runtime it executes are bound back in. `confidential/` and `~/.ssh` are not unwritable —
they are not there.

ORDER MATTERS, and it is forced, not preferred. The Landlock ruleset handles BIND_TCP while granting only
CONNECT rules, so once confinement is applied nothing can bind a port. The in-sandbox forwarder therefore
binds its listeners FIRST, then applies Landlock + seccomp, then spawns the agent — which inherits both.
AF_UNIX is allowed on this path only (the forwarders need it); there is no egress for it to open, because
there is no network.

WHAT IS STILL READABLE, stated rather than left to be discovered: the agent executes a real interpreter, so
the runtime trees that interpreter lives in are bound back read-only when they sit under $HOME (the ir venv,
an nvm node version, a uv-managed cpython). Their ANCESTOR directories exist inside the sandbox as empty
stubs — measured: with the venv at ~/workspaces/inferroute/<repo>/.venv, the sandbox shows ~/workspaces
containing only that one path down to .venv, and sibling repositories are absent. So the exposure is
InferRoute's own installed code, read-only, and never the user's other files.

Needs bubblewrap and unprivileged user namespaces — on Ubuntu-family systems, the one-time AppArmor profile
(scripts/install-confine-profile.sh). `confinement.netns_bind_available()` probes for both.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

FORWARD_PY = r'''#!/usr/bin/env python3
"""Runs as the sandbox's entry point. Binds the loopback ports the agent expects, relays each to the unix
socket its verifying proxy listens on outside, THEN confines itself, then runs the agent as a child so the
relays stay alive for its lifetime. Written by the launcher; not part of the agent's own tree."""
import argparse, os, socket, subprocess, sys, threading

def _splice(client, up):
    """Pump both directions until BOTH end, then close. A quiet direction is not a dead connection,
    and one direction's EOF says nothing about the other; shutting both down on either one turns a
    normal half-close into a reset the agent reports as "Connection error.". No idle timeout is set
    on either socket: the model's time-to-first-token is silence on this path."""
    pending = [2]
    lock = threading.Lock()

    def pump(a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            with lock:
                pending[0] -= 1
                last = pending[0] == 0
            if last:
                for s in (client, up):
                    try:
                        s.close()
                    except OSError:
                        pass

    threading.Thread(target=pump, args=(client, up), daemon=True).start()
    threading.Thread(target=pump, args=(up, client), daemon=True).start()

def _accept(listener, sock_path):
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        try:
            up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            up.connect(sock_path)
        except OSError:
            try:
                client.close()
            except OSError:
                pass
            continue
        _splice(client, up)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", action="append", default=[], metavar="PORT=SOCKET")
    ap.add_argument("--write-path", action="append", default=[])
    ap.add_argument("--confinement-dir", default=None)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    argv = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not argv:
        sys.stderr.write("netns forwarder: no command to run\n")
        return 2

    # 1. BIND FIRST — after confinement nothing may bind a port.
    listeners = []
    for m in a.map:
        port, _, sock_path = m.partition("=")
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", int(port)))
        ls.listen(128)
        listeners.append((ls, sock_path))
    for ls, sock_path in listeners:
        threading.Thread(target=_accept, args=(ls, sock_path), daemon=True).start()

    # 2. CONFINE — Landlock write scope + seccomp, inherited by the agent across exec.
    if a.confinement_dir:
        sys.path.insert(0, a.confinement_dir)
        try:
            import confinement
            confinement.apply([int(m.split("=")[0]) for m in a.map],
                              write_paths=a.write_path or None, allow_unix=True, netns_bound=True)
        except Exception as exc:                      # noqa: BLE001
            sys.stderr.write("netns forwarder: REFUSING to run unconfined inside the sandbox: %r\n" % (exc,))
            return 2

    # 3. RUN the agent as a child, so the relays outlive its exec.
    try:
        return subprocess.call(argv)
    except OSError as exc:
        sys.stderr.write("netns forwarder: cannot run %r: %s\n" % (argv[0], exc))
        return 127

if __name__ == "__main__":
    sys.exit(main())
'''


# ONE definition of the sentence that describes this confinement. The launcher stamps it into the session
# record before the sandbox object exists, and the sandbox reports it after the fact; if those were two
# strings they could drift, and the record would describe a confinement the session did not run under.
ADDRESS_LEVEL_LABEL = (
    "require, address-level (empty network namespace: no route off the machine; only the matter directory "
    "and the agent's own config bound in, so other files are absent rather than unwritable; the two "
    "verifying proxies reached over unix sockets)")


class NetnsUnavailable(RuntimeError):
    pass


def _relay(sock_path: str, port: int, stop: threading.Event) -> threading.Thread:
    """Host side: accept on a unix socket and pump to the proxy on 127.0.0.1:port."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(128)
    srv.settimeout(0.5)

    def splice(client: socket.socket, up: socket.socket) -> None:
        """Pump both directions until BOTH are done, then close.

        Two properties this has to hold, each of which was missing and each of which showed up as
        "Connection error." in the agent:

        1. NO IDLE TIMEOUT. A relayed connection that is quiet is not a broken one. The model's
           time-to-first-token is silence on this socket, and it grows with the conversation, so an
           idle timeout here fails the LONGEST prompts first — the opening request of every turn.
        2. HALF-CLOSE, NOT MUTUAL DESTRUCTION. One direction reaching EOF says nothing about the
           other. Shut down only the direction that ended and let its peer drain; close the pair
           once both pumps have finished.
        """
        pending = [2]
        lock = threading.Lock()

        def pump(a: socket.socket, b: socket.socket) -> None:
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    b.shutdown(socket.SHUT_WR)          # propagate EOF, this direction only
                except OSError:
                    pass
                with lock:
                    pending[0] -= 1
                    last = pending[0] == 0
                if last:
                    for s in (client, up):
                        try:
                            s.close()
                        except OSError:
                            pass

        threading.Thread(target=pump, args=(client, up), daemon=True).start()
        threading.Thread(target=pump, args=(up, client), daemon=True).start()

    def loop() -> None:
        try:
            while not stop.is_set():
                try:
                    client, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    up = socket.create_connection(("127.0.0.1", port), timeout=10)
                except OSError:
                    client.close()
                    continue
                up.settimeout(None)   # the 10s bounded CONNECT, never a bound on being quiet
                splice(client, up)
        finally:
            try:
                srv.close()
            except OSError:
                pass
            try:
                os.unlink(sock_path)
            except OSError:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def _prefix_of(path: str) -> Optional[str]:
    """The installation prefix a binary needs: the nearest ancestor holding both bin/ and lib/ (a venv, an
    nvm node version, a uv-managed interpreter). Falls back to the directory the binary sits in."""
    p = Path(path)
    for par in p.parents:
        if (par / "bin").is_dir() and ((par / "lib").is_dir() or (par / "lib64").is_dir()):
            return str(par)
    return str(p.parent) if p.parent != p else None


def _symlink_chain(path: str, limit: int = 40) -> List[str]:
    """Every hop from `path` to the real file. Binding only the two ends is not enough: an interpreter is
    often reached through an ALIASED directory (uv's cpython-3.14-… is a symlink to cpython-3.14.5-…), and
    that middle name must exist inside the sandbox or resolution fails with a bare ENOENT."""
    out, cur = [], path
    for _ in range(limit):
        out.append(cur)
        if not os.path.islink(cur):
            break
        target = os.readlink(cur)
        cur = target if os.path.isabs(target) else os.path.normpath(os.path.join(os.path.dirname(cur), target))
    return out


def runtime_ro_binds(*binaries: str) -> List[str]:
    """Interpreter/runtime trees that live under $HOME and must be bound back into the emptied home. System
    prefixes need no entry — /usr and friends are already bound read-only. Both the symlink path and the
    resolved path are taken: a venv's python3 and the interpreter it points at are different prefixes, and
    the sandbox needs both."""
    home = os.path.realpath(os.path.expanduser("~")) + os.sep
    out: List[str] = []
    candidates: List[str] = [sys.executable]
    for b in binaries:
        if b:
            candidates.append(shutil.which(b) or b)
    for cand in list(candidates):
        if cand and os.path.exists(cand):
            candidates.extend(_symlink_chain(cand))
    for cand in candidates:
        if not cand or not cand.startswith(home):
            continue
        prefix = _prefix_of(cand)
        if prefix and prefix.startswith(home) and prefix not in out and os.path.isdir(prefix):
            out.append(prefix)
    return out


class NetnsSandbox:
    """Host-side relays plus the bwrap command line that runs the agent inside an empty netns.

    `ports` are the loopback ports the agent already expects (the local sealed endpoint and the search
    verifier); each is relayed to its proxy in the host namespace. `rw` and `ro` are the only paths bound
    back into an otherwise-empty home.
    """

    def __init__(self, *, ports: Sequence[int], cfg_dir: str, rw: Sequence[str], ro: Sequence[str] = (),
                 binary: str = "") -> None:
        from . import confinement
        if not confinement.netns_bind_available():
            raise NetnsUnavailable(
                "address-level confinement needs bubblewrap and unprivileged network namespaces; on "
                "Ubuntu-family systems run scripts/install-confine-profile.sh once (sudo)")
        self.ports = [int(p) for p in ports if p]
        if not self.ports:
            raise NetnsUnavailable("no proxy ports to relay — refusing to build a sandbox with no channel out")
        self.cfg_dir = os.path.realpath(cfg_dir)
        self.sock_dir = os.path.join(self.cfg_dir, "tmp", "netns")
        os.makedirs(self.sock_dir, mode=0o700, exist_ok=True)
        os.chmod(self.sock_dir, 0o700)
        self.rw = [os.path.realpath(p) for p in rw if p and os.path.exists(p)]
        self.ro = list(ro) + runtime_ro_binds(binary or "pi")
        self.ro = [p for i, p in enumerate(self.ro) if p and p not in self.ro[:i]]
        self._stop = threading.Event()
        self._maps: Dict[int, str] = {}
        for port in self.ports:
            sock_path = os.path.join(self.sock_dir, f"{port}.sock")
            _relay(sock_path, port, self._stop)
            self._maps[port] = sock_path
        # The forwarder and a copy of the confinement module travel in the socket dir, which is already
        # inside the config tree we bind — so nothing of the source tree is exposed to the agent.
        self.forward_py = os.path.join(self.sock_dir, "forward.py")
        Path(self.forward_py).write_text(FORWARD_PY)
        os.chmod(self.forward_py, 0o700)
        shutil.copyfile(Path(__file__).with_name("confinement.py"), os.path.join(self.sock_dir, "confinement.py"))

    # ── the command line ──
    def wrap(self, argv: Sequence[str], *, write_paths: Sequence[str] = ()) -> List[str]:
        home = os.path.realpath(os.path.expanduser("~"))
        bwrap = shutil.which("bwrap") or "bwrap"
        cmd = [bwrap, "--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent"]
        for d in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"):
            if os.path.exists(d):
                cmd += ["--ro-bind", d, d]
        cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", home]
        for p in self.ro:
            if os.path.exists(p):
                cmd += ["--ro-bind", p, p]
        for p in [self.cfg_dir, *self.rw]:
            cmd += ["--bind", p, p]
        cmd += ["--setenv", "HOME", home, "--chdir", self.rw[0] if self.rw else home, "--"]
        cmd += [sys.executable if os.path.exists(sys.executable) else "python3", self.forward_py]
        for port, sock in self._maps.items():
            cmd += ["--map", f"{port}={sock}"]
        for w in (write_paths or [self.cfg_dir, *self.rw]):
            cmd += ["--write-path", w]
        cmd += ["--confinement-dir", self.sock_dir, "--", *argv]
        return cmd

    def label(self) -> str:
        """The confinement line the verifier stamps into the record — stated only where the bind APPLIED."""
        return ADDRESS_LEVEL_LABEL

    def close(self) -> None:
        self._stop.set()
        for sock in self._maps.values():
            try:
                os.unlink(sock)
            except OSError:
                pass


def run_in_netns_bind(argv: Sequence[str], *, ports: Sequence[int], cfg_dir: str, rw: Sequence[str],
                      ro: Sequence[str] = (), env: Optional[Dict[str, str]] = None,
                      binary: str = "", timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    """Run `argv` inside the sandbox, synchronously, and tear the relays down afterwards. Used by the
    acceptance test and by any caller that does not need the async launch path."""
    box = NetnsSandbox(ports=ports, cfg_dir=cfg_dir, rw=rw, ro=ro, binary=binary)
    try:
        return subprocess.run(box.wrap(argv), env=env, capture_output=True, text=True, timeout=timeout)
    finally:
        box.close()
