"""Step 7 — the netns matter-dir bind — as its acceptance test, run against real bubblewrap.

It skips, with the reason, unless an unprivileged empty network namespace can actually be created here (the
one-time AppArmor profile, scripts/install-confine-profile.sh). When it runs, it asserts the properties the
decision record asks for, from INSIDE the sandbox: secrets are not visible rather than merely unwritable, the
matter directory is writable, the verifying proxy is reachable, and nothing else on the network is.

On "secrets are not visible": the assertion is about READABLE FILES, not about path existence. bwrap has
to materialise the parent chain of every bind, so when the interpreter lives under $HOME — a dev venv at
~/workspaces/..., or pipx's at ~/.local/... — that chain necessarily exists inside the sandbox. An earlier
version asserted `not os.path.exists(~/workspaces)` and failed on exactly that empty chain while the
confinement was intact. Existence of a directory and reachability of its contents are different claims.
"""
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from inferroute_cli import pi_attested
from inferroute_local import confinement

pytestmark = pytest.mark.skipif(
    not confinement.netns_bind_available(),
    reason="needs the AppArmor profile (scripts/install-confine-profile.sh) so an unprivileged netns can be created",
)

PROBE = r'''
import json, os, pathlib, socket, sys, urllib.request
matter, port = sys.argv[1], sys.argv[2]
out = {}
out["ssh_visible"] = os.path.exists(os.path.expanduser("~/.ssh"))
out["confidential_visible"] = os.path.exists(os.path.expanduser("~/.inferroute/confidential"))
# Every FILE reachable under $HOME that is not inside a tree we deliberately bound. Existence of a
# directory is not the question: bwrap must materialise the parent chain of each bind, so ~/workspaces
# necessarily "exists" when the interpreter lives under it. What must be empty is the set of readable
# files outside the declared trees.
allowed = [os.path.realpath(a) for a in sys.argv[3].split(os.pathsep) if a]
leaked = []
home = os.path.realpath(os.path.expanduser("~"))
for dirpath, dirnames, filenames in os.walk(home):
    real = os.path.realpath(dirpath)
    if any(real == a or real.startswith(a + os.sep) for a in allowed):
        dirnames[:] = []                      # a declared tree: do not descend, do not report
        continue
    for fn in filenames:
        leaked.append(os.path.join(dirpath, fn))
        if len(leaked) > 40:
            break
    if len(leaked) > 40:
        break
out["leaked_files"] = leaked
try:
    pathlib.Path(matter, "written-from-inside.txt").write_text("ok"); out["matter_writable"] = True
except Exception as e: out["matter_writable"] = type(e).__name__
try:
    pathlib.Path(os.path.expanduser("~"), "escape.txt").write_text("x"); out["home_writable"] = "WROTE"
except Exception as e: out["home_writable"] = type(e).__name__
try: out["proxy"] = urllib.request.urlopen("http://127.0.0.1:%s/" % port, timeout=10).read().decode()
except Exception as e: out["proxy"] = "%s: %s" % (type(e).__name__, e)
for label, tgt in (("public_dns", ("1.1.1.1", 53)), ("public_https", ("140.82.121.4", 443)),
                   ("other_loopback", ("127.0.0.1", 9))):
    try:
        socket.create_connection(tgt, timeout=4); out[label] = "REACHED"
    except Exception as e: out[label] = type(e).__name__
try:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); out["can_bind"] = "YES"
except Exception as e: out["can_bind"] = type(e).__name__
print(json.dumps(out))
'''


@pytest.fixture
def sandbox(tmp_path):
    """A stand-in verifying proxy in the HOST namespace, plus a matter dir and a config dir. The sandbox must
    be built under the real $HOME, because the point is that $HOME is replaced by a tmpfs."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b'{"proxy":"reached"}'
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    root = tempfile.mkdtemp(dir=os.path.expanduser("~"), prefix="ir-netns-test-")
    cfg, matter = os.path.join(root, "cfg"), os.path.join(root, "matter")
    os.makedirs(cfg)
    os.makedirs(matter)
    Path(matter, "disclosure.md").write_text("the invention\n")
    probe = os.path.join(root, "probe.py")
    Path(probe).write_text(PROBE)
    # The trees the sandbox is ENTITLED to expose: the config dir, the rw paths, and the interpreter
    # trees runtime_ro_binds must bind back in because they live under $HOME (a venv, uv's cpython, nvm).
    # Anything readable outside this set is the leak the test is looking for.
    from inferroute_local import netns as _netns
    allowed = [cfg, matter, root, *_netns.runtime_ro_binds("python3")]
    yield {"port": port, "root": root, "cfg": cfg, "matter": matter, "probe": probe, "allowed": allowed}
    srv.shutdown()
    srv.server_close()
    import shutil
    shutil.rmtree(root, ignore_errors=True)


def _run(sb):
    r = pi_attested.run_in_netns_bind(
        [sys.executable, sb["probe"], sb["matter"], str(sb["port"]), os.pathsep.join(sb["allowed"])],
        ports=[sb["port"]], cfg_dir=sb["cfg"], rw=[sb["matter"], sb["root"]], binary="python3", timeout=180)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_secrets_are_absent_not_merely_unwritable(sandbox):
    out = _run(sandbox)
    assert out["ssh_visible"] is False, "~/.ssh must not be visible inside the sandbox at all"
    assert out["confidential_visible"] is False, "confidential/ must not be visible inside the sandbox at all"
    assert out["leaked_files"] == [], (
        "files outside the declared binds were readable inside the sandbox: %r" % (out["leaked_files"][:10],))


def test_the_matter_directory_is_writable_and_nothing_else_is(sandbox):
    out = _run(sandbox)
    assert out["matter_writable"] is True
    assert out["home_writable"] != "WROTE", "the emptied home must stay unwritable"


def test_the_proxy_is_reachable_and_the_network_is_not(sandbox):
    out = _run(sandbox)
    assert json.loads(out["proxy"])["proxy"] == "reached", out["proxy"]
    for key in ("public_dns", "public_https", "other_loopback"):
        assert out[key] != "REACHED", f"{key} must be unreachable from an empty netns"
    assert out["can_bind"] != "YES", "the agent must not be able to bind a port and listen"
