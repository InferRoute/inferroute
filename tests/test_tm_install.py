"""Installing the trademark index (19 Oct): the host serving it is trusted for availability only. A file
that does not hash to the value pinned in this release installs nothing and leaves nothing behind."""
import hashlib
import lzma
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from inferroute_cli import tm_install as I


@pytest.fixture
def served(monkeypatch):
    body = b"SQLite format 3\0" + b"x" * 5000
    packed = lzma.compress(body)
    state = {"serve": packed}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            data = state["serve"]
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(I, "INDEX", {"url": f"http://127.0.0.1:{server.server_port}/i.xz",
                                     "xz_sha256": hashlib.sha256(packed).hexdigest(), "xz_bytes": len(packed),
                                     "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "data": "test"})
    yield state, body
    server.shutdown()


def test_the_pinned_file_installs_and_is_recognised(tmp_path, served):
    _, body = served
    target = tmp_path / "tm" / "index.sqlite"
    I.install(target)
    assert target.read_bytes() == body and I.installed(target)
    assert sorted(p.name for p in target.parent.iterdir()) == ["index.sqlite", "index.verified"]


def test_a_substituted_file_installs_nothing(tmp_path, served):
    state, _ = served
    state["serve"] = lzma.compress(b"SQLite format 3\0" + b"y" * 5000)[: I.INDEX["xz_bytes"]]
    target = tmp_path / "tm" / "index.sqlite"
    with pytest.raises(I.InstallError, match="not the one this release names"):
        I.install(target)
    assert not target.exists() and list(target.parent.iterdir()) == []


def test_a_changed_installed_file_is_not_trusted(tmp_path, served):
    target = tmp_path / "tm" / "index.sqlite"
    I.install(target)
    data = bytearray(target.read_bytes())
    data[-1] ^= 1
    target.write_bytes(bytes(data))
    assert not I.installed(target)
