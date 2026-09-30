"""The relay between the agent's sandbox and the verifying proxies must not invent failures.

Both properties here were missing, and both surfaced to the user as the agent reporting
"Connection error." at the start of a turn, while the session's own receipt recorded the request as
served with no error — because the fault was downstream of the session, in the relay.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

from inferroute_local import netns


def _upstream(handler):
    """A throwaway TCP server on 127.0.0.1; returns (port, stop)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port, srv.close


def test_relay_sets_no_idle_timeout_on_the_upstream_socket(tmp_path, monkeypatch):
    """A quiet connection is not a broken one.

    The relay used to call ``create_connection(..., timeout=30)``, and that timeout stays on the
    socket for every later ``recv`` — so the relay destroyed any connection that produced no upstream
    bytes for 30 seconds. The model's time-to-first-token is exactly that silence, and it grows with
    the conversation, so this failed the LONGEST prompt first: the opening request of every turn.
    """
    seen: list = []
    real = socket.create_connection

    def spy(addr, *a, **kw):
        s = real(addr, *a, **kw)
        seen.append(s)
        return s

    monkeypatch.setattr(netns.socket, "create_connection", spy)

    port, stop_srv = _upstream(lambda conn: time.sleep(5))
    sock_path = str(tmp_path / "r.sock")
    stop = threading.Event()
    netns._relay(sock_path, port, stop)
    try:
        for _ in range(100):
            try:
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.connect(sock_path)
                break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("relay never accepted")
        c.sendall(b"hello")
        for _ in range(100):
            if seen:
                break
            time.sleep(0.02)
        assert seen, "relay never dialled upstream"
        assert seen[0].gettimeout() is None, (
            "the relay left a receive timeout on the upstream socket: a connection that is merely "
            "quiet will be torn down after %s s" % seen[0].gettimeout())
        c.close()
    finally:
        stop.set()
        stop_srv()


def test_relay_half_closes_instead_of_destroying_the_pair(tmp_path):
    """One direction ending says nothing about the other.

    The relay used to ``shutdown(SHUT_RDWR)`` and close BOTH sockets as soon as EITHER direction
    reached EOF. A client that finished sending and was waiting to read therefore had its answer
    thrown away, and saw a reset rather than an orderly close.
    """
    def handler(conn):
        conn.recv(65536)                 # read the request
        while conn.recv(65536):          # drain until the client half-closes
            pass
        time.sleep(0.1)
        conn.sendall(b"ANSWER")          # answer AFTER the client's write side is shut
        conn.shutdown(socket.SHUT_WR)

    port, stop_srv = _upstream(handler)
    sock_path = str(tmp_path / "r.sock")
    stop = threading.Event()
    netns._relay(sock_path, port, stop)
    try:
        for _ in range(100):
            try:
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.connect(sock_path)
                break
            except OSError:
                time.sleep(0.02)
        else:
            pytest.fail("relay never accepted")
        c.sendall(b"REQUEST")
        c.shutdown(socket.SHUT_WR)       # half-close: done sending, still reading
        c.settimeout(5)
        got = b""
        while True:
            try:
                chunk = c.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            got += chunk
        assert got == b"ANSWER", (
            "a half-close tore down the whole connection; the reply never arrived (got %r)" % got)
        c.close()
    finally:
        stop.set()
        stop_srv()


def test_forwarder_source_has_no_mutual_destruction():
    """The in-sandbox forwarder is a source string, so it cannot be imported and tested directly.

    It relays the same connections one hop further in, and had the same teardown. Gate on the
    property rather than on the text: the shutdown it performs must be write-side only.
    """
    src = netns.FORWARD_PY
    assert "SHUT_RDWR" not in src, "the in-sandbox forwarder still destroys both directions at once"
    assert "SHUT_WR" in src, "the in-sandbox forwarder no longer propagates EOF"
