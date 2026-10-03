"""Local-only tests for the host-owned VM broker boundary."""

from __future__ import annotations

import json
import http.client
import socket
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from inferroute_local.macos_vm import VMUnavailable
from inferroute_local.macos_vm import wire
from inferroute_local.macos_vm.broker import Broker


class Snapshot:
    files = {"hello.txt": b"synthetic workspace"}


class ObservedEvent(threading.Event):
    """Event that lets a test synchronize on a broker wait without sleeps."""

    def __init__(self):
        super().__init__()
        self.wait_called = threading.Event()

    def wait(self, timeout=None):
        self.wait_called.set()
        return super().wait(timeout)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = []
    chat_started = threading.Event()
    second_chat_chunk = threading.Event()
    redirect_only = False

    def log_message(self, *_args):
        pass

    def do_GET(self):
        type(self).requests.append(
            ("GET", self.path, self.headers.get("Authorization"), b"")
        )
        if self.path == "/confidential/receipt":
            payload = b'{"receipt":"synthetic"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).requests.append(
            ("POST", self.path, self.headers.get("Authorization"), body)
        )
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        if type(self).redirect_only:
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        type(self).chat_started.set()
        chunks = (b"data: synthetic-one\n\n", b"data: synthetic-two\n\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for index, chunk in enumerate(chunks):
            self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
            if index == 0:
                type(self).second_chat_chunk.wait(timeout=3)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        type(self).second_chat_chunk.set()


@pytest.fixture
def proxy_server():
    ProxyHandler.requests = []
    ProxyHandler.chat_started = threading.Event()
    ProxyHandler.second_chat_chunk = threading.Event()
    ProxyHandler.redirect_only = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def configured_broker(url):
    broker = Broker(Snapshot())
    broker.configure({"mode": "synthetic"}, url, "host-only-test-token")
    return broker


def begin_transport(client, session="fixture-session"):
    wire.send_frame(client, {"v": wire.VERSION, "session": session, "op": "host.bind"})


def send_op(client, seq, op, body=None, session="fixture-session"):
    if body is not None and not isinstance(body, (bytes, dict)):
        body = json.dumps(body, separators=(",", ":")).encode()
    return list(wire.request(client, session, seq, op, body))


def serve_thread(broker, channel, errors):
    def run():
        try:
            broker.serve(channel)
        except BaseException as exc:
            errors.append(exc)
        finally:
            channel.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_broker_uses_only_fixed_model_route_and_host_authorization(proxy_server):
    broker = configured_broker(proxy_server)
    chunks = list(broker._http("model.chat", {"messages": [{"content": "synthetic"}]}))
    assert json.loads(chunks[0]) == {"status": 200, "content_type": "text/event-stream"}
    assert b"".join(chunks[1:]) == b"data: synthetic-one\n\ndata: synthetic-two\n\n"
    method, path, authorization, body = ProxyHandler.requests[-1]
    assert (method, path, authorization) == (
        "POST",
        "/v1/chat/completions",
        "Bearer host-only-test-token",
    )
    assert json.loads(body) == {"messages": [{"content": "synthetic"}]}
    with pytest.raises(KeyError):
        list(broker._http("https://attacker.invalid/", {}))


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:1234",
        "http://localhost:1234",
        "http://127.0.0.1:1234/path",
        "http://user@127.0.0.1:1234",
        "http://127.0.0.1:1234/?q=1",
    ],
)
def test_broker_configuration_refuses_nonfixed_or_nonlocal_endpoint(url):
    with pytest.raises(VMUnavailable, match="fixed local endpoint"):
        Broker(Snapshot()).configure({}, url, "synthetic")


def test_broker_refuses_redirect_without_following_it(proxy_server):
    ProxyHandler.redirect_only = True
    broker = configured_broker(proxy_server)
    with pytest.raises(urllib.error.URLError, match="redirect refused"):
        list(broker._http("model.chat", {}))
    assert [request[1] for request in ProxyHandler.requests] == ["/v1/chat/completions"]


@pytest.mark.parametrize(
    "readiness",
    [
        {},
        {"netns": True, "guard": True, "protocol": 2},
        {"netns": True, "guard": False, "protocol": 1},
        {"netns": 1, "guard": True, "protocol": 1},
    ],
)
def test_broker_requires_exact_guest_readiness_before_any_capability(readiness):
    broker = configured_broker("http://127.0.0.1:1234")
    client, server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    try:
        begin_transport(client)
        with pytest.raises((EOFError, OSError)):
            send_op(client, 0, "guest.ready", readiness)
        thread.join(timeout=3)
        assert errors and isinstance(errors[0], VMUnavailable)
        assert not broker.ready.is_set()
    finally:
        client.close()
        thread.join(timeout=3)


@pytest.mark.parametrize(
    "session,seq", [("foreign-session", 1), ("fixture-session", 0)]
)
def test_broker_rejects_foreign_session_and_sequence_replay(session, seq):
    broker = configured_broker("http://127.0.0.1:1234")
    client, server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    try:
        begin_transport(client)
        assert send_op(
            client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        with pytest.raises((EOFError, OSError)):
            send_op(client, seq, "workspace.read", "hello.txt", session=session)
        thread.join(timeout=3)
        assert errors and isinstance(errors[0], VMUnavailable)
        assert "session/replay refused" in str(errors[0])
    finally:
        client.close()
        thread.join(timeout=3)


def test_receipt_is_available_while_model_response_is_streaming(proxy_server):
    broker = configured_broker(proxy_server)
    client, server = socket.socketpair()
    status_client, status_server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    status_errors = []
    status_thread = threading.Thread(
        target=lambda: _serve_status(broker, status_server, status_errors), daemon=True
    )
    status_thread.start()
    try:
        begin_transport(client)
        assert send_op(
            client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        send_op(client, 1, "session.plan")

        wire.send_request(client, "fixture-session", 2, "model.chat", {"stream": True})
        response = wire.receive_response(client, 2)
        first = next(response)
        assert json.loads(first) == {"status": 200, "content_type": "text/event-stream"}
        second = next(response)
        assert second == b"data: synthetic-one\n\n"
        assert ProxyHandler.chat_started.wait(timeout=2)

        wire.send_frame(
            status_client,
            {"v": wire.VERSION, "session": "fixture-session", "op": "host.bind"},
        )
        receipt = list(
            wire.request(status_client, "fixture-session", 0, "model.receipt")
        )
        assert b"".join(receipt).endswith(b'{"receipt":"synthetic"}')

        remainder = list(response)
        assert b"".join(remainder) == b"data: synthetic-two\n\n"
        ProxyHandler.second_chat_chunk.set()
        assert send_op(client, 3, "session.finish", 0) == [b"{}"]
    finally:
        client.close()
        status_client.close()
        thread.join(timeout=3)
        status_thread.join(timeout=3)
    assert not errors
    assert len(status_errors) == 1 and isinstance(status_errors[0], EOFError)


def _serve_status(broker, channel, errors):
    try:
        broker.serve_status(channel)
    except BaseException as exc:
        errors.append(exc)
    finally:
        channel.close()


def test_session_finish_marks_completion_and_tears_down_broker_transport():
    broker = configured_broker("http://127.0.0.1:1234")
    client, server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    try:
        begin_transport(client)
        assert send_op(
            client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        result = send_op(client, 1, "session.finish", 0)
        assert result == [b"{}"]
        assert broker.complete is True
        assert broker.agent_exit == 0
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert not errors
        assert client.recv(1) == b""
    finally:
        client.close()
        thread.join(timeout=3)


def test_close_interrupts_a_blocked_active_model_stream(proxy_server):
    broker = configured_broker(proxy_server)
    stream = broker._http("model.chat", {"stream": True})
    assert json.loads(next(stream)) == {
        "status": 200,
        "content_type": "text/event-stream",
    }
    assert next(stream) == b"data: synthetic-one\n\n"
    with broker._response_lock:
        assert len(broker._responses) == 1

    errors = []
    finished = threading.Event()

    def blocked_read():
        try:
            next(stream)
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    reader = threading.Thread(target=blocked_read, daemon=True)
    reader.start()
    assert ProxyHandler.chat_started.wait(timeout=2)
    broker.close()
    reader.join(timeout=2)
    assert finished.is_set() and not reader.is_alive()
    assert errors and isinstance(
        errors[0], (http.client.IncompleteRead, OSError, VMUnavailable)
    )
    with broker._response_lock:
        assert not broker._responses


def test_close_wakes_pending_session_plan_configuration_wait():
    broker = Broker(Snapshot())
    observed = ObservedEvent()
    broker.configured = observed
    client, server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    reader_errors = []
    try:
        begin_transport(client)
        assert send_op(
            client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        wire.send_request(client, "fixture-session", 1, "session.plan")

        def read_response():
            try:
                list(wire.receive_response(client, 1))
            except BaseException as exc:
                reader_errors.append(exc)

        response_reader = threading.Thread(target=read_response, daemon=True)
        response_reader.start()
        assert observed.wait_called.wait(timeout=2)
        broker.close()
        response_reader.join(timeout=2)
        thread.join(timeout=2)
        assert not response_reader.is_alive() and not thread.is_alive()
        assert errors and isinstance(errors[0], VMUnavailable)
        assert reader_errors and isinstance(reader_errors[0], (EOFError, OSError))
    finally:
        client.close()
        broker.close()
        thread.join(timeout=3)


def test_close_wakes_status_capability_configuration_wait():
    broker = Broker(Snapshot())
    observed = ObservedEvent()
    broker.configured = observed
    main_client, main_server = socket.socketpair()
    status_client, status_server = socket.socketpair()
    main_errors, status_errors, reader_errors = [], [], []
    main_thread = serve_thread(broker, main_server, main_errors)
    status_thread = threading.Thread(
        target=lambda: _serve_status(broker, status_server, status_errors), daemon=True
    )
    status_thread.start()
    try:
        begin_transport(main_client)
        assert send_op(
            main_client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        wire.send_frame(
            status_client,
            {"v": wire.VERSION, "session": "fixture-session", "op": "host.bind"},
        )
        wire.send_request(status_client, "fixture-session", 0, "model.receipt")

        def read_status():
            try:
                list(wire.receive_response(status_client, 0))
            except BaseException as exc:
                reader_errors.append(exc)

        response_reader = threading.Thread(target=read_status, daemon=True)
        response_reader.start()
        assert observed.wait_called.wait(timeout=2)
        broker.close()
        response_reader.join(timeout=2)
        assert not response_reader.is_alive()
        assert status_errors and isinstance(status_errors[0], VMUnavailable)
        assert reader_errors and isinstance(reader_errors[0], (EOFError, OSError))
    finally:
        main_client.close()
        status_client.close()
        broker.close()
        main_thread.join(timeout=3)
        status_thread.join(timeout=3)


def test_status_binding_waits_for_main_transport_binding(proxy_server):
    broker = configured_broker(proxy_server)
    observed = ObservedEvent()
    broker.bound = observed
    main_client, main_server = socket.socketpair()
    status_client, status_server = socket.socketpair()
    main_errors, status_errors = [], []
    status_thread = threading.Thread(
        target=lambda: _serve_status(broker, status_server, status_errors), daemon=True
    )
    status_thread.start()
    try:
        wire.send_frame(
            status_client,
            {"v": wire.VERSION, "session": "fixture-session", "op": "host.bind"},
        )
        assert observed.wait_called.wait(timeout=2)
        # The status listener has consumed its bind and is waiting for the main session identity.
        main_thread = serve_thread(broker, main_server, main_errors)
        begin_transport(main_client)
        assert send_op(
            main_client, 0, "guest.ready", {"netns": True, "guard": True, "protocol": 1}
        ) == [b"{}"]
        receipt = list(
            wire.request(status_client, "fixture-session", 0, "model.receipt")
        )
        assert b"".join(receipt).endswith(b'{"receipt":"synthetic"}')
        main_client.close()
        status_client.close()
        main_thread.join(timeout=3)
        status_thread.join(timeout=3)
        assert not main_thread.is_alive() and not status_thread.is_alive()
        assert len(status_errors) == 1 and isinstance(status_errors[0], EOFError)
        assert main_errors and isinstance(main_errors[0], EOFError)
    finally:
        main_client.close()
        status_client.close()
        broker.close()
        status_thread.join(timeout=3)


def test_two_sessions_keep_workspace_capabilities_separate():
    from types import SimpleNamespace

    brokers = [configured_broker("http://127.0.0.1:1234") for _ in range(2)]
    brokers[0].snapshot = SimpleNamespace(files={"disclosure.md": b"SYNTHETIC A"})
    brokers[1].snapshot = SimpleNamespace(files={"disclosure.md": b"SYNTHETIC B"})
    pairs = [socket.socketpair() for _ in brokers]
    errors = [[], []]
    threads = [
        serve_thread(broker, pair[1], error)
        for broker, pair, error in zip(brokers, pairs, errors)
    ]
    try:
        for index, (client, _) in enumerate(pairs):
            session = "session-" + str(index)
            begin_transport(client, session)
            assert send_op(
                client,
                0,
                "guest.ready",
                {"netns": True, "guard": True, "protocol": 1},
                session=session,
            ) == [b"{}"]
            assert send_op(
                client, 1, "workspace.read", "disclosure.md", session=session
            ) == [b"SYNTHETIC A" if index == 0 else b"SYNTHETIC B"]
        with pytest.raises((EOFError, OSError)):
            send_op(
                pairs[1][0], 2, "workspace.read", "disclosure.md", session="session-0"
            )
        assert send_op(
            pairs[0][0], 2, "workspace.read", "disclosure.md", session="session-0"
        ) == [b"SYNTHETIC A"]
        assert send_op(pairs[0][0], 3, "session.finish", 0, session="session-0") == [
            b"{}"
        ]
        for thread in threads:
            thread.join(timeout=3)
        assert not errors[0]
        assert len(errors[1]) == 1 and isinstance(errors[1][0], VMUnavailable)
        assert brokers[0].complete and not brokers[1].complete
        assert brokers[0].uploads == brokers[1].uploads == {}
    finally:
        for client, _ in pairs:
            client.close()
        for broker in brokers:
            broker.close()
        for thread in threads:
            thread.join(timeout=3)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"netns":true,"netns":false,"guard":true,"protocol":1}',
        b'{"netns":true,"guard":true,"protocol":NaN}',
    ],
)
def test_malformed_readiness_json_never_releases_capabilities(payload):
    broker = configured_broker("http://127.0.0.1:1234")
    client, server = socket.socketpair()
    errors = []
    thread = serve_thread(broker, server, errors)
    try:
        begin_transport(client)
        with pytest.raises((EOFError, OSError)):
            send_op(client, 0, "guest.ready", payload)
        thread.join(timeout=3)
        assert len(errors) == 1 and isinstance(errors[0], ValueError)
        assert not broker.ready.is_set()
        assert not broker.complete and not broker.uploads
    finally:
        client.close()
        broker.close()
        thread.join(timeout=3)


def test_a_proxy_that_does_not_answer_fails_one_call_not_the_session():
    """Found by the first real session through the broker (3 Oct): the upstream wait was 10 seconds, a
    sealed search takes longer than that to produce its first byte, and the exception ended serve() — the
    whole session — instead of that one call."""
    import socket as _socket
    from inferroute_local.macos_vm import broker as broker_module

    assert broker_module.HEADER_SECONDS >= 300
    listener = _socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()                                   # nothing listens here: connection refused
    broker = Broker(Snapshot())
    broker.configure({}, f"http://127.0.0.1:{port}", "synthetic", search_url=f"http://127.0.0.1:{port}")
    chunks = list(broker._http("search.query", {"q": "synthetic"}))
    assert json.loads(chunks[0])["status"] == 502
    assert json.loads(chunks[1])["error"]["type"] == "proxy_unavailable"
    # and the broker is still usable for the next call
    assert json.loads(list(broker._http("model.chat", {"messages": []}))[0])["status"] == 502


def test_a_stream_dropped_part_way_ends_early_instead_of_raising(proxy_server, monkeypatch):
    broker = configured_broker(proxy_server)
    import http.client

    real = http.client.HTTPResponse.read1
    calls = {"n": 0}

    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] > 1:
            raise ConnectionResetError("synthetic reset")
        return real(self, *a, **k)

    monkeypatch.setattr(http.client.HTTPResponse, "read1", flaky)
    chunks = list(broker._http("model.chat", {"messages": [{"content": "synthetic"}]}))
    assert json.loads(chunks[0])["status"] == 200
    assert len(chunks) == 2                              # the header, one chunk, then an early end


def test_a_request_the_size_of_a_long_conversation_is_within_the_wire_limit():
    from inferroute_local.macos_vm import wire

    assert wire.MAX_REQUEST_BYTES >= 4 * 1024 * 1024
