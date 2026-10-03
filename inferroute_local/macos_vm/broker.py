"""Host-owned VM session broker. URLs, credentials and filesystem rights stay here."""

from __future__ import annotations
import json, threading, urllib.request, urllib.error
from . import VMUnavailable
from .wire import receive_frame, receive_request, send_response, CHUNK_BYTES
import base64

CHUNK = CHUNK_BYTES


def decode(text):
    return base64.b64decode(text, validate=True)


ROUTES = {
    "model.chat": ("model", "POST", "/v1/chat/completions"),
    "model.receipt": ("model", "GET", "/confidential/receipt"),
    "intake.create": ("model", "POST", "/probant/intake/create-draft"),
    "search.verify": ("search", "GET", "/enclave"),
    "search.query": ("search", "POST", "/search"),
    "search.document": ("search", "POST", "/document"),
    "search.state": ("search", "GET", "/matter/state"),
    "search.approve": ("search", "POST", "/matter/approve"),
    "search.mark": ("search", "POST", "/matter/mark"),
    "search.record.get": ("search", "GET", "/record"),
    "search.record.put": ("search", "POST", "/record"),
    "search.lifecycle": ("search", "GET", "/lifecycle"),
    "search.activity": ("search", "POST", "/activity"),
    "search.keep_warm": ("search", "POST", "/keep-warm"),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise urllib.error.URLError("redirect refused")


class Broker:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.ready = threading.Event()
        self.configured = threading.Event()
        self.session = None
        self.bound = threading.Event()
        self.stopped = threading.Event()
        self._responses = set()
        self._response_lock = threading.Lock()
        self.plan = None
        self.targets = {}
        self.key = None
        self.complete = False
        self.agent_exit = None
        self.uploads = {}
        self._upload = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

    def configure(
        self, plan, model_url, model_key, search_url=None, create_drafts=False
    ):
        from urllib.parse import urlsplit

        for role, url in [("model", model_url), ("search", search_url)]:
            if url is None:
                continue
            parsed = urlsplit(url)
            if (
                parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
                or not parsed.port
            ):
                raise VMUnavailable("verifying proxy must be a fixed local endpoint")
            self.targets[role] = url
        self.key = model_key
        self.plan = plan
        self.create_drafts = create_drafts
        self.configured.set()

    def close(self):
        self.stopped.set()
        self.configured.set()
        self.bound.set()
        import socket

        with self._response_lock:
            responses = list(self._responses)
        for response in responses:
            try:
                response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError):
                pass

    def _http(self, operation, body):
        if self.stopped.is_set():
            raise VMUnavailable("VM broker stopped")
        role, method, path = ROUTES[operation]
        if role not in self.targets or (
            operation == "intake.create" and not self.create_drafts
        ):
            raise ValueError("operation unavailable")
        if method == "POST" and not isinstance(body, dict):
            raise ValueError("JSON object required")
        if method == "GET" and body is not None:
            raise ValueError("GET body refused")
        headers = {"Content-Type": "application/json"}
        if role == "model":
            headers["Authorization"] = "Bearer " + self.key
        request = urllib.request.Request(
            self.targets[role] + path,
            data=(
                json.dumps(body, allow_nan=False).encode() if method == "POST" else None
            ),
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as e:
            # Preserve refusal status/body from the fixed verifier, never follow redirects.
            if 300 <= e.code < 400:
                raise ValueError("proxy redirect refused")
            response = e
        with self._response_lock:
            self._responses.add(response)
        try:
            if self.stopped.is_set():
                raise VMUnavailable("VM broker stopped")
            try:
                response.fp.raw._sock.settimeout(600)
            except AttributeError:
                pass
            yield json.dumps(
                {
                    "status": response.status,
                    "content_type": response.headers.get(
                        "Content-Type", "application/json"
                    ),
                }
            ).encode()
            with response:
                while not self.stopped.is_set():
                    chunk = response.read1(CHUNK)
                    if not chunk:
                        break
                    yield chunk
                if self.stopped.is_set():
                    raise VMUnavailable("VM broker stopped")
        finally:
            response.close()
            with self._response_lock:
                self._responses.discard(response)

    def _reply(self, stream, seq, chunks, *, complete=False):
        def bounded():
            for data in chunks:
                for start in range(0, len(data), CHUNK):
                    yield data[start : start + CHUNK]

        send_response(stream, seq, bounded(), vm_complete=complete)

    def serve(self, stream):
        binding = receive_frame(stream)
        if (
            not isinstance(binding, dict)
            or set(binding) != {"v", "session", "op"}
            or binding["op"] != "host.bind"
            or type(binding["v"]) is not int
            or binding["v"] != 1
            or not isinstance(binding["session"], str)
        ):
            raise VMUnavailable("VM transport binding refused")
        self.session = binding["session"]
        self.bound.set()
        for seq in range(65536):
            frame, payload = receive_request(stream)
            if frame["seq"] != seq or frame["session"] != self.session:
                raise VMUnavailable("VM request/session/replay refused")
            if self.stopped.is_set():
                raise VMUnavailable("VM broker stopped")
            from .wire import _object, _constant

            op = frame["op"]
            body = (
                json.loads(payload, object_pairs_hook=_object, parse_constant=_constant)
                if payload
                else None
            )
            complete = False
            if not self.ready.is_set():
                if (
                    op != "guest.ready"
                    or body != {"netns": True, "guard": True, "protocol": 1}
                    or type(body.get("netns")) is not bool
                    or type(body.get("guard")) is not bool
                    or type(body.get("protocol")) is not int
                ):
                    raise VMUnavailable("guest confinement readiness refused")
                self.ready.set()
                chunks = [b"{}"]
            elif op == "session.keep-alive":
                if body is not None or not self.configured.is_set():
                    raise VMUnavailable("keep-alive capability refused")
                chunks = [b"{}"]
            elif op == "session.plan":
                if (
                    body is not None
                    or not self.configured.wait(180)
                    or self.stopped.is_set()
                    or self.plan is None
                ):
                    raise VMUnavailable("launch plan unavailable")
                chunks = [
                    json.dumps(
                        {"launch": self.plan, "files": sorted(self.snapshot.files)}
                    ).encode()
                ]
            elif op == "workspace.read":
                if not self.configured.is_set() or body not in self.snapshot.files:
                    raise VMUnavailable("workspace read capability absent")
                chunks = [self.snapshot.files[body]]
            elif op in ROUTES:
                if not self.configured.is_set():
                    raise VMUnavailable("proxy capability unavailable")
                chunks = self._http(op, body)
            elif op == "output.begin":
                from .workspace import valid_path

                if (
                    not isinstance(body, dict)
                    or set(body) != {"name", "bytes"}
                    or type(body["bytes"]) is not int
                    or not 0 <= body["bytes"] <= 4 * 1024 * 1024
                    or self._upload is not None
                ):
                    raise VMUnavailable("output quota")
                name = valid_path(body["name"])
                if name in self.uploads or len(self.uploads) >= 2048:
                    raise VMUnavailable("output replay/quota")
                self._upload = (name, body["bytes"], bytearray())
                chunks = [b"{}"]
            elif op == "output.chunk":
                if self._upload is None:
                    raise VMUnavailable("output transaction absent")
                name, size, data = self._upload
                part = decode(body)
                if len(part) > CHUNK or len(data) + len(part) > size:
                    raise VMUnavailable("output chunk quota")
                data.extend(part)
                chunks = [b"{}"]
            elif op == "output.end":
                if body is not None or self._upload is None:
                    raise VMUnavailable("output transaction absent")
                name, size, data = self._upload
                if (
                    len(data) != size
                    or sum(map(len, self.uploads.values())) + size > 32 * 1024 * 1024
                ):
                    raise VMUnavailable("output length/quota")
                self.uploads[name] = bytes(data)
                self._upload = None
                chunks = [b"{}"]
            elif op == "session.finish":
                if (
                    self._upload is not None
                    or type(body) is not int
                    or not 0 <= body <= 255
                ):
                    raise VMUnavailable("agent exit refused")
                self.agent_exit = body
                self.complete = True
                complete = True
                chunks = [b"{}"]
            else:
                raise VMUnavailable("VM operation refused")
            self._reply(stream, seq, chunks, complete=complete)
            if complete:
                return
        raise VMUnavailable("VM request quota")

    def serve_status(self, stream):
        binding = receive_frame(stream)
        if not self.bound.wait(30) or self.stopped.is_set():
            raise VMUnavailable("main transport binding unavailable")
        if (
            not isinstance(binding, dict)
            or set(binding) != {"v", "session", "op"}
            or binding["op"] != "host.bind"
            or type(binding["v"]) is not int
            or binding["v"] != 1
            or binding["session"] != self.session
        ):
            raise VMUnavailable("status transport binding refused")
        if not self.configured.wait(180) or self.stopped.is_set():
            raise VMUnavailable("status capability unavailable")
        for seq in range(65536):
            head, body = receive_request(stream)
            if (
                head["session"] != self.session
                or head["seq"] != seq
                or head["op"] not in ("model.receipt", "session.keep-alive")
                or body
            ):
                raise VMUnavailable("status operation refused")
            self._reply(
                stream,
                seq,
                (
                    [b"{}"]
                    if head["op"] == "session.keep-alive"
                    else self._http("model.receipt", None)
                ),
            )
