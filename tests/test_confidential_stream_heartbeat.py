"""A sealed reply that goes quiet mid-stream must not be cut by the AGENT's idle timer.

22 Oct 18:05Z and 21 Oct 18:22Z, kimi-k3 under load: the gateway logged a 200 (372 s, 842 KB; 917 s,
611 KB), Pi logged stop "error", error "terminated", and redid the whole reply. "terminated" is undici's
word for a body that stopped; its cause there was Pi's own body idle timer (300 s). On 21 Oct the last delta
Pi showed was 300.6 s before the cut; the receipt counted no error and no usage for the reply, i.e. the
stream was cancelled from the agent's side, and the gateway wrote its row in a `finally` as a 200.

The upstream can be silent that long while still working (a long tool call is emitted only once it parses).
The local endpoint now fills the silence with SSE comments, which every SSE parser skips.
"""
import asyncio
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from inferroute_local.confidential import server as SV
from inferroute_local.confidential.server import HEARTBEAT, create_app, with_heartbeat

TOKEN = "ir-test-token"
SILENCE_S = 1.5          # the upstream says nothing for this long, mid-reply
AGENT_IDLE_S = 0.6       # the agent's body idle timer (Pi's is 300 s; scaled down)


def _line(obj) -> bytes:
    return ("data: " + json.dumps(obj) + "\n").encode()


class _Receipt:
    is_confidential = True
    refusal = ""
    verdict = "confidential"
    counters = {"errors": 0}


class _QuietSession:
    """Streams a few deltas, goes silent (the model is writing a long tool call), then finishes."""
    receipt = _Receipt()

    def _stream(self, finish: bytes):
        async def gen():
            for i in range(3):
                yield _line({"choices": [{"index": 0, "delta": {"reasoning_content": f"t{i}"}}]})
                yield b"\n"
            await asyncio.sleep(SILENCE_S)
            yield _line({"choices": [{"index": 0, "delta": {"content": "done"}, "finish_reason": "stop"}]})
            yield b"\n"
            yield finish
        return gen()

    async def chat_completions(self, body):
        return 200, {"content-type": "text/event-stream"}, self._stream(b"data: [DONE]\n\n")

    async def messages(self, body):
        return 200, {"content-type": "text/event-stream"}, self._stream(b'event: message_stop\ndata: {"type": "message_stop"}\n\n')


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(SV, "STREAM_HEARTBEAT_S", 0.2)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(create_app(_QuietSession(), TOKEN), host="127.0.0.1", port=port,
                                        log_level="critical", timeout_keep_alive=SV.SEALED_KEEPALIVE_S))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline, "the endpoint did not start"
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


@pytest.mark.parametrize("path, finish", [("/v1/chat/completions", b"data: [DONE]"),
                                          ("/v1/messages", b"message_stop")])
def test_a_quiet_upstream_does_not_trip_the_agents_idle_timer(endpoint, path, finish):
    """Before the fix this read timed out after AGENT_IDLE_S — Pi's "terminated"."""
    timeout = httpx.Timeout(10.0, read=AGENT_IDLE_S)
    with httpx.stream("POST", endpoint + path, json={"stream": True, "messages": []},
                      headers={"authorization": f"Bearer {TOKEN}"}, timeout=timeout) as r:
        assert r.status_code == 200
        body = b"".join(r.iter_bytes())
    assert finish in body, "the reply arrived whole, through the silence"
    assert HEARTBEAT in body, "the silence was filled"
    # Nothing else changed: drop the comments and the reply is byte-for-byte what the session produced.
    expected = b"".join(_line({"choices": [{"index": 0, "delta": {"reasoning_content": f"t{i}"}}]}) + b"\n"
                        for i in range(3))
    expected += _line({"choices": [{"index": 0, "delta": {"content": "done"}, "finish_reason": "stop"}]}) + b"\n"
    assert body.replace(HEARTBEAT, b"").startswith(expected)


def _collect(gen):
    async def run():
        return [c async for c in gen]
    return asyncio.run(run())


def test_a_busy_stream_gets_no_heartbeats():
    async def busy():
        for i in range(5):
            yield _line({"i": i})
            yield b"\n"
    out = _collect(with_heartbeat(busy(), every=0.5))
    assert HEARTBEAT not in out and len(out) == 10


def test_a_heartbeat_never_lands_inside_a_line():
    """A chunk that stops mid-line (a final flush, say) is followed by silence: no comment may be written
    there, or it would be glued onto the data line and corrupt it."""
    async def split():
        yield b'data: {"a": '
        await asyncio.sleep(0.3)
        yield b"1}\n\n"
    out = _collect(with_heartbeat(split(), every=0.05))
    assert b"".join(out) == b'data: {"a": 1}\n\n'


def test_leaving_early_closes_the_upstream():
    """The agent going away must still close the relay leg, as it did before the wrapper existed."""
    closed = []

    async def upstream():
        try:
            yield b"data: 1\n\n"
            await asyncio.sleep(30)
            yield b"data: 2\n\n"
        finally:
            closed.append(True)

    async def run():
        g = with_heartbeat(upstream(), every=0.05)
        assert await g.__anext__() == b"data: 1\n\n"
        assert await g.__anext__() == HEARTBEAT
        await g.aclose()
    asyncio.run(run())
    assert closed == [True]
