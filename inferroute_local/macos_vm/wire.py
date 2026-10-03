"""Bounded framed request/reply protocol for the macOS VM bridge.

The transport binds a channel to a session. Frames carry operation names and
opaque JSON request/response bytes, never destinations, credentials, or URLs.
Each direction uses chunk acknowledgements so a slow receiver applies
backpressure instead of accumulating an unbounded response.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

VERSION = 1
# One request is the WHOLE conversation so far (the model API is stateless), so this bounds how long a
# session can get before every further turn is refused. A 256k-token context is on the order of a megabyte
# of JSON, which is where this limit used to sit; a matter with a few patents read into it would reach it.
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = 65536
CHUNK_BYTES = 3072
# Kept as a short alias for the broker/relay implementation.
CHUNK = CHUNK_BYTES
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ProtocolError(ValueError):
    """Malformed, misbound, or over-limit bridge traffic."""


def encode(data: bytes) -> str:
    """Encode one bounded-wire byte string as canonical ASCII base64."""
    if not isinstance(data, bytes):
        raise ProtocolError("base64 input must be bytes")
    return base64.b64encode(data).decode("ascii")


def decode(value: str) -> bytes:
    """Decode strict ASCII base64 received from a wire frame."""
    if not isinstance(value, str):
        raise ProtocolError("base64 input must be text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, base64.binascii.Error) as exc:
        raise ProtocolError("invalid base64 encoding") from exc


def _exact(stream: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ProtocolError("negative read length")
    data = bytearray()
    while len(data) < size:
        try:
            block = stream.recv(size - len(data))
        except InterruptedError:
            continue
        if not block:
            raise EOFError("bridge channel ended")
        data.extend(block)
    return bytes(data)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError("duplicate JSON field")
        out[key] = value
    return out


def _constant(_value: str) -> None:
    raise ProtocolError("non-finite JSON number")


def receive_frame(stream: socket.socket) -> dict[str, Any]:
    size = struct.unpack("!I", _exact(stream, 4))[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        raise ProtocolError("frame size outside limit")
    try:
        obj = json.loads(
            _exact(stream, size).decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid frame JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame must be a JSON object")
    return obj


def send_frame(stream: socket.socket, frame: Mapping[str, Any]) -> None:
    try:
        data = json.dumps(
            frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("frame cannot be encoded") from exc
    if not data or len(data) > MAX_FRAME_BYTES:
        raise ProtocolError("frame size outside limit")
    stream.sendall(struct.pack("!I", len(data)) + data)


def _ack(stream: socket.socket, seq: int, chunk: int) -> None:
    frame = receive_frame(stream)
    if (
        set(frame) != {"v", "seq", "ack"}
        or type(frame.get("v")) is not int
        or frame["v"] != VERSION
        or type(frame.get("seq")) is not int
        or frame["seq"] != seq
        or type(frame.get("ack")) is not int
        or frame["ack"] != chunk
    ):
        raise ProtocolError("chunk acknowledgement mismatch")


def _chunk_bytes(data: bytes, max_bytes: int) -> list[bytes]:
    if not isinstance(data, bytes):
        raise ProtocolError("payload must be bytes")
    if len(data) > max_bytes:
        raise ProtocolError("payload exceeds limit")
    return [data[i : i + CHUNK_BYTES] for i in range(0, len(data), CHUNK_BYTES)]


def send_request(
    stream: socket.socket,
    session: str,
    seq: int,
    op: str,
    body: bytes | Mapping[str, Any] | None = None,
) -> None:
    """Send one request, waiting for an ACK after each bounded body chunk.

    Mapping bodies are compact JSON encoded here; `bytes` bodies are sent
    verbatim. The receiver gets the byte length and chunk count in the header.
    """
    if not isinstance(session, str) or not session or len(session) > 128:
        raise ProtocolError("invalid session binding")
    if type(seq) is not int or seq < 0 or seq > 2**53 - 1:
        raise ProtocolError("invalid sequence")
    if not isinstance(op, str) or not op or len(op) > 64:
        raise ProtocolError("invalid operation")
    if body is None:
        payload = b""
    elif isinstance(body, bytes):
        payload = body
    elif isinstance(body, Mapping):
        try:
            payload = json.dumps(
                body, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ProtocolError("request body cannot be encoded") from exc
    else:
        raise ProtocolError("request body must be bytes, object, or absent")
    chunks = _chunk_bytes(payload, MAX_REQUEST_BYTES)
    send_frame(
        stream,
        {
            "v": VERSION,
            "session": session,
            "seq": seq,
            "op": op,
            "bytes": len(payload),
            "chunks": len(chunks),
        },
    )
    for index, chunk in enumerate(chunks):
        send_frame(
            stream, {"v": VERSION, "seq": seq, "chunk": index, "data": encode(chunk)}
        )
        _ack(stream, seq, index)


def receive_request(stream: socket.socket) -> tuple[dict[str, Any], bytes]:
    """Receive a request sent by `send_request`; ACK each chunk as it is read."""
    head = receive_frame(stream)
    if set(head) != {"v", "session", "seq", "op", "bytes", "chunks"}:
        raise ProtocolError("invalid request header")
    if (
        type(head["v"]) is not int
        or head["v"] != VERSION
        or not isinstance(head["session"], str)
        or not head["session"]
        or len(head["session"]) > 128
        or type(head["seq"]) is not int
        or not 0 <= head["seq"] <= 2**53 - 1
        or not isinstance(head["op"], str)
        or not head["op"]
        or len(head["op"]) > 64
        or type(head["bytes"]) is not int
        or not 0 <= head["bytes"] <= MAX_REQUEST_BYTES
        or type(head["chunks"]) is not int
        or not 0
        <= head["chunks"]
        <= (MAX_REQUEST_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES
    ):
        raise ProtocolError("invalid request header values")
    nbytes, nchunks = head["bytes"], head["chunks"]
    expected_chunks = (nbytes + CHUNK_BYTES - 1) // CHUNK_BYTES
    if nchunks != expected_chunks:
        raise ProtocolError("request chunk count mismatch")
    payload = bytearray()
    for index in range(nchunks):
        frame = receive_frame(stream)
        if (
            set(frame) != {"v", "seq", "chunk", "data"}
            or type(frame.get("v")) is not int
            or frame["v"] != VERSION
            or type(frame.get("seq")) is not int
            or frame["seq"] != head["seq"]
            or type(frame.get("chunk")) is not int
            or frame["chunk"] != index
            or not isinstance(frame.get("data"), str)
        ):
            raise ProtocolError("request chunk binding mismatch")
        chunk = decode(frame["data"])
        if not 0 < len(chunk) <= CHUNK_BYTES or len(payload) + len(chunk) > nbytes:
            raise ProtocolError("request chunk size outside limit")
        payload.extend(chunk)
        send_frame(stream, {"v": VERSION, "seq": head["seq"], "ack": index})
    if len(payload) != nbytes:
        raise ProtocolError("request byte count mismatch")
    return head, bytes(payload)


def send_response(
    stream: socket.socket,
    seq: int,
    chunks: Iterable[bytes],
    *,
    vm_complete: bool = False,
) -> None:
    """Send a bounded response stream, with a matching ACK required per chunk."""
    if type(seq) is not int or seq < 0 or seq > 2**53 - 1:
        raise ProtocolError("invalid sequence")
    if type(vm_complete) is not bool:
        raise ProtocolError("vm_complete must be boolean")
    total = 0
    index = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes) or not 0 < len(chunk) <= CHUNK_BYTES:
            raise ProtocolError("response chunk size outside limit")
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            send_frame(stream, {"v": VERSION, "seq": seq, "end": True, "ok": False})
            return
        send_frame(
            stream, {"v": VERSION, "seq": seq, "chunk": index, "data": encode(chunk)}
        )
        _ack(stream, seq, index)
        index += 1
    terminal = {"v": VERSION, "seq": seq, "end": True, "ok": True}
    if vm_complete:
        terminal["vm_complete"] = True
    send_frame(stream, terminal)


def receive_response(stream: socket.socket, seq: int) -> Iterator[bytes]:
    """Yield response chunks and ACK only when the consumer resumes iteration."""
    if type(seq) is not int or seq < 0 or seq > 2**53 - 1:
        raise ProtocolError("invalid sequence")
    expected = 0
    total = 0
    while True:
        frame = receive_frame(stream)
        if (
            type(frame.get("v")) is not int
            or frame["v"] != VERSION
            or type(frame.get("seq")) is not int
            or frame["seq"] != seq
        ):
            raise ProtocolError("response binding mismatch")
        if frame.get("end") is True:
            if (
                set(frame)
                not in (
                    {"v", "seq", "end", "ok"},
                    {"v", "seq", "end", "ok", "vm_complete"},
                )
                or type(frame.get("ok")) is not bool
                or ("vm_complete" in frame and type(frame["vm_complete"]) is not bool)
            ):
                raise ProtocolError("invalid response terminator")
            if frame["ok"] is not True:
                raise ProtocolError("peer refused request")
            return
        if (
            set(frame) != {"v", "seq", "chunk", "data"}
            or type(frame.get("chunk")) is not int
            or frame["chunk"] != expected
            or not isinstance(frame.get("data"), str)
        ):
            raise ProtocolError("response chunk order mismatch")
        chunk = decode(frame["data"])
        total += len(chunk)
        if not 0 < len(chunk) <= CHUNK_BYTES or total > MAX_RESPONSE_BYTES:
            raise ProtocolError("response chunk or total exceeds limit")
        yield chunk
        send_frame(stream, {"v": VERSION, "seq": seq, "ack": expected})
        expected += 1


def request(
    stream: socket.socket,
    session: str,
    seq: int,
    op: str,
    body: bytes | Mapping[str, Any] | None = None,
) -> Iterator[bytes]:
    """Send a request and yield its backpressure-controlled response chunks."""
    send_request(stream, session, seq, op, body)
    yield from receive_response(stream, seq)


__all__ = [
    "CHUNK",
    "CHUNK_BYTES",
    "MAX_FRAME_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "ProtocolError",
    "receive_frame",
    "receive_request",
    "receive_response",
    "request",
    "send_frame",
    "send_request",
    "send_response",
    "encode",
    "decode",
]
