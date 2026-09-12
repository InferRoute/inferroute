"""The SERVER side of the operator's e2ee protocol, re-implemented for tests.

Mirrors what the in-enclave runtime does (as read from the operator's open-source SDK): decapsulate our request, gzip-decompress the JSON, pull ``e2e_response_pk``, then
encapsulate to it for the response — as one blob or as an ``e2e_init`` + ``e2e`` SSE stream.
A client that round-trips through this and through the real chute is speaking one protocol.
"""
from __future__ import annotations

import base64
import gzip
import json
import os

from inferroute_local.confidential import e2ee


class FakeEnclave:
    def __init__(self):
        self.pk, self.sk = e2ee.backend().keygen()
        self.pubkey_b64 = base64.b64encode(self.pk).decode()
        self.last_plaintext: dict | None = None

    # -- request side --
    def open_request(self, blob: bytes) -> tuple[dict, bytes]:
        mlkem_ct = blob[:e2ee.MLKEM_CT_SIZE]
        nonce = blob[e2ee.MLKEM_CT_SIZE:e2ee.MLKEM_CT_SIZE + 12]
        shared = e2ee.backend().decaps(self.sk, mlkem_ct)
        key = e2ee.derive_key(shared, mlkem_ct, e2ee.INFO_REQ)
        plain = gzip.decompress(e2ee._open(key, nonce, blob[e2ee.MLKEM_CT_SIZE + 12:]))
        body = json.loads(plain)
        client_pk = base64.b64decode(body.pop("e2e_response_pk"))
        self.last_plaintext = body
        return body, client_pk

    # -- response side --
    def seal_response(self, client_pk: bytes, payload: dict) -> bytes:
        shared, mlkem_ct = e2ee.backend().encaps(client_pk)
        key = e2ee.derive_key(shared, mlkem_ct, e2ee.INFO_RESP)
        nonce = os.urandom(12)
        return mlkem_ct + nonce + e2ee._seal(key, nonce, gzip.compress(json.dumps(payload).encode()))

    def stream(self, client_pk: bytes, plaintext_chunks: list[bytes]) -> bytes:
        """The encrypted SSE the gateway relays: one e2e_init frame, then one e2e frame per
        chunk — chunks are whatever byte slices the server happened to write."""
        shared, mlkem_ct = e2ee.backend().encaps(client_pk)
        key = e2ee.derive_key(shared, mlkem_ct, e2ee.INFO_STREAM)
        out = [f"data: {json.dumps({'e2e_init': base64.b64encode(mlkem_ct).decode()})}\n\n".encode()]
        for c in plaintext_chunks:
            nonce = os.urandom(12)
            enc = nonce + e2ee._seal(key, nonce, c)
            out.append(f"data: {json.dumps({'e2e': base64.b64encode(enc).decode()})}\n\n".encode())
        out.append(b"data: [DONE]\n\n")
        return b"".join(out)
