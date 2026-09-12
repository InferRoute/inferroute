"""End-to-end encryption from THIS device to one Chutes TEE instance.

The wire format is the one Chutes' own clients speak (``chutes-e2ee-transport`` /
``crypto.py``) and their in-enclave ``aegis`` library decrypts, re-implemented here so the
``ir`` client depends on no vendor SDK and every byte it sends can be read in this file:

    request blob   = mlkem_ct(1088) ‖ nonce(12) ‖ chacha_ct ‖ tag(16)
    request key    = HKDF-SHA256(shared_secret, salt=mlkem_ct[:16], info=b"e2e-req-v1")
    plaintext      = gzip(JSON(payload ∪ {"e2e_response_pk": b64(our ML-KEM public key)}))

    response blob  = mlkem_ct ‖ nonce ‖ ct ‖ tag        (info b"e2e-resp-v1", gzip JSON inside)
    stream         = SSE  data: {"e2e_init": b64(mlkem_ct)}   → key with info b"e2e-stream-v1"
                     then data: {"e2e": b64(nonce ‖ ct ‖ tag)} per chunk of the underlying SSE

Key exchange is ML-KEM-768 (FIPS 203). For the REQUEST we encapsulate to the instance's
public key; for the RESPONSE the instance encapsulates to a fresh keypair we generate per
request, so the response key never leaves this process either. Symmetric layer is
ChaCha20-Poly1305 (12-byte nonce, 16-byte tag).

What this module can and cannot promise, stated once so the display never overstates it:
  * Only a holder of the private half of ``instance_pubkey`` can read the request. Whether
    that private key lives inside the attested enclave is NOT something this layer can
    check — the instance's ML-KEM key is handed to us by Chutes' API and is not committed to
    by the TDX quote (measured 2026-09-12). ``session.py`` records that as a stated
    limitation; it is never rendered as a passed check.
  * ML-KEM backend: ``cryptography`` ≥ 50 (bundled OpenSSL with ML-KEM) when available,
    else the pure-Python ``kyber-py``. Both are FIPS 203 ML-KEM-768; the bytes are identical.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MLKEM_PK_SIZE = 1184
MLKEM_CT_SIZE = 1088
NONCE_SIZE = 12
TAG_SIZE = 16

INFO_REQ = b"e2e-req-v1"
INFO_RESP = b"e2e-resp-v1"
INFO_STREAM = b"e2e-stream-v1"


class E2EEError(Exception):
    """A blob that cannot be opened, or a malformed frame. Never silently swallowed."""


# ───────────────────────────── ML-KEM-768 backend ─────────────────────────────

class _Backend:
    name: str

    def keygen(self) -> tuple[bytes, Any]:
        raise NotImplementedError

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """→ (shared_secret[32], ciphertext[1088])"""
        raise NotImplementedError

    def decaps(self, sk: Any, ct: bytes) -> bytes:
        raise NotImplementedError


class _CryptographyBackend(_Backend):
    name = "cryptography/OpenSSL ML-KEM-768"

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401  (≥ 50)
        self._m = mlkem

    def keygen(self):
        sk = self._m.MLKEM768PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk

    def encaps(self, pk: bytes):
        shared, ct = self._m.MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
        return shared, ct

    def decaps(self, sk, ct: bytes) -> bytes:
        return sk.decapsulate(ct)


class _KyberPyBackend(_Backend):
    name = "kyber-py ML-KEM-768 (pure Python)"

    def __init__(self):
        from kyber_py.ml_kem import ML_KEM_768
        self._k = ML_KEM_768

    def keygen(self):
        ek, dk = self._k.keygen()
        return ek, dk

    def encaps(self, pk: bytes):
        shared, ct = self._k.encaps(pk)
        return shared, ct

    def decaps(self, sk, ct: bytes) -> bytes:
        return self._k.decaps(sk, ct)


_BACKEND: _Backend | None = None


def backend() -> _Backend:
    global _BACKEND
    if _BACKEND is None:
        try:
            _BACKEND = _CryptographyBackend()
        except Exception:
            try:
                _BACKEND = _KyberPyBackend()
            except Exception as e:  # pragma: no cover - environment-specific
                raise E2EEError(
                    "no ML-KEM-768 implementation available: install `cryptography>=50` "
                    "or `kyber-py` (pip install 'inferroute[confidential]')"
                ) from e
    return _BACKEND


# ───────────────────────────── primitives ─────────────────────────────

def derive_key(shared_secret: bytes, mlkem_ct: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=mlkem_ct[:16], info=info).derive(shared_secret)


def _seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 → ct ‖ tag (the AEAD already appends the 16-byte tag)."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def _open(key: bytes, nonce: bytes, ct_and_tag: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct_and_tag, None)
    except Exception as e:
        raise E2EEError("authentication failed: the blob was not produced for our key, or was altered") from e


def _b64d(s: str) -> bytes:
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


# ───────────────────────────── request / response ─────────────────────────────

@dataclass
class SealedRequest:
    blob: bytes            # the bytes that leave this device
    response_sk: Any       # our per-request ML-KEM private key; never serialised
    plaintext_size: int    # bytes of JSON before gzip — for the receipt's "encrypted here" counter
    mlkem_ct: bytes        # kept so a receipt can name the exchange without revealing anything


def seal_request(instance_pubkey_b64: str, payload: dict) -> SealedRequest:
    """Encrypt ``payload`` so that only the holder of ``instance_pubkey_b64`` can read it."""
    pk = _b64d(instance_pubkey_b64)
    if len(pk) != MLKEM_PK_SIZE:
        raise E2EEError(f"instance public key is {len(pk)} bytes, not an ML-KEM-768 key ({MLKEM_PK_SIZE})")
    b = backend()
    response_pk, response_sk = b.keygen()
    shared, mlkem_ct = b.encaps(pk)
    key = derive_key(shared, mlkem_ct, INFO_REQ)
    body = json.dumps({**payload, "e2e_response_pk": base64.b64encode(response_pk).decode()}).encode()
    nonce = os.urandom(NONCE_SIZE)
    blob = mlkem_ct + nonce + _seal(key, nonce, gzip.compress(body))
    return SealedRequest(blob=blob, response_sk=response_sk, plaintext_size=len(body), mlkem_ct=mlkem_ct)


def open_response(blob: bytes, response_sk: Any) -> dict:
    """Decrypt a non-streaming response blob (``{"e2e": b64}`` already base64-decoded)."""
    if len(blob) < MLKEM_CT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise E2EEError(f"response blob too short ({len(blob)} bytes)")
    mlkem_ct = blob[:MLKEM_CT_SIZE]
    nonce = blob[MLKEM_CT_SIZE:MLKEM_CT_SIZE + NONCE_SIZE]
    shared = backend().decaps(response_sk, mlkem_ct)
    key = derive_key(shared, mlkem_ct, INFO_RESP)
    plain = _open(key, nonce, blob[MLKEM_CT_SIZE + NONCE_SIZE:])
    try:
        return json.loads(gzip.decompress(plain))
    except Exception as e:
        raise E2EEError("response decrypted but is not gzip'd JSON") from e


def stream_key(response_sk: Any, e2e_init_b64: str) -> bytes:
    mlkem_ct = _b64d(e2e_init_b64)
    if len(mlkem_ct) != MLKEM_CT_SIZE:
        raise E2EEError(f"e2e_init is {len(mlkem_ct)} bytes, not an ML-KEM-768 ciphertext")
    shared = backend().decaps(response_sk, mlkem_ct)
    return derive_key(shared, mlkem_ct, INFO_STREAM)


def open_stream_chunk(key: bytes, e2e_b64: str) -> bytes:
    raw = _b64d(e2e_b64)
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise E2EEError("stream chunk too short")
    return _open(key, raw[:NONCE_SIZE], raw[NONCE_SIZE:])


class StreamOpener:
    """Turn the ENCRYPTED SSE stream from ``/e2e/invoke`` back into the plaintext byte stream
    the enclave produced (which is itself OpenAI-style SSE, chunked arbitrarily).

    Feed raw bytes as they arrive; get plaintext bytes back. Frames that are neither
    ``e2e_init`` nor ``e2e`` (an error the gateway injects in the clear, say) are surfaced
    through ``passthrough`` so the caller can show them instead of hanging.
    """

    def __init__(self, response_sk: Any):
        self._sk = response_sk
        self._key: bytes | None = None
        self._buf = b""
        self.passthrough: list[dict] = []
        self.frames = 0
        self.ciphertext_bytes = 0

    def feed(self, data: bytes) -> bytes:
        self._buf += data
        out = bytearray()
        while True:
            i = self._buf.find(b"\n")
            if i == -1:
                break
            line, self._buf = self._buf[:i].rstrip(b"\r"), self._buf[i + 1:]
            out += self._line(line)
        return bytes(out)

    def flush(self) -> bytes:
        if not self._buf.strip():
            return b""
        line, self._buf = self._buf, b""
        return self._line(line.rstrip(b"\r\n"))

    def _line(self, line: bytes) -> bytes:
        if not line.startswith(b"data:"):
            return b""
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return b""
        try:
            ev = json.loads(payload)
        except json.JSONDecodeError:
            self.passthrough.append({"raw": payload[:200].decode("utf-8", "replace")})
            return b""
        if not isinstance(ev, dict):
            return b""
        if "e2e_init" in ev:
            self._key = stream_key(self._sk, ev["e2e_init"])
            return b""
        if "e2e" in ev:
            if self._key is None:
                raise E2EEError("stream chunk arrived before e2e_init")
            self.frames += 1
            self.ciphertext_bytes += len(ev["e2e"])
            return open_stream_chunk(self._key, ev["e2e"])
        self.passthrough.append(ev)
        return b""
