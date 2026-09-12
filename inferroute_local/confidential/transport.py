"""How sealed requests reach the enclave. Two carriers, one contract.

  InferRouteRelay  — the product path. ``api.inferroute.ai/confidential/…`` forwards the
                     sealed blob to the enclave operator's invoke endpoint under InferRoute's
                     credential and streams the (still encrypted) answer back. InferRoute sees
                     ciphertext, sizes, timing, the model and the instance id — never the words.
  DirectOperator   — bring-your-own operator key (``IR_OPERATOR_API_KEY``). InferRoute is not in
                     the path at all; used for development and by users who prefer it.

Neither carrier is trusted with anything: the attestation is fetched from the operator directly
by ``attest.py``, and the blob is sealed before it is handed to either.
"""
from __future__ import annotations

import os
from typing import AsyncIterator

import httpx

# The enclave operator's public endpoints. This is the one place they appear; everything
# user-facing says "the enclave operator".
OPERATOR_API = "https://api.chutes.ai"
OPERATOR_MODELS = "https://llm.chutes.ai/v1/models"
INVOKE_PATH = "/v1/chat/completions"
UA = "inferroute-confidential/1"


def invoke_headers(*, fleet_id: str, instance_id: str, nonce: str, stream: bool, path: str = INVOKE_PATH) -> dict:
    """The five headers the operator's gateway routes on (its own e2ee transport, verbatim names)."""
    return {"X-Chute-Id": fleet_id, "X-Instance-Id": instance_id, "X-E2E-Nonce": nonce,
            "X-E2E-Stream": "true" if stream else "false", "X-E2E-Path": path,
            "Content-Type": "application/octet-stream", "User-Agent": UA}


class Transport:
    name = "?"
    relay_sees = "ciphertext only"

    def __init__(self, http: httpx.AsyncClient):
        self.http = http

    async def models(self) -> list[dict]:
        raise NotImplementedError

    async def instances(self, fleet_id: str) -> dict:
        raise NotImplementedError

    async def invoke(self, *, fleet_id: str, instance_id: str, nonce: str, stream: bool, blob: bytes,
                     path: str = INVOKE_PATH) -> tuple[int, dict, AsyncIterator[bytes]]:
        raise NotImplementedError

    async def report_usage(self, payload: dict) -> None:
        """Best-effort, never raises: token counts the client decrypted, offered for billing."""
        return None

    async def _send(self, url: str, headers: dict, blob: bytes) -> tuple[int, dict, AsyncIterator[bytes]]:
        req = self.http.build_request("POST", url, headers=headers, content=blob)
        resp = await self.http.send(req, stream=True)

        async def _iter():
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()

        return resp.status_code, dict(resp.headers), _iter()


class DirectOperator(Transport):
    name = "direct to the enclave operator (your own key — InferRoute is not in the path)"

    def __init__(self, http: httpx.AsyncClient, api_key: str | None = None, api_base: str = OPERATOR_API):
        super().__init__(http)
        self.api_key = api_key or os.environ.get("IR_OPERATOR_API_KEY", "")
        self.api_base = api_base.rstrip("/")
        if not self.api_key:
            raise ValueError("direct carrier needs an operator API key (IR_OPERATOR_API_KEY)")

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "User-Agent": UA}

    async def models(self) -> list[dict]:
        r = await self.http.get(OPERATOR_MODELS, headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        return [{"name": m.get("id"), "fleet_id": m.get("fleet_id"), "quantization": m.get("quantization"),
                 "context_length": m.get("context_length")}
                for m in r.json().get("data", []) if m.get("fleet_id") and str(m.get("id", "")).endswith("-TEE")]

    async def instances(self, fleet_id: str) -> dict:
        r = await self.http.get(f"{self.api_base}/e2e/instances/{fleet_id}", headers=self._auth(), timeout=30)
        r.raise_for_status()
        return r.json()

    async def invoke(self, *, fleet_id, instance_id, nonce, stream, blob, path=INVOKE_PATH):
        h = {**self._auth(), **invoke_headers(fleet_id=fleet_id, instance_id=instance_id, nonce=nonce, stream=stream, path=path)}
        return await self._send(f"{self.api_base}/e2e/invoke", h, blob)


class InferRouteRelay(Transport):
    name = "InferRoute relay (ciphertext only)"

    def __init__(self, http: httpx.AsyncClient, api_url: str, api_key: str, session_id: str = ""):
        super().__init__(http)
        self.base = api_url.rstrip("/")
        self.api_key = api_key
        self.session_id = session_id

    def _auth(self) -> dict:
        h = {"Authorization": f"Bearer {self.api_key}", "User-Agent": UA}
        if self.session_id:
            h["x-inferroute-session"] = self.session_id
        return h

    async def builds(self) -> list:
        """Builds InferRoute has recorded since this client was released (additions only)."""
        try:
            r = await self.http.get(f"{self.base}/confidential/builds", headers=self._auth(), timeout=15)
            return r.json().get("builds", []) if r.status_code == 200 else []
        except Exception:
            return []

    async def models(self) -> list[dict]:
        r = await self.http.get(f"{self.base}/confidential/models", headers=self._auth(), timeout=30)
        if r.status_code == 404:
            raise RelayUnavailable("this InferRoute server does not offer the confidential lane yet")
        r.raise_for_status()
        return [{**m, "fleet_id": m.get("fleet_id") or m.get("fleet_id")} for m in r.json().get("models", [])]

    async def instances(self, fleet_id: str) -> dict:
        r = await self.http.get(f"{self.base}/confidential/instances/{fleet_id}", headers=self._auth(), timeout=30)
        if r.status_code == 404:
            raise RelayUnavailable("this InferRoute server does not offer the confidential lane yet")
        r.raise_for_status()
        return r.json()

    async def invoke(self, *, fleet_id, instance_id, nonce, stream, blob, path=INVOKE_PATH):
        h = {**self._auth(), **invoke_headers(fleet_id=fleet_id, instance_id=instance_id, nonce=nonce, stream=stream, path=path)}
        return await self._send(f"{self.base}/confidential/invoke", h, blob)

    async def report_usage(self, payload: dict) -> None:
        try:
            await self.http.post(f"{self.base}/confidential/usage", headers=self._auth(), json=payload, timeout=10)
        except Exception:
            pass


class RelayUnavailable(Exception):
    pass


def make_transport(http: httpx.AsyncClient, *, api_url: str = "", api_key: str = "", session_id: str = "",
                   prefer_direct: bool | None = None) -> Transport:
    """Direct when an operator key is present (explicit BYOK beats the relay); otherwise the relay."""
    direct_key = os.environ.get("IR_OPERATOR_API_KEY", "")
    if prefer_direct is True or (prefer_direct is None and direct_key):
        return DirectOperator(http, api_key=direct_key)
    if not api_key:
        raise ValueError("no InferRoute key (run `ir login`) and no IR_OPERATOR_API_KEY for direct mode")
    return InferRouteRelay(http, api_url=api_url, api_key=api_key, session_id=session_id)
