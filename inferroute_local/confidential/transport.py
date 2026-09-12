"""How sealed requests reach the enclave, and where the client looks up the enclave operator.

Two carriers, one contract:

  InferRouteRelay  — the product path. ``api.inferroute.ai/confidential/…`` forwards the
                     sealed blob to the enclave operator's invoke endpoint under InferRoute's
                     credential and streams the (still encrypted) answer back. InferRoute sees
                     ciphertext, sizes, timing, the model and the instance id — never the words.
  DirectOperator   — bring-your-own operator key (``IR_OPERATOR_API_KEY`` + an operator profile
                     in ``IR_OPERATOR_PROFILE``). InferRoute is not in the path at all; used for
                     development and by users who prefer it.

**No operator endpoint is compiled into this client.** The addresses to fetch attestation
evidence from, and the header names the operator's gateway routes on, arrive at run time as an
*operator profile* — from the relay (``GET /confidential/endpoints``) or, for direct mode, from a
local JSON file. To this client they are opaque strings.

What that costs in trust, stated precisely, because the honest version is narrower than the
tempting one. Everything fetched through the profile is verified independently on this device:
the TDX quote chains to Intel's pinned root, the platform's TCB and the Quoting Enclave's
identity come from Intel's own service, every GPU report from NVIDIA's, and the encryption key
is bound to our nonce inside the quote. So the profile cannot make an unattested endpoint look
attested, and it cannot get your ciphertext read by anything that is not a real TDX enclave.

Against the ENCLAVE OPERATOR that is the whole story: a profile they tampered with could only
point at some other genuinely attested enclave, whose build is not one InferRoute ships a record
of, and the recorded-build check refuses it.

Against INFERROUTE it is not, and the code should not pretend otherwise. The same relay that
serves this profile also serves additions to the build list (see builds.absorb_remote). An
attacker holding our relay could therefore point the client at a TDX enclave they control AND
supply the row that makes it recognised. Every other check would pass truthfully. What stops
that from being invisible is that such a build is marked `pending`, and the panel, the receipt
and the model preamble all say so — it can never present itself as a build InferRoute shipped
a record of. Closing it properly needs the build list signed by a key this client pins, which
is the next step and is not done yet.

Profile shape (every field a template or a literal; ``{fleet}`` / ``{nonce}`` are substituted)::

    {"evidence": "https://…/{fleet}/evidence?nonce={nonce}",
     "measurements": "https://…/measurements",
     "models": "https://…/v1/models",              # direct mode only
     "instances": "https://…/instances/{fleet}",   # direct mode only
     "invoke": "https://…/invoke",                 # direct mode only
     "fleet_field": "…",                           # direct mode only: the id field in `models`
     "headers": {"fleet": "X-…", "instance": "X-…", "nonce": "X-…", "stream": "X-…", "path": "X-…"}}
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

import httpx

INVOKE_PATH = "/v1/chat/completions"
UA = "inferroute-confidential/1"

# What THIS client sends to the InferRoute relay. The relay maps these onto whatever the operator's
# gateway expects, so the operator's own header names never appear here.
NEUTRAL_HEADERS = {"fleet": "X-IR-Fleet", "instance": "X-IR-Instance", "nonce": "X-IR-Nonce",
                   "stream": "X-IR-Stream", "path": "X-IR-Path"}


class ProfileUnavailable(Exception):
    """No operator profile: the client does not know where to fetch attestation evidence."""


@dataclass
class OperatorProfile:
    evidence: str = ""
    measurements: str = ""
    models: str = ""
    instances: str = ""
    invoke: str = ""
    headers: dict = field(default_factory=lambda: dict(NEUTRAL_HEADERS))
    # Which field of the operator's model listing carries the fleet id (direct mode only; the
    # relay normalises it to `fleet_id` before we see it). Operator naming stays in the profile.
    fleet_field: str = "fleet_id"

    @classmethod
    def from_dict(cls, d: dict) -> "OperatorProfile":
        if not isinstance(d, dict) or not d.get("evidence") or not d.get("measurements"):
            raise ProfileUnavailable("operator profile lacks the attestation endpoints")
        h = {**NEUTRAL_HEADERS, **(d.get("headers") or {})}
        return cls(evidence=d["evidence"], measurements=d["measurements"], models=d.get("models", ""),
                   instances=d.get("instances", ""), invoke=d.get("invoke", ""), headers=h,
                   fleet_field=d.get("fleet_field") or "fleet_id")

    def evidence_url(self, fleet_id: str, nonce: str) -> str:
        return self.evidence.replace("{fleet}", fleet_id).replace("{nonce}", nonce)

    def measurements_url(self) -> str:
        return self.measurements

    def instances_url(self, fleet_id: str) -> str:
        return self.instances.replace("{fleet}", fleet_id)


def load_profile_file(path: str | None = None) -> OperatorProfile:
    """The operator profile for direct mode: ``IR_OPERATOR_PROFILE`` (a JSON file)."""
    p = Path(path or os.environ.get("IR_OPERATOR_PROFILE", ""))
    if not p or not str(p) or not p.is_file():
        raise ProfileUnavailable("direct mode needs an operator profile in IR_OPERATOR_PROFILE (a JSON file)")
    try:
        return OperatorProfile.from_dict(json.loads(p.read_text()))
    except (OSError, ValueError) as e:
        raise ProfileUnavailable(f"operator profile could not be read: {type(e).__name__}") from e


def invoke_headers(names: dict, *, fleet_id: str, instance_id: str, nonce: str, stream: bool,
                   path: str = INVOKE_PATH) -> dict:
    """The five routing headers, under whichever names this carrier wants them."""
    return {names["fleet"]: fleet_id, names["instance"]: instance_id, names["nonce"]: nonce,
            names["stream"]: "true" if stream else "false", names["path"]: path,
            "Content-Type": "application/octet-stream", "User-Agent": UA}


class Transport:
    name = "?"
    relay_sees = "ciphertext only"

    def __init__(self, http: httpx.AsyncClient):
        self.http = http
        self._profile: OperatorProfile | None = None

    async def profile(self) -> OperatorProfile:
        """Where attestation evidence lives, for this carrier. Cached per session."""
        raise NotImplementedError

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

    def __init__(self, http: httpx.AsyncClient, api_key: str | None = None, profile: OperatorProfile | None = None):
        super().__init__(http)
        self.api_key = api_key or os.environ.get("IR_OPERATOR_API_KEY", "")
        if not self.api_key:
            raise ValueError("direct carrier needs an operator API key (IR_OPERATOR_API_KEY)")
        self._profile = profile or load_profile_file()

    async def profile(self) -> OperatorProfile:
        return self._profile

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "User-Agent": UA}

    async def models(self) -> list[dict]:
        r = await self.http.get(self._profile.models, headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        f = self._profile.fleet_field
        return [{"name": m.get("id"), "fleet_id": m.get(f), "quantization": m.get("quantization"),
                 "context_length": m.get("context_length")}
                for m in r.json().get("data", []) if m.get(f) and str(m.get("id", "")).endswith("-TEE")]

    async def instances(self, fleet_id: str) -> dict:
        r = await self.http.get(self._profile.instances_url(fleet_id), headers=self._auth(), timeout=30)
        r.raise_for_status()
        return r.json()

    async def invoke(self, *, fleet_id, instance_id, nonce, stream, blob, path=INVOKE_PATH):
        h = {**self._auth(), **invoke_headers(self._profile.headers, fleet_id=fleet_id, instance_id=instance_id,
                                              nonce=nonce, stream=stream, path=path)}
        return await self._send(self._profile.invoke, h, blob)


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

    async def profile(self) -> OperatorProfile:
        if self._profile is None:
            r = await self.http.get(f"{self.base}/confidential/endpoints", headers=self._auth(), timeout=30)
            if r.status_code == 404:
                raise RelayUnavailable("this InferRoute server does not offer the confidential lane yet")
            r.raise_for_status()
            self._profile = OperatorProfile.from_dict(r.json())
        return self._profile

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
        h = {**self._auth(), **invoke_headers(NEUTRAL_HEADERS, fleet_id=fleet_id, instance_id=instance_id,
                                              nonce=nonce, stream=stream, path=path)}
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
