"""Talk to the relay. Stdlib urllib only, so it ships in the open-source client unchanged.

Everything that crosses this boundary is either public (offers, statements, evidence) or sealed
(turns, results). The relay is a mailbox, not a party to the protocol: nothing here verifies or
opens anything — that is client.py's job on one side and enclave_job's on the other.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class RelayError(RuntimeError):
    def __init__(self, status: int, reason: str):
        super().__init__(f"relay {status}: {reason}")
        self.status, self.reason = status, reason


class RelayClient:
    def __init__(self, url: str, token: str, *, timeout: float = 60.0):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    # Transient pre-connect failures (DNS blips, refused connections, unreachable network)
    # are retried: sr-reflect died 9x on 2026-09-25 to a momentary gaierror. These raised BEFORE
    # any byte left the machine, so a retry cannot double-apply a POST. Read timeouts and 5xx are
    # NOT retried here: the request may have been applied server-side.
    # Named, not imported: the client whitelist forbids `import socket` in shippable modules.
    _RETRYABLE_REASONS = {"gaierror", "ConnectionRefusedError", "ConnectionResetError"}
    _RETRIES, _BACKOFF_S = 4, 2.0

    def _call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        for attempt in range(self._RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                try:
                    detail = json.load(e).get("detail") or json.load(e).get("reason") or str(e.code)
                except Exception:                    # noqa: BLE001
                    detail = str(e.code)
                raise RelayError(e.code, str(detail)) from None
            except urllib.error.URLError as e:
                if type(e.reason).__name__ in self._RETRYABLE_REASONS and attempt < self._RETRIES - 1:
                    time.sleep(self._BACKOFF_S * (2 ** attempt))
                    continue
                raise

    # ---- both roles
    def status(self) -> Dict[str, Any]:
        return self._call("GET", "/status")

    def current_offer(self, dest_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            o = self._call("GET", "/offers/current")
        except RelayError as e:
            if e.status == 404:
                return None
            raise
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
            for name, b64 in o["files"].items():
                with open(os.path.join(dest_dir, name), "wb") as fh:
                    fh.write(base64.b64decode(b64))
        return o

    def turn(self, job_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/turns/{job_id}")

    def result(self, job_id: str, dest_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            r = self._call("GET", f"/results/{job_id}")
        except RelayError as e:
            if e.status == 404:
                return None
            raise
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
            for name, b64 in r["files"].items():
                with open(os.path.join(dest_dir, name), "wb") as fh:
                    fh.write(base64.b64decode(b64))
        return r

    # ---- client role
    def create_turn(self, job_id: str, session_id: str, turn: int, firm_pub_hex: str) -> Dict[str, Any]:
        return self._call("POST", "/turns", {"job_id": job_id, "session_id": session_id, "turn": turn, "firm_pub": firm_pub_hex})

    def cancel_turn(self, job_id: str) -> Dict[str, Any]:
        """Withdraw a turn that no enclave is working on yet."""
        return self._call("DELETE", f"/turns/{job_id}")

    def put_blob(self, job_id: str, offer_lifetime_id: str, blob: bytes) -> Dict[str, Any]:
        return self._call("PUT", f"/turns/{job_id}/blob",
                          {"offer_lifetime_id": offer_lifetime_id, "blob_b64": base64.b64encode(blob).decode()})

    # ---- enclave role (orchestrator)
    def put_status(self, **st: Any) -> None:
        self._call("PUT", "/status", st)

    def post_offer(self, lifetime_id: str, offer_dir: str) -> Dict[str, Any]:
        files = {}
        for name in ("offer.json", "snp-report.bin", "gpu-attestation.txt"):
            p = os.path.join(offer_dir, name)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    files[name] = base64.b64encode(fh.read()).decode()
        return self._call("POST", "/offers", {"lifetime_id": lifetime_id, "files": files})

    def void_offer(self) -> Dict[str, Any]:
        return self._call("DELETE", "/offers/current")

    def pending(self, open: bool = False) -> List[Dict[str, Any]]:
        """Sealed turns (with blobs); open=True lists every not-done turn, blob-less unless sealed."""
        return self._call("GET", "/turns/pending?open=1" if open else "/turns/pending")

    def claim(self, job_id: str) -> Dict[str, Any]:
        return self._call("POST", f"/turns/{job_id}/claim", {})

    def release(self, job_id: str) -> Dict[str, Any]:
        return self._call("POST", f"/turns/{job_id}/release")

    def post_result(self, job_id: str, outbox_dir: str) -> Dict[str, Any]:
        files = {}
        for name in ("statement.json", "result.sealed", "offer.json", "snp-report.bin",
                     "gpu-attestation.txt", "netns-interfaces.txt", "egress-probe.txt"):
            p = os.path.join(outbox_dir, name)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    files[name] = base64.b64encode(fh.read()).decode()
        return self._call("POST", f"/results/{job_id}", {"files": files})
