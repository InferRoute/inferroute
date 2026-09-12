"""One confidential session: verify → pin → seal every request → open every answer → receipt.

Fail-closed at every step. If no instance verifies, the session REFUSES to open — it never falls
back to the normal lane silently. If the pinned instance disappears mid-session, the session moves
to another VERIFIED instance and records the switch; if none is available it refuses further
requests rather than degrade.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import AsyncIterator, Callable

import httpx

from . import attest, e2ee, translate
from .receipt import CLAIM_CONFIDENTIAL, Receipt, lane_preamble
from .transport import Transport

logger = logging.getLogger("inferroute_local.confidential")

REVERIFY_EVERY_S = 30 * 60
NONCE_SAFETY_S = 5.0


class Refused(Exception):
    """The session cannot honestly be called confidential; the reason is the message."""


@dataclass
class Pinned:
    instance_id: str
    pubkey_b64: str
    nonces: list
    nonces_expire_at: float
    report: attest.InstanceReport


class ConfidentialSession:
    def __init__(self, *, session_id: str, model_short: str, upstream_model: str, chute_id: str,
                 transport: Transport, http: httpx.AsyncClient):
        self.session_id = session_id
        self.model_short = model_short
        self.upstream_model = upstream_model
        self.chute_id = chute_id
        self.transport = transport
        self.http = http
        self.receipt = Receipt(session_id=session_id, model_short=model_short, upstream_model=upstream_model,
                               chute_id=chute_id, transport=transport.name)
        self.receipt.e2ee = {"kem": "ML-KEM-768 (FIPS 203)", "aead": "ChaCha20-Poly1305", "kdf": "HKDF-SHA256",
                             "backend": e2ee.backend().name}
        self.fleet: attest.FleetReport | None = None
        self.pinned: Pinned | None = None
        self._pool: dict[str, Pinned] = {}          # instance_id → pool entry (verified instances only)
        self._raw_evidence: list = []               # the evidence rows behind self.fleet (for the online pass)
        self._pool_expire = 0.0
        self._verified_at = 0.0
        self._lock = asyncio.Lock()
        self._closed = False

    # ───────────────────────── open: verify + pin ─────────────────────────

    async def open(self, progress: Callable[[str], None] | None = None) -> Receipt:
        say = progress or (lambda s: None)
        say("asking which instances accept sealed requests, and for their encryption keys…")
        try:
            e2 = await self.transport.instances(self.chute_id)
        except Exception as e:
            return self._refuse(f"could not list e2ee-capable instances via {self.transport.name}: {e}")
        keys = _keys_of(e2)
        say("fetching the enclave fleet's attestation evidence (this is the slow part)…")
        try:
            # the quote is checked against the very keys we will seal to
            self.fleet = await attest.fetch_and_verify(self.chute_id, self.http, e2e_pubkeys=keys)
            self._raw_evidence = self.fleet.raw
        except Exception as e:
            return self._refuse(f"could not fetch the enclave fleet's attestation evidence: {e}")
        self._verified_at = time.time()
        say("checking the platform with Intel and the GPUs with NVIDIA…")
        await self._online_pass(e2)
        verified = self.fleet.verified_ids
        say("evidence verified; pinning an enclave for this session…")
        self._absorb_pool(e2)
        eligible = [i for i in self._pool if i in verified]
        self.receipt.fleet = {"instances": len(self.fleet.instances), "verified": len(verified),
                              "e2ee_capable": len(e2.get("instances") or []), "eligible": len(eligible),
                              "failed_instance_ids": self.fleet.failed_instance_ids}
        if not eligible:
            failing = {i.instance_id[:8]: i.failing for i in self.fleet.instances if not i.verified}
            return self._refuse("no instance is BOTH verified and e2ee-capable"
                                + (f" (failing checks: {failing})" if failing else " (verified set and e2ee set are disjoint)"))
        self._pin(eligible[0], "session opened")
        self.receipt.verdict = "confidential"
        self.receipt.claim = CLAIM_CONFIDENTIAL
        self.receipt.verified_at = self.receipt.started_at
        self.receipt.save()
        return self.receipt

    async def _online_pass(self, e2: dict) -> None:
        """Intel + NVIDIA checks for every instance that passed offline AND offers a sealing key —
        the only ones a session could pin — run concurrently (each ~1–3 s)."""
        keys = _keys_of(e2)
        by_id = {str(i.get("instance_id")): i for i in (self._raw_evidence or [])}
        todo = [r for r in self.fleet.instances if r.verified and r.instance_id in keys and r.instance_id in by_id]
        await asyncio.gather(*(attest.verify_online(r, by_id[r.instance_id], self.fleet.nonce, self.http) for r in todo))

    def _refuse(self, why: str) -> Receipt:
        self.receipt.verdict, self.receipt.refusal = "refused", why
        self.receipt.note("refused", why)
        self.receipt.save()
        return self.receipt

    def _absorb_pool(self, e2: dict) -> None:
        """Only instances that VERIFIED enter the pool; the rest are never candidates."""
        reports = {i.instance_id: i for i in (self.fleet.instances if self.fleet else [])}
        ttl = e2.get("nonce_expires_in")
        expires = time.time() + float(55 if ttl is None else ttl) - NONCE_SAFETY_S
        fresh: dict[str, Pinned] = {}
        for inst in e2.get("instances") or []:
            iid = inst.get("instance_id")
            rep = reports.get(iid)
            if not iid or rep is None or not rep.verified:
                continue
            if rep.e2e_pubkey != (inst.get("e2e_pubkey") or ""):
                # the key on offer is not the key the hardware quote committed to (a rotated
                # instance, or a substituted key): never seal to it until re-verified
                self.receipt.note("key-changed", f"{iid[:8]} offers a key the verified quote does not commit to; re-verification required")
                continue
            fresh[iid] = Pinned(iid, inst.get("e2e_pubkey") or "", list(inst.get("nonces") or []), expires, rep)
        self._pool, self._pool_expire = fresh, expires

    def _pin(self, iid: str, why: str) -> None:
        p = self._pool[iid]
        self.pinned = p
        r = p.report
        self.receipt.instance = {"id": iid, "gpu_count": r.gpu_count, "mrtd": r.mrtd, "rtmrs": r.rtmrs, "chain": r.chain,
                                 "e2ee_pubkey_sha256": _sha256_b64(p.pubkey_b64), "gpus": r.gpus}
        self.receipt.checks = {k: {"ok": c.ok, "why": c.why, "label": attest.LABELS[k][0], "explain": attest.LABELS[k][1]}
                               for k, c in r.checks.items()}
        self.receipt.note("pinned", f"{iid} — {why}")

    # ───────────────────────── nonces / re-verification ─────────────────────────

    async def _take_nonce(self) -> tuple[Pinned, str]:
        async with self._lock:
            if time.time() > self._verified_at + REVERIFY_EVERY_S:
                await self._reverify()
            if self.pinned is None:
                raise Refused("no pinned instance")
            if time.time() >= self._pool_expire or not self.pinned.nonces:
                await self._refresh_pool()
            p = self.pinned
            if p is None or not p.nonces:
                raise Refused("no fresh nonce for any verified instance")
            return p, p.nonces.pop(0)

    async def _refresh_pool(self) -> None:
        e2 = await self.transport.instances(self.chute_id)
        current = self.pinned.instance_id if self.pinned else None
        self._absorb_pool(e2)
        if current in self._pool and self._pool[current].nonces:
            self.pinned = self._pool[current]
            return
        alt = next((i for i, p in self._pool.items() if p.nonces), None)
        if alt is None:
            self.pinned = None
            self.receipt.verdict = "degraded"
            self.receipt.note("no-eligible-instance", "pinned instance gone and no verified alternative has nonces")
            self.receipt.save()
            raise Refused("the verified instance is gone and no verified alternative is available — refusing to continue unverified")
        self._pin(alt, f"pinned instance {str(current)[:8]} unavailable; switched")
        self.receipt.counters["instance_switches"] = self.receipt.counters.get("instance_switches", 0) + 1
        self.receipt.save()

    async def _reverify(self) -> None:
        try:
            e2 = await self.transport.instances(self.chute_id)
            self.fleet = await attest.fetch_and_verify(self.chute_id, self.http, e2e_pubkeys=_keys_of(e2))
            self._raw_evidence = self.fleet.raw
            await self._online_pass(e2)
        except Exception as e:
            self.receipt.note("reverify-failed", str(e))
            return
        self._verified_at = time.time()
        ok = set(self.fleet.verified_ids)
        self.receipt.note("reverified", f"{len(ok)}/{len(self.fleet.instances)} instances verified")
        if self.pinned and self.pinned.instance_id not in ok:
            self.receipt.note("pinned-failed-reverify", self.pinned.instance_id)
            self.pinned = None
            self._pool = {}
        self.receipt.save()

    # ───────────────────────── the request path ─────────────────────────

    async def messages(self, body: dict) -> tuple[int, dict, AsyncIterator[bytes]]:
        """Anthropic request in → Anthropic response out; everything in between is sealed."""
        c = self.receipt.counters
        streaming = bool(body.get("stream"))
        try:
            oai = translate.to_openai(body, self.upstream_model, system_prefix=lane_preamble(self.receipt))
            pinned, nonce = await self._take_nonce()
            sealed = e2ee.seal_request(pinned.pubkey_b64, oai)
        except Refused as e:
            c["errors"] += 1
            return self._error(streaming, 503, str(e))
        except Exception as e:
            c["errors"] += 1
            return self._error(streaming, 500, f"could not seal the request: {e}")
        c["requests"] += 1
        c["plaintext_bytes_sealed_here"] += sealed.plaintext_size
        c["ciphertext_bytes_sent"] += len(sealed.blob)
        try:
            status, headers, raw = await self.transport.invoke(
                chute_id=self.chute_id, instance_id=pinned.instance_id, nonce=nonce, stream=streaming, blob=sealed.blob)
        except httpx.HTTPError as e:
            c["errors"] += 1
            return self._error(streaming, 502, f"the relay is unreachable: {e}")
        if status != 200:
            c["errors"] += 1
            try:
                detail = (await _drain(raw))[:400].decode("utf-8", "replace")
            except Exception as e:                       # the error body itself may be cut short
                detail = f"(body unreadable: {type(e).__name__})"
            return self._error(streaming, status, f"upstream {status}: {detail}")
        if streaming:
            return 200, {"content-type": "text/event-stream"}, self._open_stream(raw, sealed)
        return 200, {"content-type": "application/json"}, self._open_json(raw, sealed)

    async def chat_completions(self, body: dict) -> tuple[int, dict, AsyncIterator[bytes]]:
        """OpenAI request in → OpenAI response out, sealed AS-IS: the enclaves speak OpenAI
        natively, so an agent that speaks it gets no translation at all (Henry, 2026-09-12:
        native dialects end to end; translate only where the agent cannot). Only the model name
        is pinned, `user`/`metadata` identifiers are dropped, and the lane preamble is prepended
        to the system message."""
        c = self.receipt.counters
        streaming = bool(body.get("stream"))
        try:
            oai = translate.native_openai(body, self.upstream_model, system_prefix=lane_preamble(self.receipt))
            pinned, nonce = await self._take_nonce()
            sealed = e2ee.seal_request(pinned.pubkey_b64, oai)
        except Refused as e:
            c["errors"] += 1
            return self._error(streaming, 503, str(e), openai=True)
        except Exception as e:
            c["errors"] += 1
            return self._error(streaming, 500, f"could not seal the request: {e}", openai=True)
        c["requests"] += 1
        c["plaintext_bytes_sealed_here"] += sealed.plaintext_size
        c["ciphertext_bytes_sent"] += len(sealed.blob)
        try:
            status, headers, raw = await self.transport.invoke(
                chute_id=self.chute_id, instance_id=pinned.instance_id, nonce=nonce, stream=streaming, blob=sealed.blob)
        except httpx.HTTPError as e:
            c["errors"] += 1
            return self._error(streaming, 502, f"the relay is unreachable: {e}", openai=True)
        if status != 200:
            c["errors"] += 1
            try:
                detail = (await _drain(raw))[:400].decode("utf-8", "replace")
            except Exception as e:
                detail = f"(body unreadable: {type(e).__name__})"
            return self._error(streaming, status, f"upstream {status}: {detail}", openai=True)
        if streaming:
            return 200, {"content-type": "text/event-stream"}, self._open_stream_native(raw, sealed)
        return 200, {"content-type": "application/json"}, self._open_json_native(raw, sealed)

    async def _open_stream_native(self, raw: AsyncIterator[bytes], sealed: e2ee.SealedRequest) -> AsyncIterator[bytes]:
        """The enclave's own OpenAI SSE, decrypted and passed through byte-for-byte; usage is
        read off the stream for the receipt."""
        opener = e2ee.StreamOpener(sealed.response_sk)
        c = self.receipt.counters
        linebuf = b""
        usage: dict = {}
        try:
            async for chunk in raw:
                plain = opener.feed(chunk)
                if opener.passthrough:
                    ev = opener.passthrough.pop()
                    msg = (ev.get("error") or {}).get("message") if isinstance(ev.get("error"), dict) else json.dumps(ev)[:300]
                    yield ("data: " + json.dumps(translate.openai_error(f"upstream: {msg}")) + "\n\n").encode()
                    c["errors"] += 1
                    return
                if not plain:
                    continue
                c["response_bytes_opened_here"] += len(plain)
                linebuf += plain
                while True:
                    i = linebuf.find(b"\n")
                    if i == -1:
                        break
                    line, linebuf = linebuf[:i + 1], linebuf[i + 1:]
                    translate.scan_openai_usage(line, usage)
                    yield line
            tail = opener.flush()
            if tail:
                translate.scan_openai_usage(tail, usage)
                yield tail
            if linebuf:
                yield linebuf
        except e2ee.E2EEError as e:
            c["errors"] += 1
            yield ("data: " + json.dumps(translate.openai_error(f"could not open the enclave's reply: {e}")) + "\n\n").encode()
            return
        except (httpx.HTTPError, OSError) as e:
            c["errors"] += 1
            yield ("data: " + json.dumps(translate.openai_error(f"the connection to the enclave dropped mid-reply ({type(e).__name__}); please retry")) + "\n\n").encode()
            return
        finally:
            c["ciphertext_frames_received"] += opener.frames
        self._account(usage)

    async def _open_json_native(self, raw: AsyncIterator[bytes], sealed: e2ee.SealedRequest) -> AsyncIterator[bytes]:
        c = self.receipt.counters
        try:
            data = await _drain(raw)
            blob = base64.b64decode(json.loads(data)["e2e"]) if data[:1] == b"{" else data
            resp = e2ee.open_response(blob, sealed.response_sk)
        except (httpx.HTTPError, OSError) as e:
            c["errors"] += 1
            yield json.dumps(translate.openai_error(f"the connection to the enclave dropped mid-reply ({type(e).__name__}); please retry")).encode()
            return
        except Exception as e:
            c["errors"] += 1
            yield json.dumps(translate.openai_error(f"could not open the enclave's reply: {e}")).encode()
            return
        c["response_bytes_opened_here"] += len(data)
        self._account(translate._usage(resp.get("usage")))
        yield json.dumps(resp).encode()

    async def _open_stream(self, raw: AsyncIterator[bytes], sealed: e2ee.SealedRequest) -> AsyncIterator[bytes]:
        opener = e2ee.StreamOpener(sealed.response_sk)
        tr = translate.StreamTranslator(self.model_short)
        c = self.receipt.counters
        linebuf = b""
        try:
            async for chunk in raw:
                plain = opener.feed(chunk)
                if opener.passthrough:
                    ev = opener.passthrough.pop()
                    msg = (ev.get("error") or {}).get("message") if isinstance(ev.get("error"), dict) else json.dumps(ev)[:300]
                    yield translate.sse("error", translate.error_body(f"upstream: {msg}")).encode()
                    c["errors"] += 1
                    return
                if not plain:
                    continue
                c["response_bytes_opened_here"] += len(plain)
                linebuf += plain
                while True:
                    i = linebuf.find(b"\n")
                    if i == -1:
                        break
                    line, linebuf = linebuf[:i].decode("utf-8", "replace"), linebuf[i + 1:]
                    for ev in tr.feed_line(line):
                        yield ev.encode()
            tail = opener.flush()
            if tail:
                linebuf += tail
            if linebuf.strip():
                for ev in tr.feed_line(linebuf.decode("utf-8", "replace")):
                    yield ev.encode()
        except e2ee.E2EEError as e:
            c["errors"] += 1
            yield translate.sse("error", translate.error_body(f"could not open the enclave's reply: {e}")).encode()
            return
        except (httpx.HTTPError, OSError) as e:          # connection dropped mid-stream: a clean error, never a traceback
            c["errors"] += 1
            yield translate.sse("error", translate.error_body(f"the connection to the enclave dropped mid-reply ({type(e).__name__}); please retry")).encode()
            return
        finally:
            c["ciphertext_frames_received"] += opener.frames
        for ev in tr.finish_events():
            yield ev.encode()
        self._account(tr.usage)

    async def _open_json(self, raw: AsyncIterator[bytes], sealed: e2ee.SealedRequest) -> AsyncIterator[bytes]:
        c = self.receipt.counters
        try:
            data = await _drain(raw)
        except (httpx.HTTPError, OSError) as e:
            c["errors"] += 1
            yield json.dumps(translate.error_body(f"the connection to the enclave dropped mid-reply ({type(e).__name__}); please retry")).encode()
            return
        try:
            # The gateway hands the response blob back RAW (application/octet-stream, measured
            # 2026-09-12); the chute-side envelope {"e2e": b64} is also accepted in case it ever
            # reaches us unwrapped.
            if data[:1] == b"{":
                blob = base64.b64decode(json.loads(data)["e2e"])
            else:
                blob = data
            resp = e2ee.open_response(blob, sealed.response_sk)
        except Exception as e:
            c["errors"] += 1
            yield json.dumps(translate.error_body(f"could not open the enclave's reply: {e}")).encode()
            return
        c["response_bytes_opened_here"] += len(data)
        out = translate.from_openai(resp, self.model_short)
        self._account(out.get("usage") or {})
        yield json.dumps(out).encode()

    def _account(self, usage: dict) -> None:
        c = self.receipt.counters
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens"):
            c[k] += int(usage.get(k) or 0)
        self.receipt.save()
        asyncio.ensure_future(self.transport.report_usage({
            "session_id": self.session_id, "chute_id": self.chute_id, "model": self.upstream_model,
            "instance_id": self.pinned.instance_id if self.pinned else "", "usage": usage, "self_reported": True}))

    def _error(self, streaming: bool, status: int, message: str, openai: bool = False) -> tuple[int, dict, AsyncIterator[bytes]]:
        body = translate.openai_error(message) if openai else translate.error_body(message)

        async def _gen():
            if openai:
                yield (("data: " + json.dumps(body) + "\n\n") if streaming else json.dumps(body)).encode()
            else:
                yield (translate.sse("error", body) if streaming else json.dumps(body)).encode()

        return status, {"content-type": "text/event-stream" if streaming else "application/json"}, _gen()

    # ───────────────────────── close ─────────────────────────

    def close(self) -> Receipt:
        if not self._closed:
            self._closed = True
            from .receipt import _now
            self.receipt.ended_at = _now()
            self.receipt.save()
        return self.receipt


def _keys_of(e2: dict) -> dict[str, str]:
    return {str(i.get("instance_id")): str(i.get("e2e_pubkey") or "") for i in (e2.get("instances") or []) if i.get("instance_id")}


async def _drain(it: AsyncIterator[bytes]) -> bytes:
    parts = []
    async for chunk in it:
        parts.append(chunk)
    return b"".join(parts)


def _sha256_b64(pk_b64: str) -> str:
    import hashlib
    try:
        return hashlib.sha256(base64.b64decode(pk_b64 + "=" * (-len(pk_b64) % 4))).hexdigest()
    except Exception:
        return ""
