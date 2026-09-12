"""The session, end to end, against a fake enclave and a fake carrier: it opens only when an
instance is BOTH verified and sealable, seals every request, opens every answer (raw-blob and
streaming shapes, exactly as the gateway sends them), refreshes nonces, switches only to verified
instances, and refuses rather than degrades."""
import asyncio
import json

import pytest

from inferroute_local.confidential import attest, session as S
from tests.confidential_fake_enclave import FakeEnclave


def _report(iid: str, ok: bool = True, e2e_pubkey: str = "") -> attest.InstanceReport:
    checks = {k: attest.Check(ok, "fixture") for k in attest.REQUIRED}
    if not ok:
        checks["measurement_ok"] = attest.Check(False, "unknown MRTD")
    return attest.InstanceReport(iid, checks, gpu_count=8, mrtd="aa" * 48, rtmrs=["bb" * 48] * 4, verified=ok, chain="leaf → root",
                                 e2e_pubkey=e2e_pubkey if ok else "")


class FakeCarrier:
    """A carrier that behaves like Chutes' gateway: hands sealed blobs to the enclave and returns
    the RAW response blob (non-stream) or e2e_init/e2e SSE frames (stream)."""
    name = "fake carrier"

    def __init__(self, enclaves: dict, nonces_per: int = 2, expires_in: int = 60, reply=None):
        self.enclaves = enclaves            # instance_id → FakeEnclave
        self.nonces_per = nonces_per
        self.expires_in = expires_in
        self.calls = []
        self.instances_calls = 0
        self.reply = reply or (lambda body: {"id": "chatcmpl-1", "choices": [{"finish_reason": "stop", "message": {"content": "hi " + body["messages"][-1]["content"]}}],
                                             "usage": {"prompt_tokens": 5, "completion_tokens": 2}})
        self.usage_reports = []

    async def models(self):
        return [{"name": "fake/Model-TEE", "chute_id": "chute-1"}]

    async def instances(self, chute_id):
        self.instances_calls += 1
        return {"nonce_expires_in": self.expires_in,
                "instances": [{"instance_id": i, "e2e_pubkey": e.pubkey_b64, "nonces": [f"n-{i}-{k}-{self.instances_calls}" for k in range(self.nonces_per)]}
                              for i, e in self.enclaves.items()]}

    async def invoke(self, *, chute_id, instance_id, nonce, stream, blob, path="/v1/chat/completions"):
        self.calls.append((instance_id, nonce, stream))
        enc = self.enclaves[instance_id]
        body, client_pk = enc.open_request(blob)
        if not stream:
            out = enc.seal_response(client_pk, self.reply(body))

            async def one():
                yield out
            return 200, {"content-type": "application/octet-stream"}, one()
        text = "".join(f"data: {json.dumps(c)}\n\n" for c in self.reply(body)) + "data: [DONE]\n\n"
        wire = enc.stream(client_pk, [text.encode()[i:i + 13] for i in range(0, len(text), 13)])

        async def many():
            for i in range(0, len(wire), 50):
                yield wire[i:i + 50]
        return 200, {"content-type": "text/event-stream"}, many()

    async def report_usage(self, payload):
        self.usage_reports.append(payload)


@pytest.fixture
def world(monkeypatch, tmp_path):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    encl = {"i-a": FakeEnclave(), "i-b": FakeEnclave()}
    verified = {"i-a": True, "i-b": True}

    async def fake_fetch(chute_id, http, nonce=None, timeout=0, e2e_pubkeys=None):
        # the fake verifier "binds" whatever key the session handed it — exactly the real
        # contract: the report carries the key the quote committed to
        keys = e2e_pubkeys or {}
        world["keys_seen"] = dict(keys)
        return attest.FleetReport(chute_id, nonce or "n" * 64,
                                  [_report(i, verified[i], keys.get(i, "")) for i in encl] + [_report("i-c", False)],
                                  raw=[{"instance_id": i} for i in list(encl) + ["i-c"]])

    monkeypatch.setattr(attest, "fetch_and_verify", fake_fetch)

    async def fake_online(report, inst, nonce, http, timeout=0):
        world["online_seen"] = world.get("online_seen", []) + [report.instance_id]
        for k in attest.REQUIRED_ONLINE:
            report.checks[k] = attest.Check(True, "fixture-online")
        report.verified = report.verified and True
        return report
    monkeypatch.setattr(attest, "verify_online", fake_online)
    world = {"enclaves": encl, "verified": verified}
    return world


def _session(carrier):
    return S.ConfidentialSession(session_id="s1", model_short="fake", upstream_model="fake/Model-TEE", chute_id="chute-1",
                                 transport=carrier, http=None)


async def _drain(it):
    return b"".join([c async for c in it])


def test_opens_confidential_and_pins_a_verified_sealable_instance(world):
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    r = asyncio.run(s.open())
    assert r.verdict == "confidential" and r.instance["id"] == "i-a"
    assert sorted(world["online_seen"]) == ["i-a", "i-b"], "online checks run only for offline-verified, sealable instances"
    assert all(r.checks[k]["ok"] for k in attest.REQUIRED_ONLINE)
    assert r.fleet == {"instances": 3, "verified": 2, "e2ee_capable": 2, "eligible": 2, "failed_instance_ids": []}
    assert all(c["ok"] for c in r.checks.values()) and set(r.checks) == set(attest.REQUIRED) | set(attest.REQUIRED_ONLINE)
    assert r.claim and r.path and r.e2ee["kem"].startswith("ML-KEM-768")
    assert not any(lim["id"] == "attributed-key" for lim in r.limitations), "the key binding is a check, not a limitation"
    assert r.checks["e2e_key_bound"]["ok"] and "commits to" in r.checks["e2e_key_bound"]["explain"]


def test_the_keys_verified_are_the_keys_sealed_to(world):
    """The session fetches the instance keys FIRST and hands them to the verifier, so the quote
    is checked against the very key each request is sealed with."""
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    asyncio.run(s.open())
    assert world["keys_seen"] == {i: e.pubkey_b64 for i, e in world["enclaves"].items()}
    assert s.pinned.pubkey_b64 == s.pinned.report.e2e_pubkey


def test_a_key_the_quote_did_not_commit_to_is_never_sealed_to(world):
    """Carrier offers a key for i-a that differs from the one the verifier bound: i-a is skipped."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    orig = carrier.instances

    async def swapped(chute_id):
        e2 = await orig(chute_id)
        e2["instances"][0]["e2e_pubkey"] = FakeEnclave().pubkey_b64   # substituted AFTER verification
        return e2
    asyncio.run(s.open())
    carrier.instances = swapped
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert st == 200 and carrier.calls[-1][0] == "i-b"
    assert any(e["kind"] == "key-changed" for e in s.receipt.events)


def test_refuses_when_verified_and_sealable_sets_are_disjoint(world):
    world["verified"]["i-a"] = world["verified"]["i-b"] = False
    s = _session(FakeCarrier(world["enclaves"]))
    r = asyncio.run(s.open())
    assert r.verdict == "refused" and "verified" in r.refusal
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 503


def test_refuses_when_evidence_cannot_be_fetched(world, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("chutes down")
    monkeypatch.setattr(attest, "fetch_and_verify", boom)
    r = asyncio.run(_session(FakeCarrier(world["enclaves"])).open())
    assert r.verdict == "refused" and "chutes down" in r.refusal


async def _msg(s, body):
    st, h, it = await s.messages(body)
    return st, h, await _drain(it)


def test_non_stream_round_trip_seals_here_and_opens_here(world):
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    asyncio.run(s.open())
    st, h, body = asyncio.run(_msg(s, {"model": "fake", "max_tokens": 5, "stream": False, "messages": [{"role": "user", "content": "there"}]}))
    assert st == 200
    out = json.loads(body)
    assert out["content"] == [{"type": "text", "text": "hi there"}] and out["stop_reason"] == "end_turn"
    assert out["usage"]["input_tokens"] == 5 and out["id"].startswith("msg_")
    # the enclave saw the translated OpenAI body, never the Anthropic one
    seen = world["enclaves"]["i-a"].last_plaintext
    assert seen["model"] == "fake/Model-TEE" and seen["messages"][-1] == {"role": "user", "content": "there"}
    assert seen["messages"][0]["role"] == "system" and "Confidential session" in seen["messages"][0]["content"]
    c = s.receipt.counters
    assert c["requests"] == 1 and c["plaintext_bytes_sealed_here"] > 0 and c["input_tokens"] == 5
    assert carrier.calls[0][0] == "i-a" and carrier.calls[0][2] is False


def test_stream_round_trip_with_a_tool_call(world):
    def reply(body):
        return [{"id": "chatcmpl-9", "choices": [{"delta": {"reasoning_content": "hmm"}, "finish_reason": None}], "usage": {"prompt_tokens": 7, "completion_tokens": 0}},
                {"id": "chatcmpl-9", "choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "Bash", "arguments": '{"command":"ls"}'}}]}, "finish_reason": None}]},
                {"id": "chatcmpl-9", "choices": [{"delta": {}, "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 7, "completion_tokens": 4}}]
    carrier = FakeCarrier(world["enclaves"], reply=reply)
    s = _session(carrier)
    asyncio.run(s.open())
    st, h, body = asyncio.run(_msg(s, {"model": "fake", "stream": True, "messages": [{"role": "user", "content": "go"}],
                                       "tools": [{"name": "Bash", "input_schema": {"type": "object"}}]}))
    assert st == 200 and h["content-type"] == "text/event-stream"
    evs = [json.loads(line[6:]) for line in body.decode().split("\n") if line.startswith("data: ")]
    types = [e["type"] for e in evs]
    assert types[0] == "message_start" and types[-1] == "message_stop"
    starts = [e["content_block"] for e in evs if e["type"] == "content_block_start"]
    assert [b["type"] for b in starts] == ["thinking", "tool_use"] and starts[1]["name"] == "Bash"
    assert [e["delta"]["stop_reason"] for e in evs if e["type"] == "message_delta"] == ["tool_use"]
    assert s.receipt.counters["ciphertext_frames_received"] > 1 and s.receipt.counters["output_tokens"] == 4
    assert carrier.usage_reports and carrier.usage_reports[0]["self_reported"] is True


def test_nonces_are_consumed_then_refreshed_from_the_carrier(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=2)
    s = _session(carrier)
    asyncio.run(s.open())
    for _ in range(3):
        st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
        assert st == 200
    nonces = [c[1] for c in carrier.calls]
    assert len(set(nonces)) == 3, "a nonce is never reused"
    assert carrier.instances_calls == 2, "one listing at open, one refresh when the pool ran dry"


def test_expired_pool_is_refreshed_before_use(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=5, expires_in=0)
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert carrier.instances_calls == 2


def test_pinned_instance_vanishing_switches_only_to_a_verified_one_and_records_it(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    del carrier.enclaves["i-a"]                                   # i-a is gone from the fleet
    st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert st == 200 and carrier.calls[-1][0] == "i-b"
    assert s.receipt.instance["id"] == "i-b" and s.receipt.counters["instance_switches"] == 1
    assert any(e["kind"] == "pinned" and "switched" in e["detail"] for e in s.receipt.events)


def test_when_no_verified_instance_remains_the_session_refuses_rather_than_degrades(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    carrier.enclaves.clear()
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert st == 503 and b"refusing to continue unverified" in body
    assert s.receipt.verdict == "degraded"


def test_a_rotated_key_is_not_trusted_until_reverified(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    carrier.enclaves["i-a"] = FakeEnclave()                       # same id, new key: a restarted VM
    st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert st == 200 and carrier.calls[-1][0] == "i-b"
    assert any(e["kind"] == "key-changed" for e in s.receipt.events)


def test_tampered_reply_surfaces_as_an_error_not_as_content(world):
    carrier = FakeCarrier(world["enclaves"])
    orig = carrier.invoke

    async def tampered(**kw):
        st, h, it = await orig(**kw)
        data = bytearray(await _drain(it))
        data[-1] ^= 1

        async def one():
            yield bytes(data)
        return st, h, one()
    carrier.invoke = tampered
    s = _session(carrier)
    asyncio.run(s.open())
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert b"could not open the enclave's reply" in body and s.receipt.counters["errors"] == 1


def test_receipt_round_trips_through_disk_and_close_stamps_the_end(world):
    from inferroute_local.confidential.receipt import Receipt, latest
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    r = s.close()
    assert r.ended_at
    again = Receipt.load(r.path)
    assert again.instance == r.instance and again.checks == r.checks and latest().session_id == "s1"


def test_the_enclave_is_told_the_truth_about_the_lane_on_every_request(world):
    """The lane preamble rides on the system prompt, derived from the receipt: it names the model,
    the pinned instance, the checks that passed, the receipt path and the limitations — and says
    the session is NOT on Anthropic's servers."""
    from inferroute_local.confidential.receipt import lane_preamble
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "system": "You are Claude Code.", "messages": [{"role": "user", "content": "is this private?"}]}))
    seen = world["enclaves"]["i-a"].last_plaintext
    sysmsg = seen["messages"][0]
    assert sysmsg["role"] == "system"
    pre = lane_preamble(s.receipt)
    assert sysmsg["content"].startswith(pre) and sysmsg["content"].endswith("You are Claude Code.")
    for needle in ("fake/Model-TEE", "i-a", "Encryption key bound to enclave", s.receipt.path, "NOT running on Anthropic",
                   "vouched for by the enclave's measured software"):
        assert needle in pre, needle
    assert "attributed" not in pre
    # a refused session has no preamble to give (nothing verified)
    from inferroute_local.confidential.receipt import Receipt
    assert lane_preamble(Receipt(session_id="x", model_short="m", upstream_model="m", chute_id="c", transport="t")) == ""


def test_a_connection_dropped_mid_reply_is_a_clean_error_event_not_a_traceback(world):
    """Seen live 2026-09-12: httpx RemoteProtocolError ('incomplete chunked read') escaped as an
    ASGI traceback into the user's terminal. Every read of the upstream stream must turn a
    transport failure into an Anthropic-shaped error the client can show — and count it."""
    import httpx
    carrier = FakeCarrier(world["enclaves"])

    async def dropping(**kw):
        async def broken():
            yield b": keep-alive\n"          # a frame that needs no key, then the wire dies
            raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")
        return 200, {"content-type": "text/event-stream"}, broken()
    carrier.invoke = dropping
    s = _session(carrier)
    asyncio.run(s.open())
    st, _, body = asyncio.run(_msg(s, {"stream": True, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 200 and b"event: error" in body and b"dropped mid-reply" in body
    assert s.receipt.counters["errors"] == 1

    async def dropping_json(**kw):
        async def broken():
            raise httpx.ReadError("boom")
            yield b""
        return 200, {"content-type": "application/octet-stream"}, broken()
    carrier.invoke = dropping_json
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "y"}]}))
    assert b"dropped mid-reply" in body and s.receipt.counters["errors"] == 2

    async def bad_status(**kw):
        async def broken():
            raise httpx.ReadError("cut")
            yield b""
        return 503, {}, broken()
    carrier.invoke = bad_status
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "z"}]}))
    assert st == 503 and b"body unreadable" in body


def test_native_openai_round_trip_is_sealed_and_passed_through_untranslated(world):
    """Agents that speak OpenAI (Pi, OpenCode) get the enclave's own dialect back, byte for byte."""
    def reply(body):
        return [{"id": "chatcmpl-n", "choices": [{"index": 0, "delta": {"reasoning_content": "hmm"}, "finish_reason": None}]},
                {"id": "chatcmpl-n", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_7", "function": {"name": "bash", "arguments": "{}"}}]}, "finish_reason": None}]},
                {"id": "chatcmpl-n", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 9, "completion_tokens": 2}}]
    carrier = FakeCarrier(world["enclaves"], reply=reply)
    s = _session(carrier)
    asyncio.run(s.open())
    body = {"model": "x", "stream": True, "user": "secret-user", "messages": [{"role": "user", "content": "go"}]}
    st, h, out = asyncio.run(_oai(s, body))
    assert st == 200 and h["content-type"] == "text/event-stream"
    lines = [line for line in out.decode().split("\n") if line.startswith("data: ")]
    assert lines[-1] == "data: [DONE]"
    first = json.loads(lines[0][6:])
    assert first["choices"][0]["delta"]["reasoning_content"] == "hmm", "OpenAI shape untouched — no Anthropic events"
    seen = world["enclaves"]["i-a"].last_plaintext
    assert seen["model"] == "fake/Model-TEE" and "user" not in seen and seen["messages"][0]["role"] == "system"
    assert "Confidential session" in seen["messages"][0]["content"] and seen["messages"][-1] == {"role": "user", "content": "go"}
    assert s.receipt.counters["requests"] == 1 and s.receipt.counters["output_tokens"] == 2
    # non-stream
    carrier.reply = lambda body: {"id": "chatcmpl-1", "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 5, "completion_tokens": 1}}
    st, h, out = asyncio.run(_oai(s, {"model": "x", "stream": False, "messages": [{"role": "user", "content": "q"}]}))
    assert st == 200 and json.loads(out)["choices"][0]["message"]["content"] == "ok"


async def _oai(s, body):
    st, h, it = await s.chat_completions(body)
    return st, h, await _drain(it)


def test_public_reason_never_leaks_urls_or_hosts():
    import httpx
    from inferroute_local.confidential.session import public_reason
    req = httpx.Request("GET", "https://api.example-provider.ai/chutes/abc/evidence?nonce=deadbeef")
    e = httpx.HTTPStatusError("Client error '429 Too Many Requests' for url 'https://api.example-provider.ai/x'", request=req, response=httpx.Response(429, request=req))
    r = public_reason(e)
    assert r == "the attestation service answered 429 (rate-limited — try again in a minute)"
    assert "http" not in r and "example-provider" not in r
    r2 = public_reason(RuntimeError("boom at https://api.example-provider.ai/path and host api.example-provider.ai"))
    assert "https://" not in r2 and "example-provider.ai" not in r2 and r2.startswith("RuntimeError")
    assert public_reason(httpx.ConnectError("x", request=req)) == "the attestation service is unreachable (ConnectError)"


def test_a_429_on_evidence_refuses_with_a_clean_reason(world, monkeypatch):
    import httpx
    async def boom(*a, **k):
        req = httpx.Request("GET", "https://api.example-provider.ai/chutes/abc/evidence")
        raise httpx.HTTPStatusError("429 for url 'https://api.example-provider.ai/chutes/abc/evidence'", request=req, response=httpx.Response(429, request=req))
    monkeypatch.setattr(attest, "fetch_and_verify", boom)
    r = asyncio.run(_session(FakeCarrier(world["enclaves"])).open())
    assert r.verdict == "refused" and "answered 429" in r.refusal and "http" not in r.refusal and "example-provider" not in r.refusal
