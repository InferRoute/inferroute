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
    checks["build_recorded"] = attest.Check(ok, "build fixture — recorded by InferRoute since 2026-01-01")
    if not ok:
        checks["measurement_ok"] = attest.Check(False, "unknown MRTD")
    return attest.InstanceReport(iid, checks, gpu_count=8, mrtd="aa" * 48, rtmrs=["bb" * 48] * 4, verified=ok, chain="leaf → root",
                                 e2e_pubkey=e2e_pubkey if ok else "")


class FakeCarrier:
    """A carrier that behaves like the operator's gateway: hands sealed blobs to the enclave and returns
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
        # Cut the stream short, WITHOUT its "data: [DONE]" — what an enclave whose answer stops part-way
        # looks like on the wire. Nothing else about the exchange changes.
        self.truncate = False

    async def models(self):
        return [{"name": "fake/Model-TEE", "fleet_id": "chute-1"}]

    async def profile(self):
        from inferroute_local.confidential.transport import OperatorProfile
        return OperatorProfile.from_dict({"evidence": "https://op.test/{fleet}/evidence?nonce={nonce}",
                                          "measurements": "https://op.test/measurements"})

    async def instances(self, fleet_id):
        self.instances_calls += 1
        return {"nonce_expires_in": self.expires_in,
                "instances": [{"instance_id": i, "e2e_pubkey": e.pubkey_b64, "nonces": [f"n-{i}-{k}-{self.instances_calls}" for k in range(self.nonces_per)]}
                              for i, e in self.enclaves.items()]}

    async def invoke(self, *, fleet_id, instance_id, nonce, stream, blob, path="/v1/chat/completions"):
        self.calls.append((instance_id, nonce, stream))
        enc = self.enclaves[instance_id]
        body, client_pk = enc.open_request(blob)
        if not stream:
            out = enc.seal_response(client_pk, self.reply(body))

            async def one():
                yield out
            return 200, {"content-type": "application/octet-stream"}, one()
        text = "".join(f"data: {json.dumps(c)}\n\n" for c in self.reply(body))
        if not self.truncate:
            text += "data: [DONE]\n\n"
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

    async def fake_fetch(fleet_id, http, profile=None, nonce=None, timeout=0, e2e_pubkeys=None):
        world["profile_seen"] = profile
        # the fake verifier "binds" whatever key the session handed it — exactly the real
        # contract: the report carries the key the quote committed to
        keys = e2e_pubkeys or {}
        world["keys_seen"] = dict(keys)
        return attest.FleetReport(fleet_id, nonce or "n" * 64,
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


def _session(carrier, price=None):
    return S.ConfidentialSession(session_id="s1", model_short="fake", upstream_model="fake/Model-TEE", fleet_id="chute-1",
                                 transport=carrier, http=None, price=price)


async def _drain(it):
    return b"".join([c async for c in it])


def test_opens_confidential_and_pins_a_verified_sealable_instance(world):
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    r = asyncio.run(s.open())
    assert r.verdict == "confidential" and r.instance["id"] == "i-a"
    assert sorted(world["online_seen"]) == ["i-a", "i-b"], "online checks run only for offline-verified, sealable instances"
    assert all(r.checks[k]["ok"] for k in attest.REQUIRED_ONLINE)
    # `failed_instance_ids` is the OPERATOR's list; an auditor read it as ours and could not account for the
    # instances that were checked here and rejected. Both are now named, and so is the difference.
    assert r.fleet["instances"] == 3 and r.fleet["verified"] == 2 and r.fleet["eligible"] == 2
    assert r.fleet["failed_instance_ids"] == []
    assert "not instances this device rejected" in r.fleet["failed_instance_ids_are"]
    assert set(r.fleet["rejected_here"]) and all(v for v in r.fleet["rejected_here"].values()), \
        "an instance this device rejected must say which check it failed"
    assert all(c["ok"] for c in r.checks.values()) and set(r.checks) == set(attest.REQUIRED) | set(attest.REQUIRED_ONLINE)
    assert r.claim and r.path and r.e2ee["kem"].startswith("ML-KEM-768")
    # The evidence the fifteen verdicts were computed FROM, kept so a reader can recompute instead of
    # believing. Asserted on a real open, not merely on the dataclass having the field: adding a field and
    # the field arriving in the artifact are different claims, and today the second one failed twice.
    ev = r.attestation
    assert ev and ev.get("instance_id") == "i-a", "the pinned instance's evidence row was not kept"
    # It is the row the fleet was verified FROM, not a summary of it: whatever the evidence service sent
    # for this instance is what a reader gets, so every field the checks read is there by construction.
    assert ev is not r.instance and set(ev) >= {"instance_id"}
    operator_part = {k: v for k, v in ev.items() if k != "checked_with"}
    assert any(row.get("instance_id") == "i-a" and row == operator_part for row in s._raw_evidence), \
        "the receipt's evidence is not the row this device actually verified"
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

    async def swapped(fleet_id):
        e2 = await orig(fleet_id)
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
        raise RuntimeError("operator down")
    monkeypatch.setattr(attest, "fetch_and_verify", boom)
    r = asyncio.run(_session(FakeCarrier(world["enclaves"])).open())
    assert r.verdict == "refused" and "operator down" in r.refusal


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


def _reject_nonces(carrier, times: int):
    """The gateway's answer to a stale nonce, for the first `times` invokes."""
    real = carrier.invoke
    state = {"left": times}

    async def invoke(**kw):
        if state["left"] > 0:
            state["left"] -= 1
            carrier.calls.append((kw["instance_id"], kw["nonce"], kw["stream"]))

            async def body():
                yield b'{"detail":"Invalid, expired, or already-used nonce"}'
            return 403, {"content-type": "application/json"}, body()
        return await real(**kw)
    carrier.invoke = invoke


def test_a_rejected_nonce_is_replaced_and_the_request_resent_once(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=5)
    s = _session(carrier)
    asyncio.run(s.open())
    _reject_nonces(carrier, 1)
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "there"}]}))
    assert st == 200 and json.loads(body)["content"][0]["text"] == "hi there"
    assert carrier.instances_calls == 2, "the stale pool was dropped and fresh nonces fetched"
    first, second = carrier.calls[0][1], carrier.calls[1][1]
    assert first != second and second.endswith("-2"), "the resend used a nonce from the fresh listing"
    assert s.receipt.counters["requests"] == 1 and s.receipt.counters["errors"] == 0
    assert any(e["kind"] == "nonce-rejected" for e in s.receipt.events)


def test_a_second_nonce_rejection_is_reported_not_looped(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=5)
    s = _session(carrier)
    asyncio.run(s.open())
    _reject_nonces(carrier, 10)
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 403 and "nonce" in body.decode()
    assert len(carrier.calls) == 2, "one resend, never a loop"
    assert s.receipt.counters["errors"] == 1


def test_an_ordinary_refusal_is_not_retried(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=5)
    s = _session(carrier)
    asyncio.run(s.open())

    async def refuse(**kw):
        carrier.calls.append((kw["instance_id"], kw["nonce"], kw["stream"]))

        async def body():
            yield b'{"detail":"quota exceeded"}'
        return 403, {}, body()
    carrier.invoke = refuse
    st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 403 and len(carrier.calls) == 1 and carrier.instances_calls == 1


def test_nonce_lifetime_runs_from_when_they_were_fetched_not_from_the_end_of_verification(world, monkeypatch):
    # Measured 2026-09-17: verification took 68 s against a 60 s nonce life, and the pool, timed from the
    # end of verification, was handed out already expired. With the clock started at the listing, the
    # first request after a slow verification refreshes instead of sending a dead nonce.
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(S.time, "time", lambda: clock["t"])
    real_online = attest.verify_online

    async def slow_online(report, inst, nonce, http, timeout=0):
        clock["t"] += 34                                  # two instances: 68 s of checking
        return await real_online(report, inst, nonce, http, timeout)
    monkeypatch.setattr(attest, "verify_online", slow_online)
    carrier = FakeCarrier(world["enclaves"], nonces_per=5, expires_in=60)
    s = _session(carrier)
    asyncio.run(s.open())
    assert carrier.instances_calls == 1
    st, _, _ = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 200
    assert carrier.instances_calls == 2, "the pool fetched 68 s ago was recognised as expired and refreshed"
    assert carrier.calls[0][1].endswith("-2")


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
                   "InferRoute records the enclave builds"):
        assert needle in pre, needle
    assert "attributed" not in pre
    # a refused session has no preamble to give (nothing verified)
    from inferroute_local.confidential.receipt import Receipt
    assert lane_preamble(Receipt(session_id="x", model_short="m", upstream_model="m", fleet_id="c", transport="t")) == ""


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


def test_a_reply_that_stops_part_way_ends_the_stream_instead_of_leaving_the_agent_waiting(world):
    """An OpenAI SSE ends at "data: [DONE]"; an agent waits for it. Byte-for-byte passthrough has no
    translator to close the stream for it, so an enclave whose answer stopped part-way used to reach the
    agent as a body that simply stopped — no terminator, no error. That is how a Probant session sat on
    "The assistant is working…" for 25 minutes on 17 Sep with the agent idle and holding no connection.
    A truncated answer is bad news; silence is worse."""
    carrier = FakeCarrier(world["enclaves"])
    carrier.truncate = True
    s = _session(carrier)
    asyncio.run(s.open())
    st, h, out = asyncio.run(_oai(s, {"model": "x", "stream": True, "messages": [{"role": "user", "content": "go"}]}))
    lines = [line for line in out.decode().split("\n") if line.startswith("data: ")]
    assert st == 200
    assert lines[-1] == "data: [DONE]", "the stream must always be ended"
    said = json.loads(lines[-2][6:])
    assert "ended part-way" in json.dumps(said), "and must say why, so the agent can report it or retry"
    assert s.receipt.counters["errors"] == 1          # counted, not silently smoothed over


def test_a_complete_reply_is_not_accused_of_stopping_part_way(world):
    # The other half: the check must not fire on a normal stream, or every turn ends in a false alarm.
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    _, _, out = asyncio.run(_oai(s, {"model": "x", "stream": True, "messages": [{"role": "user", "content": "go"}]}))
    assert "ended part-way" not in out.decode()
    assert out.decode().count("data: [DONE]") == 1 and s.receipt.counters["errors"] == 0


async def _oai(s, body):
    st, h, it = await s.chat_completions(body)
    return st, h, await _drain(it)


def test_public_reason_never_leaks_urls_or_hosts():
    import httpx
    from inferroute_local.confidential.session import public_reason
    req = httpx.Request("GET", "https://api.example-provider.ai/fleets/abc/evidence?nonce=deadbeef")
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
        req = httpx.Request("GET", "https://api.example-provider.ai/fleets/abc/evidence")
        raise httpx.HTTPStatusError("429 for url 'https://api.example-provider.ai/fleets/abc/evidence'", request=req, response=httpx.Response(429, request=req))
    monkeypatch.setattr(attest, "fetch_and_verify", boom)
    r = asyncio.run(_session(FakeCarrier(world["enclaves"])).open())
    assert r.verdict == "refused" and "answered 429" in r.refusal and "http" not in r.refusal and "example-provider" not in r.refusal


def test_usage_is_priced_locally_and_reported_with_model_short_and_latency(world):
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier, price={"input": 1.0, "cached": 0.1, "output": 10.0})
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))   # 5 in / 2 out
    c = s.receipt.counters
    assert c["input_tokens"] == 5 and c["output_tokens"] == 2
    assert abs(c["estimated_cost_usd"] - (5 / 1e6 * 1.0 + 2 / 1e6 * 10.0)) < 1e-12
    rep = carrier.usage_reports[-1]
    assert rep["model_short"] == "fake" and rep["model"] == "fake/Model-TEE" and rep["economy"] is False
    assert rep["usage"]["input_tokens"] == 5 and "latency_ms" in rep["usage"]


def test_the_evidence_endpoint_comes_from_the_carrier_not_from_this_client(world):
    """No operator address is compiled in: the session asks its carrier where the evidence lives."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    prof = world["profile_seen"]
    assert prof is not None
    assert prof.evidence_url("F", "N") == "https://op.test/F/evidence?nonce=N"
    assert prof.measurements_url() == "https://op.test/measurements"


def test_a_pinned_instance_dropped_at_reverification_is_replaced_by_a_verified_one(world):
    """19 Sep, Henry's session receipt: two clean switches when instances vanished, then at the 30-minute
    re-check — "5/11 instances verified", "pinned-failed-reverify 044e7683" — the pin was dropped and never
    replaced. Every later message failed "503 no pinned instance", four automatic retries each, with five
    verified instances available. The vanish path re-pinned; the re-check path never reached that code."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    pinned_first = s.receipt.instance["id"]
    other = next(i for i in world["enclaves"] if i != pinned_first)
    world["verified"][pinned_first] = False                       # the pinned one fails the next re-check…
    s._verified_at = 0                                            # …which is due now
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert st == 200, body
    assert s.receipt.instance["id"] == other and carrier.calls[-1][0] == other
    kinds = [e["kind"] for e in s.receipt.events]
    assert "pinned-failed-reverify" in kinds and kinds[-1] == "pinned"             # dropped, then re-pinned
    assert "switched" in s.receipt.events[-1]["detail"]


def test_when_the_recheck_leaves_no_verified_instance_the_session_says_so_plainly(world):
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    asyncio.run(s.open())
    for i in world["verified"]:
        world["verified"][i] = False
    s._verified_at = 0
    st, _, body = asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    assert st == 503 and b"refusing to continue unverified" in body               # not the opaque "no pinned instance"


class _PaymentSolicitationCarrier(FakeCarrier):
    """Upstream answers 402 with the body Henry saw on screen 2026-09-20."""

    BODY = (b'{"error": {"message": "upstream 402: {\'detail\': {\'message\': \'Quota exceeded and account '
            b"balance is $0.0, please pay with fiat or send tao to 5FAKEADDRnotarealaccountXXXXXXXXXXXXXXXXXXXXXXXX'}}\"}}")

    async def invoke(self, **kw):
        self.calls.append((kw.get("instance_id"), kw.get("nonce"), kw.get("stream")))

        async def one():
            yield self.BODY
        return 402, {"content-type": "application/json"}, one()


@pytest.mark.parametrize("openai_path", [False, True])
def test_an_upstream_payment_solicitation_never_reaches_the_client(world, caplog, openai_path):
    """2026-09-20: a 402 reached a user carrying "please pay with fiat or send tao to <address>".

    Our product told a user to send cryptocurrency to a wallet address, on a surface where users trust us.
    The same body carried the provider's quota and balance. The upstream STATUS may pass through; the
    upstream BODY may not — and a scrubber for addresses alone would still have leaked the balance, which
    is why this asserts five separate fragments absent rather than one. Both dialects, because on master
    the defect was duplicated across them; this branch funnels both through one _send, and the parametrise
    is what proves that claim rather than assuming it.

    Ported from master b4c1acd (PR #18), reported by a peer session while this lane was routing through
    the affected path.
    """
    import logging as _lg
    carrier = _PaymentSolicitationCarrier(world["enclaves"])
    s = _session(carrier)
    asyncio.run(s.open())
    body = {"messages": [{"role": "user", "content": "1"}], "stream": False}
    with caplog.at_level(_lg.WARNING, logger="inferroute_local.confidential"):
        if openai_path:
            st, _, it = asyncio.run(s.chat_completions(body))
        else:
            st, _, it = asyncio.run(s.messages(body))
        text = asyncio.run(_drain(it)).decode()
    assert st == 402, text
    for leak in ("5FAKEADDR", "send tao", "balance", "Quota exceeded", "pay with fiat"):
        assert leak not in text, f"the client was told {leak!r}: {text}"
    assert "the provider answered 402" in text and "out of capacity" in text
    # …and the raw body is NOT destroyed: it stays where it is diagnostic.
    assert "5FAKEADDR" in caplog.text, "the upstream body must still reach the log"


def _stall_reverification(s, monkeypatch):
    async def boom(fleet_id):
        raise RuntimeError("the operator gateway is unreachable")
    monkeypatch.setattr(s.transport, "instances", boom)


def test_a_session_that_already_sent_is_degraded_not_refused_when_reverification_lapses(world, monkeypatch):
    """"refused" means the session never opened, and the panel says so in those words. An audit of
    23 Sep found `ir confidential show` printing "This session was NOT opened. Nothing was sent." over a
    receipt whose own counters recorded 12 sent requests, because this branch set "refused" on a session
    that had run. `degraded` is the verdict the lost-instance path above already uses for exactly this."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    s.receipt.counters["requests"] = 12
    _stall_reverification(s, monkeypatch)
    for _ in range(S.REVERIFY_FAILURES_ALLOWED - 1):
        asyncio.run(s._reverify())
        assert s.receipt.verdict == "confidential", "a tolerated failure must not change the verdict"
    with pytest.raises(S.Refused):
        asyncio.run(s._reverify())
    assert s.receipt.verdict == "degraded"
    assert "could not be re-verified" in (s.receipt.refusal or ""), "the panel prints refusal or verdict"


def test_a_session_that_never_sent_is_still_refused(world, monkeypatch):
    """The other side of the same branch: nothing was sent, so "refused" is exactly right and the
    original wording stands."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    assert s.receipt.counters["requests"] == 0
    _stall_reverification(s, monkeypatch)
    for _ in range(S.REVERIFY_FAILURES_ALLOWED - 1):
        asyncio.run(s._reverify())
    with pytest.raises(S.Refused):
        asyncio.run(s._reverify())
    assert s.receipt.verdict == "refused"
    assert s.receipt.refusal


from inferroute_local.confidential.receipt import CLAIM_CONFIDENTIAL, CLAIM_OPENED   # noqa: E402


def _body():
    return {"model": "fake", "max_tokens": 5, "stream": False,
            "messages": [{"role": "user", "content": "there"}]}


def test_a_session_that_sent_nothing_does_not_claim_that_it_did(world):
    """The claim was set once at open and never revisited, so a session that verified and then did
    nothing still asserted "this session's requests were encrypted on this device". On the machine this
    was found on, 77 of 712 confidential receipts were in exactly that state — and it is the one field
    shaped to be quoted on its own."""
    s = _session(FakeCarrier(world["enclaves"]))
    r = asyncio.run(s.open())
    assert r.verdict == "confidential" and r.counters["requests"] == 0
    assert r.claim == CLAIM_OPENED
    assert "requests were encrypted" not in r.claim
    assert "No request has been sent" in r.claim, "it must say what DID happen, not go silent"


def test_the_strong_claim_is_earned_by_a_request(world):
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    asyncio.run(_msg(s, _body()))
    assert s.receipt.counters["requests"] == 1
    assert s.receipt.claim == CLAIM_CONFIDENTIAL


def test_a_refusal_leaves_no_claim_behind(world, monkeypatch):
    """`_reverify` set the verdict and left the confidentiality paragraph attached."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    assert s.receipt.claim
    _stall_reverification(s, monkeypatch)
    for _ in range(S.REVERIFY_FAILURES_ALLOWED - 1):
        asyncio.run(s._reverify())
    with pytest.raises(S.Refused):
        asyncio.run(s._reverify())
    assert s.receipt.verdict == "refused"
    assert s.receipt.claim == "", "nothing was verified-and-used, so there is nothing to claim"


def test_a_session_that_ran_and_then_lapsed_keeps_the_claim_it_earned(world, monkeypatch):
    """The paragraph is true of the requests that WERE sealed; deleting it would understate as badly as
    the old behaviour overstated."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    asyncio.run(_msg(s, _body()))
    _stall_reverification(s, monkeypatch)
    for _ in range(S.REVERIFY_FAILURES_ALLOWED - 1):
        asyncio.run(s._reverify())
    with pytest.raises(S.Refused):
        asyncio.run(s._reverify())
    assert s.receipt.verdict == "degraded"
    assert s.receipt.claim == CLAIM_CONFIDENTIAL


def test_the_claim_never_outruns_the_counter(world, monkeypatch):
    """The invariant, stated once: the past-tense paragraph and a zero request count cannot coexist."""
    s = _session(FakeCarrier(world["enclaves"]))
    asyncio.run(s.open())
    for step in (lambda: None, lambda: asyncio.run(_msg(s, _body()))):
        step()
        if s.receipt.claim == CLAIM_CONFIDENTIAL:
            assert s.receipt.counters["requests"] > 0


def test_the_receipt_carries_our_side_of_the_exchange_so_the_key_binding_can_be_redone(world):
    """The audit brief asks an auditor to confirm the quote commits to SHA-256(challenge ‖ the key this
    session sealed to), and that our challenge appears verbatim in the attested body. Neither was possible:
    the receipt kept a HASH of the key and no challenge at all, so two of the five recomputations it asks
    for were work the file could not support. Both values are ours and neither is secret — a nonce we chose
    and a public ML-KEM key.

    The test asserts the recomputation SUCCEEDS on the recorded values rather than asserting the fields are
    present: a challenge and a key that do not reproduce the binding are two more strings in a file."""
    import hashlib

    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    r = asyncio.run(s.open())
    mine = r.attestation["checked_with"]

    assert mine["challenge"] == "n" * 64, "the challenge this device verified with was not recorded"
    assert mine["e2e_pubkey"] == world["enclaves"]["i-a"].pubkey_b64, "the key sealed to was not recorded"

    # The binding itself, recomputed from the receipt alone — which is what the brief asks of the auditor.
    want = hashlib.sha256((mine["challenge"] + mine["e2e_pubkey"]).encode()).digest()
    assert len(want) == 32
    assert mine["recompute"] == "sha256((challenge + e2e_pubkey).encode()) == the quote's report_data[0:32]"

    # And the hash we used to keep alone still agrees with the key we now keep, so an OLD receipt and a new
    # one describe the same session rather than two.
    assert mine["e2e_pubkey_sha256"] == r.instance["e2ee_pubkey_sha256"]

    # Ours must be distinguishable from the operator's without asking. Everything else in the object came
    # from the machine under audit; an auditor who cannot tell them apart has to treat all of it as theirs.
    assert "not supplied by the enclave" in mine["note"]
    assert "checked_with" not in {k for row in s._raw_evidence for k in row}, \
        "our fields were written into the operator's evidence row rather than beside it"


def test_a_receipt_dates_itself_even_when_nothing_closes_the_session(world):
    """`ended_at` is written by close(), and close() does not run when the process is killed. That left a
    complete receipt with an empty `ended_at` and no way for an auditor to tell "still running" from "died
    at a time nobody recorded". Every save now stamps the last moment the session was known to be alive."""
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    r = asyncio.run(s.open())
    assert r.ended_at == "", "this session was never closed — the fixture would not be testing anything"
    assert r.last_activity_at, "a saved receipt does not say when it was last alive"
    assert r.last_activity_at >= r.started_at

    from inferroute_local.confidential.receipt import Receipt
    on_disk = Receipt.load(r.path)
    assert on_disk.last_activity_at == r.last_activity_at, "the stamp did not reach the file"


def test_receipt_saves_do_not_share_a_temporary_name(world, tmp_path):
    """A shared ".tmp" is safe only while exactly one writer exists. The same shape in the disclosure
    record's writer produced a file that would not parse on 24 Sep, and the session it described dropped
    out of the audit pack with its five signed searches — which reads as evidence removed."""
    import threading

    from inferroute_local.confidential.receipt import Receipt

    r = Receipt(session_id="s1", model_short="m", upstream_model="u", fleet_id="f", transport="t")
    r.path = str(tmp_path / "r.json")
    seen = []
    real_replace = S.os.replace if hasattr(S, "os") else None
    del real_replace

    import os as _os
    orig = _os.replace

    def spy(src, dst):
        seen.append(str(src))
        return orig(src, dst)

    import inferroute_local.confidential.receipt as RC
    RC.os.replace = spy
    try:
        barrier = threading.Barrier(4)

        def save():
            barrier.wait()
            r.save()

        ts = [threading.Thread(target=save) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        RC.os.replace = orig

    assert len(seen) == 4
    assert len(set(seen)) == 4, f"concurrent saves shared a temporary name: {seen}"
    # And the published file is one whole document, not a mixture of four.
    assert Receipt.load(r.path).session_id == "s1"


def test_the_receipt_defines_what_its_counters_measure(world):
    """An auditor on 25 Sep found `ciphertext_bytes_sent` was 26-42% of `plaintext_bytes_sealed_here` in
    every session with traffic, could not tell from the receipt whether that was compression or two
    different layers, and reported it as unexplained.

    The answer is benign — `e2ee.seal` does `gzip.compress(body)` before encrypting, and the counter for
    "sealed here" is `len(body)` BEFORE that. But a number whose units are not stated invites the reading
    that something is missing, and "unexplained" in an audit report costs more than the lines that
    prevent it."""
    carrier = FakeCarrier(world["enclaves"])
    s = _session(carrier)
    r = asyncio.run(s.open())

    means = r.counters_mean
    # Every counter that has ever been questioned is defined, and defined IN the receipt rather than in a
    # document the auditor may not have.
    for k in ("plaintext_bytes_sealed_here", "ciphertext_bytes_sent", "response_bytes_opened_here"):
        assert k in means and len(means[k]) > 30, k
        assert k in r.counters, f"{k} is defined but not counted"
    assert "BEFORE gzip" in means["plaintext_bytes_sealed_here"]
    # The sentence that actually stops the false report.
    assert "compression, not loss" in means["ciphertext_bytes_sent"]

    from inferroute_local.confidential.receipt import Receipt
    assert Receipt.load(r.path).counters_mean == means, "the definitions did not reach the file"


# ── the 402 tripwire ──────────────────────────────────────────────────────────────────────────────
# cc-proxy-prod made 402 retryable across providers on 2026-07-04 after 2.4k tester 402s in 12h. A
# provider 402 that escapes that absorption is invisible today; this notices it from the client side.

def test_our_own_topup_notice_does_not_trip_the_wire():
    """THE CORRECTION THAT MATTERS. The expected body legitimately contains an address —
    pay_to={INFERROUTE_WALLET_ADDRESS}, inferroute's own receiving address, published on purpose so the
    user can pay it. My first reading of this had the detector backwards, keyed on an address being
    present, which would flag the normal case on every empty wallet forever."""
    from inferroute_local.confidential.session import _is_our_topup_notice
    real = ("Wallet balance empty. Deposit USDC to continue: POST a signed EIP-3009 "
            "TransferWithAuthorization to https://inferroute.ai/api/billing/wallet-topup "
            "(pay_to=0xAbC0000000000000000000000000000000000001, asset=USDC, network=base, "
            "chainId=8453, min $1), then retry.")
    assert _is_our_topup_notice(real) is True


def test_a_provider_402_trips_the_wire():
    """Anything that is not that notice reached us from upstream rather than from billing."""
    from inferroute_local.confidential.session import _is_our_topup_notice
    for body in ("Insufficient credits for this model.",
                 "",
                 '{"error":{"type":"payment_required","message":"quota exceeded"}}',
                 "Payment Required",
                 # an address alone must not buy a pass: presence of a field is not the shape
                 "please send funds to 0xAbC0000000000000000000000000000000000001"):
        assert _is_our_topup_notice(body) is False, body


def test_the_tripwire_needs_both_markers_not_either():
    """Either marker alone is reachable by accident — the phrase could appear in a provider's wording,
    and half of our URL is just a hostname. Requiring both is what makes the match ours."""
    from inferroute_local.confidential.session import _is_our_topup_notice
    assert _is_our_topup_notice("Wallet balance empty. Contact support.") is False
    assert _is_our_topup_notice("see https://inferroute.ai/api/billing/wallet-topup") is False


def test_the_tripwire_note_never_carries_the_upstream_body():
    """The receipt is something the user reads, so it is a place upstream text must not reach — the same
    reason the body is withheld from the response. The note may say the shape was wrong and how long it
    was; it may not quote it."""
    import re
    from inferroute_local.confidential import session as S
    src = _fn_body(S, "_send") if "_fn_body" in globals() else open(S.__file__).read()
    block = src[src.index("upstream-402-unexpected"):]
    block = block[:block.index("logger.warning")] if "logger.warning" in block else block[:600]
    assert "detail" not in block.replace("len(detail)", ""), \
        "the tripwire note interpolates the upstream body"
    assert "len(detail)" in block, "the note should still say how long the body was"


# ── whose fault, decided where the fact is known ─────────────────────────────────────────────────

def test_only_a_fleets_own_failures_count_against_it():
    """The bug this closes shipped earlier the same night. fleet_success counted EVERY error against the
    fleet, so a malformed request (our bug), a 402 (the account's billing state) and a relay outage
    (every fleet equally unreachable) would each demote whichever fleet happened to be selected. That is
    noise dressed as evidence, and a client-side bug would have demoted all five fleets at once."""
    from inferroute_local.confidential import session as S
    # ours, or the account's, or the relay's — true of every fleet at once, so evidence about none
    for status in (400, 401, 402, 403, 404):
        assert S.status_fault(status) not in S.COUNTS_AGAINST_FLEET, status
    # the fleet's own answer, including one we do not recognise
    for status in (429, 500, 502, 503, 504, 599):
        assert S.status_fault(status) in S.COUNTS_AGAINST_FLEET, status
    assert S.status_fault(599) == S.UPSTREAM_UNKNOWN, "an unusual status is still the fleet's answer"


def test_the_receipt_separates_fleet_attributable_errors_from_the_rest():
    """`errors` stays the honest total of everything that went wrong. `errors_fleet` is the only one the
    availability model may read."""
    from inferroute_local.confidential import session as S
    c = {}
    S._err(c, "send_failed", S.ACCOUNT_FAULT)      # 402: not the fleet's doing
    S._err(c, "seal_failed", S.CLIENT_FAULT)       # ours
    S._err(c, "stream_dropped", S.INSTANCE_FAULT)  # the fleet's
    assert c["errors"] == 3, "the total must still count everything that failed"
    assert c["errors_fleet"] == 1, "a billing state or our own bug counted against the fleet"
    assert c["fault_account"] == 1 and c["fault_client"] == 1 and c["fault_instance"] == 1


def test_a_relay_outage_does_not_demote_the_fleet_it_happened_to_pick():
    """If the relay is unreachable every fleet is equally unreachable. Blaming the selected one would
    make the chooser wander away from a healthy fleet for a reason that has nothing to do with it."""
    from inferroute_local.confidential import session as S
    assert S.TRANSPORT_FAULT not in S.COUNTS_AGAINST_FLEET
    c = {}
    for _ in range(20):
        S._err(c, "send_failed", S.TRANSPORT_FAULT)
    assert c.get("errors_fleet", 0) == 0 and c["errors"] == 20


def test_an_unopenable_reply_is_never_averaged_into_a_health_score():
    """The most dangerous finding of the 2026-09-30 review, against a classification I had shipped hours
    earlier in 58de466.

    A reply that will not open is a ChaCha20-Poly1305 authentication failure against the key an Intel TDX
    quote committed to. It is indistinguishable from a substituted key or a substituted machine, and it
    is the ONLY runtime signal that the sentence the receipt offers to be quoted on its own — "No relay,
    and no provider, could substitute the key or the hardware without failing a check on this device" —
    is being tested in anger.

    I had classified it INSTANCE_FAULT, which is the class that gets silently retried and averaged into
    an availability score. A relay attempting key substitution across a fleet would then have presented
    to a patent attorney as a slightly slow afternoon, and to the scorer as a marginally worse fleet.

    The check failed closed throughout — nothing was ever shown unverified. What was at risk was the
    notification."""
    from pathlib import Path
    from inferroute_local.confidential import session as S
    assert S.INTEGRITY_FAULT not in S.COUNTS_AGAINST_FLEET, \
        "an authentication failure is being averaged into an availability score"
    src = (Path(__file__).resolve().parent.parent
           / "inferroute_local" / "confidential" / "session.py").read_text()
    assert '_err(c, "reply_unopenable", INSTANCE_FAULT)' not in src
    assert src.count('_err(c, "reply_unopenable", INTEGRITY_FAULT)') == 4, \
        "not every unopenable-reply site is classified as an integrity failure"


def test_the_page_never_retries_an_unopenable_reply_quietly():
    """The same finding on the display side. Quiet retry of an authentication failure turns the one
    tripwire this product has into a metric."""
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent
          / "inferroute_cli" / "probant_web" / "app.js").read_text()
    body = js[js.index("function isTransient"):js.index("const AUTO_RETRIES")]
    assert 'd.includes("could not open the enclave")) return false;' in body, \
        "an unopenable reply can be retried silently"
    # and it must be excluded BEFORE the unrecognised-is-quiet default can claim it
    assert body.index('could not open the enclave') < body.index("UNNAMED_FAILURE")


# ── the record follows the machines ──────────────────────────────────────────────────────────────

def test_every_machine_that_served_keeps_its_evidence(world, tmp_path):
    """FATAL finding of the 2026-09-30 review, and it was live: `_pin` overwrites instance, checks,
    attestation and limitations, and it is called on every switch — so the previous machine's evidence
    row was DESTROYED. For every request it had served, the audit brief's "recompute the verdicts from
    it rather than reading them" became impossible, while the events list went on naming that machine.
    A record that contradicts itself, not one that is merely short. 246 of 1,006 receipts on this device
    had re-pinned."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    s.receipt.path = str(tmp_path / "r.json")
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    del carrier.enclaves["i-a"]
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))

    served = s.receipt.served_by
    assert len(served) == 2, "a machine served and left no row"
    assert [e["instance"]["id"] for e in served] == ["i-a", "i-b"]
    # the evidence for the machine that is NO LONGER pinned is still recoverable
    first = served[0]
    assert first["attestation_sha256"], "the first machine's evidence was not retained"
    blob = (tmp_path / "evidence" / f"{first['attestation_sha256']}.json")
    assert blob.exists(), "the referenced evidence file was not written"
    assert json.loads(blob.read_text()), "the retained evidence is empty"
    # every row carries the checks that were true OF THAT MACHINE
    assert all(e["checks"] for e in served)


def test_the_singular_fields_still_describe_the_current_machine(world, tmp_path):
    """Purely additive, on purpose. The audit pack reads `attestation` as a dict and its brief ships a
    runnable snippet doing `r["attestation"]["quote"]`; turning that field into a list would have made
    the pack report `receipts_with_attestation: 0` for its best-evidenced receipts and manufactured an
    audit finding against a correct client. So the shape nothing asked to change did not change."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    s.receipt.path = str(tmp_path / "r.json")
    asyncio.run(s.open())
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "1"}]}))
    del carrier.enclaves["i-a"]
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "2"}]}))
    assert isinstance(s.receipt.attestation, dict) and s.receipt.attestation
    assert s.receipt.instance["id"] == "i-b", "the singular field should name the CURRENT machine"
    assert isinstance(s.receipt.checks, dict)


def test_requests_are_credited_to_the_machine_that_carried_them(world, tmp_path):
    """`served_by` saying a machine was used, without saying for what, cannot answer the interleaving
    the verifier asks auditors to perform."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    s.receipt.path = str(tmp_path / "r.json")
    asyncio.run(s.open())
    for _ in range(3):
        asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "x"}]}))
    del carrier.enclaves["i-a"]
    asyncio.run(_msg(s, {"stream": False, "messages": [{"role": "user", "content": "y"}]}))
    served = s.receipt.served_by
    assert served[0]["requests"] == 3, f"first machine credited {served[0]['requests']}, expected 3"
    assert served[1]["requests"] >= 1
    assert sum(e["requests"] for e in served) >= s.receipt.counters["requests"]


def test_identical_evidence_is_stored_once(world, tmp_path):
    """243 KB a row, up to 18 pins in a real session. Content-addressing means re-pinning the same
    machine costs nothing, and the same machine seen by many sessions is stored once for all of them."""
    carrier = FakeCarrier(world["enclaves"], nonces_per=1)
    s = _session(carrier)
    s.receipt.path = str(tmp_path / "r.json")
    asyncio.run(s.open())
    s._remember_served("i-a", "again", s.pinned)
    s._remember_served("i-a", "and again", s.pinned)
    shas = {e["attestation_sha256"] for e in s.receipt.served_by if e["attestation_sha256"]}
    files = list((tmp_path / "evidence").glob("*.json"))
    assert len(shas) == 1 and len(files) == 1, "the same evidence was stored more than once"
