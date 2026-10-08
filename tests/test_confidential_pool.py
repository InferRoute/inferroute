"""The verified pool is no longer capped at the first random instance draw (2026-10-07: 5 of 16 detect runs
stopped with "no verified alternative"), and growing it relaxes nothing.

Pinned both ways, as asked: a fleet whose opening draw and refresh draw share no instance keeps working
(known positive), and an instance that fails attestation is never admitted however many draws show it
(known negative)."""
import asyncio

import pytest

from inferroute_local.confidential import attest, session as S
from inferroute_local.confidential import transport as T
from tests.confidential_fake_enclave import FakeEnclave

N = 14


def _report(iid, ok, key):
    checks = {k: attest.Check(ok, "fixture") for k in attest.REQUIRED}
    checks["build_recorded"] = attest.Check(ok, "build fixture — recorded by InferRoute since 2026-01-01")
    if not key:
        checks["e2e_key_bound"] = attest.Check(False, "no encryption key supplied to bind")
    ok = ok and bool(key)
    return attest.InstanceReport(iid, checks, gpu_count=8, mrtd="aa" * 48, rtmrs=["bb" * 48] * 4,
                                 verified=ok, chain="leaf → root", e2e_pubkey=key if ok else "")


class Fleet:
    """14 instances; each listing returns a chosen slice, as the operator's random 5-of-N does."""

    def __init__(self, draws, bad=()):
        self.enc = {f"i{k}": FakeEnclave() for k in range(N)}
        self.draws = list(draws)            # successive listings: lists of instance ids
        self.bad = set(bad)
        self.candidates_calls = 0
        self.calls = []
        self.name = "fake carrier"

    def _listing(self):
        ids = self.draws.pop(0) if len(self.draws) > 1 else self.draws[0]
        return {"nonce_expires_in": 60,
                "instances": [{"instance_id": i, "e2e_pubkey": self.enc[i].pubkey_b64, "nonces": [f"{i}-n{j}" for j in range(3)]}
                              for i in ids]}

    async def candidates(self, fleet_id, nonce):
        self.candidates_calls += 1
        e2 = self._listing()
        return {"scheme": T.DEFAULT_SCHEME, "nonce_expires_in": 60, "instances": e2["instances"],
                "evidence": [{"instance_id": i} for i in self.enc], "unavailable_instance_ids": [],
                "registry": {"configs": []}}

    async def nonces(self, fleet_id):
        return self._listing()

    async def invoke(self, *, fleet_id, instance_id, nonce, stream, blob, path="/v1/chat/completions"):
        self.calls.append(instance_id)
        enc = self.enc[instance_id]
        body, pk = enc.open_request(blob)
        out = enc.seal_response(pk, {"id": "x", "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}],
                                     "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

        async def one():
            yield out
        return 200, {"content-type": "application/octet-stream"}, one()

    async def report_usage(self, payload):
        pass


@pytest.fixture
def fake_checks(monkeypatch, tmp_path):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    state = {"bad": set()}

    def fake_verify(fleet_id, doc, nonce):
        keys = {i["instance_id"]: i["e2e_pubkey"] for i in doc.get("instances") or []}
        reps = [_report(r["instance_id"], r["instance_id"] not in state["bad"], keys.get(r["instance_id"], ""))
                for r in doc["evidence"]]
        return attest.FleetReport(fleet_id, nonce, reps, raw=list(doc["evidence"]))

    def fake_verify_instance(row, nonce, reference, key=None):
        return _report(row["instance_id"], row["instance_id"] not in state["bad"], key or "")

    async def fake_online(report, inst, nonce, http, timeout=0):
        for k in attest.REQUIRED_ONLINE:
            report.checks[k] = attest.Check(True, "fixture-online")
        return report

    monkeypatch.setattr(attest, "verify_candidates", fake_verify)
    monkeypatch.setattr(attest, "verify_instance", fake_verify_instance)
    monkeypatch.setattr(attest, "verify_online", fake_online)
    return state


def _session(fleet):
    return S.ConfidentialSession(session_id="p1", model_short="lane", upstream_model="sealed", fleet_id="fl_1",
                                 transport=fleet, http=None)


async def _send(s):
    return await s.chat_completions({"model": "lane", "messages": [{"role": "user", "content": "x"}]})


def _lose(s, iid):
    """The pinned instance vanishes: it stops appearing and has no nonces left."""
    s._pool.pop(iid, None)
    s.pinned.nonces.clear()


def test_disjoint_draws_keep_the_session_alive_without_new_evidence(fake_checks):
    first, second = [f"i{k}" for k in range(5)], [f"i{k}" for k in range(5, 10)]
    fleet = Fleet([first, second])
    s = _session(fleet)
    r = asyncio.run(s.open())
    assert r.verdict == "confidential" and s.pinned.instance_id in first
    _lose(s, s.pinned.instance_id)
    st, _, _ = asyncio.run(_send(s))
    assert st == 200, s.receipt.refusal
    assert fleet.calls[-1] in second, "the session must re-pin to an instance from the refresh draw"
    assert fleet.candidates_calls == 1, "late keys are checked against quotes already held: no evidence refetch"
    assert s.receipt.counters.get("instance_switches") == 1


def test_an_instance_that_fails_attestation_is_never_admitted_however_often_it_is_drawn(fake_checks):
    bad = [f"i{k}" for k in range(5, 10)]
    fake_checks["bad"] = set(bad)
    fleet = Fleet([["i0"]] + [bad] * 20)
    s = _session(fleet)
    assert asyncio.run(s.open()).verdict == "confidential"
    _lose(s, "i0")
    for _ in range(3):
        asyncio.run(_send(s))
    assert not any(c in bad for c in fleet.calls), "an instance that failed attestation was sealed to"
    assert s.receipt.verdict == "degraded" and "no verified alternative" in s.receipt.refusal


def test_a_key_the_held_quote_does_not_bind_is_not_admitted_late(fake_checks, monkeypatch):
    """The late-key path re-runs the SAME checks; a key the quote did not commit to fails them."""
    def strict(row, nonce, reference, key=None):
        return _report(row["instance_id"], False, key or "")          # the binding check fails for this key
    monkeypatch.setattr(attest, "verify_instance", strict)
    fleet = Fleet([["i0"], ["i7"]])
    s = _session(fleet)
    asyncio.run(s.open())
    _lose(s, "i0")
    asyncio.run(_send(s))
    assert "i7" not in fleet.calls


def test_a_recently_failed_instance_is_tried_last(fake_checks):
    S.record_failure("i0")
    fleet = Fleet([["i0", "i1", "i2"]])
    s = _session(fleet)
    asyncio.run(s.open())
    assert s.pinned.instance_id == "i1", "a just-failed instance was re-picked ahead of healthy ones"
    assert S._by_recent_failure(["i0", "i1"]) == ["i1", "i0"]
    assert S._by_recent_failure(["i0"]) == ["i0"], "tried last, not never: on a small fleet it may be all there is"


def test_an_unknown_evidence_scheme_is_refused_not_guessed(monkeypatch, tmp_path):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    with pytest.raises(attest.UnsupportedScheme):
        attest.verify_candidates("fl_1", {"scheme": "something-else/v9", "instances": [], "evidence": []}, "ab" * 32)

    class Odd(Fleet):
        async def candidates(self, fleet_id, nonce):
            doc = await super().candidates(fleet_id, nonce)
            return {**doc, "scheme": "something-else/v9"}
    r = asyncio.run(_session(Odd([["i0"]])).open())
    assert r.verdict == "refused" and "cannot verify" in r.refusal


def test_union_draws_keeps_every_instance_seen_and_the_shortest_expiry():
    a = {"nonce_expires_in": 60, "instances": [{"instance_id": "x", "nonces": ["1"]}, {"instance_id": "y", "nonces": ["2"]}]}
    b = {"nonce_expires_in": 50, "instances": [{"instance_id": "y", "nonces": ["3"]}, {"instance_id": "z", "nonces": ["4"]}]}
    u = T.union_draws([a, b, None])
    assert [i["instance_id"] for i in u["instances"]] == ["x", "y", "z"]
    assert next(i for i in u["instances"] if i["instance_id"] == "y")["nonces"] == ["3"], "freshest nonces win"
    assert u["nonce_expires_in"] == 50
