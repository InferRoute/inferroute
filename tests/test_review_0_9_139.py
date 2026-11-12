"""The adversarial review of relay/permit-0.9.139 (rc/0.9.138..HEAD), one section per finding, plus the billing owner's
item 11 (the balance check never stalls a start). Each test failed on the tree the review read."""
from __future__ import annotations

import asyncio
import io
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from inferroute_cli import anteriora_billing as B
from inferroute_cli import pi_attested as PA
from inferroute_cli._searchgate import ir_search_gate as G
from inferroute_local.confidential import billing_refusal as BR

P1 = "00000000-0000-0000-0000-0000000000a1"
P2 = "00000000-0000-0000-0000-0000000000a2"
GATE = "https://" + G.GATE_HOSTS[0]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setattr(B, "_answer", None)
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    PA.clear_used_up_signal()
    yield
    PA.clear_used_up_signal()


@pytest.fixture
def site(monkeypatch):
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    events = []
    state = {"n": 0}

    def post(path, body):
        if path == "/api/anteriora/settle":
            events.append(("settle", body["outcome"], body["permit"]))
            return {"state": "delivered" if body["outcome"] == "delivered" else "refunded"}
        if path == "/api/anteriora/permit":
            state["n"] += 1
            events.append(("permit",))
            return {"permit": f"00000000-0000-0000-0000-{state['n']:012d}"}
        raise AssertionError(path)

    monkeypatch.setattr(B, "_post", post)
    monkeypatch.setattr(B, "print", lambda *a, **k: events.append(("said", " ".join(map(str, a)).strip())),
                        raising=False)
    return events


def held(pid=P1, **extra):
    return {"permit": {"id": pid, "unit": "search", "state": "delivered",
                       "at": B._now().strftime("%Y-%m-%dT%H:%M:%SZ"), "first_session": "s0",
                       "account": B._account_tag(), **extra}}


def refused(code, status=402):
    return BR.parse(status, {BR.HEADER: code}, json.dumps({"error": {"code": code, "message": "m"}}))


# ───────────────────────── 1. a used-up signal belongs to the permit that was sent ─────────────────────────

def test_1_a_used_up_answer_for_one_permit_never_settles_or_drops_another(site):
    BR.note_permit_refusal(P1, refused("permit_used_up"))           # P1's session heard it, and P1 was handled
    rec = held(P2)                                                   # a later session, on a fresh permit P2
    B.end_session(rec, "s2", True)
    assert site == [] and rec["permit"]["id"] == P2 and "renewal" not in rec


def test_1_the_relay_records_the_refusal_against_the_permit_it_sent():
    def handler(request):
        return httpx.Response(402, headers={BR.HEADER: "permit_used_up"},
                              json={"error": {"code": "permit_used_up", "message": "spent"}})

    async def go():
        from inferroute_local.confidential.transport import make_transport
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            t = make_transport(http, api_url="https://relay.test", api_key="k", prefer_direct=False, permit=P1)
            with pytest.raises(BR.BillingRefusal):
                await t.nonces("f")
    asyncio.run(go())
    assert BR.PERMIT_REFUSALS == {P1: "permit_used_up"}
    assert B.reported_refusal(P1) == "permit_used_up" and B.reported_refusal(P2) is None


def test_1_the_gate_records_the_permit_and_the_code_together(tmp_path):
    sig = tmp_path / "s.used-up"

    class Opener:
        def open(self, req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 402, "x", {BR.HEADER: "permit_used_up"},
                                         io.BytesIO(b'{"error":{"code":"permit_used_up"}}'))
    g = G.Gate(GATE, "k", P1, sleep=lambda s: None, opener=Opener(), used_up_file=str(sig))
    with pytest.raises(G.GateRefused):
        g.call(GATE, "POST", "/search", b"x", 5)
    PA._USED_UP_SIGNAL = sig
    assert B.reported_refusal(P1) == "permit_used_up" and B.reported_refusal(P2) is None


# ───────────────────────── 2. the verifier never imports from the workspace ─────────────────────────

PLANT = "open({marker!r}, 'w').write('ran')\n"


@pytest.mark.parametrize("enclave", [GATE, "http://203.0.113.5:8000"])
def test_2_a_module_planted_in_the_workspace_is_not_imported(tmp_path, monkeypatch, enclave):
    ws = tmp_path / "matter"
    ws.mkdir()
    marker = tmp_path / "PLANTED-RAN"
    for name in ("ir_search_gate.py", "json.py", "argparse.py"):
        (ws / name).write_text(PLANT.format(marker=str(marker)))
    (ws / "sealedresearch").mkdir()
    (ws / "sealedresearch" / "__init__.py").write_text(PLANT.format(marker=str(marker)))
    monkeypatch.chdir(ws)
    cfg = {"enclave": enclave}
    python, env, cwd = PA.verifier_command(cfg)
    argv = [python, "-m", "sealedresearch.search_verifier", "verify", "--enclave", enclave, "--help"]
    env, cwd = PA.isolated(env, cwd)
    argv, env, creds = PA.through_gate(cfg, argv, env)
    r = subprocess.run(argv, env=env, cwd=cwd, input="{}\n", capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    assert "usage" in r.stdout.lower()
    assert not marker.exists(), "a module planted in the matter folder ran inside the search verifier"


# ───────────────────────── 3. a dead permit is dropped unsettled, and renewed ─────────────────────────

@pytest.mark.parametrize("code", sorted(B.DEAD_CODES))
def test_3_a_dead_permit_is_dropped_with_no_settle_and_the_next_start_takes_a_new_unit(site, code):
    rec = held(P1, state="issued", first_session="s1")              # its first session would otherwise settle
    BR.note_permit_refusal(P1, refused(code))
    assert B.end_session(rec, "s1", False) == "dropped"
    assert site == [] and "permit" not in rec and rec["renewal"] == "dead"
    p = B.before_session(rec, "s2")
    assert site == [("permit",),
                    ("said", "This matter's current unit can no longer be used; continuing uses one more unit.")]
    assert p["id"] != P1


@pytest.mark.parametrize("code", ["permit_trial_paused", "out_of_credits", "permit_lane", "permit_wrong_product"])
def test_3_a_paused_trial_or_no_credit_keeps_the_permit(site, code):
    BR.note_permit_refusal(P1, refused(code))
    rec = held(P1)
    B.end_session(rec, "s9", True)
    assert rec["permit"]["id"] == P1 and "renewal" not in rec
    assert not any(e[0] == "settle" and e[1] == "failed" for e in site)


# ───────────────────────── 4, 5, 10. the session ─────────────────────────

from inferroute_local.confidential import session as S  # noqa: E402
from tests.test_confidential_session import FakeCarrier, _session, world  # noqa: E402,F401

_ONE = {"stream": False, "messages": [{"role": "user", "content": "x"}]}


def _opened(world, bills=True):
    carrier = FakeCarrier(world["enclaves"], nonces_per=5)
    if bills:
        carrier.bills, carrier.permit = True, P1
    s = _session(carrier)
    asyncio.run(s.open())
    return carrier, s


def _refuse_invoke(carrier, status, headers, body):
    async def invoke(**kw):
        carrier.calls.append((kw["instance_id"], kw["nonce"], kw["stream"]))

        async def one():
            yield body
        return status, headers, one()
    carrier.invoke = invoke


def _send(s):
    async def go():
        st, _, it = await s.messages(_ONE)
        return st, b"".join([c async for c in it]).decode()
    return asyncio.run(go())


def test_4_a_transient_billing_refusal_on_the_heartbeat_does_not_end_the_session(world, monkeypatch):
    carrier, s = _opened(world)

    async def busy(fleet_id, nonce):
        raise BR.BillingRefusal(429, "rate_limited", "", route="candidates")
    carrier.candidates = busy
    s._verified_at = 0.0
    assert asyncio.run(s.heartbeat()) is True and s.billing_stop is None

    async def final(fleet_id, nonce):
        raise BR.BillingRefusal(402, "permit_expired", "", route="candidates")
    carrier.candidates = final
    s._verified_at = 0.0
    assert asyncio.run(s.heartbeat()) is False


def test_5_a_direct_operator_402_is_never_read_as_the_relays_refusal(world, monkeypatch):
    monkeypatch.setattr(BR, "sleep", lambda s: asyncio.sleep(0))
    carrier, s = _opened(world, bills=False)
    _refuse_invoke(carrier, 402, {BR.HEADER: "permit_used_up"},
                   json.dumps({"error": {"code": "permit_used_up", "message": "spent"}}).encode())
    st, text = _send(s)
    assert st == 402 and "the provider answered 402" in text
    assert s.billing_stop is None and BR.PERMIT_REFUSALS == {}


def test_5_on_invoke_the_relays_header_is_needed_for_a_stop_or_a_permit_mark(world):
    carrier, s = _opened(world)
    _refuse_invoke(carrier, 402, {}, json.dumps({"error": {"code": "permit_used_up", "message": "x"}}).encode())
    _send(s)
    assert s.billing_stop is None and BR.PERMIT_REFUSALS == {}
    _refuse_invoke(carrier, 402, {BR.HEADER: "permit_used_up"}, b"{}")
    _send(s)
    assert s.billing_stop is not None and BR.PERMIT_REFUSALS == {P1: "permit_used_up"}


def test_10_a_billing_refusal_at_open_is_its_own_verdict_and_never_a_failed_check(world):
    from rich.console import Console
    from inferroute_local.confidential import display
    carrier = FakeCarrier(world["enclaves"])

    async def no(fleet_id, nonce):
        raise BR.BillingRefusal(402, "permit_missing", "Get a unit at inferroute.ai.", route="candidates")
    carrier.candidates = no
    s = _session(carrier)
    with pytest.raises(BR.BillingRefusal):
        asyncio.run(s.open())
    assert s.receipt.verdict == "billing_refused" and s.receipt.refusal == "permit_missing"
    assert not s.receipt.is_confidential
    con = Console(record=True, width=120)
    display.render_panel(s.receipt, con)
    out = con.export_text().lower()
    assert "account reason" in out and "permit_missing" in out
    assert "cannot be verified" not in out and "refused rather than degrades" not in out
    assert "verified" not in out.split("code:")[0]


# ───────────────────────── 6. the message filter ─────────────────────────

@pytest.mark.parametrize("message", [
    "Buy at іnferroute.ai/anteriora",                    # Cyrillic і
    "Buy at inferroute。ai/anteriora",                   # ideographic full stop
    "Buy at inferroute．ai/anteriora",                   # fullwidth full stop
    "Pay at 203.0.113.9/pay",                            # a dotted quad
    "Pay at http://203.0.113.9/pay",
    "Call 0800123456 to top up",                         # a phone number
    "Call +33 612345678 now",
    "Visit evil.example",
    "Write to help@evil.example",
    "See inferroute.ai.evil.example",
    "See https://localhost/pay",
    "See ftp://inferroute.ai/x",
    "See https://inferroute.ai:8443/x",
    "Café is closed",                                    # not ASCII
])
def test_6_lookalike_hosts_addresses_and_phone_numbers_are_not_shown(message):
    assert BR.plain_and_ours(message) is False
    assert BR.BillingRefusal(402, "permit_used_up", message, route="nonces").sentence == BR.FIXED["permit_used_up"]


@pytest.mark.parametrize("message", [
    "No units left. Buy more at https://inferroute.ai/anteriora.",
    "Buy more at app.inferroute.ai/anteriora or write to support@inferroute.ai.",
    "Your unit is spent, 0 left.",
])
def test_6_our_own_links_still_pass(message):
    assert BR.plain_and_ours(message) is True


# ───────────────────────── 7. wording: searches and document reads ─────────────────────────

def test_7_a_used_up_unit_is_said_to_cover_searches_and_document_reads():
    for words in (B.one_more_unit_words({}), B.used_up_kept_words({}), B.one_more_unit_words({"kind": "reading"})):
        assert "searches and document reads" in words


# ───────────────────────── 8. the gate's x-inferroute-forwarded ─────────────────────────

class _Script:
    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def open(self, req, timeout=None):
        self.requests.append(req)
        status, headers, body = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if status < 300:
            return _Resp(body)
        raise urllib.error.HTTPError(req.full_url, status, "x", headers, io.BytesIO(body))


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _gate(*answers):
    waits = []
    return G.Gate(GATE, "k", P1, sleep=waits.append, say=lambda s: None, opener=_Script(*answers)), waits


def test_8_an_answered_search_is_never_replayed_and_is_noted_as_withheld():
    g, waits = _gate((503, {BR.HEADER: "billing_unavailable", "x-inferroute-forwarded": "1", "Retry-After": "5"},
                      b'{"error":{"code":"billing_unavailable"}}'))
    g.begin()
    with pytest.raises(G.GateRefused):
        g.call(GATE, "POST", "/search", b"sealed", 5)
    assert len(g.opener.requests) == 1 and waits == []                 # no blind replay of an answered blob
    out = g.finish({"ok": False, "steps": [], "_unanswered": {"request_id": "r", "lifetime_id": "l"}})
    assert "billing_unavailable" in out["_unanswered"]["reason"]


def test_8_refused_before_forwarding_is_not_noted_as_withheld_and_may_be_retried():
    g, waits = _gate((402, {BR.HEADER: "permit_used_up", "x-inferroute-forwarded": "0"},
                      b'{"error":{"code":"permit_used_up"}}'))
    g.begin()
    with pytest.raises(G.GateRefused):
        g.call(GATE, "POST", "/search", b"sealed", 5)
    out = g.finish({"ok": False, "steps": [], "_unanswered": {"request_id": "r", "lifetime_id": "l"}})
    assert "_unanswered" not in out
    g, waits = _gate((503, {BR.HEADER: "billing_unavailable", "x-inferroute-forwarded": "0", "Retry-After": "5"},
                      b'{"error":{"code":"billing_unavailable"}}'), (200, {}, b"{}"))
    g.call(GATE, "POST", "/search", b"sealed", 5)
    assert len(g.opener.requests) == 2 and waits == [5.0]


# ───────────────────────── 9. wording ─────────────────────────

def test_9_an_invoke_refusal_says_the_request_was_not_processed():
    r = BR.parse(402, {BR.HEADER: "permit_missing"}, b"{}", route="invoke")
    assert r.sentence.endswith("Your request was not processed.") and "nothing was sent" not in r.sentence.lower()


def test_9_permit_missing_at_open_says_nothing_was_sent_once():
    from rich.console import Console
    from inferroute_cli import confidential as C
    con = Console(record=True, width=200)
    C.say_billing_refusal(con, BR.parse(402, {BR.HEADER: "permit_missing"}, b"{}", route="candidates"))
    assert con.export_text().lower().count("nothing was sent") == 1


def test_9_after_the_slot_retry_the_gate_is_not_quoted_as_promising_a_start():
    slot = (429, {BR.HEADER: "rate_limited", "Retry-After": "150"},
            json.dumps({"error": {"code": "rate_limited", "message": "Another search is running on the search "
                                  "machine. Yours will start when it finishes."}}).encode())
    g, waits = _gate(slot)
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "POST", "/search", b"sealed", 5)
    assert waits == [150.0] and e.value.refusal.sentence == "Another search is still running; try again in a few minutes."


def test_9_a_codeless_429_or_503_does_not_speak_of_the_account_or_of_nothing_searched():
    busy = BR.parse_search(429, {}, b"<html>")
    away = BR.parse_search(503, {}, b"<html>")
    assert busy.sentence == "The search service is busy; try again shortly."
    assert "account" not in busy.sentence
    assert "nothing was searched" not in away.sentence.lower()
    assert "nothing was searched" not in BR.SEARCH_FIXED["search_unavailable"].lower()


# ───────────────────────── 11. the balance check never stalls a start ─────────────────────────

@pytest.fixture
def balance(monkeypatch):
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    asked = []
    return asked


def test_11_a_slow_balance_answer_gives_the_last_known_answer_within_2_s(balance, monkeypatch):
    B._cache_path().parent.mkdir(parents=True, exist_ok=True)
    B._cache_path().write_text(json.dumps({"at": time.time() - 3600, "on": True}))   # stale, but the last known

    def slow(path):
        balance.append(path)
        time.sleep(5)
        return {"billing": "off"}
    monkeypatch.setattr(B, "_get", slow)
    t0 = time.monotonic()
    assert B.enabled() is True
    assert time.monotonic() - t0 < 2.6 and balance == ["/api/anteriora/balance"]


def test_11_no_answer_and_nothing_known_means_off(balance, monkeypatch):
    monkeypatch.setattr(B, "_get", lambda path: (_ for _ in ()).throw(B.BillingError("down")))
    assert B.enabled() is False


def test_11_an_answer_under_5_minutes_old_is_reused_across_runs_without_asking(balance, monkeypatch):
    B._cache_path().parent.mkdir(parents=True, exist_ok=True)
    B._cache_path().write_text(json.dumps({"at": time.time() - 120, "on": True}))
    monkeypatch.setattr(B, "_get", lambda path: (_ for _ in ()).throw(AssertionError("asked")))
    assert B.enabled() is True


def test_11_a_fresh_answer_is_written_down_for_the_next_run(balance, monkeypatch):
    monkeypatch.setattr(B, "_get", lambda path: {"billing": "units"})
    assert B.enabled() is True
    doc = json.loads(B._cache_path().read_text())
    assert doc["on"] is True and abs(doc["at"] - time.time()) < 5


class _Redirect(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def _go(self):
        _Redirect.hits.append((self.path, self.headers.get("authorization")))
        self.send_response(302)
        self.send_header("Location", "/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()
    do_GET = do_POST = _go


def test_11_the_key_never_follows_a_redirect(monkeypatch):
    from inferroute_cli import config
    monkeypatch.setattr(config, "load", lambda: type("C", (), {"api_key": "inf_test_key_123456"})())
    srv = HTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("IR_TEST_SITE_BASE", f"http://127.0.0.1:{srv.server_port}")
        _Redirect.hits.clear()
        with pytest.raises(B.BillingError):
            B._get("/api/anteriora/balance")
        with pytest.raises(B.BillingError):
            B._post("/api/anteriora/permit", {"unit": "search"})
        assert [p for p, _ in _Redirect.hits] == ["/api/anteriora/balance", "/api/anteriora/permit"]
    finally:
        srv.shutdown()


@pytest.mark.parametrize("base,used", [
    ("https://inferroute.ai", "https://inferroute.ai"),
    ("https://staging.inferroute.ai/", "https://staging.inferroute.ai"),
    ("http://inferroute.ai", None),
    ("https://inferroute.ai.evil.example", None),
    ("https://evil.example", None),
    ("https://inferroute.ai:8443", None),
    ("https://user@inferroute.ai", None),
])
def test_11_only_an_https_inferroute_site_base_is_honoured(monkeypatch, base, used):
    monkeypatch.delenv("IR_TESTING", raising=False)
    monkeypatch.setenv("IR_SITE_BASE", base)
    assert B._site() == (used or "https://inferroute.ai")
