"""The client half of the relay-entitlement contract (Nov 2026).

The permit header goes only to the relay's gated routes; a billing refusal on /confidential/* is read from its header
(then its body), never blames an enclave, never walks to another fleet or model, is waited out once when the relay
says so, and is shown to the person in the relay's own words only when those words are short plain text whose links
are all on inferroute.ai."""
import asyncio
import json

import httpx
import pytest

from inferroute_local.confidential import billing_refusal as BR
from inferroute_local.confidential.transport import BillingRefusal, make_transport

FINAL = sorted(BR.FINAL_CODES)


def _refusal(status, code, message=None, *, header=True, body=True, retry_after=None, extra_headers=None):
    h = {"content-type": "application/json"}
    if header:
        h[BR.HEADER] = code
    if retry_after is not None:
        h["retry-after"] = str(retry_after)
    h.update(extra_headers or {})
    err = {"type": "billing_error"}
    if body:
        err["code"] = code
    if message is not None:
        err["message"] = message
    return httpx.Response(status, headers=h, json={"error": err})


@pytest.fixture
def waits(monkeypatch):
    seen = []

    async def fake_sleep(s):
        seen.append(s)
    monkeypatch.setattr(BR, "sleep", fake_sleep)
    return seen


def _relay(handler, permit="p-1"):
    """A relay transport over a mock handler; returns (run, seen) where run(coro_fn) executes against it."""
    seen = []

    def h(request):
        seen.append(request)
        return handler(request)

    def run(fn):
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as http:
                t = make_transport(http, api_url="https://relay.test", api_key="k", session_id="s1",
                                   prefer_direct=False, permit=permit)
                return await fn(t)
        return asyncio.run(go())
    return run, seen


# ───────────────────────── the permit header: gated routes only ─────────────────────────

def _ok(request):
    p = request.url.path
    if p.endswith("/lanes"):
        return httpx.Response(200, json={"lanes": []})
    if p.endswith("/builds"):
        return httpx.Response(200, json={"builds": []})
    if p.endswith("/fleet-health"):
        return httpx.Response(200, json={"fleets": {}})
    return httpx.Response(200, json={"instances": []})


async def _every_route(t):
    await t.candidates("f", "n")
    await t.nonces("f")
    await t.invoke(fleet_id="f", instance_id="i", nonce="n", stream=False, blob=b"x")
    await t.builds()
    await t.fleet_health()
    await t.models()
    await t.report_usage({"session_id": "s1", "usage": {}, "permit": "should-not-travel"})


def test_the_permit_goes_to_the_gated_routes_and_nowhere_else():
    run, seen = _relay(_ok, permit="p-1")
    run(_every_route)
    by_path = {r.url.path.rsplit("/", 1)[-1]: r for r in seen}
    for gated in ("candidates", "nonces", "invoke"):
        assert by_path[gated].headers.get("x-inferroute-permit") == "p-1", gated
    for ungated in ("builds", "fleet-health", "lanes", "usage"):
        assert "x-inferroute-permit" not in by_path[ungated].headers, ungated
    assert "permit" not in json.loads(by_path["usage"].content)


def test_no_permit_no_header_anywhere():
    """An InferRoute session with no permit sends exactly what it sent before the contract."""
    run, seen = _relay(_ok, permit="")
    run(_every_route)
    assert len(seen) == 7
    assert all("x-inferroute-permit" not in r.headers for r in seen)
    assert all(r.headers.get("x-inferroute-session") == "s1" for r in seen)


def test_the_v1_instances_route_counts_as_gated():
    from inferroute_local.confidential.transport import GATED_ROUTES
    assert {"candidates", "nonces", "invoke", "instances"} == set(GATED_ROUTES)


# ───────────────────────── refusals on candidates / nonces ─────────────────────────

@pytest.mark.parametrize("code", FINAL)
@pytest.mark.parametrize("route", ["candidates", "nonces"])
def test_a_402_billing_refusal_is_raised_typed_once_with_the_relays_words(code, route, waits):
    msg = f"Refused: {code}. See https://inferroute.ai/anteriora for units."
    run, seen = _relay(lambda r: _refusal(402, code, msg))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.candidates("f", "n") if route == "candidates" else t.nonces("f"))
    e = ei.value
    assert (e.status, e.code, e.route) == (402, code, route)
    assert e.final and not e.retryable
    assert e.sentence == msg
    assert len(seen) == 1 and waits == []          # final: one request, no wait, no retry


def test_rate_limited_is_waited_out_once_then_asked_again(waits):
    answers = [_refusal(429, "rate_limited", "Slow down.", retry_after=7), httpx.Response(200, json={"instances": []})]
    run, seen = _relay(lambda r: answers.pop(0))
    assert run(lambda t: t.nonces("f")) == {"instances": []}
    assert len(seen) == 2 and waits == [7.0]


def test_a_second_429_is_surfaced_not_looped(waits):
    run, seen = _relay(lambda r: _refusal(429, "permit_busy", retry_after=3))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.candidates("f", "n"))
    assert ei.value.code == "permit_busy" and len(seen) == 2 and waits == [3.0]


def test_a_long_retry_after_is_capped(waits):
    run, _ = _relay(lambda r: _refusal(503, "billing_unavailable", retry_after=3600))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.nonces("f"))
    assert waits == [BR.RETRY_AFTER_CAP_S]
    assert ei.value.sentence == BR.FIXED["billing_unavailable"]


def test_billing_unavailable_with_no_message_says_try_again_shortly(waits):
    run, _ = _relay(lambda r: _refusal(503, "billing_unavailable", retry_after=1))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.nonces("f"))
    assert ei.value.sentence == BR.FIXED["billing_unavailable"] and "shortly" in ei.value.sentence


def test_the_code_is_read_from_the_header_alone():
    run, _ = _relay(lambda r: httpx.Response(402, headers={BR.HEADER: "permit_expired"}, content=b"refused"))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.candidates("f", "n"))
    assert ei.value.code == "permit_expired" and ei.value.sentence == BR.FIXED["permit_expired"]


def test_the_code_is_read_from_the_body_alone():
    run, _ = _relay(lambda r: _refusal(402, "out_of_credits", "No credit left.", header=False))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.nonces("f"))
    assert ei.value.code == "out_of_credits" and ei.value.sentence == "No credit left."
    assert ei.value.code_from_header is False


def test_the_header_wins_over_the_body():
    run, _ = _relay(lambda r: httpx.Response(402, headers={BR.HEADER: "permit_lane"},
                                             json={"error": {"code": "out_of_credits", "message": "m"}}))
    with pytest.raises(BillingRefusal) as ei:
        run(lambda t: t.nonces("f"))
    assert ei.value.code == "permit_lane"


def test_a_402_with_no_code_is_still_an_ordinary_http_error():
    """A PR #99-shaped 402 (a bare string body, no code) is not a billing refusal: it behaves as it did."""
    run, seen = _relay(lambda r: httpx.Response(402, json={"detail": "Wallet balance empty"}))
    with pytest.raises(httpx.HTTPStatusError):
        run(lambda t: t.candidates("f", "n"))
    assert len(seen) == 1


def test_a_code_at_the_wrong_status_or_unlisted_is_not_a_billing_refusal():
    for status, code in ((503, "out_of_credits"), (402, "rate_limited"), (402, "permit_new_thing")):
        run, _ = _relay(lambda r, s=status, c=code: _refusal(s, c, "x"))
        with pytest.raises(httpx.HTTPStatusError):
            run(lambda t: t.nonces("f"))


# ───────────────────────── what a person is shown ─────────────────────────

@pytest.mark.parametrize("message", [
    "Buy units at https://evil.example/pay",
    "Buy units at evil.example/pay",
    "Write to billing@evil.example",
    "Pay at https://inferroute.ai.evil.example/x",
    "Pay at https://inferroute.ai@evil.example/x",
    "Pay at https://notinferroute.ai/x",
    "x" * 301,
    "<b>refused</b>",
    "[red]refused[/red]",
    "line one\nline two",
    "",
])
def test_an_inadmissible_message_is_replaced_by_our_sentence(message):
    e = BR.BillingRefusal(402, "permit_used_up", message, route="candidates")
    assert e.sentence == BR.FIXED["permit_used_up"]


@pytest.mark.parametrize("message", [
    "No units left. Buy more at https://inferroute.ai/anteriora.",
    "No units left. Buy more at https://app.inferroute.ai/anteriora?x=1",
    "Write to support@inferroute.ai.",
    "Buy more at inferroute.ai/anteriora",
    "Your unit for this matter is spent, 0 left.",
])
def test_an_admissible_message_is_shown_verbatim(message):
    assert BR.BillingRefusal(402, "permit_used_up", message, route="nonces").sentence == message


def test_an_unlisted_code_never_shows_server_text():
    assert BR.admissible_message("permit_new_thing", "Hello from the relay") is False
    assert BR.parse(402, {BR.HEADER: "permit_new_thing"}, b'{"error":{"message":"hi"}}') is None


def test_on_invoke_a_body_only_code_is_classified_but_its_words_are_not_shown():
    """The header is the relay's own mark. A body alone on invoke may have come from beyond the relay."""
    r = BR.parse(402, {}, json.dumps({"error": {"code": "out_of_credits", "message": "Balance is $0.0"}}).encode(),
                 route="invoke")
    assert r is not None and r.code == "out_of_credits" and r.sentence == BR.FIXED["out_of_credits"]
    r = BR.parse(402, {BR.HEADER: "out_of_credits"}, json.dumps({"error": {"message": "No credit."}}).encode(),
                 route="invoke")
    assert r.sentence == "No credit."


def test_every_code_has_a_fixed_sentence_and_the_frozen_rule_covers_it():
    assert set(BR.FIXED) == BR.CODES
    for c in BR.FINAL_CODES | BR.UNAVAILABLE_CODES | {"permit_busy"}:
        assert BR.is_billing_code(c)
    assert not BR.is_billing_code("IR-C1001")


def test_retry_after_reads_seconds_and_dates():
    assert BR.parse_retry_after("12") == 12.0
    assert BR.parse_retry_after(None) is None and BR.parse_retry_after("soon") is None
    import email.utils
    import time
    d = BR.parse_retry_after(email.utils.formatdate(time.time() + 20, usegmt=True))
    assert 15 <= d <= 21
