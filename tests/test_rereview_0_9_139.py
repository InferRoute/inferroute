"""The re-review of relay/permit-0.9.139's fixes: five items, A to E. Each test failed on fd6ea7a."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from inferroute_cli import anteriora_billing as B
from inferroute_local.confidential import billing_refusal as BR

P1 = "00000000-0000-0000-0000-0000000000b1"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setattr(B, "_answer", None)
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))


@pytest.fixture
def site(monkeypatch):
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    events, state = [], {"n": 0, "reused": False}

    def post(path, body):
        if path == "/api/anteriora/settle":
            events.append(("settle", body["outcome"]))
            return {"state": "delivered"}
        if path == "/api/anteriora/permit":
            events.append(("permit",))
            if state["reused"]:
                return {"permit": P1, "reused": True}
            state["n"] += 1
            return {"permit": f"00000000-0000-0000-0000-{state['n']:012d}"}
        raise AssertionError(path)

    monkeypatch.setattr(B, "_post", post)
    monkeypatch.setattr(B, "print", lambda *a, **k: events.append(("said", " ".join(map(str, a)).strip())),
                        raising=False)
    return events, state


def held(state="delivered", age=dt.timedelta(0), **rec):
    at = (B._now() - age).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {**rec, "permit": {"id": P1, "unit": "search", "state": state, "at": at, "first_session": "s0",
                              "account": B._account_tag()}}


def refused(code):
    return BR.parse(402, {BR.HEADER: code}, json.dumps({"error": {"code": code, "message": "m"}}))


# ───────────────────────── A ─────────────────────────

@pytest.mark.parametrize("code", ["permit_lane", "permit_wrong_product"])
def test_A_a_lane_or_product_refusal_keeps_the_permit(site, code):
    events, _ = site
    BR.note_permit_refusal(P1, refused(code))
    rec = held()
    B.end_session(rec, "s1", True)
    assert rec["permit"]["id"] == P1 and "renewal" not in rec and events == []
    assert code not in B.DEAD_CODES and code not in BR.PERMIT_REFUSAL_CODES
    assert B.DEAD_CODES == {"permit_invalid", "permit_expired"}


def test_A_one_more_unit_is_said_only_when_the_site_did_not_hand_the_same_permit_back(site):
    events, state = site
    rec = {"renewal": "used_up"}
    state["reused"] = True
    B.before_session(rec, "s2")
    assert events == [("permit",)] and "renewal" not in rec
    events.clear()
    state["reused"] = False
    rec = {"renewal": "used_up"}
    B.before_session(rec, "s3")
    assert events == [("permit",), ("said", B.ONE_MORE_UNIT_WORDS.format(whose="This matter's"))]


# ───────────────────────── B ─────────────────────────

@pytest.mark.parametrize("kind,cluster", [("reading", False), ("reading", True)])
def test_B_a_readings_permit_lives_6_hours_and_is_renewed_before_the_session(site, kind, cluster):
    events, _ = site
    rec = held(age=dt.timedelta(hours=7), kind=kind, intake="x", **({"cluster": True} if cluster else {}))
    assert B.current_permit(rec) is None
    p = B.before_session(rec, "s2")
    assert p["id"] != P1
    assert events == [("permit",), ("said", "This reading's current unit has expired; continuing uses one more unit.")]


def test_B_a_readings_permit_under_6_hours_is_kept_and_a_matters_lives_30_days(site):
    events, _ = site
    assert B.current_permit(held(age=dt.timedelta(hours=5), kind="reading")) is not None
    assert B.current_permit(held(age=dt.timedelta(days=29))) is not None
    rec = held(age=dt.timedelta(days=31))
    assert B.current_permit(rec) is None
    B.before_session(rec, "s2")
    assert events[-1] == ("said", "This matter's current unit has expired; continuing uses one more unit.")


# ───────────────────────── C ─────────────────────────

def test_C_an_answer_that_arrives_after_the_2_s_is_still_kept(monkeypatch):
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    B._cache_path().parent.mkdir(parents=True, exist_ok=True)
    B._cache_path().write_text(json.dumps({"at": time.time() - 3600, "on": False}))
    done = threading.Event()

    def slow(path):
        time.sleep(2.5)
        done.set()
        return {"billing": "units"}
    monkeypatch.setattr(B, "_get", slow)
    assert B.enabled() is False                                       # the last known answer, in time
    assert done.wait(5)
    for _ in range(50):
        if json.loads(B._cache_path().read_text())["on"] is True:
            break
        time.sleep(0.05)
    assert json.loads(B._cache_path().read_text())["on"] is True      # the late answer, kept for next time
    monkeypatch.setattr(B, "_get", lambda path: (_ for _ in ()).throw(AssertionError("asked again")))
    B._answer = None
    assert B.enabled() is True


def test_C_the_very_first_start_waits_up_to_5_s(monkeypatch):
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    assert not B._cache_path().exists()

    def slowish(path):
        time.sleep(3)
        return {"billing": "units"}
    monkeypatch.setattr(B, "_get", slowish)
    t0 = time.monotonic()
    assert B.enabled() is True and time.monotonic() - t0 < 5.5


# ───────────────────────── D ─────────────────────────

@pytest.mark.parametrize("message", ["Call +1 900 555 0100 to top up", "Call 900-555-0100", "Call (900) 555.0100",
                                     "Call 900 5550100"])
def test_D_a_spaced_or_dashed_phone_number_is_not_shown(message):
    assert BR.plain_and_ours(message) is False


def test_D_ordinary_numbers_still_pass():
    assert BR.plain_and_ours("Your unit is spent, 0 left. Try again in 30 minutes.") is True


# ───────────────────────── E ─────────────────────────

@pytest.mark.parametrize("base,want", [
    ("https://inferroute.ai", "https://inferroute.ai"),
    ("https://staging.inferroute.ai/", "https://staging.inferroute.ai"),
    ("http://127.0.0.1:9", "https://inferroute.ai"),
    ("https://evil.example", "https://inferroute.ai"),
    ("https://inferroute.ai.evil.example", "https://inferroute.ai"),
])
def test_E_one_rule_for_the_site_in_billing_and_search_setup(monkeypatch, base, want):
    from inferroute_cli import site_base
    monkeypatch.delenv("IR_TESTING", raising=False)
    monkeypatch.setenv("IR_SITE_BASE", base)
    assert site_base.site_base() == want
    assert B._site() == want
    code = "import inferroute_cli.probant_search_setup as s; print(s.SITE)"
    env = {k: v for k, v in os.environ.items() if k not in ("IR_TESTING", "IR_TEST_SITE_BASE")}
    out = subprocess.run([sys.executable, "-c", code], env={**env, "IR_SITE_BASE": base},
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == want, out.stderr[-500:]


def test_E_the_test_override_needs_IR_TESTING_and_reaches_a_subprocess(monkeypatch):
    from inferroute_cli import site_base
    assert site_base.site_base() == "http://127.0.0.1:9"              # conftest's fence, by the environment
    code = ("import inferroute_cli.probant_search_setup as s, inferroute_cli.anteriora_billing as b; "
            "print(s.SITE, b._site())")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.split() == ["http://127.0.0.1:9", "http://127.0.0.1:9"], out.stderr[-500:]
    env = {k: v for k, v in os.environ.items() if k != "IR_TESTING"}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.split() == ["https://inferroute.ai", "https://inferroute.ai"]
