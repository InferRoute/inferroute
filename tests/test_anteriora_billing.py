"""Anteriora units on the client (19 Oct). What a founder relies on: billing off changes nothing; one unit
covers a matter, not each session; a session that produced nothing gives the unit back; an empty account is
told so before anything opens; and nothing about the matter is sent to the account service."""
import datetime as dt
import json

import pytest

from inferroute_cli import anteriora_billing as B
from inferroute_cli import probant as S


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    return tmp_path


@pytest.fixture
def service(monkeypatch):
    calls = []
    state = {"units": 1, "n": 0}

    def post(path, body):
        calls.append((path, body))
        if path == "/api/anteriora/permit":
            if state["units"] < 1:
                raise B.BillingError("No searches left on this account. Buy more at inferroute.ai/anteriora.")
            state["units"] -= 1
            state["n"] += 1
            return {"permit": f"00000000-0000-0000-0000-{state['n']:012d}", "balanceAfter": state["units"]}
        if path == "/api/anteriora/settle":
            if body["outcome"] == "failed":
                state["units"] += 1
                return {"state": "refunded"}
            return {"state": "delivered"}
        raise AssertionError(path)

    monkeypatch.setattr(B, "_post", post)
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    return calls, state


def test_billing_off_asks_nothing_and_changes_nothing(monkeypatch):
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    monkeypatch.setattr(B, "_post", lambda *a: (_ for _ in ()).throw(AssertionError("no call when off")))
    rec = {}
    assert B.before_session(rec, "s1") is None and rec == {}
    assert B.after_session(rec, "s1", True) is None


def test_one_unit_covers_the_matter_not_each_session(service):
    calls, state = service
    rec = {"kind": "name"}
    p = B.before_session(rec, "s1")
    assert p["unit"] == "name_check" and state["units"] == 0
    assert B.after_session(rec, "s1", True) == "delivered"
    assert B.before_session(rec, "s2")["id"] == p["id"]          # reused: no second unit taken
    assert [c[0] for c in calls].count("/api/anteriora/permit") == 1


def test_a_session_that_produced_nothing_gives_the_unit_back(service):
    _, state = service
    rec = {}
    B.before_session(rec, "s1")
    assert B.after_session(rec, "s1", False) == "refunded"
    assert "permit" not in rec and state["units"] == 1


def test_an_empty_account_is_told_before_anything_opens(service):
    _, state = service
    state["units"] = 0
    with pytest.raises(B.BillingError, match="No searches left"):
        B.before_session({}, "s1")


def test_a_permit_older_than_its_window_is_not_reused(service):
    calls, _ = service
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=B.PERMIT_DAYS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = {"permit": {"id": "x", "unit": "search", "state": "delivered", "at": old}}
    service[1]["units"] = 1
    assert B.before_session(rec, "s9")["id"] != "x"


def test_the_device_id_is_random_stable_and_private(home):
    import stat
    first = B.device_id()
    assert len(first) == 32 and B.device_id() == first
    assert stat.S_IMODE((home / "ir" / "device-id").stat().st_mode) == 0o600


def test_nothing_about_the_matter_is_sent(service, home):
    calls, _ = service
    rec = {"kind": "name", "client": "Acme", "matter": "secret-brand", "workspace": "/x"}
    B.before_session(rec, "s1")
    B.after_session(rec, "s1", True)
    for _, body in calls:
        assert set(body) <= {"unit", "sessionId", "permit", "outcome", "deviceId"}
        assert "secret" not in json.dumps(body) and "Acme" not in json.dumps(body)


def test_opening_a_matter_with_no_unit_left_refuses_before_the_session(home, service, monkeypatch, capsys):
    _, state = service
    state["units"] = 0
    S.main(["new", "Acme", "gadget"])
    monkeypatch.setattr("inferroute_cli.confidential.launch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")))
    assert S.main(["open", "Acme/gadget"]) != 0
    assert "No searches left" in capsys.readouterr().err


def test_opening_a_matter_records_its_permit_and_settles_it(home, service, monkeypatch):
    S.main(["new", "Acme", "gadget"])
    seen = {}

    def fake_launch(args, agent="pi", probant=None):
        seen.update(probant)
        rdir = S.records_dir("Acme", "gadget")
        rdir.mkdir(parents=True, exist_ok=True)
        (rdir / f"{probant['session_id']}.searches.json").write_text("[]")
        return 0

    monkeypatch.setattr("inferroute_cli.confidential.launch", fake_launch)
    assert S.main(["open", "Acme/gadget"]) == 0
    rec = S.load_record("Acme", "gadget")
    assert rec["permit"]["state"] == "delivered" and rec["permit"]["first_session"] == seen["session_id"]


def _site_answers(monkeypatch, home, status, body):
    """The site's real refusal, as an HTTP error from urlopen: nothing leaves this computer."""
    import io
    import urllib.error
    from inferroute_cli import config
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    monkeypatch.setattr(config, "load", lambda: type("C", (), {"api_key": "inf_test_key_123456"})())

    def refuse(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, status, "x", {}, io.BytesIO(json.dumps(body).encode()))

    monkeypatch.setattr("urllib.request.urlopen", refuse)


@pytest.mark.parametrize("status,body,words", [
    (402, {"error": "Nothing left on this account for this. Buy more at inferroute.ai/anteriora.",
           "needsPurchase": True}, "no checks or searches left"),
    (403, {"error": "Your plan's devices are all in use. Add a seat, or remove a device from your account page.",
           "deviceLimit": True}, "maximum number of computers"),
])
def test_an_empty_account_or_a_full_device_list_is_said_in_the_apps_words(home, monkeypatch, status, body, words):
    """22 Oct, pilot audit: a 402 or 403 from /api/anteriora/permit reached the founder as "Something went
    wrong… Try once more", with the buy link under Technical details. The words come from the app now, the
    home page shows them as the message, and the 403 no longer points to an account page that does not exist."""
    from inferroute_cli import probant_home as H
    _site_answers(monkeypatch, home, status, body)
    with pytest.raises(B.BillingError) as got:
        B.before_session({}, "s1")
    said = str(got.value)
    assert words in said.lower() and "account page" not in said
    # As the home page sees it: the launcher's stderr, merged into the tail it reads.
    msg = H.failure_message(["Opening Acme/gadget", f"  {said}"])
    assert msg.startswith(said) and msg != H.GENERIC_FAILURE
    if status == 402:
        assert "inferroute.ai/anteriora" in msg
    else:
        assert "support@inferroute.ai" in msg and "account page" not in msg


def test_any_other_refusal_is_not_worded_as_an_empty_account(home, monkeypatch):
    """22 Oct: a 403 that is not the device limit (a proxy, a revoked key) used to read "Nothing left on this
    account", sending a founder to buy what they already had."""
    _site_answers(monkeypatch, home, 403, {})
    with pytest.raises(B.BillingError) as got:
        B.before_session({}, "s1")
    assert "left" not in str(got.value) and "403" in str(got.value)
