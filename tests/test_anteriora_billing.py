"""Anteriora units on the client (19 Oct). What a founder relies on: billing off changes nothing; one unit
covers a matter, not each session; a session that produced nothing gives the unit back; an empty account is
told so before anything opens; and nothing about the matter is sent to the account service."""
import datetime as dt
import json

import pytest

from inferroute_cli import anteriora_billing as B
from inferroute_cli import probant as S


@pytest.fixture(autouse=True)
def _fresh_answer(monkeypatch):
    monkeypatch.setattr(B, "_answer", None)


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
        assert set(body) <= {"unit", "sessionId", "permit", "outcome", "deviceId", "kind", "intake_id"}
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


# ───────────────────── 22 Oct: units only, the switch on the server ─────────────────────

def _answers_balance(monkeypatch, body=None, fail=False):
    asked = []

    def get(path):
        asked.append(path)
        if fail:
            raise B.BillingError("unreachable")
        return body
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    monkeypatch.setattr(B, "_get", get)
    return asked


@pytest.mark.parametrize("body,fail,on", [
    ({"billing": "units", "balance": {}}, False, True),
    ({"billing": "off"}, False, False),
    ({}, False, False),                       # an older service that does not say
    (None, True, False),                      # no answer at all
])
def test_billing_is_on_exactly_when_the_service_says_units(monkeypatch, body, fail, on):
    asked = _answers_balance(monkeypatch, body, fail)
    assert B.enabled() is on
    assert asked == ["/api/anteriora/balance"]


def test_the_answer_is_asked_once_and_kept_briefly(monkeypatch):
    asked = _answers_balance(monkeypatch, {"billing": "units"})
    assert B.enabled() and B.enabled() and B.enabled()
    assert len(asked) == 1
    B._answer = (B._answer[0] - B.BALANCE_TTL - 1, True)
    B.enabled()
    assert len(asked) == 2


def test_the_environment_variable_only_overrides(monkeypatch):
    asked = _answers_balance(monkeypatch, {"billing": "units"})
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "0")
    assert B.enabled() is False
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    assert B.enabled() is True
    assert asked == []


def test_no_key_means_off_without_asking(home, monkeypatch):
    from inferroute_cli import config
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    monkeypatch.setattr(config, "load", lambda: type("C", (), {"api_key": ""})())
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("asked")))
    assert B.enabled() is False


def test_an_unreachable_service_means_off(home, monkeypatch):
    """The real path, through urlopen: the conftest points the site at a port nothing listens on."""
    from inferroute_cli import config
    monkeypatch.delenv("IR_ANTERIORA_BILLING", raising=False)
    monkeypatch.setattr(config, "load", lambda: type("C", (), {"api_key": "inf_test_key_123456"})())
    assert B.enabled() is False


def test_a_settle_refused_for_good_drops_the_permit(home, service):
    calls, state = service
    state["units"] = 2
    rec = {}
    first = B.before_session(rec, "s1")

    def gone(path, body):
        raise B.BillingError("not found", 404)
    B._post, keep = gone, B._post
    try:
        assert B.after_session(rec, "s1", True) == "gone"
    finally:
        B._post = keep
    assert "permit" not in rec
    assert B.before_session(rec, "s2")["id"] != first["id"]     # the next session asks anew


def test_a_settle_that_could_not_reach_the_service_keeps_the_permit(home, service):
    rec = {}
    B.before_session(rec, "s1")
    keep = B._post
    B._post = lambda *a: (_ for _ in ()).throw(B.BillingError("could not reach", 0))
    try:
        assert B.after_session(rec, "s1", True) is None
    finally:
        B._post = keep
    assert rec["permit"]["state"] == "issued"


def test_a_permit_the_service_already_refunded_is_dropped(home, service, monkeypatch):
    rec = {}
    B.before_session(rec, "s1")
    monkeypatch.setattr(B, "_post", lambda path, body: {"state": "refunded", "already": True})
    assert B.after_session(rec, "s1", True) == "refunded" and "permit" not in rec


def test_an_issued_permit_past_the_refund_window_is_not_reused(home, service):
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=B.ISSUED_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = {"permit": {"id": "x", "unit": "search", "state": "issued", "at": old}}
    assert B.before_session(rec, "s9")["id"] != "x"


def test_a_permit_taken_under_another_key_is_not_reused(home, service, monkeypatch):
    service[1]["units"] = 2
    rec = {}
    monkeypatch.setattr(B, "_account_tag", lambda: "aaaa")
    first = B.before_session(rec, "s1")
    B.after_session(rec, "s1", True)
    monkeypatch.setattr(B, "_account_tag", lambda: "bbbb")
    assert B.before_session(rec, "s2")["id"] != first["id"]


def test_settle_is_not_skipped_when_the_cached_answer_expired(home, service, monkeypatch):
    """A session can outlast the cached answer; an issued permit is settled regardless."""
    rec = {}
    B.before_session(rec, "s1")
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "0")
    assert B.after_session(rec, "s1", True) == "delivered"


# ───────────────────── readings ─────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    """As above, plus what cmd_intake changes for its session (cwd, the reading's variables), undone after."""
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    for name in ("IR_INTAKE_DIR", "IR_ATTESTED_CONFINE"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _stage(home, text="A sealed reading. " * 20):
    from inferroute_cli import probant_intake as I
    return I.stage(text, "notes.md")


def test_a_reading_asks_for_a_search_unit_keyed_by_its_intake(home, service, monkeypatch):
    calls, state = service
    meta = _stage(home)
    seen = {}

    def fake_launch(args, agent="pi", probant=None):
        seen.update(probant)
        return 0
    monkeypatch.setattr("inferroute_cli.confidential.launch", fake_launch)
    monkeypatch.setattr(B, "reading_delivered", lambda ident: True)
    S.cmd_intake(str(home / "Probant" / ".intake" / meta["id"]), proposals_only=True)
    permit_calls = [b for p, b in calls if p == "/api/anteriora/permit"]
    assert permit_calls == [{"unit": "search", "sessionId": seen["session_id"], "deviceId": B.device_id(),
                             "kind": "reading", "intake_id": meta["id"]}]
    assert seen["permit"] == B.load_reading(meta["id"])["permit"]["id"]
    assert B.load_reading(meta["id"])["permit"]["state"] == "delivered"
    assert state["units"] == 0


def test_a_reading_that_produced_nothing_gives_its_unit_back(home, service, monkeypatch):
    _, state = service
    meta = _stage(home)
    monkeypatch.setattr("inferroute_cli.confidential.launch", lambda *a, **k: 0)
    S.cmd_intake(str(home / "Probant" / ".intake" / meta["id"]), proposals_only=True)
    assert state["units"] == 1 and "permit" not in B.load_reading(meta["id"])


def test_the_same_reading_reuses_its_delivered_permit(home, service, monkeypatch):
    calls, _ = service
    meta = _stage(home)
    monkeypatch.setattr("inferroute_cli.confidential.launch", lambda *a, **k: 0)
    monkeypatch.setattr(B, "reading_delivered", lambda ident: True)
    d = str(home / "Probant" / ".intake" / meta["id"])
    S.cmd_intake(d, proposals_only=True)
    S.cmd_intake(d, proposals_only=True)
    assert [c[0] for c in calls].count("/api/anteriora/permit") == 1


def test_a_reading_with_billing_off_asks_nothing(home, monkeypatch):
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "0")
    monkeypatch.setattr(B, "_post", lambda *a: (_ for _ in ()).throw(AssertionError("no call when off")))
    meta = _stage(home)
    seen = {}
    monkeypatch.setattr("inferroute_cli.confidential.launch", lambda a, agent="pi", probant=None: seen.update(probant) or 0)
    S.cmd_intake(str(home / "Probant" / ".intake" / meta["id"]), proposals_only=True)
    assert "permit" not in seen


def test_a_reading_on_an_empty_account_is_said_in_plain_words(home, monkeypatch, capsys):
    """(k) The home page starts a reading as `probant intake …` and shows failure_message of its output."""
    from inferroute_cli import probant_home as H
    meta = _stage(home)
    _site_answers(monkeypatch, home, 402, {"needsPurchase": True})
    monkeypatch.setattr("inferroute_cli.confidential.launch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")))
    assert S.main(["intake", str(home / "Probant" / ".intake" / meta["id"])]) != 0
    err = capsys.readouterr().err
    msg = H.failure_message([line.strip() for line in err.splitlines() if line.strip()])
    assert msg.startswith(B.NO_UNITS_WORDS) and "inferroute.ai/anteriora" in msg


def test_a_matter_session_carries_its_permit_to_the_launch(home, service, monkeypatch):
    S.main(["new", "Acme", "gadget"])
    seen = {}
    monkeypatch.setattr("inferroute_cli.confidential.launch",
                        lambda a, agent="pi", probant=None: seen.update(probant) or 0)
    assert S.main(["open", "Acme/gadget"]) == 0
    calls, _ = service
    assert seen["permit"] == "00000000-0000-0000-0000-000000000001"      # the id the service issued
    assert ("/api/anteriora/settle", {"permit": seen["permit"], "outcome": "failed",
                                      "sessionId": seen["session_id"]}) in calls   # nothing searched: given back


# ───────────────────── the permit goes with the sealed session ─────────────────────

def test_the_relay_sends_the_permit_header_on_invoke_only_when_there_is_one_and_never_with_usage():
    import asyncio
    import httpx
    from inferroute_local.confidential.transport import make_transport
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={})

    async def run(permit):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            t = make_transport(http, api_url="https://relay.test", api_key="k", session_id="s1",
                               prefer_direct=False, permit=permit)
            await t.report_usage({"session_id": "s1", "usage": {}})
            await t.invoke(fleet_id="f", instance_id="i", nonce="n", stream=False, blob=b"x")

    asyncio.run(run("p-1"))
    usage, invoke = seen
    # Relay-entitlement contract: the permit is logged on invoke rows only, so usage carries it nowhere.
    assert "x-inferroute-permit" not in usage.headers and "permit" not in json.loads(usage.content)
    assert invoke.headers["x-inferroute-permit"] == "p-1"
    seen.clear()
    asyncio.run(run(""))
    usage, invoke = seen
    assert "x-inferroute-permit" not in usage.headers and "permit" not in json.loads(usage.content)
    assert "x-inferroute-permit" not in invoke.headers


# ───────────────────── cluster sessions (anteriora cluster) ─────────────────────
# Henry's decision: a cluster session uses the reading's permit while that permit is live, otherwise one search unit.

def _cluster(home):
    from inferroute_cli import probant_cluster as P
    src = home / "folder"
    src.mkdir()
    (src / "a.md").write_text("A jacket with coolant channels moulded between the cells. " * 5)
    meta = P.stage(sorted(src.rglob("*.md")), "folder")
    return meta["id"], P.path_of(meta["id"])


def _round(d, monkeypatch, *, finds=0, seen=None):
    """One cluster round through the real _cluster_round, with the launch faked to append `finds` findings."""
    from inferroute_cli import probant_cluster as P

    def fake_launch(args, agent="pi", probant=None):
        if seen is not None:
            seen.append(dict(probant))
        doc = P.meta_of(d.name)["documents"][0]["name"]
        n = len(P.candidates(d.name))
        with (d / P.CANDIDATES).open("a") as fh:
            for k in range(finds):
                fh.write(json.dumps({"source": doc, "quote": "coolant channels moulded between the cells",
                                     "title": f"finding {n + k}", "summary": "a jacket"}) + "\n")
        return 0
    monkeypatch.setattr("inferroute_cli.confidential.launch", fake_launch)
    return S._cluster_round(d, "read", out={}, cwd=d, label="job")


def test_a_cluster_session_carries_a_search_unit_when_the_run_holds_none(home, service, monkeypatch):
    calls, state = service
    ident, d = _cluster(home)
    seen = []
    _round(d, monkeypatch, finds=1, seen=seen)
    permits = [b for p, b in calls if p == "/api/anteriora/permit"]
    assert permits == [{"unit": "search", "sessionId": seen[0]["session_id"], "deviceId": B.device_id(),
                        "kind": "reading", "intake_id": ident}]
    rec = B.load_reading(ident, cluster=True)
    assert seen[0]["permit"] == rec["permit"]["id"] and rec["permit"]["state"] == "delivered"
    assert state["units"] == 0
    # host-side, never in the cluster folder the sessions work in
    assert not any("permit" in p.name for p in d.rglob("*"))


def test_later_cluster_sessions_reuse_the_runs_live_permit(home, service, monkeypatch):
    calls, _ = service
    ident, d = _cluster(home)
    seen = []
    for _ in range(3):
        _round(d, monkeypatch, finds=1, seen=seen)
    assert [c[0] for c in calls].count("/api/anteriora/permit") == 1
    assert len({s["permit"] for s in seen}) == 1 and len({s["session_id"] for s in seen}) == 3


def test_a_cluster_round_that_found_nothing_gives_the_unit_back_and_the_next_takes_one(home, service, monkeypatch):
    calls, state = service
    ident, d = _cluster(home)
    seen = []
    _round(d, monkeypatch, finds=0, seen=seen)
    assert state["units"] == 1 and "permit" not in B.load_reading(ident, cluster=True)
    _round(d, monkeypatch, finds=1, seen=seen)
    assert [c[0] for c in calls].count("/api/anteriora/permit") == 2 and seen[0]["permit"] != seen[1]["permit"]


def test_a_cluster_run_past_its_permits_window_takes_a_new_unit(home, service, monkeypatch):
    calls, _ = service
    ident, d = _cluster(home)
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=B.ISSUED_HOURS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    B.save_reading({"kind": "reading", "intake": ident, "cluster": True,
                    "permit": {"id": "stale", "unit": "search", "state": "issued", "at": old}})
    seen = []
    _round(d, monkeypatch, finds=1, seen=seen)
    assert seen[0]["permit"] != "stale" and [c[0] for c in calls].count("/api/anteriora/permit") == 1


def test_cluster_workers_share_one_unit_taken_before_they_start(home, service, monkeypatch):
    import subprocess
    calls, state = service
    ident, d = _cluster(home)
    started = []

    class FakeProc:
        def __init__(self, argv, **kw):
            started.append(B.load_reading(ident, cluster=True).get("permit"))

        def wait(self):
            return 0
    monkeypatch.setattr(subprocess, "Popen", FakeProc)
    monkeypatch.setattr(S, "cmd_cluster", lambda *a, **k: 0)
    assert S._cluster_workers(ident, home / "folder", 3, "", "", 0, total_jobs=5) == 0
    assert len(started) == 3 and all(p and p["id"] == started[0]["id"] for p in started)
    assert [c[0] for c in calls].count("/api/anteriora/permit") == 1
    # No worker delivered (the fake ones did nothing): the unit taken for the run is given back.
    assert state["units"] == 1 and "permit" not in B.load_reading(ident, cluster=True)


def test_a_cluster_session_with_billing_off_carries_no_permit(home, monkeypatch):
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "0")
    monkeypatch.setattr(B, "_post", lambda *a: (_ for _ in ()).throw(AssertionError("no call when off")))
    ident, d = _cluster(home)
    seen = []
    _round(d, monkeypatch, finds=1, seen=seen)
    assert "permit" not in seen[0]


def test_a_cluster_on_an_empty_account_stops_before_launching(home, service, monkeypatch):
    _, state = service
    state["units"] = 0
    ident, d = _cluster(home)
    monkeypatch.setattr("inferroute_cli.confidential.launch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")))
    with pytest.raises(S.ProbantError, match="No searches left"):
        S._cluster_round(d, "read", out={}, cwd=d)
