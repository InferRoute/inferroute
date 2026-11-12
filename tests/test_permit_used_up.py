"""A permit the search gate (or the relay) answers 402 permit_used_up for (billing owner's ruling, Nov 2026).

What must hold: it is settled as DELIVERED before it is dropped (the site hands an unsettled permit straight back), it is
never settled as failed, the next start says it uses one more unit and then takes a fresh one, a settle that cannot be
made keeps the permit for the next start to settle first, and an empty account after the drop is told in the app's
own no-units sentence.
"""
import io
import json
import urllib.error

import pytest

from inferroute_cli import anteriora_billing as B
from inferroute_cli import pi_attested as PA
from inferroute_cli import probant as S
from inferroute_cli import probant_home as H
from inferroute_cli._searchgate import ir_search_gate as G
from inferroute_local.confidential import billing_refusal as BR

PERMIT = "00000000-0000-0000-0000-000000000001"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.setattr(B, "_answer", None)
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    monkeypatch.setenv("IR_ANTERIORA_BILLING", "1")
    PA.clear_used_up_signal()
    yield
    PA.clear_used_up_signal()


@pytest.fixture
def site(monkeypatch):
    """The account service. `events` holds every call and every line the app printed, in order."""
    events = []
    state = {"n": 1, "units": 5, "settle": "ok", "watch": None}

    def post(path, body):
        if path == "/api/anteriora/settle":
            # the record as it is at the moment of the settle: the permit must still be there
            held = (state["watch"] or {}).get("permit")
            events.append(("settle", body["outcome"], body["permit"], bool(held)))
            if state["settle"] == "down":
                raise B.BillingError("could not reach the account service", 0)
            if state["settle"] == "5xx":
                raise B.BillingError("the account service answered 503", 503)
            return {"state": "delivered"}
        if path == "/api/anteriora/permit":
            events.append(("permit",))
            if state["units"] < 1:
                raise B.BillingError(B.NO_UNITS_WORDS)
            state["units"] -= 1
            state["n"] += 1
            return {"permit": f"00000000-0000-0000-0000-{state['n']:012d}"}
        raise AssertionError(path)

    monkeypatch.setattr(B, "_post", post)
    monkeypatch.setattr(B, "print", lambda *a, **k: events.append(("said", " ".join(map(str, a)).strip())),
                        raising=False)
    return events, state


def held(**extra):
    return {"permit": {"id": PERMIT, "unit": "search", "state": "delivered", "at": B._now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "first_session": "s0", "account": B._account_tag(), **extra}}


def gate_says_used_up(permit=PERMIT, code="permit_used_up"):
    """The relay refused `permit` (the one the transport sent) with a final permit code."""
    BR.note_permit_refusal(permit, BR.parse(402, {"x-inferroute-billing-code": code},
                                            json.dumps({"error": {"code": code, "message": "No searches left."}})))


# ───────────────────────── settle, then drop ─────────────────────────

def test_the_settle_precedes_the_drop(site):
    events, state = site
    rec = held()
    state["watch"] = rec
    gate_says_used_up()
    assert B.end_session(rec, "s1", False) == "dropped"
    assert events == [("settle", "delivered", PERMIT, True)]            # settled while the permit was still held
    assert "permit" not in rec and rec["renewal"] == "used_up"


@pytest.mark.parametrize("delivered", [True, False])
def test_a_used_up_permit_is_never_settled_as_failed(site, delivered):
    events, state = site
    for settle in ("ok", "down"):
        state["settle"] = settle
        rec = held(state="issued", first_session="s1")                   # its first session: would settle "failed"
        gate_says_used_up()
        B.end_session(rec, "s1", delivered)
        B.after_session(rec, "s1", delivered)                            # e.g. the cluster parent, after its workers
    assert events and all(e[1] == "delivered" for e in events if e[0] == "settle")


def test_the_next_start_says_one_more_unit_and_takes_a_fresh_permit(site):
    events, state = site
    rec = held()
    gate_says_used_up()
    B.end_session(rec, "s1", True)
    events.clear()
    p = B.before_session(rec, "s2")
    assert events == [("said", "This matter's searches and document reads for its current unit are used up; "
                               "continuing uses one more unit."),
                      ("permit",)]
    assert p["id"] != PERMIT and rec["permit"]["id"] == p["id"] and "renewal" not in rec
    events.clear()
    assert B.before_session(rec, "s3")["id"] == p["id"] and events == []   # said once, not at every start


def test_a_settle_that_fails_keeps_the_permit_and_the_next_start_settles_it_first(site):
    events, state = site
    for failure in ("down", "5xx"):
        events.clear()
        state["settle"] = failure
        rec = held()
        gate_says_used_up()
        assert B.end_session(rec, "s1", True) == "kept"
        assert rec["permit"]["id"] == PERMIT and rec["permit"]["used_up"] is True and "renewal" not in rec
        # next start, the service still down: the used-up sentence, and no new unit taken
        with pytest.raises(B.BillingError) as e:
            B.before_session(rec, "s2")
        assert "used up" in str(e.value) and rec["permit"]["id"] == PERMIT
        assert [x[0] for x in events] == ["settle", "settle"]
        # and once it answers: settle first, then the line, then a fresh unit
        state["settle"] = "ok"
        events.clear()
        p = B.before_session(rec, "s3")
        assert [x[:2] for x in events] == [("settle", "delivered"), ("said", B.one_more_unit_words(rec)), ("permit",)]
        assert p["id"] != PERMIT


def test_no_units_left_after_the_drop_shows_the_no_units_sentence(monkeypatch):
    from inferroute_cli import config
    monkeypatch.setattr(config, "load", lambda: type("C", (), {"api_key": "inf_test_key_123456"})())
    seen = []

    def urlopen(req, timeout=None):
        seen.append(req.full_url)
        if req.full_url.endswith("/settle"):
            return io.BytesIO(b'{"state": "delivered"}')
        raise urllib.error.HTTPError(req.full_url, 402, "x", {}, io.BytesIO(json.dumps(
            {"error": {"type": "billing_error", "code": "units_none", "message": "none"}}).encode()))

    monkeypatch.setattr("inferroute_cli.anteriora_billing._open", urlopen)
    rec = held(used_up=True)                                             # used up, its settle still to make
    with pytest.raises(B.BillingError) as e:
        B.before_session(rec, "s2")
    assert str(e.value) == B.NO_UNITS_WORDS
    assert [u.rsplit("/", 1)[-1] for u in seen] == ["settle", "permit"]
    assert H.failure_message([f"  {B.one_more_unit_words(rec)}", f"  {e.value}"]) == B.NO_UNITS_WORDS + " Nothing was sent."


# ───────────────────────── where "used up" is heard ─────────────────────────

def test_a_session_without_a_used_up_answer_settles_as_before(site):
    events, _ = site
    rec = held(state="issued", first_session="s1")
    B.end_session(rec, "s1", False)
    assert events == [("settle", "failed", PERMIT, False)]               # an ordinary unit given back, unchanged


def test_the_gate_tells_the_launcher_through_a_file_it_alone_writes(tmp_path):
    sig = tmp_path / "s.used-up"
    script = [(402, {"x-inferroute-billing-code": "permit_used_up"},
               json.dumps({"error": {"code": "permit_used_up", "message": "No searches left."}}).encode())]

    class Opener:
        def open(self, req, timeout=None):
            status, h, body = script[0]
            raise urllib.error.HTTPError(req.full_url, status, "x", h, io.BytesIO(body))

    g = G.Gate("https://" + G.GATE_HOSTS[0], "k", PERMIT, sleep=lambda s: None, opener=Opener(), used_up_file=str(sig))
    with pytest.raises(G.GateRefused):
        g.call(g.base, "POST", "/search", b"x", 5)
    assert json.loads(sig.read_text()) == {"permit": PERMIT, "code": "permit_used_up"}
    PA._USED_UP_SIGNAL = sig
    assert PA.permit_refusal_signalled(PERMIT) == "permit_used_up" and PA.permit_refusal_signalled("another") is None
    assert B.reported_refusal(PERMIT) == "permit_used_up"
    PA.clear_used_up_signal()
    assert B.reported_refusal(PERMIT) is None


def test_a_session_on_the_gate_with_a_permit_is_given_a_signal_file_under_confidential(tmp_path, monkeypatch):
    import select
    import subprocess
    from inferroute_cli import config
    monkeypatch.setattr(config, "load", lambda: config.Credentials(api_url="https://x", api_key="k"))
    conf = tmp_path / "ir" / "confidential"
    conf.mkdir(parents=True)
    (conf / "search.json").write_text(json.dumps({"enclave": "https://" + G.GATE_HOSTS[0]}))
    for k in ("IR_MATTER_RECORD_DIR", "IR_MATTER_STATE_FILE", "IR_MATTER_CUTOFF"):
        monkeypatch.delenv(k, raising=False)
    got = {}

    class Proc:
        def __init__(self, argv, **kw):
            self.stdin = io.StringIO()
            self.stdin.close = lambda: got.__setitem__("stdin", self.stdin.getvalue())
            self.stdout = io.StringIO('{"listening": 4}\n')

    monkeypatch.setattr(subprocess, "Popen", Proc)
    monkeypatch.setattr(select, "select", lambda r, w, x, t: (r, [], []))
    monkeypatch.setattr(PA, "_SEARCH_PROXIES", [])
    PA.start_search_proxy(permit=PERMIT)
    sent = json.loads(got["stdin"])
    assert sent["permit"] == PERMIT and sent["used_up_file"].endswith(".used-up")
    assert str(conf) in sent["used_up_file"] and PA._USED_UP_SIGNAL is not None
    PA.start_search_proxy()                                             # billing off: no permit, no signal
    assert "used_up_file" not in json.loads(got["stdin"]) and PA._USED_UP_SIGNAL is None


# ───────────────────────── through the launcher and the home page ─────────────────────────

def test_a_matter_whose_permit_ran_out_is_renewed_at_the_next_open(site, monkeypatch, capsys):
    events, state = site
    S.main(["new", "Acme", "gadget"])

    def session_where_the_gate_says_used_up(args, agent="pi", probant=None):
        gate_says_used_up(probant["permit"])
        return 0

    monkeypatch.setattr("inferroute_cli.confidential.launch", session_where_the_gate_says_used_up)
    assert S.main(["open", "Acme/gadget"]) == 0
    first = [e for e in events if e[0] == "settle"]
    rec = S.load_record("Acme", "gadget")
    assert [e[:3] for e in first] == [("settle", "delivered", "00000000-0000-0000-0000-000000000002")]
    assert "permit" not in rec and rec["renewal"] == "used_up"
    events.clear()
    monkeypatch.setattr("inferroute_cli.confidential.launch", lambda *a, **k: 0)
    assert S.main(["open", "Acme/gadget"]) == 0
    assert [e[0] for e in events][:2] == ["said", "permit"]
    rec = S.load_record("Acme", "gadget")
    assert rec["permit"]["id"].endswith("3") and "renewal" not in rec


def test_a_reading_keeps_its_renewal_mark_across_starts(site, monkeypatch):
    rec = {"kind": "reading", "intake": "20261112T101010Z-abcdef", "permit": held()["permit"]}
    monkeypatch.setattr(B, "_reading_path", lambda i, cluster=False: PA.search_config_path().parent / f"{i}.json")
    gate_says_used_up()
    B.end_session(rec, "s1", True)
    B.save_reading(rec)
    again = B.load_reading(rec["intake"])
    assert again.get("renewal") == "used_up" and "permit" not in again
    assert B.one_more_unit_words(again).startswith("This reading's")


def test_the_home_page_shows_the_one_more_unit_line_and_the_used_up_sentence():
    line = B.one_more_unit_words({})
    assert H.unit_notice_in(["Opening Acme/gadget", f"  {line}", "checking…"]) == line
    assert H.unit_notice_in(["Opening Acme/gadget"]) == ""
    kept = B.used_up_kept_words({})
    assert H.failure_message(["Opening Acme/gadget", f"  {kept}"]) == kept
    js = (PA.Path(H.__file__).resolve().parent / "probant_web" / "home.js").read_text()
    assert 'if (l.notice) box.append(el("div", "launch-notice", l.notice));' in js
