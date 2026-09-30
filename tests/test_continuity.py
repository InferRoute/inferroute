"""The continuity lane: a fleet going bad must not become the user's problem.

Henry, 2026-09-30, in priority order: minimise errors the user sees, then prefer the biggest models,
and do not disturb the single-model path.
"""
import asyncio
import time

import pytest

from inferroute_local.confidential import availability as av
from inferroute_local.confidential import continuity as C


class FakeReceipt:
    def __init__(self, sid, short):
        self.session_id, self.model_short = sid, short
        self.served_by = [{"instance": {"id": f"i-{short}"}, "requests": 0, "model_short": short}]
        self.counters = {"requests": 0}
        self.events = []
        self.verdict = "confidential"
    def note(self, kind, detail):
        self.events.append({"kind": kind, "detail": detail})


class FakeSession:
    """Behaves like an open ConfidentialSession as far as the facade is concerned."""
    def __init__(self, cand, *, fails=0, fault="fleet"):
        self.fleet_id, self.model_short = cand.fleet_id, cand.model_short
        self.upstream_model = cand.upstream_model
        self.receipt = FakeReceipt(f"s-{cand.model_short}", cand.model_short)
        self.last_fault = ""
        self.fails, self.fault = fails, fault
        self.closed = False
        self.calls = 0
    async def messages(self, body):
        self.calls += 1
        self.receipt.counters["requests"] += 1
        if self.fails > 0:
            self.fails -= 1
            self.last_fault = self.fault
            return (503, {}, iter([b"error"]))
        self.last_fault = ""
        return (200, {}, iter([b"ok"]))
    chat_completions = messages
    def close(self):
        # SYNCHRONOUS, like the real ConfidentialSession.close, which the launcher calls without await.
        # The fake had it async; the facade then "closed" spares by building a coroutine nobody ran, so
        # a promoted-away session would have been left open in production while the test passed.
        self.closed = True
        return self.receipt


def _cands():
    return [
        C.Candidate("f-big", "kimi-k3", "moonshotai/Kimi-K3-TEE", context_length=256000),
        C.Candidate("f-mid", "glm-5.2", "zai-org/GLM-5.2-TEE", context_length=256000),
        C.Candidate("f-small", "deepseek-v4-flash", "deepseek/DeepSeek-TEE", context_length=256000),
    ]


def _lane(opened, **kw):
    """`opened` maps model_short -> FakeSession (or an Exception to raise)."""
    async def opener(cand):
        v = opened[cand.model_short]
        if isinstance(v, Exception):
            raise v
        return v
    return C.Continuity(_cands(), opener, beliefs=av.Beliefs(path=None),
                        policy=av.Policy(rank=av.RANK_CAPABILITY), **kw)


def _run(coro):
    return asyncio.run(coro)


# ── the primary objective: the user does not see the failure ─────────────────────────────────────

def test_a_failing_fleet_is_carried_by_the_standby_and_the_user_sees_a_200():
    """THE WHOLE POINT. The active fleet refuses; a standby that was verified in the background answers
    the same request; the caller receives a 200 and never learns anything happened."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()                       # deterministic: warm synchronously for the test
        assert lane.standby is not None, "nothing was warmed, so nothing could carry the failure"
        status, _, _ = await lane.messages({"messages": []})
        return status, lane, sessions
    status, lane, sessions = _run(go())
    assert status == 200, "the user was shown the failure"
    assert lane.switches == 1
    assert lane.active.model_short == "glm-5.2"
    assert sessions["glm-5.2"].calls == 1, "the standby did not actually serve the request"
    assert any(e["kind"] == "carried" for e in lane.active.receipt.events)


def test_without_a_standby_the_failure_is_reported_rather_than_hidden():
    """Smoothness is not silence. With nothing warmed there is nothing to carry the request, and
    pretending otherwise would hang the turn instead of answering it."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        lane.standby = None                      # nothing warmed yet
        return (await lane.messages({"messages": []}))[0], lane
    status, lane = _run(go())
    assert status == 503 and lane.switches == 0
    assert any(e["kind"] == "no-standby" for e in lane.active.receipt.events)


# ── the faults that must NOT cause a switch ──────────────────────────────────────────────────────

@pytest.mark.parametrize("fault", ["integrity", "account", "client", "transport", "route"])
def test_faults_another_fleet_cannot_help_with_do_not_burn_the_standby(fault):
    """`account` is billing and `client` is our own bug — both true of every fleet at once. `transport`
    means the relay is unreachable, so every fleet is equally unreachable.

    And `integrity` is the one that matters: an unopenable reply is an authentication failure against
    the key the hardware quote committed to, indistinguishable from a substituted key or machine.
    Silently moving to another fleet is precisely how a key-substitution attempt across a fleet would
    be made to look like a slow afternoon."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1, fault=fault),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        return (await lane.messages({"messages": []}))[0], lane, sessions
    status, lane, sessions = _run(go())
    assert status == 503, f"{fault} was hidden from the user"
    assert lane.switches == 0, f"the lane switched fleets over a {fault} fault"
    assert sessions["glm-5.2"].calls == 0, "the standby was spent on a fault it cannot fix"


def test_integrity_is_excluded_by_name_and_not_by_omission():
    """A later edit to COUNTS_AGAINST_FLEET must not be able to make an authentication failure
    switchable by accident."""
    assert "integrity" not in C.SWITCHABLE
    from inferroute_local.confidential import session as S
    assert S.INTEGRITY_FAULT not in C.SWITCHABLE


# ── the standby must be worth promoting ──────────────────────────────────────────────────────────

def test_a_stale_standby_is_not_promoted():
    """Promoting evidence older than the session's own re-verification interval would use attestation
    the active session would itself have refused by now."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        lane.standby_at = time.time() - C.STANDBY_MAX_AGE_S - 1
        return (await lane.messages({"messages": []}))[0], lane, sessions
    status, lane, sessions = _run(go())
    assert status == 503 and lane.switches == 0
    assert sessions["glm-5.2"].closed, "the stale standby was left open"
    assert any(e["kind"] == "standby-stale" for e in lane.active.receipt.events)


def test_a_smaller_context_is_never_warmed_as_a_standby():
    """The most consequential silent degradation available here, and the first design missed it
    entirely: failing a long disclosure over to a smaller window truncates it mid-document, which is
    worse than the error it avoids."""
    async def go():
        cands = [C.Candidate("f-big", "kimi-k3", "K3", context_length=256000),
                 C.Candidate("f-small", "deepseek-v4-flash", "DS", context_length=32000)]
        sessions = {"kimi-k3": FakeSession(cands[0]), "deepseek-v4-flash": FakeSession(cands[1])}
        async def opener(c):
            return sessions[c.model_short]
        lane = C.Continuity(cands, opener, beliefs=av.Beliefs(path=None),
                            policy=av.Policy(rank=av.RANK_CAPABILITY))
        await lane.open()
        await lane._warm()
        return lane
    lane = _run(go())
    assert lane.standby is None, "a smaller-context fleet was warmed as a standby"


# ── the record ───────────────────────────────────────────────────────────────────────────────────

def test_the_conversations_record_names_every_machine_that_served_it():
    """Each session's receipt is honest about itself. Without this, no artefact is honest about the
    whole conversation."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        await lane.messages({"messages": []})
        return lane
    lane = _run(go())
    served = lane.active.receipt.served_by
    ids = [(r["instance"]["id"], r.get("from_previous_session")) for r in served]
    assert ("i-kimi-k3", "s-kimi-k3") in ids, "the machine that served first is missing from the record"
    assert ("i-glm-5.2", None) in ids
    assert lane.active.receipt.counters["continuity_switches"] == 1


# ── the second objective, and only the second ────────────────────────────────────────────────────

def test_the_biggest_model_is_preferred_when_it_is_available():
    async def go():
        sessions = {c.model_short: FakeSession(c) for c in _cands()}
        lane = _lane(sessions)
        await lane.open()
        return lane
    lane = _run(go())
    assert lane.active.model_short == "kimi-k3"
    assert lane.order[0] == "kimi-k3"


def test_availability_outranks_capability():
    """The order Henry gave: errors first, size second. A fleet that will not open loses to one that
    will, however much the policy prefers it."""
    async def go():
        sessions = {"kimi-k3": RuntimeError("fleet down"),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        return lane
    lane = _run(go())
    assert lane.active.model_short == "glm-5.2", "an unopenable fleet was used because it was bigger"


def test_no_candidate_opening_raises_rather_than_returning_a_broken_lane():
    async def go():
        sessions = {c.model_short: RuntimeError("down") for c in _cands()}
        lane = _lane(sessions)
        await lane.open()
    with pytest.raises(Exception):
        _run(go())


# ── the constraint: the single-model path must not change ────────────────────────────────────────

def test_the_single_model_path_cannot_reach_this_lane():
    """Henry: "it should not affect our current single model serving mode."

    The invariant is not that nothing builds the lane — Probant does — but that NOTHING ELSE CAN. One
    construction site, reached only when a caller passes `continuity=True`, defaulting to False, and
    disabled by IR_NO_MODEL_FALLBACK even for the caller that asks."""
    import inspect
    import pathlib
    import subprocess

    from inferroute_cli import confidential as C

    root = pathlib.Path(__file__).resolve().parent.parent
    r = subprocess.run(["grep", "-rn", "Continuity(", "--include=*.py",
                        "inferroute_cli/", "inferroute_local/"], cwd=root, capture_output=True, text=True)
    sites = [ln for ln in r.stdout.splitlines() if ln.strip() and "continuity.py" not in ln]
    assert len(sites) == 1, "more than one way into the side lane:\n" + "\n".join(sites)
    # The ENCLOSING function, not the line: grep returns the call site's text, which of course does not
    # contain the name of the function it sits in.
    assert "cont.Continuity(" in inspect.getsource(C._open_continuity), \
        "the one construction site is not inside _open_continuity"

    # opt-in, and off by default
    assert inspect.signature(C._open_session).parameters["continuity"].default is False
    src = inspect.getsource(C._open_session)
    assert "if continuity and os.environ.get(\"IR_NO_MODEL_FALLBACK\") != \"1\":" in src
    # and only Probant asks
    launch = inspect.getsource(C.launch)
    assert "continuity=probant is not None" in launch

    # a lane that will not open must degrade to the ordinary path, never to a worse one
    assert "Falls through to the single-session path below" in src


def test_the_reason_a_fleet_was_chosen_reaches_the_record():
    """Found on a LIVE run, not in a test: the lane recorded that a standby was ready and said nothing
    about how the active fleet had been picked. The ordering note is made while CHOOSING, before any
    session exists to write it to, so it was being dropped — and it is the one decision a reader would
    most want to audit."""
    async def go():
        sessions = {c.model_short: FakeSession(c) for c in _cands()}
        lane = _lane(sessions)
        await lane.open()
        return lane
    lane = _run(go())
    kinds = [e["kind"] for e in lane.active.receipt.events]
    assert "continuity-order" in kinds, f"the ordering decision was lost; recorded {kinds}"
    assert "continuity-open" in kinds
    order_note = next(e for e in lane.active.receipt.events if e["kind"] == "continuity-order")
    assert "kimi-k3" in order_note["detail"] and ">" in order_note["detail"]


def test_the_surviving_receipt_carries_the_whole_story_not_just_the_switch():
    """Found on a live failover: the receipt that survived said the conversation had switched and been
    carried, while the decisions that led there — which fleets were considered and why, and that a
    standby had been verified and held in reserve — stayed on the receipt nobody reads afterwards.

    Evidence without the reasoning is half a record, and the half that is missing is the half an
    auditor would ask about."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        await lane.messages({"messages": []})
        return lane
    lane = _run(go())
    kinds = [e["kind"] for e in lane.active.receipt.events]
    for expected in ("continuity-order", "continuity-open", "standby-ready", "switched", "carried"):
        assert expected in kinds, f"{expected} was lost in the switch; receipt has {kinds}"
    # and the carried-over ones say where they came from, so the record is not silently reattributed
    carried = [e for e in lane.active.receipt.events if e.get("from_previous_session")]
    assert carried and all(e["from_previous_session"] == "s-kimi-k3" for e in carried)
