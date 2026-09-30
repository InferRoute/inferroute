"""The continuity lane: a fleet going bad must not become the user's problem.

Henry, 2026-09-30, in priority order: minimise errors the user sees, then prefer the biggest models,
and do not disturb the single-model path.
"""
import asyncio
import time

import pytest

from inferroute_local.confidential import availability as av
from inferroute_local.confidential import continuity as C


async def _aiter(chunks):
    for c in chunks:
        yield c


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
        # Cleared on DISPATCH, as the real session now does. And an ASYNC generator, as the real one
        # always returns: the fake used to hand back `iter([...])`, a sync iterator, so
        # _commit_on_first_chunk early-returned and 14 of 18 tests never executed the commit path they
        # existed to cover. A fake that is easier to write than the real thing tests the fake.
        self.last_fault = ""
        if self.fails > 0:
            self.fails -= 1
            self.last_fault = self.fault
            return (503, {}, _aiter([b"error"]))
        return (200, {}, _aiter([b"ok"]))
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
    # and only Probant asks, and only when explicitly switched on
    launch = inspect.getsource(C.launch)
    assert 'os.environ.get("IR_PROBANT_CONTINUITY")' in launch, \
        "the lane has no switch at all"
    assert "continuity=use_continuity" in launch

    # a lane that will not open must degrade to the ordinary path, never to a worse one
    assert "Falls through to the single-session path below" in src


def test_the_claim_the_lane_depends_on_is_conditioned():
    """The lane is ON since Henry's ruling of 2026-09-30, and it is only honest because the claim it
    would otherwise break was conditioned first. The API is stateless, so `body` is the whole conversation and every
    switch re-sends the entire disclosure to a second enclave. The product prints this to the
    professional before they type anything, and repeats it in French to a named client:

        "Your text is encrypted here; only that machine can open it."

    Continuity makes that false in substance, not in bookkeeping — it is a claim about who can read the
    invention. attest.LIMITATIONS conditions nothing about it. Changing a client-facing confidentiality
    claim is a decision, not a commit, so the lane is reachable only on purpose until it is made.

    This test exists to fail loudly if someone removes the gate without removing the reason."""
    import inspect
    from inferroute_cli import confidential as C
    from inferroute_cli import probant_trust

    launch = inspect.getsource(C.launch)
    assert "IR_PROBANT_CONTINUITY" in launch, "the lane cannot be turned off"
    src = open(probant_trust.__file__).read()

    # RENDERED, not grepped. The first version of this assertion searched ai_item's SOURCE and failed on
    # the comment that quotes the old sentence to explain why it was removed — a source search cannot
    # tell a string being printed from one being discussed.
    from inferroute_local.confidential import attest as _att
    class _R:
        # The FULL required set: ai_item short-circuits to "the checks did not pass" otherwise, and the
        # assertions below then measure the fixture instead of the wording.
        checks = {k: {"ok": True} for k in (
            "e2e_key_bound", "tdx_shape", "build_recorded", "gpu_verified", "measurement_ok",
            "chain_ok", "sig_ok", "nonce_in_body", "spki_bound", "quote_sig", "root_pinned",
            "not_revoked", "tcb_current", "qe_current", "gpu_in_signed_evidence")}
        verdict = "confidential"; model_short = "kimi-k3"; upstream_model = "x/K3-TEE"
        started_at = "2026-09-30T22:00:00Z"; verified_at = started_at
        instance = {"id": "i-a"}
        limitations = [{"id": k, "text": t} for k, t in _att.LIMITATIONS]
        served_by = [{"instance": {"id": "i-a"}}]
    one = " ".join(probant_trust.ai_item(_R())["points"])
    _R.served_by = [{"instance": {"id": x}} for x in "abc"]
    three = " ".join(probant_trust.ai_item(_R())["points"])

    assert "only that machine can open it" not in one, \
        "the AI lane still claims one machine while a session can move between several"

    # TWO naive-reader tests failed earlier wordings for the same reason: the tick and the condition
    # ARGUED on the same screen — one machine above, more than one below — and both readers described
    # the small print as taking back what the big print promised. "So far" makes it a running count,
    # which cannot be contradicted by a later one.
    # FOUR readers, four revisions, and then Henry asked the question that ended it: "i dont understand
    # why allowing machines to switch has to weaken the claim." It does not. Every request is sealed to
    # ONE machine's key and e2e_key_bound verifies that machine's quote commits to it before anything is
    # sent — identical whether a session uses one machine or five. The count was never the guarantee,
    # and conditioning the claim meant apologising for a number that was never the promise.
    #
    # So: the guarantee is stated unconditionally, and the count is a FACT, reported like a meter
    # reading. No "if", no "so far", no apology.
    assert "Machines that have opened it: 1 — the receipt names each." in one
    assert "Machines that have opened it: 3 — the receipt names each." in three
    # and it is not filed as a LIMITATION — a limitation is something we cannot prove, and the word
    # itself told four readers this was bad news
    assert not any(k == "machines-per-session" for k, _ in _att.LIMITATIONS), \
        "a behaviour we can prove is filed as something we cannot"
    # Lead with the thing no reader knew: that the text leaves at all. All three learned it from the
    # small print or not at all.
    assert "leaves this computer encrypted" in one, "the card no longer says the text leaves"
    assert "opened only inside hardware this computer checked first" in one, "the claim went singular"
    # ...and it must not deny a worry the reader did not have: "nobody says that unless somebody
    # somewhere was worried about unverified ones."
    assert "never an unverified one" not in one
    # ...nor argue its own case: "somebody has had this fight before and pre-loaded the answer."

    # ...and the behaviour is described on the page, beside the other descriptions
    from inferroute_cli.probant_trust import ai_item as _ai
    assert any("not tied to one machine" in m for m in probant_trust.ai_item(_R())["more"]), \
        "nothing on the page says a session may move between machines"
    # ...while the SEARCH lane keeps its singular claim, which it earns by refusing any other enclave
    assert "only that machine can open it" in src, \
        "the search lane's claim was weakened; it pins expect_lifetime_id and is still true"


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


class EmptyStreamSession(FakeSession):
    """Answers 200 and then produces nothing — a fleet that accepts a request and never delivers a
    token. The commonest shape of a fleet going bad, and the one a status code cannot express."""
    def __init__(self, cand, *, fault="instance", raises=False, then=None):
        super().__init__(cand)
        self._fault, self._raises, self._then = fault, raises, then
    async def messages(self, body):
        self.calls += 1
        if self._then is not None and self.calls > 1:
            return await FakeSession.messages(self, body)
        outer = self
        async def stream():
            if outer._raises:
                raise RuntimeError("connection dropped")
            outer.last_fault = outer._fault
            return
            yield b""                                  # pragma: no cover - makes this a generator
        self.last_fault = ""
        return (200, {}, stream())
    chat_completions = messages


def test_a_stream_that_dies_before_its_first_token_is_carried():
    """A 200 is not yet an answer: the status and headers have not reached the client, because the
    server sends them when it starts iterating. So a fleet that accepts the request and then produces
    nothing is still recoverable — and that is exactly how a struggling fleet fails."""
    async def go():
        sessions = {"kimi-k3": EmptyStreamSession(_cands()[0]),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        st, _, stream = await lane.messages({"messages": []})
        return st, lane, sessions
    st, lane, sessions = _run(go())
    assert st == 200, "an empty stream reached the user"
    assert lane.switches == 1 and lane.active.model_short == "glm-5.2"
    assert sessions["glm-5.2"].calls == 1


def test_a_stream_that_raises_before_its_first_token_is_carried():
    async def go():
        sessions = {"kimi-k3": EmptyStreamSession(_cands()[0], raises=True),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        return (await lane.messages({"messages": []}))[0], lane
    st, lane = _run(go())
    assert st == 200 and lane.switches == 1


def test_once_a_token_is_committed_the_conversation_stays_where_it_is():
    """THE BOUNDARY, and it is deliberate. Once a byte has gone to the client the answer belongs to
    that machine; silently restarting a half-delivered reply on another model would produce a worse
    artefact than the error it hid. The first chunk is delivered, and a later failure surfaces."""
    async def go():
        class DiesAfterContent(FakeSession):
            async def messages(self, body):
                self.calls += 1
                outer = self
                async def stream():
                    yield b'{"delta":"partial"}'
                    outer.last_fault = "instance"
                    raise RuntimeError("dropped mid-reply")
                return (200, {}, stream())
            chat_completions = messages
        sessions = {"kimi-k3": DiesAfterContent(_cands()[0]),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        st, _, stream = await lane.messages({"messages": []})
        got, err = [], None
        try:
            async for c in stream:
                got.append(c)
        except Exception as e:
            err = e
        return st, got, err, lane, sessions
    st, got, err, lane, sessions = _run(go())
    assert st == 200 and got == [b'{"delta":"partial"}'], "the committed content was not delivered"
    assert err is not None, "a mid-reply failure was swallowed"
    assert lane.switches == 0, "a half-delivered answer was restarted on another model"
    assert sessions["glm-5.2"].calls == 0


def test_an_empty_stream_with_no_standby_reports_rather_than_hanging():
    """The path that had a latent NameError: nothing warmed, nothing to carry it, and the caller still
    needs a truthful answer rather than an empty body that looks like success."""
    async def go():
        sessions = {"kimi-k3": EmptyStreamSession(_cands()[0]),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        lane.standby = None
        st, _, stream = await lane.messages({"messages": []})
        body = b"".join([c async for c in stream])
        return st, body, lane
    st, body, lane = _run(go())
    assert st == 503 and b"no answer" in body
    assert lane.switches == 0


def test_parallel_requests_meeting_one_outage_spend_only_one_standby():
    """An agent issues PARALLEL tool calls, so `_call` is re-entrant and several requests can meet the
    same failing fleet at once. Unserialised, each would switch — and one bad fleet would burn every
    standby in sequence, the lane spending its whole reserve on a single outage."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=5),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        results = await asyncio.gather(*[lane.messages({"messages": []}) for _ in range(4)])
        return [r[0] for r in results], lane, sessions
    statuses, lane, sessions = _run(go())
    assert lane.switches == 1, f"one outage cost {lane.switches} standbys"
    assert lane.active.model_short == "glm-5.2"
    assert statuses.count(200) >= 1, "no request survived the outage"
    # the ones that arrived after the move are told so rather than switching again
    assert any(e["kind"] in ("already-carried", "carried") for e in lane.active.receipt.events)


def test_a_stream_we_walk_away_from_is_closed():
    """Abandoning an async generator leaves its `finally` to the collector, whenever that is.
    session.py's stream closes over an httpx response and folds its frame counts in there, so an
    abandoned stream means a connection held open and counters silently short — at exactly the moment
    the lane is already coping with a failing fleet and needs its connections most."""
    closed = {"n": 0}

    class Watched(FakeSession):
        async def messages(self, body):
            self.calls += 1
            outer = self
            async def stream():
                try:
                    outer.last_fault = "instance"
                    return
                    yield b""                          # pragma: no cover
                finally:
                    closed["n"] += 1
            return (200, {}, stream())
        chat_completions = messages

    async def go():
        sessions = {"kimi-k3": Watched(_cands()[0]),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        return (await lane.messages({"messages": []}))[0], lane
    st, lane = _run(go())
    assert st == 200 and lane.switches == 1
    assert closed["n"] == 1, "the abandoned stream's cleanup never ran"


def test_a_transient_drop_does_not_brick_every_later_turn():
    """THE FATAL ONE, and it was mine. `last_fault` was cleared only in `_account`, which on the
    STREAMING path runs at the very end of the generator — so a mid-stream drop returned without ever
    reaching it and the field stayed set for the life of the session.

    `_commit_on_first_chunk` then read that stale value as "did THIS request fail", threw away the next
    perfectly healthy answer, shut its stream (so `_account` never ran and the fault stayed stale), and
    did it again on the turn after. Reproduced before the fix: one transient drop turned every
    subsequent turn into a 503, forever. The single-session path this replaces would have served them
    all. A lane whose first priority is fewer errors was converting one into an unrecoverable session.

    With a standby it was not fatal but still wrong: a healthy 200 discarded, a standby burned, and the
    same disclosure re-sealed to a SECOND enclave — a privacy-surface expansion caused by a bookkeeping
    field."""
    class StickyFault(FakeSession):
        """Sets last_fault mid-stream and never clears it — exactly what a real session did between
        requests before the fix, because _account is unreachable after a mid-stream drop."""
        def __init__(self, cand):
            super().__init__(cand)
            self.dropped_once = False
        async def messages(self, body):
            self.calls += 1
            self.last_fault = ""                      # the real session now clears on DISPATCH
            outer = self
            if not self.dropped_once:
                self.dropped_once = True
                async def dies():
                    yield b'{"delta":"partial"}'      # commits, then drops mid-reply
                    outer.last_fault = "instance"
                    raise RuntimeError("dropped mid-reply")
                return (200, {}, dies())
            async def fine():
                yield b'{"delta":"healthy"}'
            return (200, {}, fine())
        chat_completions = messages

    async def go():
        sessions = {"kimi-k3": StickyFault(_cands()[0]),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        lane.standby = None                           # no reserve: the pure form of the bug
        out = []
        for _ in range(4):
            st, _h, stream = await lane.messages({"messages": []})
            try:
                body = b"".join([c async for c in stream])
            except Exception:
                body = b"<dropped>"
            out.append((st, body))
        return out, lane
    out, lane = _run(go())
    first, rest = out[0], out[1:]
    assert first[0] == 200, "the first turn should still commit its partial content"
    for i, (st, body) in enumerate(rest, start=2):
        assert st == 200, f"turn {i} returned {st}: a transient drop bricked the session"
        assert b"healthy" in body, f"turn {i} delivered {body!r}"
    assert lane.switches == 0, "a healthy turn was treated as a failure and burned a standby"


def test_the_fleet_that_just_failed_is_never_warmed_as_the_next_standby():
    """`order` is computed once at open and nothing removed a fleet that failed, so after a switch the
    warm walked straight back to it — spending a full attestation to guarantee the NEXT switch lands on
    the machine that just broke. The default path after every switch, not a rare interleaving."""
    async def go():
        sessions = {"kimi-k3": FakeSession(_cands()[0], fails=1),
                    "glm-5.2": FakeSession(_cands()[1]),
                    "deepseek-v4-flash": FakeSession(_cands()[2])}
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        await lane.messages({"messages": []})         # kimi-k3 fails, glm-5.2 carries it
        lane.standby = None
        await lane._warm()
        return lane
    lane = _run(go())
    assert "kimi-k3" in lane.failed
    assert lane.standby is not None and lane.standby.model_short == "deepseek-v4-flash", \
        f"warmed {lane.standby and lane.standby.model_short} — the fleet that just failed, or nothing"


def test_a_sweep_that_opens_nothing_backs_off():
    """Without a cooldown the warm-retry rate is the REQUEST rate: a full attestation sweep across
    every candidate on every turn, for the life of a session in which the others refuse this device."""
    async def go():
        attempts = {"n": 0}
        async def opener(cand):
            if cand.model_short == "kimi-k3":
                return FakeSession(cand)
            attempts["n"] += 1
            raise RuntimeError("refuses this device")
        lane = C.Continuity(_cands(), opener, beliefs=av.Beliefs(path=None),
                            policy=av.Policy(rank=av.RANK_CAPABILITY))
        await lane.open()
        # open() schedules its OWN warm in the background. Let it finish before measuring, or its two
        # opener calls land in the window and read as a cooldown that leaked.
        if lane._warming is not None:
            await lane._warming
        await lane._warm()
        after_first = attempts["n"]
        for _ in range(5):
            lane._warm_later()
            await asyncio.sleep(0)
        return after_first, attempts["n"], lane
    after_first, total, lane = _run(go())
    assert after_first >= 1, "the first sweep did not try"
    assert total == after_first, f"a failed sweep restarted {total - after_first} more times with no backoff"
    assert lane._warm_blocked_until > 0


def test_a_standby_that_will_not_open_counts_against_it():
    """open() records a refusal; this path did not, so a fleet that only ever fails as a standby
    accumulated nothing against it and was retried for the life of the session."""
    async def go():
        async def opener(cand):
            if cand.model_short == "kimi-k3":
                return FakeSession(cand)
            raise RuntimeError("no")
        beliefs = av.Beliefs(path=None)
        lane = C.Continuity(_cands(), opener, beliefs=beliefs,
                            policy=av.Policy(rank=av.RANK_CAPABILITY))
        await lane.open()
        await lane._warm()
        return beliefs
    beliefs = _run(go())
    assert beliefs.view("f-mid").verify.evidence > 0, "a refusing standby left no evidence"


def test_the_status_line_follows_the_session_that_is_serving(tmp_path):
    """The status line is "the thing people screenshot", and it is a shell snippet that greps ONE
    receipt path baked in at launch. After a switch that path is the ABANDONED session's: its byte and
    cost counters stop moving while still rendering as live, beside the name of a model that is no
    longer answering. A pointer the lane keeps on the active session keeps it honest without the shell
    needing to know a lane exists."""
    async def go():
        sessions = {}
        for c in _cands():
            fs = FakeSession(c)
            fs.receipt.path = str(tmp_path / f"{c.model_short}.json")
            (tmp_path / f"{c.model_short}.json").write_text("{}")
            sessions[c.model_short] = fs
        sessions["kimi-k3"].fails = 1
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        first = (tmp_path / "current.json").resolve()
        await lane.messages({"messages": []})
        return first, (tmp_path / "current.json").resolve(), lane
    before, after, lane = _run(go())
    assert before.name == "kimi-k3.json", f"the pointer did not start on the active session ({before})"
    assert lane.switches == 1
    assert after.name == "glm-5.2.json", f"the pointer did not follow the switch ({after})"


def test_a_superseded_session_is_not_stamped_as_ended_while_it_may_still_be_serving():
    """A caller captures `self.active` and then awaits. If another request switches during that await,
    closing the session it captured stamps ended_at and saves — and everything the in-flight request
    goes on to seal is then recorded on a receipt that says it had already finished."""
    async def go():
        sessions = {c.model_short: FakeSession(c) for c in _cands()}
        sessions["kimi-k3"].fails = 1
        lane = _lane(sessions)
        await lane.open()
        await lane._warm()
        await lane.messages({"messages": []})
        return lane, sessions
    lane, sessions = _run(go())
    assert lane.switches == 1
    assert not sessions["kimi-k3"].closed, "the superseded session was stamped as ended mid-flight"
    assert sessions["kimi-k3"] in lane.retired
    lane.close()
    assert sessions["kimi-k3"].closed, "a retired session was never closed at all"
