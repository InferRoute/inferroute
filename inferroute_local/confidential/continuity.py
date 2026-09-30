"""Several verified sessions, one conversation: the lane where a fleet going bad is not the user's problem.

Henry, 2026-09-30, in priority order: "minimise user reaching errors / maximise smoothness of the agent",
then "prioritise big/smart models over smaller ones for this specific probant agent", and — the
constraint that shapes everything here — "this is almost like a side lane ... it should not affect our
current single model serving mode."

WHY A FACADE AND NOT A MUTABLE SESSION. The obvious design is to let a Session change its fleet. Three
adversarial reviews found four fatal blockers to exactly that, and every one of them is a consequence of
MUTATION:

  - the model name is sealed INSIDE the ciphertext (translate.to_openai bakes it into the body before
    _send_sealed seals it), so a sealed request is not portable to another fleet
  - `fleet_id` is read outside the lock that pins the instance — inert while frozen, a live race once not
  - `_verified_at` is one clock for the whole session, so verifying fleet B would mark fleet A fresh
  - the lane preamble asserts "The assistant in this session is {model} ... never say otherwise", and
    `upstream_model` is never rewritten — so a switch would instruct the new model to misidentify itself

Nothing here mutates. Each underlying session is today's ConfidentialSession, on one fleet, with its own
pool, its own verification clock, its own price and its own preamble. Switching swaps WHICH session the
next request goes to. All four blockers are answered by construction rather than by four fixes, and the
single-model path is untouched: nothing constructs this unless a caller asks for it.

WHAT SMOOTHNESS ACTUALLY REQUIRES. A cold switch is not smooth — opening a session means fetching and
verifying attestation evidence, which the code itself calls "the slow part" and which measured 68 s. A
user watching a 68-second pause has not been protected from anything. So the standby is opened BEFORE it
is needed, in the background, while the user is reading or typing, and a switch is then a pointer move.
That is the whole difference between failover that helps and failover that is just a slower error.

WHAT THIS CANNOT DO. Failover is transparent only for failures that happen BEFORE the reply starts —
which is where the retryable ones live (no eligible instance, fleet capacity, 5xx). Once a 200 and the
first bytes have gone to the client, the conversation is committed to that machine; a mid-stream failure
still surfaces. That boundary is stated rather than blurred, because a facade that silently restarted a
half-delivered answer would produce a worse artefact than the error it hid.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from . import availability as av
from .session import COUNTS_AGAINST_FLEET, INSTANCE_FAULT, TRANSPORT_FAULT

# Faults another fleet can actually help with. `account` (billing) and `client` (our own bug) are true
# everywhere at once, so switching for them would burn a standby to reach the same answer. `transport`
# means the relay is unreachable and every fleet is equally unreachable. `integrity` is deliberately
# absent and must stay absent: an unopenable reply is an authentication failure against the key the
# hardware quote committed to, and quietly moving to another fleet is precisely how a key-substitution
# attempt would be made to look like a slow afternoon.
SWITCHABLE = frozenset(COUNTS_AGAINST_FLEET)

# How long a standby may sit unverified before it is refreshed. Under the session's own re-verification
# interval, so a standby is never promoted on evidence the active session would have refused.
STANDBY_MAX_AGE_S = 20 * 60.0


@dataclass
class Candidate:
    fleet_id: str
    model_short: str
    upstream_model: str
    context_length: int = 0
    meta: Optional[dict] = None


class Continuity:
    """Delegates to one open session; keeps another verified and ready behind it."""

    def __init__(self, candidates, opener: Callable[[Candidate], Awaitable], *,
                 beliefs: Optional[av.Beliefs] = None, policy: Optional[av.Policy] = None,
                 prober: Optional[av.Prober] = None, transport=None, note=None):
        self.candidates = list(candidates)
        self.opener = opener                       # Candidate -> an OPEN session, or raises
        self.beliefs = beliefs or av.Beliefs()
        self.policy = policy or av.Policy(rank=av.RANK_CAPABILITY)
        self.prober = prober or av.Prober()
        self.transport = transport
        self._on_note = note                       # optional: a display hook, e.g. the status line
        self.active = None
        self.standby = None
        self.standby_at = 0.0
        self._warming: Optional[asyncio.Task] = None   # STRONG reference: a fire-and-forget task can be
        self._closed = False                           # collected mid-flight, which loses the standby
        self._pending_notes: list = []                 # notes made before a receipt exists to hold them
        self.switches = 0
        self.order: list = []

    def note(self, kind: str, detail: str) -> None:
        """Every continuity decision goes into the RECORD, not only onto a screen.

        These events are the only place a reader can learn that the conversation moved, why, and what
        was held in reserve — so they default to the receipt rather than to a callback nobody passed.
        A display hook is layered on top, never in place of it.

        BUFFERED UNTIL THERE IS A RECEIPT. The most important note of all — which fleets were
        considered, in what order, and why — is made while CHOOSING, before any session exists to write
        it to. A live run showed it being dropped: the lane recorded that a standby was ready and said
        nothing about how the active fleet had been picked, which is the one decision a reader would
        want to audit."""
        try:
            if self.active is not None:
                for k, d in self._pending_notes:
                    self.active.receipt.note(k, d)
                self._pending_notes.clear()
                self.active.receipt.note(kind, detail)
            else:
                self._pending_notes.append((kind, detail))
        except Exception:                             # noqa: BLE001 — bookkeeping never fails a turn
            pass
        if self._on_note is not None:
            try:
                self._on_note(kind, detail)
            except Exception:                         # noqa: BLE001
                pass

    # ── what the server talks to ──
    @property
    def receipt(self):
        return self.active.receipt if self.active else None

    @property
    def model_short(self) -> str:
        return self.active.model_short if self.active else ""

    @property
    def upstream_model(self) -> str:
        return self.active.upstream_model if self.active else ""

    # The name the CLIENT is told, ASSIGNED by the launcher (so an attribute, not a property). It is
    # deliberately the lane's and deliberately stable across a switch: the agent caches the model list,
    # and renaming the model underneath a running conversation would be a second failure mode invented
    # to report the first. What actually served is in the receipt, per machine and per request — where
    # an auditor looks and the agent does not.
    shown_model = ""

    # ── opening ──
    async def open(self):
        """Open the best candidate the evidence and the policy agree on, then warm the next one."""
        async def probe(fleet_id: str):
            if self.transport is None:
                return -1, 0
            p = await self.prober.probe(self.transport, fleet_id)
            return p.instances, p.nonce_depth

        pairs = [(c.fleet_id, c.model_short) for c in self.candidates]
        chosen = await av.choose(pairs, self.policy, self.beliefs, probe,
                                 meta={c.model_short: (c.meta or {}) for c in self.candidates})
        self.order = list(chosen.order)
        self.note("continuity-order", f"{' > '.join(self.order)} — {chosen.reason}")

        last = None
        for short in self.order:
            cand = self._by_short(short)
            if cand is None:
                continue
            try:
                self.active = await self.opener(cand)
            except Exception as e:                    # noqa: BLE001 — try the next one; that is the point
                last = e
                self.beliefs.observed_verify(cand.fleet_id, 0, 1, time.time())
                continue
            self.beliefs.observed_verify(cand.fleet_id, 1, 1, time.time())
            self.note("continuity-open", f"serving from {short}; "
                                         f"{len(self.order) - 1} other fleet(s) behind it")
            self._warm_later()
            return self.active.receipt
        raise last or RuntimeError("no candidate fleet could be opened")

    def _by_short(self, short: str) -> Optional[Candidate]:
        return next((c for c in self.candidates if c.model_short == short), None)

    # ── the standby ──
    def _warm_later(self) -> None:
        """Start warming, at most one at a time, holding a STRONG reference to the task.

        A bare `ensure_future` is only weakly held by the loop, so the standby could be collected
        mid-open and the lane would silently be back to having no fallback at all — the same defect the
        review found in the usage reporter, where what went missing was the data the whole design rests
        on."""
        if self._closed or (self._warming and not self._warming.done()):
            return
        try:
            self._warming = asyncio.ensure_future(self._warm())
        except RuntimeError:                          # no running loop (sync context): warm on demand
            self._warming = None

    async def _warm(self) -> None:
        """Open the next acceptable candidate ahead of need. A switch is then a pointer move rather
        than the 68-second attestation the user would otherwise wait through."""
        if self._closed or self.standby is not None:
            return
        active_short = self.active.model_short if self.active else ""
        for short in self.order:
            if short == active_short:
                continue
            cand = self._by_short(short)
            if cand is None or not self._compatible(cand):
                continue
            try:
                s = await self.opener(cand)
            except Exception:                         # noqa: BLE001 — a standby that will not open is
                continue                              # not an error; try the next, silently
            if self._closed:
                _quietly_close(s)
                return
            self.standby, self.standby_at = s, time.time()
            self.note("standby-ready", f"{short} verified and held in reserve")
            return

    def _compatible(self, cand: Candidate) -> bool:
        """A standby must be able to hold the conversation that would move to it.

        Context length was missing from the first design entirely, and it is the most consequential
        silent degradation available here: failing a long disclosure over to a smaller window truncates
        it mid-document, which is worse than the error being avoided. Unknown context (the relay does
        not publish it today) is treated as compatible rather than blocking every switch — stated as a
        gap rather than hidden as a default."""
        active = self._by_short(self.active.model_short) if self.active else None
        if not active or not active.context_length or not cand.context_length:
            return True
        return cand.context_length >= active.context_length

    # ── the request path ──
    async def messages(self, body: dict):
        return await self._call("messages", body)

    async def chat_completions(self, body: dict):
        return await self._call("chat_completions", body)

    async def _call(self, name: str, body: dict):
        sess = self.active
        resp = await getattr(sess, name)(body)
        status = resp[0]
        fleet = sess.fleet_id
        if status == 200:
            # A 200 IS NOT YET AN ANSWER. The status and headers have not reached the client — the server
            # sends them when it starts iterating — so a stream that dies before producing anything is
            # still recoverable, and that is exactly where a struggling fleet fails: it accepts the
            # request, then never produces a token.
            #
            # So the first chunk is drawn here, before committing. Nothing is held back from the user
            # that they would not have been waiting for anyway: this is the time-to-first-token they are
            # already sitting through. Once a single byte is committed the conversation belongs to that
            # machine and a later failure surfaces — restarting a half-delivered answer would produce a
            # worse artefact than the error it hid.
            resp, empty_fault = await self._commit_on_first_chunk(sess, resp)
            if resp is None:                          # died before producing anything; carried below
                return await self._carry(sess, name, body, empty_fault)
            self.beliefs.observed_serve(fleet, 1, 0, time.time())
            self._freshen_standby()
            return resp
        fault = getattr(sess, "last_fault", "")
        if fault in COUNTS_AGAINST_FLEET:
            self.beliefs.observed_serve(fleet, 0, 1, time.time())
        if fault in SWITCHABLE and await self._switch(fault):
            retried = await getattr(self.active, name)(body)
            if retried[0] == 200:
                self.beliefs.observed_serve(self.active.fleet_id, 1, 0, time.time())
                self.note("carried", f"{sess.model_short} failed ({fault}); "
                                     f"{self.active.model_short} answered — the user saw nothing")
            return retried
        return resp

    async def _commit_on_first_chunk(self, sess, resp):
        """Pull the first chunk. Returns (replayed response, "") or (None, fault) if it died empty."""
        status, headers, stream = resp
        if not hasattr(stream, "__aiter__"):
            return resp, ""                           # non-streaming: already whole
        first = None
        try:
            async for chunk in stream:
                first = chunk
                break
        except Exception:                             # noqa: BLE001
            # A stream that RAISES on its first read produced nothing, so nothing is committed — and it
            # is a fault of the machine serving it, whatever the session managed to record before the
            # exception. Reading last_fault here would usually find "" and send the caller down the
            # path that re-asks the same failing session.
            return None, INSTANCE_FAULT
        if first is None:
            # Ended cleanly with no content. The session's own class if it set one, an instance fault
            # otherwise: an enclave that accepts a request and delivers nothing has failed, and the
            # absence of a label is not the absence of a failure.
            return None, (getattr(sess, "last_fault", "") or INSTANCE_FAULT)
        fault = getattr(sess, "last_fault", "")
        if fault and fault in SWITCHABLE:
            return None, fault

        async def replay():
            yield first
            async for chunk in stream:
                yield chunk

        return (status, headers, replay()), ""

    async def _carry(self, sess, name: str, body: dict, fault: str):
        """The failure path shared by a refused send and a stream that died empty."""
        if fault in COUNTS_AGAINST_FLEET:
            self.beliefs.observed_serve(sess.fleet_id, 0, 1, time.time())
        if fault in SWITCHABLE and await self._switch(fault):
            retried = await getattr(self.active, name)(body)
            if retried[0] == 200:
                self.beliefs.observed_serve(self.active.fleet_id, 1, 0, time.time())
                self.note("carried", f"{sess.model_short} failed ({fault}); "
                                     f"{self.active.model_short} answered — the user saw nothing")
            return retried
        # Nothing could carry it. Hand back a truthful failure rather than re-asking the session that
        # just failed, which is what an earlier version did and which turns one failure into two.
        return 503, {}, _one(b'{"error":{"message":"the enclave produced no answer"}}')

    async def _switch(self, why: str = "") -> bool:
        """Promote the standby. Only ever a pointer move — anything slow happened in the background."""
        if self.standby is None:
            self.note("no-standby", f"{self.active.model_short} failed ({why}) with nothing warmed")
            return False
        if time.time() - self.standby_at > STANDBY_MAX_AGE_S:
            # Older than the session's own re-verification interval: promoting it would use evidence the
            # active session would itself have refused by now.
            stale, self.standby = self.standby, None
            self.note("standby-stale", f"{stale.model_short} held too long to promote; reopening")
            _quietly_close(stale)
            self._warm_later()
            return False
        old, self.active = self.active, self.standby
        self.standby, self.standby_at = None, 0.0
        self.switches += 1
        self.note("switched", f"{old.model_short} -> {self.active.model_short} ({why})")
        self._record_switch(old)
        _quietly_close(old)
        self._warm_later()
        return True

    def _record_switch(self, old) -> None:
        """Carry the machines the previous session used into the receipt this session now owns, so the
        record of the CONVERSATION names every enclave that served it. Without this each session's
        receipt is honest about itself and no artefact is honest about the whole."""
        try:
            prior = list(getattr(old.receipt, "served_by", []) or [])
            for row in prior:
                row = dict(row)
                row["from_previous_session"] = old.receipt.session_id
                self.active.receipt.served_by.insert(0, row)
            # The continuity EVENTS too, not only the evidence. A live run showed the surviving receipt
            # carrying `switched` and `carried` while the decisions that led there — which fleets were
            # considered and why, and that a standby had been verified and held — stayed behind on the
            # receipt nobody reads afterwards. Evidence without the reasoning is half a record.
            carried_kinds = ("continuity-order", "continuity-open", "standby-ready",
                             "switched", "carried", "no-standby", "standby-stale")
            prior_events = [dict(e, from_previous_session=old.receipt.session_id)
                            for e in (getattr(old.receipt, "events", []) or [])
                            if e.get("kind") in carried_kinds]
            self.active.receipt.events[:0] = prior_events
            self.active.receipt.counters["continuity_switches"] = self.switches
            self.active.receipt.note(
                "continuity", f"this conversation began on {old.model_short} "
                              f"({old.receipt.counters.get('requests', 0)} requests) and moved here")
        except Exception:                             # noqa: BLE001 — bookkeeping must never fail a turn
            pass

    def _freshen_standby(self) -> None:
        if self.standby is not None and time.time() - self.standby_at > STANDBY_MAX_AGE_S:
            stale, self.standby = self.standby, None
            _quietly_close(stale)
        if self.standby is None:
            self._warm_later()

    def close(self):
        """SYNCHRONOUS, because ConfidentialSession.close is and the launcher calls it without await.
        Returns the active receipt, as a single session does, so this stays a drop-in."""
        self._closed = True
        if self._warming is not None and not self._warming.done():
            self._warming.cancel()
        for s in (self.standby, self.active):
            if s is not None:
                _quietly_close(s)
        try:
            self.beliefs.save()
        except Exception:                             # noqa: BLE001
            pass
        return self.active.receipt if self.active else None


async def _one(payload: bytes):
    yield payload


def _quietly_close(session):
    try:
        return session.close()
    except Exception:                                 # noqa: BLE001 — closing a spare must never raise
        return None
