# Availability for a live-critical sealed session

**Henry, 2026-09-30:** "a completely optimal design on this, where any prior potential information is
used to make the best informed decision when it comes to model selection for this specific kind of task
where live availability is critical. not only the choice of the model at the beginning of the conv but
handling as proactively as possible the fallbacks when current model used becomes unavailable."

Written after he said of the current system: *"this doesn't sound like a smart system."* He is right.
This document says why, precisely, and what replaces it.

## The defect class

**Every layer reconstructs, by heuristic, information another layer holds as fact.**

| Holds the fact | Guesses it | How |
|---|---|---|
| the lane — an HTTP `status` int | the page | 22 substring tests over a 338-string vocabulary |
| the relay — every client's traffic | the client | reads its own receipt files off disk |
| the error's producer — whether it can clear | the consumer | a regex list, extended per incident |

Everything shipped tonight added guesses to that pile. The design below removes the need to guess.

## Measured facts this rests on

1. `_account()` is called from four sites, **all success paths** (session.py:512, 529, 575, 600). It is
   the only caller of `report_usage`. **The relay is fed successes and never failures** — a fleet failing
   95% of requests does not look worse to it, it looks *quieter*.
2. `_account` receives `latency_ms`, forwards it to the relay, and **stores it nowhere locally**. A
   leading indicator of degradation, computed and dropped.
3. `model_short`, `upstream_model`, `fleet_id` are fixed in `__init__` (session.py:57-66). A session
   cannot change model, whatever happens to the fleet.
4. `receipt.instance` and `receipt.attestation` are written **once**, at open (177, 191). `self.pinned`
   rotates afterwards (230, 234, 312, 361). **The record names one machine while several served.** Every
   one was verified, so this is not a security failure — it is an under-report in the one dimension this
   product sells.
5. Selection (`health_ordered`) runs **once, at session open**. glm-5.2 degraded from 0% to 95% request
   failure over one day; a session opened at 10:00 stayed on it.
6. `fleet_yield` measures instances that VERIFY. On 2026-09-30 glm-5.2 held a perfect 3/3 while failing
   95% of requests: rated best exactly when worst.
7. All errors currently count against the fleet, including 400 (our malformed request) and 402 (account
   billing). **A client bug would demote every fleet.**

## Principles

1. **Decide on typed facts, never on prose.**
2. **Decide per request, not per session.**
3. **Feed the aggregator everything, especially failures.**
4. **Recency beats volume** — fleets are non-stationary; a flat window cannot see a collapse.
5. **Attribute correctly** — instance, fleet, account, or us. Only the first two are evidence about a fleet.
6. **Recover in the lane, invisibly.** The page is the last resort, not the first.
7. **Switching costs the prefix cache** — require evidence and hysteresis; never flap.
8. **The record follows the machines.** If several served, the record says so.

## The design

### 1. A typed outcome at the producer

Every request ends in an `Outcome` carrying a class, not a sentence:

    ok                 latency_ms, usage
    instance_fault     this machine: 500/502/503/504, stream drop, unopenable reply
    fleet_fault        no eligible instance; all verified instances failing
    account_fault      402 at auth, 401, 403        — evidence about NOTHING
    client_fault       400 malformed, seal failure   — evidence about US
    unknown            anything not classified

The class drives retry, switching and scoring. The sentence remains for humans. A stable code travels in
the error body so the page matches one code exactly instead of 22 substring tests, and an unknown code
reads as genuinely unknown rather than "our regexes missed".

### 2. Report every outcome, not just usage

`report_usage` becomes `report_outcome`, called on success **and** failure, carrying
`{fleet_id, instance_id, model, class, latency_ms, usage?}`. This is the precondition for the relay ever
answering authoritatively, and it is one call site away today.

### 3. A time-decayed availability model

Per fleet, an EWMA over wall-clock, not a flat count:

    success   half-life ~10 min within a session, ~6 h persisted across sessions
    latency   same, as the leading indicator (fleets slow before they fail)

Only `instance_fault` and `fleet_fault` count against a fleet. Shrinkage toward "fine" stays, so a fleet
is demoted on evidence and never for being new. This replaces the flat 10-observation window, which is
blind to time and therefore blind to exactly the failure we measured.

### 4. Selection per request, with hysteresis

Before each request, if the current fleet's decayed estimate drops below a floor **and** a candidate's
lower confidence bound exceeds the current's upper bound (the separation rule already built), switch.
Require sustained evidence, not one failure, because switching costs the prefix cache — measured at
381,771 input tokens against 38,169 cached in one real session.

### 5. Proactive probing in idle time

A chat session is mostly idle — the user is reading or typing. Use it: re-probe the current fleet and the
top alternative between turns, and pre-warm a replacement when the current one is marginal. This is the
"switch ahead of time" the current design cannot do, and it costs the user nothing.

### 6. Silent failover inside the lane, including across fleets

On `instance_fault`: drop the instance, retry on another verified instance of the same fleet (exists
today). If the fleet has no healthy instance: **switch fleet and retry, transparently**. Requires the
session's fleet to become mutable — fact 3.

### 7. The record follows the machines

This is the honesty constraint, and it is why fact 4 must be fixed before fact 3 ships.

`receipt.attestation` becomes a **list** — one entry per machine that served, each with the requests it
answered. The lane preamble stops naming a single instance as though it were the only one. A session that
switched model says so, with the attestation for each.

Every machine is verified before use either way; what changes is that the record stops under-reporting
which ones. Without this, mid-session switching would make the record say something untrue, and a record
that says something untrue is worse than a session that failed.

## Order of work

1. Typed outcomes + stable code (removes the guessing; unblocks everything)
2. Report every outcome to the relay (unblocks the authoritative answer)
3. Attribution fix — 400/402 stop counting against fleets (a correctness bug shipped tonight)
4. Time-decayed model replacing the flat window
5. Record follows the machines (honesty precondition)
6. Mutable fleet + in-lane cross-fleet failover
7. Idle-time probing
8. Relay endpoint; then retire the client-side epidemiology it stands in for

1-4 are self-contained and safe. 5-6 change what the record claims and must not be rushed.
