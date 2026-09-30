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

---

# Adversarial review 1 — privacy and failure modes (2026-09-30)

Findings that **falsify parts of the design above**. Kept verbatim in substance; the design's order of
work is wrong until these are folded in.

## Fatal

**F1. A sealed request is not portable across fleets.** `translate.to_openai`/`native_openai` bake
`{"model": upstream_model}` into the body (translate.py:163, 481) at session.py:414/437 — *before*
`_send_sealed`, which seals that same dict on both attempts (331). §6's "switch fleet and retry inside
the lane" would send fleet A's model name to fleet B's enclave. The request shape is model-specific too
(`thinking_key_for`, translate.py:192). Cross-fleet failover must re-enter at `messages()` /
`chat_completions()`, not inside `_send_sealed`. The "one call site away" framing does not apply.

**F2. `fleet_id` is read outside the lock that pins the instance.** session.py:330 takes `(pinned, nonce)`
under `_lock`; 342-343 reads `self.fleet_id` outside it. Inert while the field is frozen; a live,
intermittent mismatch the moment fact 3 makes it mutable. Carry `fleet_id` inside `Pinned`.

**F3. `_verified_at` is one session-wide clock** (78, set at 109/306, gating 210/273). Per-fleet
selection would verify fleet B, mark the clock fresh, then seal to a fleet-A instance whose evidence is
older than `REVERIFY_EVERY_S` — breaking the one invariant the lane sells. Verification state must be
per-fleet BEFORE §6. Also: `_absorb_pool` replaces the pool wholesale (171), so each switch discards the
other fleet's nonces and every switch-back costs a full re-verify — the code calls it "the slow part"
and measures 68 s.

**F4. §7 fixes the wrong fields.** `lane_preamble` (receipt.py:164-186) is prepended to EVERY request and
asserts `The assistant in this session is {upstream_model}`, `instance {id[:8]}`, the passed-check list,
and `never say otherwise`. `_pin` rewrites `receipt.instance` (177), `checks` (179), `attestation` (191),
`limitations` (202) — but `upstream_model` and `model_short` are **never rewritten** (60-61). A silent
cross-model failover therefore instructs the NEW model to tell a patent attorney it is the OLD model, on
the OLD instance, and never to say otherwise. Worse than a session that failed, by this document's own
standard. The verdict vocabulary has no state for it either (`unopened|confidential|refused|degraded`).

## Serious

**S5. Silent re-pricing.** `self.price` is fixed at `__init__` (71); `_account` computes
`estimated_cost_usd` from it (607-611). A cross-fleet switch leaves the receipt's running cost at the
wrong rate with nothing saying so. `model_short` is also echoed into the response itself (534, 599), so
the API answer names the model the user asked for regardless of which produced the tokens.

**S6. `context_length` is ignored.** `models()` already returns it (transport.py:182, 233). Failing a
380k-token disclosure over to a smaller-context fleet truncates or fails hard mid-document. For this
client that is the most consequential silent degradation, and the design did not mention it.

**S7. The prefix cache dies on INSTANCE switches too.** The preamble embeds `instance {id[:8]}` and is
recomputed per request from the live receipt (414, 437), so the system prefix changes on every instance
rotation — already happening today, uncounted, via `_RETRY_ON_OTHER_INSTANCE`.

**S8. §2 would hand the untrusted relay signals derived from DECRYPTED bytes.** Most classes are not new:
for 400/402/429/5xx the relay produced the status itself. Three are new, and they are the ones behind the
AEAD:
  - `reply_unopenable` — a ChaCha20-Poly1305 auth failure. Not a padding oracle, but a per-attempt
    confirmation channel for an active relay calibrating a key-substitution or downgrade attempt.
  - `stream_truncated` — whether the *plaintext* ended with `[DONE]`. A one-bit fact about content.
  - `Refused` from `_take_nonce` — **this device's own attestation verdict**. A relay that also serves the
    build list (transport.py:220-226) could A/B test which forged builds a given client accepts and read
    the answer back.
  Sharpening it: `report_usage` is a **no-op on DirectOperator** (143-145); it exists only where
  InferRoute is the untrusted party. **Rule: the outcome vocabulary is closed and enumerated in code, and
  no class derivable from decrypted bytes goes on the wire.**

**S9. §2 reports turns that never left the device** (seal_failed 416/439, `Refused` 332), telling the
relay the user composed a turn and hit send while nothing went out.

**S10. §5's "costs the user nothing" is false against our own disclosure sentence.** Each probe is an
authenticated, session-tagged `instances()` call. It subdivides the think-time interval the product
discloses as "timing". Constraint to write down now: **probes fire on a fixed wall-clock schedule, never
on a user-activity trigger**, or it becomes keystroke-adjacent. Unanalysed: `instances()` is also the
nonce source (157-170); a probe may invalidate the pool the session holds.

**S11. The 2am one.** `_account` fires `asyncio.ensure_future(report_usage(...))` (613) — no strong
reference (GC can drop it mid-flight, biasing the very sample §3 learns from) — on the SAME
`httpx.AsyncClient` as `invoke`, `instances` and attestation. At the measured 95%-failure rate each
failure spawns a 10 s POST; if the relay is the sick component those hang while more are created, and the
availability telemetry competes for connections with the requests it measures. Bounded queue, single
drain task, hard in-flight cap, separate client.

**S12. §6 makes the availability mechanism a new cause of unavailability.**
`REVERIFY_FAILURES_ALLOWED = 3` (291-304) counts consecutive failures; each switch needs a fresh
`fetch_and_verify` + online pass against Intel and NVIDIA (attest.py:551, 568). A 2am flap — or those
services rate-limiting us *because* we now attest far more often — trips it, the daemon's `_watch` sees
`heartbeat() == False` and shuts the endpoint down after `GRACE_S = 20`. No per-fleet failure accounting,
no backoff on switching.

## Cosmetic

**C13.** Retry double-counts `plaintext_bytes_sealed_here`/`ciphertext_bytes_sent` against a flat
`requests` (336-339), so the ratio an auditor reads as compression is compression plus an unstated retry
multiplier.

**C14.** No AAD on the sealed request (e2ee.py:136, 141): `fleet_id`, `instance_id`, nonce, stream flag
and path travel as rewritable headers. Misrouting fails harmlessly (no decapsulation), but a relay can
replay a captured sealed request under a fresh nonce and have the enclave process the disclosure again —
no read access, but not what the receipt will say. Binding `{fleet_id, instance_id, nonce, model}` into
the AAD would also turn F1 into a loud failure instead of a quiet one.

## Checked and NOT issues

- A 400 does not correlate with what the attorney typed: `translate.py` contains zero `raise`s;
  `to_openai`/`native_openai` are total and silently drop what they do not understand.
- Context-overflow leaking length: strictly weaker than the `len(sealed.blob)` the relay already has.
- Latency reporting: already sent today, and the relay times its own forwarded request anyway.
- `session_id` correlation: `x-inferroute-session` is on every relay call already.
- The §3 attribution fix (400/402 stop counting against fleets): correct and overdue. **Shipped, 58de466.**

---

# Adversarial review 3 — the decision procedure (2026-09-30)

Run against all 1,006 receipts on disk, not against the doc. It corrects review 1, corrects this
document, and finds that **the machinery shipped tonight never executes**.

## F-A. `health_ordered` is a no-op on every fleet. VERIFIED INDEPENDENTLY.

The gate is `expected >= 1.0` where `expected = live x yield x success`. Scored on today's real data:

    deepseek-v4-flash   4 live  y 0.95  s 1.00   3.79  PASS
    glm-5.1            18 live  y 0.30  s 0.58   3.07  PASS
    kimi-k3             4 live  y 0.84  s 0.85   2.85  PASS
    kimi-k2.6          12 live  y 0.22  s 0.94   2.47  PASS
    glm-5.2             3 live  y 0.88  s 0.52   1.37  PASS     <- 49% request failure

Minimum 1.37. Every fleet passes, so the function returns after ONE probe and the yield, success,
interval and tie-break code never runs on any candidate but the first. glm-5.2 — the fleet that motivated
this whole line of work — clears the "looks fine, spend nothing more" gate with 37% margin.

## F-B. Dimensional error: a bigger fleet is allowed to fail more

`live` is a count, `yield` and `success` are rates, and the product is thresholded at 1.0. Inverting the
gate gives the failure rate at which each fleet is first noticed: glm-5.2 (3 instances) 62%, kimi-k3 (4)
70%, **glm-5.1 (18) 81%**. Backwards from the user's view. And with `live` a small integer the score moves
in steps of `y x s`, so the gate is really "is live >= 2 or 3", quantized.

## F-C. The aging-out cliff: the worst fleet becomes the best by being forgotten

`_YIELD_SCAN = 400` against 1,006 receipts, never pruned. When a model's last receipt leaves the window
`fleet_yield` returns `(1.0, 0)` and the interval `(0.0, 1.0)`. glm-5.1 today: 12/50 instances verify, 56%
request failure. A week from now, with its last receipts pushed out, it would score `18 x 1.0 x 1.0 = 18`
— **top of the list by a factor of five, for having been avoided.** The estimator steps discontinuously
from "known bad" to "assumed perfect", fastest for the models used least.

## F-D / F-E. The separation rule cannot fire, and the unsampled arm reverts to optimism

A 10-request session must show SEVEN visible failures before a switch is permitted. In the 31% phase of
the measured incident it never fires. And once you leave a fleet you stop generating evidence about it, so
its estimate decays back toward the "fine" prior while the fleet you are on is judged on real failures:
measured, glm-5.1 reads 1.000 under every decay setting because its decayed evidence weight is exactly
zero. **The fleets you avoid recover their reputation fastest.**

## Attempted fix, and why it was REVERTED

Replacing the score with a probability — `P(at least one instance verifies) x P(the request succeeds)`,
gated at 0.90 — fixes F-A and F-B and ranks correctly (glm-5.2 0.52 FAIL, glm-5.1 0.57 FAIL, deepseek
1.00 PASS). It was written, measured, and reverted, because `1 - (1-y)^live` saturates to 1.0 for any
decent yield and `live >= 3`, which collapses the yield interval to a width of 0.01. All uncertainty then
sits in `success`, none of it is propagated, and the tie rule can never fire — so preference never wins
and the chooser becomes a hair-trigger acting on false precision. On the live data it reordered away from
the user's chosen default on fake intervals.

**That is worse than inert.** An inert gate follows the user's stated preference, which is a safe
default; a hair-trigger one overrides it on manufactured confidence. Reverted rather than defended.

The correct form is the reviewer's: a single Beta posterior per fleet with exponential forgetting
(`a <- rho*a + x`, `b <- rho*b + (1-x)`), so the point estimate and the interval come from ONE object,
plus **returning the evidence weight `a+b` at every decision point** and refusing to rank a fleet first
when its weight is at the prior floor without a live probe first. That pairing is what makes decay safe;
decay alone reintroduces F-E.

## Corrections to this document

- **Fact 1 was slightly wrong.** `_account` is not reached only on success: session.py:507-512 falls
  through to it after a `stream_truncated`, so one failure class already reaches the relay labelled as
  usage, with a latency inflated by the truncation — and that is the sample §3 wanted as its leading
  indicator.
- **The switching-cost figure was the weakest available example.** 381,771 input against 38,169 cached is
  a 9.1% hit rate; fleet-wide across 1,006 receipts it is **81.0%**. And a switch costs one cold prefill
  of the current context — mean 33,169 tokens, about **$0.01** — not a session's tokens. The hysteresis
  here is calibrated as though it were a dollar or more. An economic rule (switch iff
  `remaining_requests x delta_p_fail x cost_of_a_visible_failure > cost_of_switching`) breaks even around
  **delta_p < 0.01**, where the separation rule demands 0.3-0.5. Roughly 40x too conservative, and every
  unit of that conservatism is paid in failures the attorney sees.

## Claim of review 3 that does NOT hold

"`_err()` never calls `receipt.save()`, so failures are systematically under-recorded on disk." Measured:
**371 receipts carry a non-zero error count, 1,787 errors in total.** Counters written by `_err` reach
disk via the save in `_account` on interleaved successes and via `close()`. The residual risk is real but
narrower than stated: a process KILLED during a terminal run of failures loses that tail. The related
claim that "zero of 1,006 receipts carry any `errors_*` field" is true and has a simpler cause — those
fields were added hours ago.

## Signals already on disk that nothing reads

`receipt.events[]` carries timestamped `reverified 3/4 instances` rows — a within-session yield time
series, already recorded, while `fleet_yield` reads one snapshot per receipt taken at open.
`counters.instance_switches` (56 of the last 400 receipts). `nonce-rejected` events (85), a distinct fault
pooled into one integer. Per-instance attribution, discarded into a fleet average. Nonce depth, collapsed
to a boolean inside the expression that computes it. `verdict`/`refusal`, a labelled terminal outcome no
scorer reads.

**A time-decayed model could be backfitted from the receipts already on disk, with no new instrumentation.**
