"""What we believe about each fleet, and which one to send the next request to.

Henry, 2026-09-30, of the version this replaces: "this doesn't sound like a smart system." It was not.
Three adversarial reviews and docs/DESIGN-availability-2026-09-30.md record why in full; the four faults
that shaped this module:

  1. THE SELECTOR NEVER RAN. The gate was `live x yield x success >= 1.0`, which every fleet cleared
     (minimum 1.37 on real data) — so the ranking returned after one probe and nothing else executed.
     A count multiplied by two rates is not a probability, and thresholding it at 1.0 meant a BIGGER
     fleet was allowed to fail more: 81% for an 18-instance fleet, 62% for a 3-instance one.

  2. AN AGEING CLIFF. Evidence was the last 10 observations within the last 400 receipt files. When a
     fleet's records fell out of that window it scored PERFECT — so the fleets you avoid because they
     are broken recover their reputation fastest, and rank top for having been avoided.

  3. CONFIDENCE GREW ON STALE DATA. A Wilson interval narrows as 1/sqrt(n) whatever the ages of the n.
     Measured: one fleet's 10-receipt window spanned a run from 100% success to 5%, and the interval
     over it excluded both ends. More history made the system more certain about a staler average.

  4. THE UNSAMPLED ARM REVERTED TO OPTIMISM. Stop using a fleet and you stop generating evidence about
     it, so it decays back toward "fine" while the fleet you are on is judged on real failures.

The fix for 2, 3 and 4 is the same object: a Beta belief with EXPONENTIAL FORGETTING. Evidence decays
with wall-clock, so `a + b` is an effective sample size that SHRINKS when a fleet is not being observed.
That gives three properties at once, none of which needed a separate rule:

  - no cliff: evidence fades smoothly instead of falling out of a window
  - confidence is bounded by recent throughput: at arrival rate L and half-life H, `a + b` saturates
    near L*H/ln2, so a drifting process can never be measured to arbitrary precision
  - an abandoned fleet's interval WIDENS rather than its estimate improving, so it ties with everything
    and the caller's stated preference decides — instead of winning on a prior

And the rule that makes decay safe, without which decay alone reintroduces fault 4: a fleet whose
evidence has decayed to the prior is UNKNOWN, not fine, and must be probed live before it can be
ranked first.
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

# Half-lives, in seconds. Chosen against the measured incident rather than by feel: one fleet went from
# 0% to 95% request failure over about nine hours, so a memory of hours (not minutes, not days) is what
# tracks it. A 10-minute half-life — proposed in the first draft — leaves an effective sample of ~3 at
# typing pace, which cannot support any judgement at all.
SERVE_HALF_LIFE_S = 6 * 3600.0
VERIFY_HALF_LIFE_S = 12 * 3600.0      # attestation health moves more slowly than request health

# A weak prior, deliberately. The old one was 8 pseudo-requests all successful, which took 8 consecutive
# total failures to reach 0.5 and 24 to reach 0.25 — far too slow against a fleet that degrades in hours.
# Weak enough to move, strong enough that one bad request does not condemn a fleet.
PRIOR_A = 1.0
PRIOR_B = 1.0
PRIOR_STRENGTH = PRIOR_A + PRIOR_B

# Below this much decayed evidence a fleet is UNKNOWN rather than healthy: it has not been observed
# recently enough to say anything, and the caller must probe before ranking it first.
MIN_EVIDENCE = 2.0

Z = 1.96                               # 95%


def _wilson(p: float, n: float) -> Tuple[float, float]:
    """A Wilson score interval on an EFFECTIVE sample size.

    Wilson is defined for an integer count; `n` here is `a + b` after decay, so it is fractional and
    shrinks with staleness. That is the point: the same formula then stops being able to express
    confidence the evidence no longer supports, which is fault 3 above, and it needs no extra rule.
    """
    if n <= 0:
        return 0.0, 1.0
    denom = 1.0 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / denom
    half = (Z / denom) * math.sqrt(max(p * (1 - p) / n + Z * Z / (4 * n * n), 0.0))
    return max(0.0, centre - half), min(1.0, centre + half)


@dataclass
class Belief:
    """Beta(a, b) with exponential forgetting. `a` is evidence for, `b` against, both decaying."""
    half_life_s: float
    a: float = PRIOR_A
    b: float = PRIOR_B
    t: float = 0.0                     # when a and b were last brought up to date

    def _decay_to(self, at: float) -> None:
        if self.t and at > self.t:
            rho = 0.5 ** ((at - self.t) / self.half_life_s)
            # The PRIOR is not forgotten — only the evidence on top of it. Decaying the prior too would
            # let a and b fall toward zero, where every interval is [0, 1] and the estimate is undefined.
            self.a = PRIOR_A + (self.a - PRIOR_A) * rho
            self.b = PRIOR_B + (self.b - PRIOR_B) * rho
        self.t = max(self.t, at)

    def observe(self, successes: float, failures: float, at: float) -> None:
        if successes < 0 or failures < 0:
            return
        self._decay_to(at)
        self.a += successes
        self.b += failures

    def at(self, now: float) -> "Belief":
        """A copy brought up to `now`, so reading never mutates the stored belief."""
        c = Belief(self.half_life_s, self.a, self.b, self.t)
        c._decay_to(now)
        return c

    @property
    def evidence(self) -> float:
        """Decayed observations on top of the prior. Near zero means UNKNOWN, never means fine."""
        return max(0.0, self.a + self.b - PRIOR_STRENGTH)

    @property
    def p(self) -> float:
        n = self.a + self.b
        return self.a / n if n > 0 else 0.5

    def interval(self) -> Tuple[float, float]:
        return _wilson(self.p, self.a + self.b)

    def as_dict(self) -> dict:
        return {"a": round(self.a, 6), "b": round(self.b, 6), "t": self.t}


@dataclass
class FleetView:
    """Everything believed and observed about one fleet, at one moment."""
    fleet_id: str
    serve: Belief
    verify: Belief
    live_instances: int = -1           # -1 = could not ask. NEVER conflated with 0.
    nonce_depth: int = 0               # total nonces across instances: headroom, not a boolean
    probed_at: float = 0.0

    @property
    def known(self) -> bool:
        """Has this fleet been observed recently enough to be judged at all?"""
        return self.serve.evidence >= MIN_EVIDENCE

    def p_usable(self) -> float:
        """P(the next request is served). Bounded in [0,1] and independent of fleet SIZE — the old score
        multiplied a rate by an instance count, which let a big broken fleet outrank a small healthy one.

        Fleet size enters only as a gate: with no verified instance there is nothing to send to."""
        if self.live_instances == 0:
            return 0.0
        return self.serve.p * self.verify.p

    def interval(self) -> Tuple[float, float]:
        slo, shi = self.serve.interval()
        vlo, vhi = self.verify.interval()
        # Both factors carry uncertainty, so both are propagated. The version this replaces scaled one
        # interval by the other's POINT estimate, which dropped the larger source of variance and made
        # intervals narrower — so ties became rarer and the selector acted on differences more often.
        # The error ran against its own stated purpose.
        return slo * vlo, shi * vhi


# ── the selection policy ─────────────────────────────────────────────────────────────────────────
#
# Henry, 2026-09-30: "prioritizing smartest models as a setting given to server so that in other use
# case we can also prioritize in the other way around, for this agent we want the biggest models when
# they are available."
#
# So the ORDER a caller wants and the AVAILABILITY we measure are separate concerns, and this module
# keeps them separate. A policy says which fleet a caller would rather have; the beliefs say which ones
# can actually serve. Probant ranks by capability because the user's survey is worth the best
# model available; a cheap batch job can pass RANK_COST against the same beliefs and get the opposite
# order out, with no change here.
RANK_CAPABILITY = "capability"         # biggest/ablest first — Probant
RANK_COST = "cost"                     # cheapest first
RANK_PREFERENCE = "preference"         # exactly the order the caller listed

# Capability, when the operator does not tell us. Measured 2026-09-30: /confidential/models returns only
# {chute_id, fleet_id, name} — the relay DROPS the context_length and quantization that the upstream
# catalogue carries, so there is nothing authoritative to rank by yet. This table is the stopgap and is
# explicitly the weakest part of this module: it is a judgement, not a measurement.
#
# The server should own it. When /confidential/models grows `capability` (or context_length and
# parameter count to derive it from), `capability_of` uses that and this table stops being consulted —
# which is the setting Henry asked for, in the place he asked for it.
_CAPABILITY_FALLBACK = {
    "kimi-k3": 100, "kimi-k2.6": 90, "glm-5.2": 80, "glm-5.1": 70, "deepseek-v4-flash": 40,
}


def capability_of(model_short: str, meta: Optional[dict] = None) -> float:
    """The operator's number if it sends one, ours only if it does not.

    Order of trust: an explicit `capability`, then context_length as a proxy (a longer window is a
    bigger model often enough to rank by, and it is the field the upstream catalogue actually has),
    then the local table, then neutral. A model nobody has an opinion about sorts mid-table rather than
    last, so an unknown NEW model is not permanently un-choosable."""
    m = meta or {}
    for key in ("capability", "capability_rank"):
        v = m.get(key)
        if isinstance(v, (int, float)):
            return float(v)
    ctx = m.get("context_length")
    if isinstance(ctx, (int, float)) and ctx > 0:
        return float(ctx) / 1000.0
    return float(_CAPABILITY_FALLBACK.get(model_short, 50))


@dataclass
class Policy:
    """How a caller wants fleets ordered, and how good is good enough."""
    rank: str = RANK_PREFERENCE
    floor: float = 0.80                # the service level a fleet must clear to be used at all
    # A fleet whose lower bound clears this is good enough to stop looking — a SERVICE LEVEL, a
    # probability, not the "expected usable instance count >= 1.0" that every fleet passed.
    good_enough: float = 0.90

    def key(self, short: str, meta: Optional[dict], preference_index: int) -> tuple:
        if self.rank == RANK_CAPABILITY:
            return (-capability_of(short, meta), preference_index)
        if self.rank == RANK_COST:
            return (capability_of(short, meta), preference_index)
        return (preference_index,)


# ── the store, and what it learns from ───────────────────────────────────────────────────────────

def _ts(value) -> float:
    """An ISO-8601 stamp as epoch seconds, or 0. Receipts and events both carry Zulu times."""
    if not value:
        return 0.0
    import datetime as _dt
    try:
        s = str(value).replace("Z", "+00:00")
        return _dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


class Beliefs:
    """Per-fleet beliefs, persisted, and backfilled from the receipts already on disk.

    The backfit matters more than it looks. Three reviews all landed on the same point: the monitoring
    this product needs is ALREADY BEING WRITTEN and nothing reads it. `receipt.events[]` carries
    timestamped `reverified 3/4 instances verified` rows — a within-session attestation time series, 37
    of them on this device — while the old estimator read ONE snapshot per receipt, taken at open, and
    then complained it could not see a collapse. `no-eligible-instance` (33) and `reverify-failed` (4)
    are labelled failures nothing scored. This class reads all of it, with each row weighted by its own
    timestamp, so a new install is not starting from zero and today's belief reflects today.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else (
            Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
            / "confidential" / "availability.json")
        self.serve: Dict[str, Belief] = {}
        self.verify: Dict[str, Belief] = {}
        self.models: Dict[str, str] = {}        # fleet_id -> model_short, for the policy
        self._loaded_through = 0.0

    def _s(self, fleet: str) -> Belief:
        return self.serve.setdefault(fleet, Belief(SERVE_HALF_LIFE_S))

    def _v(self, fleet: str) -> Belief:
        return self.verify.setdefault(fleet, Belief(VERIFY_HALF_LIFE_S))

    # ── learning ──
    def observed_serve(self, fleet: str, ok: int, failed: int, at: float) -> None:
        self._s(fleet).observe(ok, failed, at)

    def observed_verify(self, fleet: str, eligible: int, total: int, at: float) -> None:
        if total > 0 and 0 <= eligible <= total:
            self._v(fleet).observe(eligible, total - eligible, at)

    def backfit(self, receipts_dir: Optional[Path] = None, *, limit: int = 2000) -> int:
        """Replay every receipt in timestamp order. Returns how many rows were learned from."""
        d = Path(receipts_dir) if receipts_dir else self.path.parent / "receipts"
        try:
            files = sorted(d.glob("*.json"))[-limit:]
        except OSError:
            return 0
        rows: list[tuple[float, str, str, tuple]] = []
        for f in files:
            try:
                r = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            fleet = r.get("fleet_id") or ""
            if not fleet:
                continue
            short = r.get("model_short") or ""
            if short:
                self.models[fleet] = short
            opened = _ts(r.get("started_at"))
            ended = _ts(r.get("ended_at")) or opened

            fl = r.get("fleet") or {}
            inst, elig = fl.get("instances"), fl.get("eligible")
            if isinstance(inst, int) and isinstance(elig, int) and inst > 0:
                rows.append((opened, fleet, "verify", (elig, inst)))

            # The within-session series nothing has ever read.
            for e in (r.get("events") or []):
                kind, at = e.get("kind"), _ts(e.get("ts")) or opened
                detail = str(e.get("detail") or "")
                if kind == "reverified":
                    m = __import__("re").match(r"\s*(\d+)/(\d+)\s+instances verified", detail)
                    if m:
                        ok_n, tot_n = int(m.group(1)), int(m.group(2))
                        if tot_n > 0:
                            rows.append((at, fleet, "verify", (ok_n, tot_n)))
                elif kind in ("no-eligible-instance", "reverify-failed", "pinned-failed-reverify"):
                    rows.append((at, fleet, "verify", (0, 1)))
                # `nonce-rejected` is deliberately NOT scored: a stale nonce pool is this client's
                # problem, not the enclave's, and the code that handles it says so. Pooling it into a
                # fleet's record was one of the ways the old estimator blamed fleets for our state.

            c = r.get("counters") or {}
            reqs = c.get("requests")
            errs = c.get("errors_fleet", c.get("errors"))
            if isinstance(reqs, int) and reqs > 0 and isinstance(errs, int):
                bad = min(max(errs, 0), reqs)
                rows.append((ended, fleet, "serve", (reqs - bad, bad)))

        rows.sort(key=lambda t: t[0])                 # chronological: decay only makes sense in order
        for at, fleet, kind, payload in rows:
            if not at:
                continue
            if kind == "verify":
                self.observed_verify(fleet, payload[0], payload[1], at)
            else:
                self.observed_serve(fleet, payload[0], payload[1], at)
        self._loaded_through = rows[-1][0] if rows else 0.0
        return len(rows)

    # ── reading ──
    def view(self, fleet: str, now: Optional[float] = None) -> FleetView:
        t = now or time.time()
        return FleetView(fleet_id=fleet, serve=self._s(fleet).at(t), verify=self._v(fleet).at(t))

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "v": 1,
                "serve": {k: v.as_dict() for k, v in self.serve.items()},
                "verify": {k: v.as_dict() for k, v in self.verify.items()},
                "models": self.models}, indent=1))
            os.replace(tmp, self.path)
        except OSError:
            pass                                       # telemetry must never break a session

    def load(self) -> bool:
        try:
            d = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return False
        for key, store, hl in (("serve", self.serve, SERVE_HALF_LIFE_S),
                               ("verify", self.verify, VERIFY_HALF_LIFE_S)):
            for fleet, b in (d.get(key) or {}).items():
                try:
                    store[fleet] = Belief(hl, float(b["a"]), float(b["b"]), float(b["t"]))
                except (KeyError, TypeError, ValueError):
                    continue
        self.models.update(d.get("models") or {})
        return True


# ── choosing ─────────────────────────────────────────────────────────────────────────────────────

@dataclass
class Choice:
    order: list                        # fleets, best first, unusable ones last
    reason: str                        # one line, for the receipt and the panel
    probed: list = field(default_factory=list)
    views: dict = field(default_factory=dict)


async def choose(candidates, policy: Policy, beliefs: Beliefs, probe, *,
                 meta: Optional[dict] = None, now: Optional[float] = None) -> Choice:
    """Order `candidates` (fleet_id, model_short) for a caller who wants `policy`.

    THE RULE THAT MAKES DECAY SAFE: evidence can DEMOTE a fleet, but the ABSENCE of evidence never does.

    A fleet whose record has decayed to the prior is UNKNOWN, and unknown is not bad — ranking it last
    would mean a fleet we stopped using can never earn a record again, which is the trap the previous
    version fell into from the other side (it ranked them FIRST, at a perfect score, for having been
    avoided). So an unknown fleet is probed live: if it answers with instances holding nonces it stays
    eligible at whatever rank the policy gives it, and the session's own requests then re-earn its
    record within minutes. If it does not answer, it is out — measured, not assumed.

    A fleet with evidence BELOW the floor is demoted however much the caller wants it. That is the one
    direction measurement is allowed to override preference, and it is the direction that protects the
    user: glm-5.2 sits at 0.54 with 255 units of evidence, and no capability ranking should send a
    user's survey there.
    """
    t = now or time.time()
    meta = meta or {}
    pairs = list(candidates)
    ordered = sorted(range(len(pairs)), key=lambda i: policy.key(pairs[i][1], meta.get(pairs[i][1]), i))

    usable: list[tuple[tuple, str]] = []
    unusable: list[tuple[tuple, str]] = []
    probed: list[str] = []
    views: dict = {}
    reason = ""

    for i in ordered:
        fleet, short = pairs[i]
        v = beliefs.view(fleet, t)
        views[short] = v
        lo, _hi = v.interval()

        if v.known and lo >= policy.good_enough:
            usable.append(((policy.key(short, meta.get(short), i)), short))
            reason = reason or f"{short}: measured {v.serve.p:.0%} of requests served, {v.serve.evidence:.0f} recent observations"
            break                                      # evidence is enough; spend nothing more

        if v.known and v.serve.p < policy.floor:
            unusable.append(((policy.key(short, meta.get(short), i)), short))
            reason = reason or f"{short} set aside: {v.serve.p:.0%} served over {v.serve.evidence:.0f} observations"
            continue

        # UNKNOWN, or known-but-middling: ask the fleet itself before judging it.
        live, depth = -1, 0
        try:
            live, depth = await probe(fleet)
        except Exception:                              # a probe that fails is "could not ask", never "bad"
            live, depth = -1, 0
        probed.append(short)
        v.live_instances, v.nonce_depth, v.probed_at = live, depth, t
        if live == 0:
            unusable.append(((policy.key(short, meta.get(short), i)), short))
            reason = reason or f"{short} has no instances right now"
            continue
        usable.append(((policy.key(short, meta.get(short), i)), short))
        if not reason:
            reason = (f"{short}: no recent record, probed live and found {live} instance(s)"
                      if not v.known else
                      f"{short}: {v.serve.p:.0%} served recently, {live} instance(s) live")

    usable.sort(key=lambda t_: t_[0])
    unusable.sort(key=lambda t_: t_[0])
    seen = [s for _, s in usable] + [s for _, s in unusable]
    # Anything never reached (we stopped early) keeps its policy order behind what we did look at.
    rest = [pairs[i][1] for i in ordered if pairs[i][1] not in seen]
    return Choice(order=seen + rest, reason=reason or "no fleet could be assessed", probed=probed, views=views)


# ── what a live probe can actually tell us ───────────────────────────────────────────────────────
#
# Measured 2026-09-30 against the live relay. `GET /confidential/instances/{fleet}` returns ~10 KB:
#
#     {"instances": [{"instance_id": ..., "e2e_pubkey": ..., "nonces": [...]}, ...],
#      "nonce_expires_in": ..., "nonce_expires_at": ...}
#
# The previous probe reduced all of that to ONE integer — a count of instances holding at least one
# nonce — and threw the rest away, including inside the very expression that computed it. Four signals
# were being discarded, all of them free and all of them about exactly what this mission needs:
#
#   nonce depth    how much headroom an instance has, not whether it has any. An instance down to its
#                  last nonce is one request from unusable; the boolean called it healthy.
#   pubkey churn   e2e_pubkey changes when an instance restarts. Comparing successive probes is free
#                  restart detection, and restarts are the leading edge of a fleet going bad.
#   instance churn which instance_ids appeared and vanished between probes — fleet stability, and the
#                  thing that precedes a collapse rather than reporting it afterwards.
#   nonce_expires_in  how fast the operator is rotating, which bounds how stale our pool may be.
#
# There is no utilisation endpoint and /confidential/fleet-health is still 404, so these four are the
# whole of what the API can tell us today. Filed with the relay lane; until it answers, this is it.


@dataclass
class Probe:
    """One live look at a fleet. `instances = -1` means COULD NOT ASK, never 'none'."""
    fleet_id: str
    at: float
    instances: int = -1
    usable: int = 0                    # instances holding at least one nonce AND a key
    nonce_depth: int = 0               # total nonces across usable instances
    thinnest: int = 0                  # fewest nonces held by any usable instance
    expires_in: float = 0.0
    arrived: int = 0                   # instance_ids not present at the previous probe
    departed: int = 0
    restarted: int = 0                 # same id, DIFFERENT e2e_pubkey — the only true instability signal

    @property
    def reachable(self) -> bool:
        return self.instances >= 0

    @property
    def churn(self) -> int:
        """Id turnover between listings. NOT a health signal — see `sampled` below."""
        return self.arrived + self.departed

    # THE LISTING IS A SAMPLE, NOT A CENSUS — and reading it as a census is a mistake this module very
    # nearly shipped. Measured 2026-09-30, eight listings seconds apart:
    #
    #   kimi-k2.6   every listing 5 instances, but 12 DISTINCT ids across the eight, no key ever changed
    #   kimi-k3     every listing 3 instances, the same 3 every time
    #
    # So k2.6's ids turning over is the endpoint sampling a larger pool, not instances restarting. The
    # first reading of this data said "34 churn events a minute" and correlated it with k2.6's 0.22
    # attestation yield at 3.6x — a clean split with no overlap, and the wrong conclusion. Feeding churn
    # in as ill-health would have demoted the fleets with the MOST instances.
    #
    # It also reframes the yield itself: verifying five sampled instances and then finding the pinned one
    # absent from the next sample is US treating a sample as a census, not the fleet being unhealthy.
    # A large part of k2.6's 0.22 is our own measurement.
    #
    # `restarted` (an id keeping its place while its e2e_pubkey changes) is unaffected by sampling and
    # is the one instability signal here that means what it says.
    @property
    def sampled(self) -> bool:
        """True when ids turn over while the listing SIZE holds — the signature of a sampled pool."""
        return self.churn > 0 and self.arrived == self.departed and self.restarted == 0

    def line(self) -> str:
        if not self.reachable:
            return "could not ask"
        bits = [f"{self.usable}/{self.instances} usable", f"{self.nonce_depth} nonces"]
        if self.thinnest <= 1 and self.usable:
            bits.append(f"thinnest holds {self.thinnest}")
        if self.restarted:
            bits.append(f"{self.restarted} restarted")
        if self.sampled:
            bits.append(f"listing samples a larger pool (+{self.arrived}/-{self.departed})")
        elif self.arrived or self.departed:
            bits.append(f"+{self.arrived}/-{self.departed}")
        return ", ".join(bits)


class Prober:
    """Turns successive `instances()` listings into observations, by remembering the last one."""

    def __init__(self) -> None:
        self._last: Dict[str, Dict[str, str]] = {}      # fleet -> {instance_id: e2e_pubkey}

    async def probe(self, transport, fleet_id: str, *, now: Optional[float] = None) -> Probe:
        t = now or time.time()
        try:
            e2 = await transport.instances(fleet_id)
        except Exception:                               # noqa: BLE001 — could not ask
            return Probe(fleet_id, t)
        rows = e2.get("instances") or []
        seen: Dict[str, str] = {}
        usable = depth = 0
        thinnest = 0
        for i in rows:
            iid, key, nonces = i.get("instance_id"), i.get("e2e_pubkey"), (i.get("nonces") or [])
            if not iid:
                continue
            seen[str(iid)] = str(key or "")
            if key and nonces:
                usable += 1
                depth += len(nonces)
                thinnest = len(nonces) if thinnest == 0 else min(thinnest, len(nonces))
        prev = self._last.get(fleet_id)
        arrived = departed = restarted = 0
        if prev is not None:
            arrived = len(set(seen) - set(prev))
            departed = len(set(prev) - set(seen))
            restarted = sum(1 for k, v in seen.items() if k in prev and prev[k] and v and prev[k] != v)
        self._last[fleet_id] = seen
        try:
            expires = float(e2.get("nonce_expires_in") or 0.0)
        except (TypeError, ValueError):
            expires = 0.0
        return Probe(fleet_id, t, instances=len(rows), usable=usable, nonce_depth=depth,
                     thinnest=thinnest, expires_in=expires,
                     arrived=arrived, departed=departed, restarted=restarted)
