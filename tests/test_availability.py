"""The availability model. Every test here names the defect it exists to prevent — all of them were
found by adversarial review of the version this replaces, on 2026-09-30."""
import asyncio
import json
import time

import pytest

from inferroute_local.confidential import availability as A


# ── decay: the fix for three faults at once ──────────────────────────────────────────────────────

def test_stale_evidence_becomes_unknown_not_confident():
    """FAULT: a Wilson interval narrows as 1/sqrt(n) whatever the AGE of the n, so more history made the
    old estimator more certain about a staler average. Measured: one fleet's window spanned a run from
    100% success to 5% and the interval over it excluded both ends."""
    now = time.time()
    b = A.Belief(A.SERVE_HALF_LIFE_S)
    for _ in range(30):
        b.observe(1, 0, now - 24 * 3600)
    old = b.at(now)
    fresh = A.Belief(A.SERVE_HALF_LIFE_S)
    for _ in range(30):
        fresh.observe(1, 0, now)
    f = fresh.at(now)
    assert old.evidence < A.MIN_EVIDENCE, "a day-old record still counted as knowledge"
    assert (old.interval()[1] - old.interval()[0]) > (f.interval()[1] - f.interval()[0]) * 3, \
        "stale evidence did not widen the interval"


def test_an_abandoned_fleet_widens_rather_than_reverting_to_optimism():
    """THE FLAP. Stop using a fleet and you stop generating evidence about it, so under any scheme that
    decays toward a 'fine' prior it looks BETTER than the fleet you are on — which is judged on real
    failures. The old estimator did exactly this: a fleet measured at 56% failure read 1.000 once its
    receipts aged out, and would have ranked top for having been avoided.

    Here the point estimate does drift toward the prior, but the EVIDENCE falls with it, so the fleet
    becomes UNKNOWN and must be probed rather than trusted."""
    now = time.time()
    bad = A.Belief(A.SERVE_HALF_LIFE_S)
    for _ in range(40):
        bad.observe(0, 1, now - 48 * 3600)            # measured terrible, two days ago
    v = bad.at(now)
    assert v.p > 0.3, "the fixture is wrong: the estimate should have drifted toward the prior"
    assert v.evidence < A.MIN_EVIDENCE, \
        "an abandoned fleet kept enough evidence to be ranked without a probe — this is the flap"


def test_confidence_is_bounded_by_recent_throughput():
    """A drifting process cannot be measured to arbitrary precision. With forgetting, `a + b` saturates
    near L*H/ln2, so no amount of history buys certainty the data does not support."""
    now = time.time()
    b = A.Belief(A.SERVE_HALF_LIFE_S)
    for i in range(2000):                              # one request a minute for ~33 hours
        b.observe(1, 0, now - (2000 - i) * 60)
    n_eff = b.at(now).a + b.at(now).b
    saturation = (1 / 60.0) * A.SERVE_HALF_LIFE_S / 0.693
    assert n_eff < saturation * 1.5, f"evidence grew without bound: {n_eff:.0f}"


# ── the rule that makes decay safe ───────────────────────────────────────────────────────────────

def _pairs():
    return [("f-cap", "kimi-k3"), ("f-mid", "glm-5.2"), ("f-cheap", "deepseek-v4-flash")]


def test_evidence_demotes_but_absence_of_evidence_does_not():
    """The one direction measurement may override what the caller asked for. A fleet MEASURED below the
    floor is set aside however much the policy wants it; a fleet with no record is probed, not demoted —
    ranking the unknown last means a fleet we stopped using can never earn a record again."""
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(60):                                 # the capability pick is measurably bad
        b.observed_serve("f-cap", 0, 1, now)
    async def probe(_f):
        return 4, 40
    c = asyncio.run(A.choose(_pairs(), A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[0] != "kimi-k3", "a measurably failing fleet was still ranked first by capability"
    assert c.order[-1] == "kimi-k3", "the failing fleet was not set aside"
    assert "glm-5.2" in c.probed or "deepseek-v4-flash" in c.probed, "an unknown fleet was not probed"


def test_an_unknown_fleet_that_cannot_answer_is_dropped():
    """Probed, not assumed — in either direction."""
    now = time.time()
    b = A.Beliefs(path=None)
    async def probe(fleet):
        return (0, 0) if fleet == "f-cap" else (4, 40)
    c = asyncio.run(A.choose(_pairs(), A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[-1] == "kimi-k3" and "no instances" in c.reason


def test_a_probe_that_fails_is_unknown_not_empty():
    """'We could not ask' must never read as 'there is nothing there'."""
    now = time.time()
    b = A.Beliefs(path=None)
    async def probe(_f):
        raise RuntimeError("network")
    c = asyncio.run(A.choose(_pairs(), A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert set(c.order) == {"kimi-k3", "glm-5.2", "deepseek-v4-flash"}


# ── policy: the caller's order, the server's numbers ─────────────────────────────────────────────

def test_the_same_beliefs_serve_opposite_policies():
    """Henry, 2026-09-30: biggest models for Probant, "so that in other use case we can also prioritize
    in the other way around". Order and availability are separate concerns and stay separate."""
    now = time.time()
    b = A.Beliefs(path=None)
    async def probe(_f):
        return 4, 40
    cap = asyncio.run(A.choose(_pairs(), A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    cost = asyncio.run(A.choose(_pairs(), A.Policy(rank=A.RANK_COST), b, probe, now=now))
    assert cap.order[0] == "kimi-k3" and cost.order[0] == "deepseek-v4-flash"
    assert cap.order == list(reversed(cost.order))


def test_the_server_owns_capability_and_the_local_table_is_only_a_fallback():
    """The setting Henry asked to live on the server. /confidential/models returns only
    {fleet_ref, fleet_id, name} today — measured — so the local table is a stopgap that must lose to any
    number the operator sends."""
    assert A.capability_of("deepseek-v4-flash", {"capability": 999}) == 999
    assert A.capability_of("kimi-k3", {"capability": 1}) == 1, "the local table overrode the server"
    assert A.capability_of("anything", {"context_length": 256000}) == 256.0
    # a model nobody has an opinion about sorts mid-table, never last, or it can never be chosen
    mid = A.capability_of("a-brand-new-model")
    assert A.capability_of("deepseek-v4-flash") < mid < A.capability_of("kimi-k3")


# ── the probe: what the listing can and cannot say ───────────────────────────────────────────────

class _Listing:
    def __init__(self, *rounds):
        self.rounds, self.i = list(rounds), 0
    async def instances(self, _fleet):
        r = self.rounds[min(self.i, len(self.rounds) - 1)]
        self.i += 1
        return {"instances": r, "nonce_expires_in": 60}


def _inst(iid, key="k", n=10):
    return {"instance_id": iid, "e2e_pubkey": key, "nonces": [f"n{i}" for i in range(n)]}


def test_a_sampled_listing_is_not_instability():
    """THE MISREADING THIS ALMOST SHIPPED. Measured on the live relay: kimi-k2.6 returns exactly 5
    instances every listing but 12 distinct ids across 8 listings, with no e2e_pubkey ever changing —
    the endpoint samples a larger pool. Read as churn it correlated with low attestation yield at 3.6x,
    a clean split with no overlap, and the wrong conclusion: feeding it in as ill-health would have
    demoted the fleets with the MOST instances."""
    p = A.Prober()
    t = _Listing([_inst("a"), _inst("b"), _inst("c")], [_inst("d"), _inst("e"), _inst("c")])
    asyncio.run(p.probe(t, "f"))
    pr = asyncio.run(p.probe(t, "f"))
    assert pr.sampled is True and pr.restarted == 0
    assert "samples a larger pool" in pr.line()


def test_a_restart_is_real_and_survives_sampling():
    """An id keeping its place while its key changes cannot be explained by sampling."""
    p = A.Prober()
    t = _Listing([_inst("a", "k1"), _inst("b", "k1")], [_inst("a", "k2"), _inst("b", "k1")])
    asyncio.run(p.probe(t, "f"))
    pr = asyncio.run(p.probe(t, "f"))
    assert pr.restarted == 1 and pr.sampled is False


def test_nonce_depth_is_a_number_not_a_boolean():
    """The old probe collapsed the whole listing to a count of instances holding AT LEAST ONE nonce, so
    an instance one request from unusable scored the same as one with fifty."""
    p = A.Prober()
    t = _Listing([_inst("a", n=50), _inst("b", n=1)])
    pr = asyncio.run(p.probe(t, "f"))
    assert pr.nonce_depth == 51 and pr.thinnest == 1 and pr.usable == 2
    assert "thinnest holds 1" in pr.line()


def test_could_not_ask_is_not_zero_instances():
    p = A.Prober()
    class _Boom:
        async def instances(self, _f):
            raise RuntimeError("down")
    pr = asyncio.run(p.probe(_Boom(), "f"))
    assert pr.instances == -1 and pr.reachable is False and pr.line() == "could not ask"


# ── the backfit: read the monitoring we already write ────────────────────────────────────────────

def test_the_backfit_reads_the_event_series_nothing_else_reads(tmp_path):
    """`receipt.events[]` carries timestamped `reverified N/M instances verified` rows — a within-session
    attestation series, already written, that the old estimator ignored in favour of ONE snapshot taken
    at open, and then could not see a collapse."""
    d = tmp_path / "receipts"
    d.mkdir()
    (d / "r.json").write_text(json.dumps({
        "fleet_id": "f", "model_short": "m",
        "started_at": "2026-09-30T00:00:00Z", "ended_at": "2026-09-30T01:00:00Z",
        "fleet": {"instances": 4, "eligible": 4},
        "counters": {"requests": 10, "errors_fleet": 0},
        "events": [{"ts": "2026-09-30T00:30:00Z", "kind": "reverified",
                    "detail": "1/8 instances verified"}]}))
    b = A.Beliefs(path=tmp_path / "a.json")
    n = b.backfit(d)
    assert n == 3, f"the event row was not learned from (rows={n})"
    # Read at the receipt's OWN time, not now: otherwise this asserts how long ago the fixture is dated,
    # and it would drift from passing to failing with nothing changed. (It did, on the first run: a
    # 12-hour half-life had correctly decayed the 12 observations to 4.5 by the time the test ran.)
    at = A._ts("2026-09-30T01:00:00Z")
    v = b.view("f", at)
    assert v.verify.evidence > 8, "the within-session series did not reach the belief"
    # and the 1/8 row pulled the estimate well below the 4/4 snapshot taken at open
    assert v.verify.p < 0.6, "the event series was read but did not move the belief"


def test_a_stale_nonce_pool_is_not_the_fleets_fault(tmp_path):
    """`nonce-rejected` says this client's pool went stale, not that the enclave is unhealthy — the code
    that handles it says so. Pooling it into a fleet's record is how the old estimator blamed fleets for
    our own state."""
    d = tmp_path / "receipts"
    d.mkdir()
    (d / "r.json").write_text(json.dumps({
        "fleet_id": "f", "model_short": "m", "started_at": "2026-09-30T00:00:00Z",
        "events": [{"ts": "2026-09-30T00:10:00Z", "kind": "nonce-rejected", "detail": "x"}] * 20}))
    b = A.Beliefs(path=tmp_path / "a.json")
    b.backfit(d)
    assert b.view("f", time.time()).verify.evidence == 0


def test_beliefs_survive_a_restart(tmp_path):
    now = time.time()
    p = tmp_path / "a.json"
    b = A.Beliefs(path=p)
    for _ in range(20):
        b.observed_serve("f", 1, 0, now)
    b.models["f"] = "m"
    b.save()
    b2 = A.Beliefs(path=p)
    assert b2.load() and b2.models["f"] == "m"
    assert abs(b2.view("f", now).serve.p - b.view("f", now).serve.p) < 1e-6


def test_no_path_means_in_memory_not_the_users_real_store(tmp_path, monkeypatch):
    """Every test in this file and the continuity suite passes `path=None` believing it gets no
    persistence. It was resolving to ~/.inferroute/confidential/availability.json — inert only while
    nothing called save(), and then the live experiments in this session called it and wrote synthetic
    failures into the user's own evidence, where they then steered real model selection.

    "No path" and "the default path" are different requests."""
    import time
    b = A.Beliefs(path=None)
    assert b.path is None
    b.observed_serve("f", 0, 50, time.time())
    b.save()                                          # must be a no-op, not a write
    assert b.load() is False
    assert b.backfit() == 0, "an in-memory store went looking for receipts on disk"

    # and the default still persists where it always did
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    d = A.Beliefs()
    assert d.path is not None and str(tmp_path) in str(d.path)
    d.observed_serve("f", 1, 0, time.time())
    d.save()
    assert d.path.exists()


def test_a_fleet_that_serves_perfectly_but_never_verifies_is_set_aside(tmp_path, monkeypatch):
    """The floor used to be gated on `serve` alone while promotion used the interval of serve x verify.
    A fleet whose requests always succeed but whose machines never attest cannot be OPENED at all — and
    was never demoted, so it was probed, ranked first by capability, and burned a full attestation on
    every launch."""
    import asyncio
    import time
    from inferroute_local.confidential import availability as A
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(40):
        b.observed_serve("f-cap", 1, 0, now)          # every request succeeds...
        b.observed_verify("f-cap", 0, 4, now)         # ...on machines that never verify
    for _ in range(10):
        b.observed_serve("f-mid", 9, 1, now)
        b.observed_verify("f-mid", 4, 4, now)
    v = b.view("f-cap", now)
    assert v.serve.p > 0.9, "fixture: requests should look perfect"
    assert v.p_usable() < 0.3, "the combined score did not see the attestation failure"

    async def probe(_f):
        return 4, 40
    pairs = [("f-cap", "kimi-k3"), ("f-mid", "glm-5.2")]
    c = asyncio.run(A.choose(pairs, A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[0] != "kimi-k3", "a fleet that cannot be opened was still ranked first"


def test_a_fleet_is_set_aside_only_when_something_beats_it(tmp_path, monkeypatch):
    """MEASURED LIVE, 2026-09-30, and the system chose the worse model because of it. kimi-k3 was
    opening perfectly — 4 of 4 machines eligible — with the best record of any fleet: 78% of requests
    served, 95% of machines verifying. p_usable 0.74, under an 0.80 floor, so it was discarded. glm-5.1
    had NO record at all and ranks lower on capability; it was probed, found to have instances, and
    used instead.

    Being below a bar is not a reason to refuse the best thing available, and an unknown fleet must
    never stand in for a better one."""
    import asyncio
    import time
    from inferroute_local.confidential import availability as A
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(14):                                # good, but under an absolute floor
        b.observed_serve("f-cap", 8, 2, now)
        b.observed_verify("f-cap", 19, 1, now)
    v = b.view("f-cap", now)
    assert v.known and v.p_usable() < A.Policy().floor, "fixture: must sit below the floor"

    async def probe(_f):
        return 4, 40
    pairs = [("f-cap", "kimi-k3"), ("f-unknown", "glm-5.1")]
    c = asyncio.run(A.choose(pairs, A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[0] == "kimi-k3", \
        f"a measured-good fleet lost to an unmeasured one: {c.order}"


def test_the_reason_describes_the_fleet_that_will_serve(tmp_path, monkeypatch):
    """It latched on the first fleet EXAMINED, which in policy order is frequently one that was then
    set aside — so the line written into the receipt explained a fleet that is not the one running."""
    import asyncio
    import time
    from inferroute_local.confidential import availability as A
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(12):
        b.observed_serve("f-mid", 10, 0, now)
        b.observed_verify("f-mid", 4, 0, now)

    async def probe(_f):
        return 4, 40
    pairs = [("f-cap", "kimi-k3"), ("f-mid", "glm-5.2")]
    c = asyncio.run(A.choose(pairs, A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.reason.startswith(c.order[0]), \
        f"the reason explains {c.reason.split(':')[0]} but {c.order[0]} will serve"


def test_a_fleet_measured_at_zero_is_set_aside_even_with_only_unknowns_beside_it():
    """The companion to the rule above, and the reason it needs two thresholds rather than one. Setting
    aside only against a MEASURED alternative would keep a fleet measured at zero for as long as the
    others were merely unknown. There is a point where "never tried" really is the better bet."""
    import asyncio
    import time
    from inferroute_local.confidential import availability as A
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(60):
        b.observed_serve("f-cap", 0, 1, now)
    assert b.view("f-cap", now).p_usable() < A.Policy().broken

    async def probe(_f):
        return 4, 40
    pairs = [("f-cap", "kimi-k3"), ("f-unknown", "glm-5.1")]
    c = asyncio.run(A.choose(pairs, A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[0] != "kimi-k3", "a fleet measured at zero was still ranked first"
    assert c.order[-1] == "kimi-k3"


def test_a_fleet_we_know_is_failing_sorts_behind_one_we_have_never_tried():
    """A fleet examined and set aside used to rank AHEAD of one nobody had assessed, so a fallback
    chain would reach for the machine known to be failing before the one simply untried — and the
    continuity lane's warm, which reads this order, drew its standby preferentially from the set that
    had just been rejected."""
    import asyncio
    import time
    from inferroute_local.confidential import availability as A
    now = time.time()
    b = A.Beliefs(path=None)
    for _ in range(60):
        b.observed_serve("f-bad", 0, 1, now)           # measured, broken
    for _ in range(12):
        b.observed_serve("f-ok", 10, 0, now)           # measured, good
        b.observed_verify("f-ok", 4, 0, now)

    async def probe(_f):
        return 4, 40
    # policy order puts the bad one second and the never-seen one last
    pairs = [("f-ok", "kimi-k3"), ("f-bad", "kimi-k2.6"), ("f-new", "glm-5.2")]
    c = asyncio.run(A.choose(pairs, A.Policy(rank=A.RANK_CAPABILITY), b, probe, now=now))
    assert c.order[0] == "kimi-k3"
    assert c.order.index("glm-5.2") < c.order.index("kimi-k2.6"), \
        f"the known-failing fleet ranked ahead of the untried one: {c.order}"
