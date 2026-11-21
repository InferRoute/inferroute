"""A fleet's health window must age in TIME, not only in count.

MEASURED, 2026-11-17 to 2026-11-20. A Chutes fault on kimi-k2.6 (05:25-07:18Z on the 17th)
left 9 failed receipts on this device. `_YIELD_PER_MODEL` keeps the 10 newest observations OF
THAT MODEL, so from about 09:02Z every request for kimi-k2.6 ranked below glm-5.2 and was served
by it -- at roughly 3x the list price -- for three days, while each run's own summary still named
kimi. No new kimi receipt could arrive, because arriving required being selected, and being
selected required a better score than the one the old receipts pinned.

That is a self-sustaining verdict: the evidence that excluded the model was kept current by the
exclusion. A count-based window cannot age out observations for a model it has stopped choosing,
which is the one case where ageing matters.

`x-inferroute-no-model-fallback` cannot prevent it either: the choice is made on this device,
before any request leaves.
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from inferroute_cli import confidential as C


def _receipt(dirpath, name, model, *, age_hours, instances, eligible, requests=10, errors=0):
    started = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    (dirpath / name).write_text(json.dumps({
        "session_id": f"s-{name}:{model}",
        "model_short": model,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fleet": {"instances": instances, "eligible": eligible},
        "counters": {"requests": requests, "errors_fleet": errors},
    }))


@pytest.fixture
def receipts(tmp_path, monkeypatch):
    d = tmp_path / ".inferroute" / "confidential" / "receipts"
    d.mkdir(parents=True)
    monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
    return d


def test_a_fleets_bad_day_stops_counting_once_it_is_old(receipts):
    """The regression. Nine failed observations, all older than the window, must not decide."""
    for i in range(9):
        _receipt(receipts, f"old-{i:02d}.json", "kimi-k2.6",
                 age_hours=96, instances=12, eligible=1, requests=5, errors=5)

    y, n = C.fleet_yield("kimi-k2.6")
    s, reqs = C.fleet_success("kimi-k2.6")
    assert n == 0, f"stale receipts were counted as current evidence ({n} of them)"
    assert y == 1.0, f"a fleet was demoted on four-day-old observations (yield {y})"
    assert reqs == 0 and s == 1.0, f"success scored off stale receipts ({s} over {reqs} requests)"


def test_a_fleets_bad_hour_still_counts_while_it_is_fresh(receipts):
    """The control. Without this, the test above would pass on a scanner that reads nothing."""
    for i in range(9):
        _receipt(receipts, f"new-{i:02d}.json", "kimi-k2.6",
                 age_hours=1, instances=12, eligible=1, requests=5, errors=5)

    y, n = C.fleet_yield("kimi-k2.6")
    s, reqs = C.fleet_success("kimi-k2.6")
    assert n == 9, f"fresh observations were not read ({n})"
    assert y < 0.5, f"a fleet verifying 1 of 12 instances an hour ago scored {y}"
    assert s < 0.5, f"a fleet erroring on every request an hour ago scored {s}"


def test_fresh_and_stale_together_are_judged_on_the_fresh_only(receipts):
    """A model that recovered must be scored on the recovery, not on the fault plus it."""
    for i in range(9):
        _receipt(receipts, f"a-old-{i:02d}.json", "kimi-k2.6",
                 age_hours=96, instances=12, eligible=1, requests=5, errors=5)
    for i in range(3):
        _receipt(receipts, f"b-new-{i:02d}.json", "kimi-k2.6",
                 age_hours=2, instances=8, eligible=8, requests=20, errors=0)

    y, n = C.fleet_yield("kimi-k2.6")
    assert n == 3, f"the stale fault was mixed into the verdict ({n} observations)"
    assert y > 0.9, f"a fleet verifying 8 of 8 twice in the last two hours scored {y}"


def test_a_receipt_with_no_readable_clock_is_not_current(receipts):
    """Fails OPEN. We cannot say an undated receipt is current, and the false negative we must
    avoid is 'stop using a healthy fleet for ever' -- so no clock means no demotion, which
    degrades to the declared capability-first preference rather than to a frozen ranking."""
    for i, started in enumerate(["", "not-a-date", None]):
        body = {"model_short": "kimi-k2.6",
                "fleet": {"instances": 12, "eligible": 1},
                "counters": {"requests": 5, "errors_fleet": 5}}
        if started is not None:
            body["started_at"] = started
        (receipts / f"undated-{i}.json").write_text(json.dumps(body))

    y, n = C.fleet_yield("kimi-k2.6")
    assert (y, n) == (1.0, 0), f"an undated receipt was treated as current evidence ({y}, {n})"


def test_a_receipt_slightly_ahead_of_our_clock_is_still_current(receipts):
    """Two machines' clocks differ. A receipt stamped a minute in the future is not stale."""
    _receipt(receipts, "future.json", "kimi-k2.6",
             age_hours=-1 / 60.0, instances=12, eligible=1, requests=5, errors=5)
    y, n = C.fleet_yield("kimi-k2.6")
    assert n == 1, "a receipt one minute ahead of this clock was discarded as not current"
    assert y < 0.5


def test_the_bound_is_declared_and_not_a_literal_in_three_places():
    """One constant, used by every scanner, so the three cannot drift apart."""
    assert C._YIELD_MAX_AGE_S == 24 * 3600
    src = (__import__("pathlib").Path(C.__file__)).read_text()
    assert src.count("_observation_is_current(r)") == 3, (
        "the time bound is applied at a different number of sites than the three per-model "
        "scanners; a scanner without it keeps the old frozen verdict")
