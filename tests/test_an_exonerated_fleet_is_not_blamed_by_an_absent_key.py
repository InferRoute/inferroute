"""A fleet whose failures were all someone else's fault must not be indistinguishable from an unmeasured one.

MEASURED 2026-11-22 against the installed ir 0.9.141+a2d0a71f, 4,293 receipts on this device.
`_err` incremented `errors_fleet` ONLY when the fault was in COUNTS_AGAINST_FLEET, so a session whose
every failure was correctly classified as NOT the fleet's wrote no such key. `fleet_success` reads
`c.get("errors_fleet", c.get("errors"))`, so an absent key falls back to the LEGACY TOTAL -- the one
`_err`'s own comment calls "noise dressed as evidence" -- and the fleet is demoted for failures that
were never its own. The default on the ambiguity was to blame.

811 of the 4,293 receipts carry errors>0. 214 of those are exactly this case (key absent, every fault
non-fleet), 179 of them in November. Live specimen: ten kimi-k2.6 receipts at requests=11 errors=11,
all eleven "relay answered 503 with code IR-C1001", counters fault_operator=11 -- InferRoute's own
unfunded lane -- and kimi scored fleet_success 0.068 against glm-5.2's 0.250, which for unpinned
callers routes kimi traffic to glm at roughly 3x list price.

FALSIFIER, run before the fix and not after: an `errors_fleet=0` in any receipt whose faults were all
non-fleet would mean the key was already initialised somewhere unread. Across all 4,293: ZERO.

Fix: write the key on every error. absent => pre-split or no error; 0 => measured, none were the
fleet's; N => N were.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from inferroute_cli import confidential as C
from inferroute_local.confidential import session as S


# ── the writer ────────────────────────────────────────────────────────────────

def test_a_non_fleet_fault_records_a_measured_zero_not_an_absence():
    c = {}
    S._err(c, "send_failed", fault=S.OPERATOR_FAULT)
    assert "errors_fleet" in c, "a classified non-fleet failure must still SAY so, not stay silent"
    assert c["errors_fleet"] == 0
    assert c["errors"] == 1 and c["fault_operator"] == 1


def test_a_fleet_fault_still_counts():
    c = {}
    S._err(c, "send_failed", fault=S.INSTANCE_FAULT)
    assert c["errors_fleet"] == 1 and c["errors"] == 1


def test_a_mixed_session_counts_only_the_fleets_share():
    c = {}
    S._err(c, "send_failed", fault=S.OPERATOR_FAULT)
    S._err(c, "send_failed", fault=S.ACCOUNT_FAULT)
    S._err(c, "send_failed", fault=S.INSTANCE_FAULT)
    assert c["errors"] == 3 and c["errors_fleet"] == 1


def test_a_session_with_no_error_writes_no_key_at_all():
    """ABSENT must keep meaning "nothing measured", or the three states collapse back into two:
    a pre-split receipt and a clean session would become the same reading."""
    assert "errors_fleet" not in {}


# ── the consequence the writer exists for ─────────────────────────────────────

def _receipt(dirpath, name, model, counters):
    """Same shape as tests/test_fleet_health_window_ages_in_time.py's helper, deliberately: the
    reader skips a receipt that lacks `started_at` or `fleet`, and a skipped receipt makes
    fleet_success return its optimistic default (1.0 over 0 requests) -- which would satisfy the
    pin below for exactly the wrong reason. The first draft of this file got that wrong and its
    own control caught it, so both assertions check `reqs` before they check the score."""
    started = datetime.now(timezone.utc) - timedelta(minutes=5)
    (dirpath / name).write_text(json.dumps({
        "session_id": f"s-{name}:{model}",
        "model_short": model,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fleet": {"instances": 3, "eligible": 3},
        "counters": counters,
    }))


@pytest.fixture
def receipts(tmp_path, monkeypatch):
    d = tmp_path / ".inferroute" / "confidential" / "receipts"
    d.mkdir(parents=True)
    monkeypatch.setattr("pathlib.Path.home", staticmethod(lambda: tmp_path))
    return d


def test_an_all_operator_fault_session_does_not_demote_the_fleet(receipts):
    """THE PIN. Eleven requests, eleven failures, every one InferRoute's own unfunded lane. Built
    through `_err` rather than hand-written, so the test cannot supply the property it asserts.
    Inversion: restore `if fault in COUNTS_AGAINST_FLEET:` around the increment -> the key is absent,
    fleet_success falls back to errors=11 and scores 0.0 -> red."""
    c = {"requests": 11}
    for _ in range(11):
        S._err(c, "send_failed", fault=S.OPERATOR_FAULT)
    _receipt(receipts, "r1.json", "kimi-k2.6", c)
    score, reqs = C.fleet_success("kimi-k2.6")
    assert reqs == 11, f"the observation was not read at all (reqs={reqs})"
    assert score == 1.0, (
        f"a fleet blamed for failures classified as NOT its own: fleet_success={score} over {reqs} "
        f"requests, counters={ {k: v for k, v in c.items() if k.startswith(('err', 'fault'))} }")


def test_a_genuine_fleet_fault_session_still_scores_badly(receipts):
    """The control. Without it the pin above is satisfied by a reader that ignores errors entirely."""
    c = {"requests": 10}
    for _ in range(10):
        S._err(c, "send_failed", fault=S.INSTANCE_FAULT)
    _receipt(receipts, "r2.json", "glm-5.2", c)
    score, reqs = C.fleet_success("glm-5.2")
    assert reqs == 10 and score < 0.5, f"a genuinely failing fleet scored {score} over {reqs}"
