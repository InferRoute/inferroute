"""`ir cline`: hand over the daemon's values, and ship the guard that makes a wrong value fail closed.

Cline's OpenAI-compatible provider is a settings-panel form. The published `cline` package carries
CLINE_DIR, CLINE_DATA_DIR and CLINE_BIN_PATH and NO base-URL or provider variable, so the config cannot
be written from outside without guessing at internal state. What Cline does have, alone among the agents
we support apart from Pi, is a pre-request hook that can abort.
"""
import re

from inferroute_cli import cline as C
from inferroute_cli import confidential_daemon as D


def test_it_refuses_to_pretend_without_a_daemon(monkeypatch, capsys):
    """A per-launch endpoint is no use here: Cline's settings outlive any one command."""
    monkeypatch.setattr(D, "running", lambda: None)
    assert C.cmd_cline([]) == 2
    err = capsys.readouterr().err
    assert "daemon start" in err
    assert "settings panel" in err, "say WHY this one is different, or it reads as a missing feature"


def test_it_hands_over_exactly_what_the_form_asks_for(monkeypatch, capsys):
    monkeypatch.setattr(D, "running", lambda: {"port": 4111, "token": "ir-live-token",
                                               "model": "kimi-k2.6", "serving": True,
                                               "session_id": "abc", "started_at": "now"})
    assert C.cmd_cline([]) == 0
    out = capsys.readouterr().out
    assert "http://127.0.0.1:4111/v1" in out, "OpenAI dialect: Cline appends /chat/completions"
    assert "ir-live-token" in out and "kimi-k2.6" in out
    assert "cline plugin install" in out and str(C.plugin_path()) in out


def test_a_daemon_that_stopped_serving_is_not_offered():
    """Handing over values for an endpoint returning 503 would configure a session that cannot work."""
    import inspect
    src = inspect.getsource(C.cmd_cline)
    assert 'st.get("serving")' in src


def test_the_plugin_aborts_with_the_field_the_runtime_actually_READS():
    """The decisive detail. @cline/core 0.0.85 reads `stop === true` and takes the reason from
    `cancelReason`. The plugin guide says `{ stop: true, reason }`; the blog post says `{ skip: true }`.
    A veto returning the wrong key looks like enforcement and does nothing — which is the one failure a
    guard must never have."""
    ts = C.plugin_path().read_text(encoding="utf-8")
    # The RETURN, not the file: the comment above it names the wrong field on purpose, to record why.
    returns = [l for l in ts.splitlines() if "return " in l and "{" in l]
    assert returns, "the hook returns nothing at all"
    assert any("stop: true" in l and "cancelReason" in l for l in returns), returns
    assert not any("skip" in l for l in returns), returns


def test_the_plugin_treats_every_uncertainty_as_a_refusal():
    """Unreachable, 401, 503, a non-confidential verdict: all of them are reasons not to send. A guard
    that only refuses on the cases it anticipated is a guard that fails open."""
    ts = C.plugin_path().read_text(encoding="utf-8")
    assert "could not be reached" in ts           # network failure
    assert "answered ${res.status}" in ts         # 401 / 503
    assert 'verdict === "confidential"' in ts     # anything else refuses
    assert "catch" in ts, "an exception must become a refusal, not propagate"
    # and it must hook the model request, not merely the tools
    assert "beforeModel" in ts


def test_the_plugin_sends_the_session_key():
    """The endpoint requires it; without the header the plugin would 401 against its own session and
    refuse everything."""
    ts = C.plugin_path().read_text(encoding="utf-8")
    assert "IR_ATTESTED_KEY" in ts and "authorization" in ts


def test_the_plugin_does_not_recheck_on_every_single_request():
    """A check before each request would put a round trip in front of every turn. Bounded staleness is
    the trade, and it is stated rather than accidental."""
    ts = C.plugin_path().read_text(encoding="utf-8")
    m = re.search(r"RECHECK_MS\s*=\s*([\d_]+)", ts)
    assert m and 1_000 <= int(m.group(1).replace("_", "")) <= 120_000
