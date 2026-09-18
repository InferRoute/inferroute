"""What the system is allowed to SAY about a session's confinement, and the single definition behind it.

These run everywhere — they are about the claims, not the sandbox, and a machine without bubblewrap must
still be prevented from shipping a bundle that overstates what confined the agent.
"""
import pytest

from inferroute_cli import pi_attested, probant_export
from inferroute_local import netns


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("IR_ATTESTED_CONFINE", "IR_ATTESTED_NETNS_BIND", "IR_PROBANT_DEV_UNCONFINED"):
        monkeypatch.delenv(var, raising=False)


def test_the_label_has_one_definition(monkeypatch):
    """The launcher stamps the line before the sandbox exists; the sandbox reports it afterwards. Two
    strings could drift and the record would then describe a confinement the session never ran under."""
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    monkeypatch.setenv("IR_ATTESTED_NETNS_BIND", "1")
    assert pi_attested.confinement_label() == netns.ADDRESS_LEVEL_LABEL
    assert netns.NetnsSandbox.label(object()) == netns.ADDRESS_LEVEL_LABEL   # unbound: no sandbox needed


def test_the_label_states_the_bind_only_when_it_applies(monkeypatch):
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    assert "empty network namespace" not in pi_attested.confinement_label()
    monkeypatch.setenv("IR_ATTESTED_NETNS_BIND", "1")
    assert "empty network namespace" in pi_attested.confinement_label()
    assert "absent rather than" in pi_attested.confinement_label()


def test_the_bind_is_planned_only_in_require_mode(monkeypatch):
    monkeypatch.setattr("inferroute_local.confinement.netns_bind_available", lambda: True)
    assert pi_attested.plan_netns_bind() is False                      # default (best-effort) mode
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    assert pi_attested.plan_netns_bind() is True
    monkeypatch.setenv("IR_PROBANT_DEV_UNCONFINED", "1")
    assert pi_attested.plan_netns_bind() is False                      # dev override never promises it
    monkeypatch.delenv("IR_PROBANT_DEV_UNCONFINED")
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "off")
    assert pi_attested.plan_netns_bind() is False


def test_the_plan_and_the_precheck_ask_the_same_question(monkeypatch):
    """If the precheck could pass while the sandbox cannot be built, a launch would promise address-level
    confinement to its records and then run without it."""
    monkeypatch.setenv("IR_ATTESTED_CONFINE", "require")
    for available in (True, False):
        monkeypatch.setattr("inferroute_local.confinement.netns_bind_available", lambda a=available: a)
        monkeypatch.setattr("inferroute_local.confinement.userns_restricted", lambda: True)
        ok, _ = pi_attested.confine_precheck()
        assert ok is available and pi_attested.plan_netns_bind() is available


@pytest.mark.parametrize("recorded, expected", [
    ("", "not recorded"),
    ("unconfined (developer override)", "UNCONFINED"),
    ("not confined", "UNCONFINED"),
    ("best-effort (port-level; not required)", "best-effort"),
    ("require (address-level egress enforced or the session does not start)", "write access"),
    (netns.ADDRESS_LEVEL_LABEL, "not present in the agent's filesystem"),
])
def test_the_export_says_only_what_the_recorded_line_supports(recorded, expected):
    assert expected in probant_export._reach_note(recorded)


def test_an_egress_only_require_session_does_not_claim_its_files_were_invisible():
    """Require mode confined egress by address long before the matter-dir bind existed, and those sessions
    left the record directory merely write-denied. The word "address-level" in the recorded line is
    therefore NOT the discriminator — the line saying the files were absent is."""
    legacy = "require (address-level egress enforced or the session does not start)"
    assert "not present" not in probant_export._reach_note(legacy)
    assert "write access" in probant_export._reach_note(legacy)


def test_a_best_effort_session_is_never_described_as_required():
    """The defect this check exists for: every non-'unconfined' line used to read 'require-mode
    confinement', so a session that would have run even with no confinement available claimed a guarantee."""
    note = probant_export._reach_note("best-effort (port-level; not required)")
    assert "require-mode" not in note and "would still have run" in note
