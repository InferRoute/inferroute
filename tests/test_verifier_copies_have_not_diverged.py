"""The two verifier copies have silently diverged TWICE.

`inferroute_cli/pi_attested/verify_record.py` (this repo, becomes the client wheel) and
`sealed-research/sealedresearch/verify_record.py` (the other session's copy) are the same
verifier maintained in two places. Twice now a capability has landed in one and not the other,
and both times it was found by a person reading bytes rather than by a gate:

  * firmware-floor enforcement (2026-09-28, goal-queue item (a)) — landed in sealed-research,
    did not reach the shipped client;
  * windowed `min_tcb` (2026-09-28) — same again: present in sealed-research, absent from the
    served 0.9.65 AND 0.9.66 wheels.

Byte-equality is the WRONG test: the copies legitimately differ (package layout, imports, and
features one side genuinely does not need). What must not differ is the set of SECURITY
CAPABILITIES, because a client verifying a record is entitled to every check the other copy
knows how to make.

This test SKIPS when the sibling repo is not on the machine, so it is inert in CI and live on
the machine where deploys are cut. A skip is not a pass; the reason is printed.
"""
from __future__ import annotations

import pathlib

import pytest

SIBLING = pathlib.Path("/home/henry/workspaces/inferroute/sealed-research/sealedresearch/verify_record.py")
OURS = pathlib.Path(__file__).resolve().parents[1] / "inferroute_cli" / "pi_attested" / "verify_record.py"

# A capability is a marker that is present IFF the check exists. Each is a behaviour a client
# would lose if only one copy had it — not a stylistic string. Add a row when either side gains
# a security check; that is the point at which a human decides whether it must be ported.
CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("windowed firmware floor", "floor valid_from"),
    ("firmware TCB floor at all", "min_tcb"),
    ("windowed policy identity", "valid_from"),
    ("revocation fetch is SKIP, never 'revoked'", "check-revocation"),
    ("VCEK-only signing key", "VCEK"),
    ("explicit stdio entries, not a Rego default", "allow_stdio_access"),
    ("runtime logging denial", "allow_runtime_logging"),
    ("platform fragment disclosure", "aci-cc-infra-fragment"),
)


# Drift that is KNOWN, OPEN, and blocked on something other than a port. Listing it here keeps the
# gate live for a THIRD divergence instead of going permanently red and being ignored — but the list
# cannot rot: an entry that has stopped drifting FAILS, forcing its removal.
KNOWN_OPEN_DRIFT: dict[str, str] = {
    "platform fragment disclosure": (
        "In the shipped client only; the sibling does not disclose the pinned ACI infra fragment's "
        "containers. Found by this test on its first run, not by a human. The other session owns it."
    ),
}


def _missing(text: str) -> set[str]:
    return {name for name, marker in CAPABILITIES if marker not in text}


@pytest.mark.skipif(not SIBLING.exists(), reason=f"sibling verifier not on this machine: {SIBLING}")
def test_the_shipped_verifier_has_every_capability_the_sibling_has():
    """A capability the OTHER copy has and ours lacks is a check the CLIENT cannot make."""
    ours, theirs = OURS.read_text(), SIBLING.read_text()
    ours_missing = _missing(ours) - _missing(theirs) - set(KNOWN_OPEN_DRIFT)
    assert not ours_missing, (
        "the SHIPPED verifier is missing capabilities the sibling copy has, so a client cannot "
        f"make these checks: {sorted(ours_missing)}. Port them, or add a row to CAPABILITIES "
        "recording the deliberate decision not to."
    )


@pytest.mark.skipif(not SIBLING.exists(), reason=f"sibling verifier not on this machine: {SIBLING}")
def test_divergence_is_reported_in_both_directions():
    """Ours having something theirs lacks is not a client-facing defect, but it is still drift and
    the next port should know about it. Fails loudly rather than silently accumulating."""
    ours, theirs = OURS.read_text(), SIBLING.read_text()
    theirs_missing = _missing(theirs) - _missing(ours) - set(KNOWN_OPEN_DRIFT)
    assert not theirs_missing, (
        f"the sibling copy is missing capabilities this one has: {sorted(theirs_missing)}. Not a "
        "client-facing gap, but the copies have drifted and the other session should be told."
    )


def test_the_capability_list_actually_discriminates():
    """A marker that is present in EVERY file cannot detect anything. Each marker must be absent
    from a text that lacks the capability, or this whole gate is a control that always passes."""
    for name, marker in CAPABILITIES:
        assert marker not in "", name
        assert marker in OURS.read_text() or SIBLING.exists(), name


@pytest.mark.skipif(not SIBLING.exists(), reason=f"sibling verifier not on this machine: {SIBLING}")
def test_the_known_drift_list_cannot_rot():
    """An exemption that outlives the thing it exempts is a control that always passes. If an entry
    here has stopped drifting, it must be DELETED, or the gate quietly stops watching that
    capability forever."""
    ours, theirs = OURS.read_text(), SIBLING.read_text()
    actually_drifting = _missing(ours) ^ _missing(theirs)
    stale = set(KNOWN_OPEN_DRIFT) - actually_drifting
    assert not stale, (
        f"these are no longer drifting and must be removed from KNOWN_OPEN_DRIFT: {sorted(stale)}. "
        "Leaving them exempts a capability that is now in sync, so a FUTURE divergence in it would "
        "go unnoticed."
    )
