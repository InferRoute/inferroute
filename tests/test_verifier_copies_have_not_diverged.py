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
    # EMPTY, and that is the correct state: the copies are in sync as of 2026-09-29, after the
    # sealed-research session re-vendored on canonical 1740188. An entry here is an EXEMPTION, and
    # the anti-rot test below fails when one outlives the drift it exempted — which is what emptied
    # this dict: it fired twice, once per closed drift, and refused to let a stale entry sit.
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


def test_no_capability_has_vanished_from_BOTH_copies():
    """The hole the other session found in my first version, which read:

        assert marker not in ""                              # true of every string, always
        assert marker in OURS.read_text() or SIBLING.exists() # passes whenever the sibling is on disk

    Both assertions were decoration. The second is the dangerous one: on the machine where the
    sibling checkout exists — the machine where deploys are cut — it passed for EVERY marker
    regardless of the file's contents.

    The real hazard it was meant to cover: a capability removed from BOTH copies. The divergence
    tests compare the two sets and see no difference, so they stay green while the client quietly
    loses a check. A marker present in neither copy means either a deliberate removal (delete the
    row) or a silent regression (restore the code). Both need a human."""
    ours = OURS.read_text()
    theirs = SIBLING.read_text() if SIBLING.exists() else ""
    vanished = [name for name, marker in CAPABILITIES if marker not in ours and marker not in theirs]
    assert not vanished, (
        f"these capabilities are in NEITHER copy: {vanished}. Either they were dropped on purpose — "
        f"then delete the row from CAPABILITIES — or they were lost, and no divergence test can see "
        f"it because both sides lost them together."
    )


def test_that_check_can_actually_FAIL():
    """A guard is worth what it refuses. Feed the same predicate a marker neither copy contains and
    confirm it is reported, rather than trusting that it would be."""
    ours = OURS.read_text()
    theirs = SIBLING.read_text() if SIBLING.exists() else ""
    fake = "a-capability-marker-no-verifier-has-4f2a9c"
    vanished = [n for n, mk in (("invented", fake),) if mk not in ours and mk not in theirs]
    assert vanished == ["invented"], "the vanished-capability predicate cannot detect a missing marker"


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
