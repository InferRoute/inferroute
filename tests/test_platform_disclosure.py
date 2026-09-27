"""Name what the platform adds, instead of reporting "unresolved" as though nobody looked.

An ACI policy must reference Microsoft's infrastructure fragment — excluding it leaves the platform
unable to mount its own layers and the group never starts (tested 2026-09-28 on a real Confidential
group). So the dependency is permanent, and the only honest options are to describe it or to imply
ignorance of it. These pin the description, and pin that describing it SOFTENS NOTHING.
"""
import base64
import io
from contextlib import redirect_stdout

import pytest

from tests.test_verify_record import _load

FEED = "mcr.microsoft.com/aci/aci-cc-infra-fragment"
ISSUER = ("did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
          "::eku:1.3.6.1.4.1.311.76.59.1.3")

POLICY = '''package policy

fragments := [
  {
    "feed": "%s",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "%s",
    "minimum_svn": "4"
  }
]

containers := [{"allow_elevated":false,"allow_stdio_access":false,"exec_processes":[],"layers":["aa"]}]
''' % (FEED, ISSUER)


def _m():
    return _load()


def test_the_real_shaped_policy_is_disclosed():
    d = _m().platform_dependency_disclosure(POLICY)
    assert d is not None
    dep = d["dependencies"][0]
    assert dep["feed"] == FEED
    assert "allow_stdio_access true" in dep["says"]


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t.replace(FEED, "evil.example/frag"), "unknown feed"),
    (lambda t: t.replace("I__iuL25oXEVFdTP", "XXXXXXXXXXXXXXXX"), "issuer tampered"),
    (lambda t: t.replace('"minimum_svn": "4"', '"minimum_svn": "1"'), "below floor"),
    (lambda t: t.replace('"minimum_svn": "4"', '"minimum_svn": "four"'), "unparseable svn"),
    (lambda t: t + "\nfragments := []\n", "two fragment arrays"),
])
def test_anything_not_exactly_the_pinned_dependency_is_not_disclosed(mutate, why):
    """INVERSION: when we cannot identify it, "unresolved" is the honest word and must survive."""
    assert _m().platform_dependency_disclosure(mutate(POLICY)) is None, why


def test_base64_is_not_a_policy():
    """REGRESSION: passing the base64 in place of the text returned None and read exactly like a
    policy with no platform dependency at all — silence that looked like a clean result."""
    assert _m().platform_dependency_disclosure(base64.b64encode(POLICY.encode()).decode()) is None


def test_disclosure_adds_a_blocker_rather_than_removing_one():
    """The dependency still blocks. Describing it must never shorten the list."""
    m = _m()
    words = dict(m.PLAIN_BLOCKER_WORDS)
    key = ("platform containers supplied by the cloud provider are part of the effective policy and "
           "are not ours to constrain")
    assert key in words, "the platform blocker must have an exact plain rendering, not the fallback"
    rendered = m.plain_blockers([f"policy abc123: {key}"])
    assert len(rendered) == 1
    assert "cloud platform" in rendered[0]
    assert "in its original words" not in rendered[0], "fell through to the verbatim fallback"


def test_the_plain_rendering_does_not_claim_anyone_read_anything():
    m = _m()
    key = ("platform containers supplied by the cloud provider are part of the effective policy and "
           "are not ours to constrain")
    text = m.plain_blockers([f"policy abc123: {key}"])[0].lower()
    for overclaim in ("was read", "were read", "accessed your", "exposed"):
        assert overclaim not in text
