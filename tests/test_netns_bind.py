"""Step 7 — the netns matter-dir bind — as a LIVE test, so its gap shows as a named skip, never as silence.

It skips unless an unprivileged empty network namespace can actually be created here, which needs the
AppArmor profile Henry installs (scripts/install-confine-profile.sh). Until then it is a visible SKIP with
that reason. When the profile is installed but the step-7 wrapper is not yet built, it skips again with that
reason — so it never reads as a pass and never fails. Once the wrapper exists it becomes its acceptance test:
from inside the sandbox, secrets and the confidential/ tree are not readable, the matter dir is writable, and
only the two local verifying proxies are reachable.
"""
import pytest

from inferroute_local.confinement import netns_available

pytestmark = pytest.mark.skipif(
    not netns_available(),
    reason="needs the AppArmor profile (scripts/install-confine-profile.sh) so an unprivileged netns can be created",
)


def _step7_wrapper():
    """The step-7 builder that runs a command inside a bwrap netns binding ONLY the matter dir, with the two
    proxies relayed in. Returns the callable, or None if step 7 is not implemented yet."""
    from inferroute_cli import pi_attested
    return getattr(pi_attested, "run_in_netns_bind", None)


def test_netns_bind_confines_reads_writes_and_egress(tmp_path):
    run = _step7_wrapper()
    if run is None:
        pytest.skip("netns is available here, but the step-7 matter-dir bind wrapper is not built yet")
    # When step 7 lands, assert (per the decision record):
    #   - a read of ~/.ssh and of INFERROUTE_HOME/confidential/ from inside the sandbox fails (not visible);
    #   - the matter workspace dir is writable;
    #   - both local verifying proxies are reachable, and nothing else on the network is.
    # The concrete calls are written against run_in_netns_bind once its signature is fixed in step 7.
    raise AssertionError("step-7 acceptance assertions to be filled in when run_in_netns_bind exists")
