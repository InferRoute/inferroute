"""The confinement precheck: in require mode the launch refuses unless egress can be confined by
ADDRESS, and it names the one-time install; otherwise it uses port-level confinement and states the
residual. The netns probe and userns flag are stubbed so the logic is tested on every platform."""
import subprocess
import sys
from pathlib import Path

import pytest

from inferroute_cli import pi_attested as P
from inferroute_local import confinement as C

HERE = Path(__file__).resolve().parent.parent


@pytest.fixture
def stub(monkeypatch):
    def set_env(mode):
        if mode is None:
            monkeypatch.delenv("IR_ATTESTED_CONFINE", raising=False)
        else:
            monkeypatch.setenv("IR_ATTESTED_CONFINE", mode)

    def platform(address_level, restricted, linux=True, abi=8):
        monkeypatch.setattr(C.sys, "platform", "linux" if linux else "darwin")
        monkeypatch.setattr(C, "netns_available", lambda: address_level)
        monkeypatch.setattr(C, "userns_restricted", lambda: restricted)
        monkeypatch.setattr(C, "landlock_abi", lambda _libc: abi)
    return set_env, platform


def test_require_launches_only_with_address_level(stub):
    set_env, platform = stub
    set_env("require")
    platform(address_level=True, restricted=False)
    ok, notice = P.confine_precheck()
    assert ok and "ADDRESS" in notice


def test_require_refuses_and_names_the_install_when_userns_restricted(stub):
    set_env, platform = stub
    set_env("require")
    platform(address_level=False, restricted=True)
    ok, notice = P.confine_precheck()
    assert not ok and "install-confine-profile.sh" in notice


def test_require_refuses_off_linux(stub):
    set_env, platform = stub
    set_env("require")
    platform(address_level=False, restricted=False, linux=False)
    ok, notice = P.confine_precheck()
    assert not ok and "cannot confine egress by address" in notice


def test_default_uses_port_level_and_states_the_residual(stub):
    set_env, platform = stub
    set_env(None)
    platform(address_level=False, restricted=True)
    ok, notice = P.confine_precheck()
    assert ok and "port-level" in notice and "still reachable" in notice


def test_default_reports_address_level_when_available(stub):
    set_env, platform = stub
    set_env(None)
    platform(address_level=True, restricted=False)
    ok, notice = P.confine_precheck()
    assert ok and "ADDRESS" in notice and "residual" not in notice.lower()


def test_off_disables_and_says_nothing(stub):
    set_env, platform = stub
    set_env("off")
    ok, notice = P.confine_precheck()
    assert ok and notice == ""


def test_no_landlock_warns_but_launches(stub):
    set_env, platform = stub
    set_env(None)
    platform(address_level=False, restricted=False, abi=0)
    ok, notice = P.confine_precheck()
    assert ok and "cannot confine" in notice


@pytest.mark.skipif(sys.platform != "linux" or not __import__("shutil").which("shellcheck"),
                    reason="shellcheck not available")
def test_install_script_passes_shellcheck():
    r = subprocess.run(["shellcheck", str(HERE / "scripts" / "install-confine-profile.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_install_script_and_profile_exist():
    assert (HERE / "scripts" / "install-confine-profile.sh").exists()
    prof = (HERE / "scripts" / "apparmor" / "ir-pi-bwrap").read_text()
    assert "userns," in prof and "/usr/bin/bwrap" in prof
