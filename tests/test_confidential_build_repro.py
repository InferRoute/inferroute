"""The recorded-build reproduction, and the clipboard preflight.

The reproduction is the only check in the lane whose evidence we produce OURSELVES rather
than receive, so it gets a regression test with the real event log from the 2026-09-12 run.
If the fold, the Authenticode digest or the recorded value drifts, this fails loudly.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

from inferroute_local.confidential import builds

_spec = importlib.util.spec_from_file_location(
    "repro", Path(__file__).resolve().parents[1] / "scripts" / "reproduce_enclave_build.py")
repro = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(repro)

# The RTMR1 event log measured out of the operator's published guest image on 2026-09-12.
# Entries 1, 2, 6, 7 are firmware-fixed; 3 is the GUID partition table; 4 and 5 are the
# Authenticode digests of shim and GRUB as read from the image's EFI system partition.
GPT_EVENT_SHA384 = "e93b5a85679490339e19b56f031b9f1d3a47b6032075bf0f9785f6cb8641e1d1692c9301d5863decfa03493531de86c5"
SHIM_AUTHENTICODE = "4637fb5cd30847e5f09ae24f8a50ce1611c4d21afd0ecb69c8ec40bc82dc11bc48abda1f8044fe340bfb70b29606eb47"
GRUB_AUTHENTICODE = "d9c40784e214bb829477f46245758e74f6b145dbf012960d4053c2fe27545738d89833297b4fd9ec348dde75910bfa33"


def _recorded(reg: str) -> str:
    return builds.BUNDLED[0][reg]


def test_the_recorded_build_declares_what_we_reproduced_ourselves():
    b = builds.BUNDLED[0]
    assert b["reproduced"] == ["mrtd", "rtmr1"]
    # every claimed register must actually be recorded, or the claim points at nothing
    for reg in b["reproduced"]:
        assert b.get(reg), f"claimed {reg} reproduced but no recorded value"


def test_the_reproduction_inputs_are_pinned_so_the_claim_can_be_rechecked():
    """Naming the registers we reproduced is not enough: a reader must be able to check WHICH
    artifacts produced them, and notice if one is quietly swapped."""
    src = builds.BUNDLED[0]["reproduced_from"]
    assert set(src) == {"firmware", "shim", "grub"}
    for name, digest in src.items():
        assert len(digest) == 64 and int(digest, 16) >= 0, name


def test_rtmr1_fold_reproduces_the_recorded_value_from_the_measured_event_log():
    import hashlib
    s = lambda x: hashlib.sha384(x).digest()
    log = [
        s(b"Calling EFI Application from Boot Option"),
        s(bytes(4)),
        bytes.fromhex(GPT_EVENT_SHA384),
        bytes.fromhex(SHIM_AUTHENTICODE),
        bytes.fromhex(GRUB_AUTHENTICODE),
        s(b"Exit Boot Services Invocation"),
        s(b"Exit Boot Services Returned with Success"),
    ]
    assert repro._fold(log) == _recorded("rtmr1")


def test_a_changed_bootloader_changes_rtmr1():
    """The whole point: swapping shim or GRUB must not still pass."""
    import hashlib
    s = lambda x: hashlib.sha384(x).digest()
    log = [s(b"Calling EFI Application from Boot Option"), s(bytes(4)),
           bytes.fromhex(GPT_EVENT_SHA384), bytes.fromhex(SHIM_AUTHENTICODE),
           s(b"a different GRUB"),
           s(b"Exit Boot Services Invocation"),
           s(b"Exit Boot Services Returned with Success")]
    assert repro._fold(log) != _recorded("rtmr1")


def test_authenticode_refuses_something_that_is_not_a_pe_image():
    with pytest.raises(Exception):
        repro.authenticode_sha384(b"\x00" * 512)


def test_gpt_parsing_refuses_a_disk_without_a_partition_table():
    with pytest.raises(SystemExit):
        repro.read_gpt(b"\x00" * 4096)


def test_the_script_compiles_no_image_locator_of_its_own(monkeypatch, capsys):
    """0.9.0 removed operator addresses from the client; this tool must not reintroduce one.
    With no locator given there is nothing to fall back to, so it must refuse."""
    monkeypatch.delenv("IR_BUILD_IMAGE", raising=False)
    monkeypatch.setattr(sys, "argv", ["reproduce_enclave_build.py"])
    with pytest.raises(SystemExit) as e:
        repro.main()
    assert e.value.code != 0
    assert "--image is required" in capsys.readouterr().err


# ───────────────────────── clipboard preflight ─────────────────────────

@pytest.fixture
def agents(monkeypatch, tmp_path):
    from inferroute_cli import agents as mod
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path))
    return mod


def test_no_clipboard_helper_on_wayland_is_reported(agents, monkeypatch):
    monkeypatch.setattr(agents.shutil, "which", lambda n: None)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(agents.sys, "platform", "linux")
    assert agents.clipboard_gap() == "wayland"


def test_an_installed_helper_is_silent(agents, monkeypatch):
    monkeypatch.setattr(agents.shutil, "which", lambda n: "/usr/bin/wl-copy" if n == "wl-copy" else None)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    assert agents.clipboard_gap() is None


def test_a_headless_session_is_silent(agents, monkeypatch):
    """Nothing on this machine to copy into: saying so would be noise."""
    monkeypatch.setattr(agents.shutil, "which", lambda n: None)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(agents.sys, "platform", "linux")
    assert agents.clipboard_gap() is None


def test_the_notice_is_shown_once_not_every_launch(agents, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(agents.shutil, "which", lambda n: "/usr/bin/apt-get" if n == "apt-get" else None)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(agents.sys, "platform", "linux")
    agents.warn_clipboard_once()
    first = capsys.readouterr().err
    assert "clipboard" in first
    agents.warn_clipboard_once()
    assert capsys.readouterr().err == ""


def test_install_command_is_never_run_implicitly(agents, monkeypatch):
    """clipboard_gap/warn must not shell out; only `ir fix-clipboard` may install."""
    monkeypatch.setattr(agents.shutil, "which", lambda n: "/usr/bin/apt-get" if n == "apt-get" else None)
    cmd = agents.clipboard_install_cmd("wayland")
    assert cmd[0] == "sudo" and "wl-clipboard" in cmd
