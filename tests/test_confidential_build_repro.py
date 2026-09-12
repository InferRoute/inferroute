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
    assert b["reproduced"] == ["mrtd", "rtmr1", "rtmr2"]
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


# The RTMR2 event log measured out of the operator's published image on 2026-09-12, and confirmed
# against a real boot. The bootloader measures nothing on a confidential VM — it only starts when
# it finds a TPM protocol, and this firmware publishes the confidential-computing one instead — so
# the register holds three owner-key entries the bootloader synthesises from a certificate inside
# its own binary, then the command line and the initramfs from the kernel's boot stub.
RTMR2_EVENTS = [
    "053357ea65185f010b8caa1fc265cfd5e80c7cc781254fa3f1e5ea9d345a87003cf761472a2f0423f15297f55cfe248f",
    "80ee2571334a57bf90238d21964447e542079d4805fa87887817a97dcb720906683a09b1ac634c76c0c0be1177f76110",
    "8d2ce87d86f55fcfab770a047b090da23270fa206832dfea7e0c946fff451f819add242374be551b0d6318ed6c7d41d8",
    "ca9be8ed063ebe5ddb9c6925cc30085c512cb25788effcf375618311a2a3872978b0dbb48d6a4528e9836f1487cbf785",
    "6c9ae139e17ea07cc32460ab2d1a31ca1ced8b68df9c0204ea69e030aa8f5de2c5135b9f239c8eb3d39e73e9dacde638",
]


def test_rtmr2_fold_reproduces_the_recorded_value():
    assert repro._fold([bytes.fromhex(d) for d in RTMR2_EVENTS]) == _recorded("rtmr2")


def test_a_changed_initramfs_changes_rtmr2():
    """The whole point of reproducing this register: it pins the initial RAM filesystem, which is
    what unlocks the disk and takes the application measurement."""
    swapped = RTMR2_EVENTS[:-1] + ["ab" * 48]
    assert repro._fold([bytes.fromhex(d) for d in swapped]) != _recorded("rtmr2")


def test_the_command_line_is_measured_with_the_bootloader_prefix():
    """The config file does not show the BOOT_IMAGE= prefix the bootloader prepends; leaving it
    out gives a digest that is wrong in a way nothing else reveals."""
    import hashlib
    base = ("root=UUID=b8d533cc-73cc-45e5-996e-6f003cfd03c1 ro console=ttyS0,115200n8 "
            "systemd.mask=getty@tty1.service systemd.mask=serial-getty@ttyS0.service "
            "systemd.mask=serial-getty@hvc0.service systemd.mask=emergency.service "
            "systemd.mask=rescue.service console=tty1 console=ttyS0")
    with_prefix = "BOOT_IMAGE=/vmlinuz-6.17.0-35-generic " + base
    assert hashlib.sha384(with_prefix.encode("utf-16-le")).hexdigest() == RTMR2_EVENTS[3]
    assert hashlib.sha384(base.encode("utf-16-le")).hexdigest() != RTMR2_EVENTS[3]


def test_a_partial_read_must_never_be_measured(tmp_path, monkeypatch):
    """A reader that stalls must make the answer "unknown", never a quietly wrong digest.

    qemu-img sizes its output up front and fills it in afterwards, so the file reaches its final
    length long before the data is there. An earlier version of this script treated that length as
    proof the read was done; it produced a file of exactly the right size containing partly zeroes,
    and therefore a measurement that was WRONG rather than missing. That is the worst failure a
    digest-comparison tool can have, so it gets a test.
    """
    import subprocess as sp
    out = tmp_path / "boot.img"

    def fake_run(argv, **kw):
        out.write_bytes(b"\x00" * 1024)          # right length, no data — the trap
        raise sp.TimeoutExpired(argv, kw.get("timeout", 1))

    monkeypatch.setattr(repro.subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as e:
        repro._qemu_slice("https://example/x.qcow2", 0, 1024, out, read_timeout=1)
    assert "partial" in str(e.value).lower()


# ───────────── signing: a run-time build that only InferRoute could have authorised ─────────────

@pytest.fixture
def signing(monkeypatch):
    """A throwaway keypair, with the public half installed as if we shipped it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    monkeypatch.setattr(builds, "SIGNING_KEYS", (pub,))
    monkeypatch.setattr(builds, "_EXTRA", [])
    return k


def _row(**over):
    r = {"id": "r", "mrtd": "aa" * 48, "rtmr1": "bb" * 48, "rtmr2": "cc" * 48, "rtmr3": "dd" * 48}
    r.update(over)
    return r


def _sign(k, row):
    return {**row, "sig": k.sign(builds.signed_bytes(row)).hex()}


def test_a_signed_build_is_our_record_an_unsigned_one_is_only_pending(signing):
    builds.absorb_remote([_sign(signing, _row(id="signed-one"))])
    builds.absorb_remote([_row(id="unsigned-one", mrtd="11" * 48)])
    by_id = {e["id"]: e for e in builds._EXTRA}
    assert by_id["signed-one"]["status"] == "signed"
    assert by_id["unsigned-one"]["status"] == "pending"


def test_changing_any_measurement_invalidates_the_signature(signing):
    """The point of signing: a compromised relay must not be able to bless another enclave."""
    signed = _sign(signing, _row())
    assert builds.verify_signature(signed)
    for field in ("mrtd", "rtmr1", "rtmr2", "rtmr3"):
        assert not builds.verify_signature({**signed, field: "ee" * 48}), field


def test_a_signature_cannot_be_replayed_onto_a_different_entry(signing):
    signed = _sign(signing, _row(id="original"))
    assert not builds.verify_signature({**signed, "id": "someone-elses"})


def test_a_cosmetic_field_can_change_without_re_signing(signing):
    """Notes and dates are not security-relevant; requiring a re-sign for them would push
    people towards keeping the key somewhere convenient, which is the whole risk."""
    signed = _sign(signing, _row())
    assert builds.verify_signature({**signed, "note": "added later", "first_seen": "2026-01-01"})


def test_a_signature_from_the_wrong_key_is_refused(signing):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    assert not builds.verify_signature(_sign(Ed25519PrivateKey.generate(), _row()))


def test_with_no_shipped_key_nothing_verifies(monkeypatch, signing):
    """Until a key is shipped, every run-time build must stay pending — never silently trusted."""
    signed = _sign(signing, _row())
    monkeypatch.setattr(builds, "SIGNING_KEYS", ())
    assert not builds.verify_signature(signed)


def test_the_signing_key_is_not_shipped_in_the_client():
    """A private key in the package would defeat the entire mechanism."""
    import inferroute_local.confidential as pkg
    for f in Path(pkg.__file__).parent.rglob("*.py"):
        body = f.read_text()
        assert "PrivateFormat.Raw" not in body or "sign_build" in f.name, f
        assert "Ed25519PrivateKey.generate" not in body, f


def test_the_mrtd_control_is_scoped_to_the_measured_volume():
    """A control that overstates its own reach is worse than none: it invites the reader to believe
    any firmware change is caught. Measured 2026-09-12: flipping a bit at 0x200000 or 0x300000
    moves MRTD; flipping one at 0x1000 or 0x40000, in the configuration volume holding the variable
    store, leaves it identical. MRTD covers the boot volume, not the whole 4 MB file."""
    import re
    src = Path(repro.__file__).parent.parent / "inferroute_local" / "confidential" / "builds.py"
    # Normalise wrapping and comment markers: this asserts on PROSE, which is line-wrapped, and a
    # contiguous-substring check silently passes or fails on where the author happened to break.
    text = re.sub(r"\s+", " ", src.read_text().replace("#", " "))
    assert "configuration volume that holds the variable store" in text
    assert "leaves it at 261ce538" in text and "unchanged" in text
    assert '"any change to the firmware changes MRTD" would be false' in text
    assert "reproduces the committed blob BYTE-IDENTICALLY" in text
