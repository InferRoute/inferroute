"""scripts/sign_macos_runtime.py: what it signs, what it refuses, and that the client accepts the result."""
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from inferroute_local.macos_vm import VMUnavailable, runtime

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sign_macos_runtime", REPO / "scripts/sign_macos_runtime.py")
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)

# magic, cputype arm64, cpusubtype, filetype MH_EXECUTE
RUNNER = bytes.fromhex("cffaedfe" "0c000001" "00000000" "02000000") + b"SYNTHETIC RUNNER" * 8


@pytest.fixture
def inputs(tmp_path, capsys):
    key = tmp_path / "signing.key"
    signer.keygen(SimpleNamespace(key=str(key)))
    public = capsys.readouterr().out.split("public key:")[1].split()[0]
    guest = tmp_path / "guest"
    guest.mkdir()
    files = {"kernel": b"SYNTHETIC KERNEL" * 64, "initrd": b"SYNTHETIC IMAGE" * 64}
    for name, data in files.items():
        (guest / name).write_bytes(data)
    (guest / "guest-manifest.json").write_text(json.dumps({
        "arch": "aarch64", "pi_version": "0.84.1",
        "artifacts": {n: {"bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()} for n, d in files.items()}}))
    runner = tmp_path / "ProbantVM"
    runner.write_bytes(RUNNER)
    policy = {"schema": 2, "public_key": public, "runner_signing": "adhoc-pinned"}
    return SimpleNamespace(key=key, guest=guest, runner=runner, policy=policy, tmp=tmp_path)


def build(inputs, out="out"):
    a = SimpleNamespace(key=str(inputs.key), runner=str(inputs.runner), guest=str(inputs.guest), version="0.0.1",
                        out=str(inputs.tmp / out), minimum_macos="12.0")
    signer.build(a)
    return next((inputs.tmp / out).glob("*.whl"))


def test_the_key_is_private_to_its_owner_and_never_overwritten(inputs):
    assert inputs.key.stat().st_mode & 0o077 == 0
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        signer.keygen(SimpleNamespace(key=str(inputs.key)))
    inputs.key.chmod(0o644)
    with pytest.raises(SystemExit, match="readable by others"):
        build(inputs)


def test_the_built_wheel_is_what_the_client_stages(inputs, monkeypatch):
    wheel = build(inputs)
    assert wheel.name == "inferroute_macos_vm_runtime-0.0.1-py3-none-macosx_11_0_arm64.whl"
    site = inputs.tmp / "site-packages"
    with zipfile.ZipFile(wheel) as z:
        z.extractall(site)
        assert (z.getinfo("inferroute_macos_vm_runtime/ProbantVM").external_attr >> 16) & 0o111
    monkeypatch.setattr(runtime, "check_codesign", lambda *a: None)
    staged = runtime.stage(site / "inferroute_macos_vm_runtime", inputs.policy, architecture="arm64", os_version="15.0")
    try:
        assert staged.runner.read_bytes() == RUNNER
        assert staged.runner.stat().st_mode & 0o777 == 0o500
    finally:
        staged.close()
    # ...and not under any other key
    other = dict(inputs.policy, public_key="ab" * 32)
    with pytest.raises(VMUnavailable, match="signature"):
        runtime.stage(site / "inferroute_macos_vm_runtime", other, architecture="arm64", os_version="15.0")


def test_the_same_inputs_give_the_same_wheel(inputs):
    assert build(inputs, "a").read_bytes() == build(inputs, "b").read_bytes()


def test_a_development_runner_is_never_signed(inputs):
    inputs.runner.write_bytes(RUNNER + b"PROBANT_VM_DEVELOPMENT_BUILD guest console is copied to stderr")
    with pytest.raises(SystemExit, match="DEVELOPMENT runner"):
        build(inputs)


def test_the_marker_the_signer_looks_for_is_the_one_the_runner_prints():
    swift = (REPO / "native/macos/ProbantVM.swift").read_text()
    block = swift.split("#if PROBANT_DEV_CONSOLE")[1].split("#else")[0]
    assert signer.DEV_MARKER.decode() in block
    assert signer.DEV_MARKER.decode() not in swift.replace(block, "")
    assert "PROBANT_DEV_CONSOLE" in (REPO / "native/macos/build_runner.sh").read_text()


@pytest.mark.parametrize("data", [
    b"#!/bin/sh\necho not a runner\n" + b"x" * 64,
    bytes.fromhex("cffaedfe" "07000001" "00000000" "02000000") + b"x" * 64,       # x86_64
    bytes.fromhex("cffaedfe" "0c000001" "00000000" "06000000") + b"x" * 64,       # arm64, but a dylib
])
def test_only_an_arm64_executable_is_a_runner(inputs, data):
    inputs.runner.write_bytes(data)
    with pytest.raises(SystemExit, match="arm64 Mach-O executable"):
        build(inputs)


def test_a_kernel_from_a_different_build_is_refused(inputs):
    (inputs.guest / "kernel").write_bytes(b"ANOTHER KERNEL" * 64)
    with pytest.raises(SystemExit, match="ONE build_guest.py run"):
        build(inputs)


def test_verify_needs_no_private_key_and_catches_a_swapped_file(inputs, capsys):
    wheel = build(inputs)
    policy = inputs.tmp / "policy.json"
    policy.write_text(json.dumps(inputs.policy))
    assert signer.verify(SimpleNamespace(wheel=str(wheel), policy=str(policy))) == 0
    tampered = inputs.tmp / "tampered.whl"
    with zipfile.ZipFile(wheel) as src, zipfile.ZipFile(tampered, "w") as dst:
        for item in src.infolist():
            dst.writestr(item, b"SWAPPED" if item.filename.endswith("/kernel") else src.read(item))
    capsys.readouterr()
    assert signer.verify(SimpleNamespace(wheel=str(tampered), policy=str(policy))) == 1
    assert "FAIL  kernel" in capsys.readouterr().out
