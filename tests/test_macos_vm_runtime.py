import hashlib, json, os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from inferroute_local.macos_vm import VMUnavailable
from inferroute_local.macos_vm import runtime


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    root.mkdir()
    key = Ed25519PrivateKey.generate()
    policy = {
        "schema": 1,
        "public_key": key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex(),
        "team_id": "TESTTEAM01",
        "runner_identifier": "ai.inferroute.ProbantVM",
    }
    artifacts = {}
    for name, data in [
        ("ProbantVM", b"SYNTHETIC RUNNER"),
        ("kernel", b"SYNTHETIC KERNEL"),
        ("initrd", b"SYNTHETIC IMAGE"),
    ]:
        (root / name).write_bytes(data)
        artifacts[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    body = {
        "schema": "inferroute.macos-vm/1",
        "protocol": 1,
        "architecture": "arm64",
        "minimum_macos": "12.0",
        "pi_version": "0.84.1",
        "development_only": False,
        "artifacts": artifacts,
    }

    def sign():
        m = {
            **body,
            "signature": key.sign(runtime.DOMAIN + runtime.canonical(body)).hex(),
        }
        (root / "runtime.json").write_text(json.dumps(m))
        return m

    sign()
    monkeypatch.setattr(runtime, "check_codesign", lambda *a: None)
    return root, policy, body, sign


def test_private_verified_staging_survives_source_replacement(candidate):
    root, policy, body, _ = candidate
    staged = runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")
    try:
        old = staged.directory / "kernel"
        (root / "kernel").write_bytes(b"SYNTHETIC ATTACK")
        (root / "initrd").unlink()
        (root / "initrd").write_bytes(b"SYNTHETIC NEW IMAGE")
        assert old.read_bytes() == b"SYNTHETIC KERNEL"
        assert (staged.directory / "initrd").read_bytes() == b"SYNTHETIC IMAGE"
        assert staged.directory.stat().st_mode & 0o777 == 0o700
        assert (staged.directory / "boot.json").stat().st_mode & 0o222 == 0
    finally:
        staged.close()
    assert not staged.directory.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("development_only", True),
        ("protocol", 2),
        ("architecture", "x86_64"),
        ("minimum_macos", "99.0"),
        ("schema", "other"),
        ("pi_version", "0.0.0"),
    ],
)
def test_signed_but_unsupported_refuses(candidate, field, value):
    root, policy, body, sign = candidate
    body[field] = value
    sign()
    with pytest.raises(VMUnavailable):
        runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")


def test_tampered_manifest_refuses(candidate):
    root, policy, body, _ = candidate
    m = json.loads((root / "runtime.json").read_text())
    m["development_only"] = True
    (root / "runtime.json").write_text(json.dumps(m))
    with pytest.raises(VMUnavailable, match="signature"):
        runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "wrong-bytes", "fifo"])
def test_unsafe_artifact_refuses(candidate, kind, tmp_path):
    root, policy, body, _ = candidate
    p = root / "kernel"
    outside = tmp_path / "outside"
    outside.write_bytes(p.read_bytes())
    p.unlink()
    if kind == "symlink":
        p.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, p)
    elif kind == "wrong-bytes":
        p.write_bytes(b"X" * body["artifacts"]["kernel"]["bytes"])
    else:
        os.mkfifo(p)
    with pytest.raises(VMUnavailable):
        runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")


def test_untrusted_codesign_refuses(candidate, monkeypatch):
    root, policy, _, _ = candidate

    def refused(*args):
        raise VMUnavailable("signing refused")

    monkeypatch.setattr(runtime, "check_codesign", refused)
    with pytest.raises(VMUnavailable, match="signing"):
        runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")


def test_missing_policy_cannot_use_environment_key(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "POLICY_PATH", tmp_path / "missing")
    monkeypatch.setenv("IR_MAC_VM_PUBLIC_KEY", "0" * 64)
    with pytest.raises(VMUnavailable, match="not provisioned"):
        runtime.trusted_policy()


def test_actual_dev_fixture_has_no_vendor_signature(tmp_path):
    p = tmp_path / "runtime.json"
    p.write_text('{"schema":1,"development_only":true}')
    with pytest.raises(VMUnavailable):
        runtime.stage(
            tmp_path,
            {"public_key": "0" * 64},
            architecture="arm64",
            os_version="15.7.7",
        )
