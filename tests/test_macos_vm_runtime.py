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


def test_an_installer_that_hard_links_its_files_is_not_refused(candidate, tmp_path, monkeypatch):
    """uv links every installed file from its cache. The first real install of this client refused its own
    policy file as "unsafe runtime metadata" for having two names."""
    root, policy, body, _ = candidate
    for name in ("kernel", "initrd", "ProbantVM", "runtime.json"):
        os.link(root / name, tmp_path / ("cache-" + name))
    staged = runtime.stage(root, policy, architecture="arm64", os_version="15.7.7")
    try:
        assert (staged.directory / "kernel").read_bytes() == b"SYNTHETIC KERNEL"
        assert (staged.directory / "kernel").stat().st_nlink == 1          # the staged copy is its own file
    finally:
        staged.close()
    linked_policy = tmp_path / "policy.json"
    linked_policy.write_text(json.dumps({"schema": 2, "public_key": "ab" * 32, "runner_signing": "adhoc-pinned"}))
    os.link(linked_policy, tmp_path / "cache-policy.json")
    monkeypatch.setattr(runtime, "POLICY_PATH", linked_policy)
    assert runtime.trusted_policy()["schema"] == 2


@pytest.mark.parametrize("kind", ["symlink", "hardlink-to-other-bytes", "wrong-bytes", "fifo"])
def test_unsafe_artifact_refuses(candidate, kind, tmp_path):
    root, policy, body, _ = candidate
    p = root / "kernel"
    outside = tmp_path / "outside"
    outside.write_bytes(p.read_bytes())
    p.unlink()
    if kind == "symlink":
        p.symlink_to(outside)
    elif kind == "hardlink-to-other-bytes":
        outside.write_bytes(b"X" * body["artifacts"]["kernel"]["bytes"])
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


# ── the two signing tiers, and where the runtime is installed ────────────────────────────────────────────


def _write_policy(tmp_path, monkeypatch, value):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(value))
    monkeypatch.setattr(runtime, "POLICY_PATH", p)
    return p


def test_the_adhoc_tier_is_a_policy_of_its_own_and_nothing_else_is(tmp_path, monkeypatch):
    key = "ab" * 32
    _write_policy(tmp_path, monkeypatch, {"schema": 2, "public_key": key, "runner_signing": "adhoc-pinned"})
    assert runtime.signing_tier(runtime.trusted_policy()) == "adhoc-pinned"
    for bad in (
        {"schema": 2, "public_key": key, "runner_signing": "none"},
        {"schema": 2, "public_key": key, "runner_signing": "adhoc-pinned", "team_id": "TESTTEAM01"},
        {"schema": 2, "public_key": key},
        {"schema": 3, "public_key": key, "runner_signing": "adhoc-pinned"},
        {"schema": True, "public_key": key, "team_id": "TESTTEAM01", "runner_identifier": "x"},
        {"schema": 2, "public_key": "ab" * 31, "runner_signing": "adhoc-pinned"},
    ):
        _write_policy(tmp_path, monkeypatch, bad)
        with pytest.raises(VMUnavailable, match="not provisioned"):
            runtime.trusted_policy()


def test_the_original_developer_id_policy_still_reads_as_developer_id(tmp_path, monkeypatch):
    _write_policy(tmp_path, monkeypatch, {"schema": 1, "public_key": "ab" * 32, "team_id": "TESTTEAM01",
                                          "runner_identifier": "ai.inferroute.ProbantVM"})
    assert runtime.signing_tier(runtime.trusted_policy()) == "developer-id"


def test_codesign_is_asked_for_the_developer_id_chain_only_in_that_tier(tmp_path, monkeypatch):
    seen = []

    class Done:
        returncode = 0

    monkeypatch.setattr(runtime.subprocess, "run", lambda argv, **k: seen.append(argv) or Done())
    runtime.check_codesign(tmp_path / "ProbantVM", {"schema": 2, "public_key": "ab" * 32, "runner_signing": "adhoc-pinned"})
    runtime.check_codesign(tmp_path / "ProbantVM", {"schema": 1, "public_key": "ab" * 32, "team_id": "TESTTEAM01",
                                                    "runner_identifier": "ai.inferroute.ProbantVM"})
    assert "-R" not in seen[0] and seen[0][:3] == ["/usr/bin/codesign", "--verify", "--strict"]
    assert "-R" in seen[1] and "TESTTEAM01" in seen[1][seen[1].index("-R") + 1]


def test_a_signature_macos_will_not_accept_refuses_in_either_tier(tmp_path, monkeypatch):
    class Refused:
        returncode = 1

    monkeypatch.setattr(runtime.subprocess, "run", lambda argv, **k: Refused())
    for policy in ({"schema": 2, "public_key": "ab" * 32, "runner_signing": "adhoc-pinned"},
                   {"schema": 1, "public_key": "ab" * 32, "team_id": "TESTTEAM01", "runner_identifier": "a.b"}):
        with pytest.raises(VMUnavailable, match="signing requirement refused"):
            runtime.check_codesign(tmp_path / "ProbantVM", policy)

    def missing(argv, **k):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(runtime.subprocess, "run", missing)
    with pytest.raises(VMUnavailable, match="could not be checked"):
        runtime.check_codesign(tmp_path / "ProbantVM", {"schema": 2, "public_key": "ab" * 32, "runner_signing": "adhoc-pinned"})


def test_a_client_without_the_runtime_package_says_which_package(tmp_path, monkeypatch):
    _write_policy(tmp_path, monkeypatch, {"schema": 2, "public_key": "ab" * 32, "runner_signing": "adhoc-pinned"})
    monkeypatch.setattr(runtime, "RUNTIME_DIR", tmp_path / "absent")
    monkeypatch.setattr("sys.platform", "darwin")
    with pytest.raises(VMUnavailable, match="inferroute-macos-vm-runtime"):
        runtime.locate()


def test_the_runtime_lives_beside_the_client_not_inside_it():
    assert runtime.RUNTIME_DIR.name == "inferroute_macos_vm_runtime"
    assert runtime.RUNTIME_DIR.parent == Path(runtime.__file__).resolve().parents[2]


def test_the_policy_this_tree_ships_is_well_formed_and_packaged():
    repo = Path(runtime.__file__).resolve().parents[2]
    policy = json.loads((repo / "docs/trust/macos-vm-policy.json").read_text())
    assert set(policy) == {"schema", "public_key", "runner_signing"} and len(bytes.fromhex(policy["public_key"])) == 32
    assert '"docs/trust/macos-vm-policy.json" = "inferroute_cli/trust/macos-vm-policy.json"' in (repo / "pyproject.toml").read_text()
