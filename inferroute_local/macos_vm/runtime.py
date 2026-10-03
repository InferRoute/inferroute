"""Authenticate and privately stage vendor runtime artifacts before executing them.

The trusted policy is shipped in client code, NEVER read from the candidate bundle
or environment. No development manifest/signature bypass is accepted here.
"""

from __future__ import annotations
import hashlib, json, os, platform, stat, subprocess, tempfile, shutil
from dataclasses import dataclass
from pathlib import Path
from . import VMUnavailable

POLICY_PATH = (
    Path(__file__).resolve().parents[2] / "inferroute_cli/trust/macos-vm-policy.json"
)
DOMAIN = b"InferRoute Probant macOS VM runtime v1\0"
MAX_ARTIFACT = 512 * 1024 * 1024


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise VMUnavailable("duplicate runtime metadata")
        value[key] = item
    return value


def load_json(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise VMUnavailable("unsafe runtime metadata")
        body = os.read(fd, limit + 1)
        if len(body) > limit:
            raise VMUnavailable("runtime metadata quota")
        return json.loads(body, object_pairs_hook=unique)
    finally:
        os.close(fd)


def canonical(body):
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def trusted_policy():
    try:
        value = load_json(POLICY_PATH)
        if (
            set(value) != {"schema", "public_key", "team_id", "runner_identifier"}
            or value["schema"] != 1
        ):
            raise ValueError()
        if (
            len(bytes.fromhex(value["public_key"])) != 32
            or not value["team_id"]
            or not value["runner_identifier"]
        ):
            raise ValueError()
        return value
    except (OSError, ValueError, TypeError, KeyError) as e:
        raise VMUnavailable(
            "the signed macOS VM runtime policy is not provisioned in this client"
        ) from e


@dataclass
class Runtime:
    directory: Path
    manifest: dict

    def close(self):
        shutil.rmtree(self.directory)

    @property
    def runner(self):
        return self.directory / "ProbantVM"


def verify_signature(manifest, policy):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = manifest["signature"]
        body = {k: v for k, v in manifest.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy["public_key"])).verify(
            bytes.fromhex(signature), DOMAIN + canonical(body)
        )
    except Exception as e:
        raise VMUnavailable("macOS VM vendor manifest signature refused") from e


def check_codesign(path, policy):
    # Explicit requirement pins both the independent vendor Team ID and executable ID.
    # Do not interpolate package fields into code-signing requirements.
    team = policy["team_id"]
    identifier = policy["runner_identifier"]
    import re

    if not re.fullmatch(r"[A-Z0-9]{10}", team) or not re.fullmatch(
        r"[A-Za-z0-9.-]+", identifier
    ):
        raise VMUnavailable("invalid trusted signing policy")
    requirement = f'anchor apple generic and identifier "{identifier}" and certificate leaf[subject.OU] = "{team}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    result = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "-R", requirement, str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode:
        raise VMUnavailable("macOS VM executable signing requirement refused")


def stage(root, policy, *, architecture=None, os_version=None):
    """Private copied artifacts, retained until VM stop. Never boots original URLs."""
    directory = None
    try:
        root = Path(root)
        if root.is_symlink():
            raise VMUnavailable("runtime bundle must not be a symlink")
        manifest = load_json(root / "runtime.json")
        if set(manifest) != {
            "schema",
            "protocol",
            "architecture",
            "minimum_macos",
            "pi_version",
            "development_only",
            "artifacts",
            "signature",
        }:
            raise VMUnavailable("unknown runtime manifest fields")
        verify_signature(manifest, policy)
        if (
            manifest["schema"] != "inferroute.macos-vm/1"
            or type(manifest["protocol"]) is not int
            or manifest["protocol"] != 1
            or manifest["development_only"] is not False
        ):
            raise VMUnavailable("development or unsupported VM runtime refused")
        arch = architecture or platform.machine()
        version = os_version or platform.mac_ver()[0]
        if arch != "arm64" or manifest["architecture"] != arch:
            raise VMUnavailable("this Mac architecture has no validated VM runtime")
        import re

        minimum = manifest["minimum_macos"]
        if not isinstance(minimum, str) or not re.fullmatch(
            r"\d+\.\d+(?:\.\d+)?", minimum
        ):
            raise VMUnavailable("invalid macOS deployment requirement")
        if tuple(map(int, (version + ".0.0").split(".")[:3])) < tuple(
            map(int, (minimum + ".0.0").split(".")[:3])
        ):
            raise VMUnavailable("macOS is older than the bundled VM runtime supports")
        if manifest["pi_version"] != "0.84.1":
            raise VMUnavailable("unsupported bundled Pi version")
        artifacts = manifest["artifacts"]
        if not isinstance(artifacts, dict) or set(artifacts) != {
            "ProbantVM",
            "kernel",
            "initrd",
        }:
            raise VMUnavailable("incomplete VM runtime")
        directory = Path(tempfile.mkdtemp(prefix="probant-vm-runtime-"))
        directory.chmod(0o700)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name, record in artifacts.items():
                if (
                    not isinstance(record, dict)
                    or set(record) != {"bytes", "sha256"}
                    or type(record["bytes"]) is not int
                    or not 0 < record["bytes"] <= MAX_ARTIFACT
                    or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                ):
                    raise VMUnavailable("invalid runtime artifact record")
                source = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd
                )
                try:
                    info = os.fstat(source)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size != record["bytes"]
                    ):
                        raise VMUnavailable("unsafe runtime artifact")
                    target = os.open(
                        directory / name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o500 if name == "ProbantVM" else 0o400,
                    )
                    try:
                        digest = hashlib.sha256()
                        count = 0
                        while True:
                            data = os.read(source, 1024 * 1024)
                            if not data:
                                break
                            count += len(data)
                            if count > record["bytes"]:
                                raise VMUnavailable("runtime artifact grew")
                            digest.update(data)
                            offset = 0
                            while offset < len(data):
                                offset += os.write(target, data[offset:])
                        os.fsync(target)
                    finally:
                        os.close(target)
                    if (
                        count != record["bytes"]
                        or digest.hexdigest() != record["sha256"]
                    ):
                        raise VMUnavailable("runtime artifact integrity refused")
                finally:
                    os.close(source)
        finally:
            os.close(root_fd)
        check_codesign(directory / "ProbantVM", policy)
        # Inner boot manifest contains only hashes of copies already authenticated above.
        boot = {
            "schema": 1,
            "development_only": False,
            "architecture": arch,
            "artifacts": {n: {"file": n, **artifacts[n]} for n in ("kernel", "initrd")},
        }
        (directory / "boot.json").write_bytes(canonical(boot))
        (directory / "boot.json").chmod(0o400)
        return Runtime(directory, manifest)
    except Exception as e:
        if directory is not None:
            shutil.rmtree(directory)
        if isinstance(e, VMUnavailable):
            raise
        raise VMUnavailable("macOS VM runtime verification/setup refused") from e


def locate():
    import sys

    if sys.platform != "darwin":
        raise VMUnavailable("macOS VM backend requires macOS")
    policy = trusted_policy()
    # No PATH/environment lookup; the delivered app owns its complete runtime.
    root = Path(__file__).resolve().parents[2] / "inferroute_cli/macos_runtime"
    return stage(root, policy)
