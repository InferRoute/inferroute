#!/usr/bin/env python3
"""Sign the macOS VM runtime and package it as the wheel a Mac client installs beside `inferroute`.

Why this exists
---------------
On a Mac, a Probant session's agent runs inside a small Linux virtual machine. Three files make that
machine: the runner (`ProbantVM`, built on a Mac from native/macos/ProbantVM.swift), a Linux kernel and
a guest image (both from native/macos/guest/build_guest.py, byte-for-byte reproducible from pinned
inputs). The client will start NOTHING unless a manifest naming all three by sha256 carries a signature
from the key pinned inside the client (`inferroute_cli/trust/macos-vm-policy.json`). Whoever holds the
private half decides what runs on every client Mac, so it is kept the way the build-signing key is: in
a file you choose, mode 600, never in a repo, a wheel, the guest or a report.

    sign_macos_runtime.py keygen --key KEYFILE
        Make the keypair. Prints the PUBLIC half and the policy file to commit. Refuses to overwrite.

    sign_macos_runtime.py build --key KEYFILE [--passphrase-prompt] --runner ProbantVM --guest DIR --version V --out DIR
        KEYFILE is either the bare key `keygen` writes or the offline publication key's encrypted PEM.
        Check the three artifacts, write the signed runtime.json, and build
        inferroute_macos_vm_runtime-V-py3-none-macosx_11_0_arm64.whl. Deterministic: the same inputs
        and key give the same wheel.

    sign_macos_runtime.py verify WHEEL [--policy FILE]
        Check a built wheel against the policy the client ships. No private key needed.

What `build` refuses
--------------------
  * a runner that is not a 64-bit arm64 Mach-O executable;
  * a DEVELOPMENT runner (compiled with -D PROBANT_DEV_CONSOLE, which copies the guest's console to
    stderr): it carries a marker string and is never signed;
  * a kernel or guest image whose hash differs from the guest-manifest.json beside it — i.e. anything
    but the output of one build_guest.py run;
  * a key file readable by anyone else.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from inferroute_local.macos_vm import runtime  # noqa: E402

PACKAGE = "inferroute_macos_vm_runtime"
DIST = "inferroute_macos_vm_runtime"
TAG = "py3-none-macosx_11_0_arm64"
DEV_MARKER = b"PROBANT_VM_DEVELOPMENT_BUILD"
MACHO_64 = bytes.fromhex("cffaedfe")            # MH_MAGIC_64, little-endian
CPU_ARM64 = bytes.fromhex("0c000001")           # CPU_TYPE_ARM64, little-endian
MH_EXECUTE = (2).to_bytes(4, "little")
ZIP_TIME = (2026, 1, 1, 0, 0, 0)
ARTIFACTS = ("ProbantVM", "kernel", "initrd")
POLICY_SOURCE = REPO / "docs/trust/macos-vm-policy.json"


def _private(path: Path, passphrase_env: str | None = None, prompt: bool = False):
    """The key, from either file format this project uses: a bare hex seed (what `keygen` here writes) or
    the passphrase-protected PEM of the offline publication key (`ir probant reference new-key`). The
    passphrase comes from a prompt or from $VAR — never from argv."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit(f"{path} is readable by others (mode {oct(mode & 0o777)}); chmod 600 it first")
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        password = None
        if passphrase_env:
            value = os.environ.get(passphrase_env, "")
            if not value:
                raise SystemExit(f"--passphrase-env {passphrase_env} is set but ${passphrase_env} is empty")
            password = value.encode()
        elif prompt:
            import getpass
            password = getpass.getpass("passphrase for the signing key: ").encode()
        try:
            key = ser.load_pem_private_key(data, password=password)
        except TypeError:
            raise SystemExit(f"{path} is encrypted; use --passphrase-prompt (or --passphrase-env VAR)")
        except ValueError:
            raise SystemExit("could not unlock the key: wrong passphrase, or not an Ed25519 key")
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 key")
        return key
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data.decode().strip()))


def _public_hex(key) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    return key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def keygen(a) -> int:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    p = Path(a.key)
    if p.exists():
        raise SystemExit(f"{p} already exists — refusing to overwrite a signing key")
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(raw.hex() + "\n")
    policy = {"schema": 2, "public_key": _public_hex(k), "runner_signing": "adhoc-pinned"}
    print(f"private key: {p} (mode 600 — keep it out of every repo, wheel and backup you do not control)")
    print(f"public key:  {policy['public_key']}")
    print(f"\nCommit this as {POLICY_SOURCE.relative_to(REPO)} — it is what makes a client trust the key:\n")
    print(json.dumps(policy, indent=1))
    return 0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_runner(data: bytes) -> None:
    if data[:4] != MACHO_64 or data[4:8] != CPU_ARM64 or data[12:16] != MH_EXECUTE:
        raise SystemExit("the runner is not a 64-bit arm64 Mach-O executable (a universal or Intel build is not accepted)")
    if DEV_MARKER in data:
        raise SystemExit("this is a DEVELOPMENT runner (built with DEV_CONSOLE=1): it copies the guest's console "
                         "to stderr and is never signed. Build it again without DEV_CONSOLE.")


def manifest_for(files: dict, pi_version: str, minimum_macos: str) -> dict:
    return {"schema": "inferroute.macos-vm/1", "protocol": 1, "architecture": "arm64",
            "minimum_macos": minimum_macos, "pi_version": pi_version, "development_only": False,
            "artifacts": {n: {"bytes": len(files[n]), "sha256": sha256(files[n])} for n in ARTIFACTS}}


def write_wheel(out: Path, version: str, members: dict) -> Path:
    """A wheel by hand: fixed order, fixed timestamps, so the same inputs give the same bytes."""
    info = f"{DIST}-{version}.dist-info"
    meta = (f"Metadata-Version: 2.1\nName: inferroute-macos-vm-runtime\nVersion: {version}\n"
            "Summary: The signed Linux VM runtime a Probant session's agent runs in on an arm64 Mac.\n"
            "Requires-Python: >=3.10\n")
    wheel = f"Wheel-Version: 1.0\nGenerator: sign_macos_runtime.py\nRoot-Is-Purelib: false\nTag: {TAG}\n"
    entries = [(f"{PACKAGE}/{name}", data, 0o755 if name == "ProbantVM" else 0o644) for name, data in members.items()]
    entries += [(f"{info}/METADATA", meta.encode(), 0o644), (f"{info}/WHEEL", wheel.encode(), 0o644)]
    record = "".join(
        f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()},{len(data)}\n"
        for name, data, _ in entries) + f"{info}/RECORD,,\n"
    entries.append((f"{info}/RECORD", record.encode(), 0o644))
    path = out / f"{DIST}-{version}-{TAG}.whl"
    with zipfile.ZipFile(path, "w") as z:
        for name, data, mode in entries:
            zi = zipfile.ZipInfo(name, ZIP_TIME)
            zi.external_attr = (stat.S_IFREG | mode) << 16
            # The guest image is already compressed and the wheel is hashed whole; store it as it is.
            zi.compress_type = zipfile.ZIP_STORED if name.endswith("/initrd") else zipfile.ZIP_DEFLATED
            z.writestr(zi, data, compresslevel=None if zi.compress_type == zipfile.ZIP_STORED else 9)
    return path


def build(a) -> int:
    key = _private(Path(a.key), a.passphrase_env, a.passphrase_prompt)
    guest = Path(a.guest)
    files = {"ProbantVM": Path(a.runner).read_bytes(), "kernel": (guest / "kernel").read_bytes(),
             "initrd": (guest / "initrd").read_bytes()}
    check_runner(files["ProbantVM"])
    built = json.loads((guest / "guest-manifest.json").read_text())
    for name in ("kernel", "initrd"):
        want = built["artifacts"][name]
        if want["sha256"] != sha256(files[name]) or want["bytes"] != len(files[name]):
            raise SystemExit(f"{name} is not the one guest-manifest.json describes — use the output of ONE build_guest.py run")
    if built.get("arch") != "aarch64":
        raise SystemExit("the guest was not built for aarch64")
    body = manifest_for(files, built["pi_version"], a.minimum_macos)
    manifest = {**body, "signature": key.sign(runtime.DOMAIN + runtime.canonical(body)).hex()}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    members = {"__init__.py": b'"""The signed macOS VM runtime for Probant. Data only; nothing here is imported."""\n',
               "runtime.json": json.dumps(manifest, indent=1, sort_keys=True).encode() + b"\n",
               "guest-manifest.json": (guest / "guest-manifest.json").read_bytes(), **files}
    path = write_wheel(out, a.version, members)
    digest = sha256(path.read_bytes())
    (out / (path.name + ".sha256")).write_text(f"{digest}  {path.name}\n")
    print(f"signed by:  {_public_hex(key)}")
    for name in ARTIFACTS:
        print(f"  {name:10} {len(files[name]) / 1e6:6.1f} MB  sha256 {sha256(files[name])}")
    print(f"wheel:      {path}  ({path.stat().st_size / 1e6:.1f} MB)\nsha256:     {digest}")
    if POLICY_SOURCE.exists() and json.loads(POLICY_SOURCE.read_text()).get("public_key") != _public_hex(key):
        print(f"\nWARNING: {POLICY_SOURCE.relative_to(REPO)} pins a DIFFERENT key. A client built from this "
              "tree will refuse this runtime.")
    return 0


def verify(a) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    policy = json.loads(Path(a.policy).read_text())
    with zipfile.ZipFile(a.wheel) as z:
        manifest = json.loads(z.read(f"{PACKAGE}/runtime.json"))
        body = {k: v for k, v in manifest.items() if k != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy["public_key"])).verify(
                bytes.fromhex(manifest["signature"]), runtime.DOMAIN + runtime.canonical(body))
        except Exception:                                   # noqa: BLE001
            print("FAIL  the manifest is not signed by the key in the policy")
            return 1
        print(f"ok    manifest signed by {policy['public_key']}")
        bad = 0
        for name, rec in manifest["artifacts"].items():
            data = z.read(f"{PACKAGE}/{name}")
            good = len(data) == rec["bytes"] and sha256(data) == rec["sha256"]
            bad += not good
            print(f"{'ok  ' if good else 'FAIL'}  {name:10} {rec['sha256']}")
        runner = z.read(f"{PACKAGE}/ProbantVM")
        if DEV_MARKER in runner:
            print("FAIL  the runner is a development build")
            bad += 1
        print(f"      runner signing tier the policy asks for: {runtime.signing_tier(policy)}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--key", required=True); k.set_defaults(fn=keygen)
    b = sub.add_parser("build")
    for flag in ("--key", "--runner", "--guest", "--version", "--out"):
        b.add_argument(flag, required=True)
    b.add_argument("--minimum-macos", default="12.0")
    b.add_argument("--passphrase-prompt", action="store_true", help="type the key's passphrase at a prompt")
    b.add_argument("--passphrase-env", default=None, metavar="VAR", help="read the key's passphrase from $VAR")
    b.set_defaults(fn=build)
    v = sub.add_parser("verify"); v.add_argument("wheel"); v.add_argument("--policy", default=str(POLICY_SOURCE))
    v.set_defaults(fn=verify)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
