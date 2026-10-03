"""Vendor-only offline assembly; does not sign, notarize, install or publish.

Inputs must come from vendor CI, not end-user machines. Private signing keys are
never read here. An unsigned development VM cannot pass the staging check.
"""

import argparse
import json
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "host-runtime",
        "client",
        "vm-runtime",
        "policy",
        "shell",
        "output",
        "version",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("vendor assembly requires macOS")
    client = Path(args.client).resolve()
    sys.path.insert(0, str(client))
    from inferroute_local.macos_vm import runtime

    policy = runtime.load_json(Path(args.policy))
    # The policy comes from the independently reviewed vendor build configuration.
    verified = runtime.stage(Path(args.vm_runtime), policy)
    verified.close()
    python_root = Path(args.host_runtime).resolve()
    subprocess.run(
        [
            str(python_root / "bin/python3"),
            "-I",
            "-c",
            "import cryptography, fastapi, httpx, rich, uvicorn",
        ],
        check=True,
    )
    purelib = Path(
        subprocess.check_output(
            [
                str(python_root / "bin/python3"),
                "-I",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            text=True,
        ).strip()
    )
    # Install into bundled site-packages so browser session subprocesses using
    # the same interpreter can import the client without PYTHONPATH or cwd.
    relative_site = purelib.relative_to(python_root)
    output = Path(args.output).absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    contents = output / "Contents"
    resources = contents / "Resources"
    resources.mkdir(parents=True)
    (contents / "MacOS").mkdir()
    shutil.copy2(args.shell, contents / "MacOS/Probant")
    (contents / "MacOS/Probant").chmod(0o755)
    shutil.copytree(python_root, resources / "python", symlinks=True)
    packaged_client = resources / "python" / relative_site
    packaged_client.mkdir(parents=True, exist_ok=True)
    for package in ("inferroute_cli", "inferroute_local"):
        shutil.copytree(
            client / package,
            packaged_client / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "macos_runtime"),
        )
    trust = packaged_client / "inferroute_cli/trust"
    trust.mkdir(exist_ok=True)
    (trust / "macos-vm-policy.json").write_bytes(runtime.canonical(policy))
    shutil.copytree(args.vm_runtime, packaged_client / "inferroute_cli/macos_runtime")
    shutil.copy2(Path(__file__).with_name("app_entry.py"), resources / "app_entry.py")
    info = {
        "CFBundleExecutable": "Probant",
        "CFBundleIdentifier": policy["runner_identifier"] + ".app",
        "CFBundleName": "Probant",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": args.version,
        "CFBundleVersion": args.version,
        "LSMinimumSystemVersion": runtime.load_json(
            Path(args.vm_runtime) / "runtime.json"
        )["minimum_macos"],
    }
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    print(
        "Unsigned app assembled. Vendor signing, notarization and installation gates remain."
    )


if __name__ == "__main__":
    main()
