#!/usr/bin/env python3
"""Fill scripts/install_probant.sh.in with a release's version and the two wheel fingerprints.

    render_install_script.py --client WHEEL --runtime WHEEL --out install-probant.sh

The version is read from the wheel file names, which must agree; the fingerprints are computed here from the
files that will be published, so the script cannot name a file other than the one the site serves.
"""
import argparse
import hashlib
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_of(path: Path, pattern: str) -> str:
    m = re.fullmatch(pattern, path.name)
    if not m:
        raise SystemExit(f"{path.name} is not named the way the installer expects ({pattern})")
    return m.group(1)


def render(client: Path, runtime: Path) -> str:
    v1 = version_of(client, r"inferroute-([0-9][0-9A-Za-z.]*)-py3-none-any\.whl")
    v2 = version_of(runtime, r"inferroute_macos_vm_runtime-([0-9][0-9A-Za-z.]*)-py3-none-macosx_11_0_arm64\.whl")
    if v1 != v2:
        raise SystemExit(f"the client is {v1} and the runtime is {v2}: a release ships one version of each")
    text = (HERE / "install_probant.sh.in").read_text()
    for key, value in (("@VERSION@", v1), ("@CLIENT_SHA256@", sha256(client)), ("@RUNTIME_SHA256@", sha256(runtime))):
        text = text.replace(key, value)
    left = re.findall(r"@[A-Z0-9_]+@", text)
    if left:
        raise SystemExit(f"unfilled placeholders: {left}")
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--client", required=True)
    ap.add_argument("--runtime", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    out.write_text(render(Path(a.client), Path(a.runtime)))
    out.chmod(out.stat().st_mode | stat.S_IXUSR)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
