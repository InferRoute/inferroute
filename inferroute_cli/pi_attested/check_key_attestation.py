#!/usr/bin/env python3
"""check_key_attestation.py - check, with a tool that is not InferRoute's, who InferRoute's publication key belongs to.

Run it from anywhere:   python3 stationery/check_key_attestation.py

What it checks: the pack carries an attestation naming InferRoute's publication key and a Sigstore bundle over it. This
runs Sigstore's own verification (certificate chain to Sigstore's roots, the identity you expect, the signature over the
attestation, and its inclusion in the public Rekor log) with `cosign` if you have it, otherwise with the `sigstore`
package fetched at a pinned version by `uv` or into a throwaway environment. verify_record.py deliberately does not do this
itself: a second trust system inside a program whose value is that you can read all of it.

What a PASS means, and does not: a public log shows that the Google account named below signed a statement naming this
key, at the logged time. It does NOT make the key independent of the account that holds it, and it does not
authenticate earlier records or the contents of the reference. Decide whether that identity is the one you meant to trust;
this script defaults to the one InferRoute publishes, and `--identity` lets you test another.

Needs the network (Sigstore's trust root and the log). Exit codes: 0 PASS, 1 FAIL, 3 COULD NOT RUN (nothing was decided).
Reads only the pack's trust-anchors folder. Writes nothing in the pack.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_IDENTITY = "henry@inferroute.ai"
DEFAULT_ISSUER = "https://accounts.google.com"
SIGSTORE_PIN = "sigstore==4.5.0"


def _run(cmd, timeout=240):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def _tool_commands(bundle, attestation, identity, issuer):
    """(name, argv) in the order to try: cosign, then uv, then a throwaway virtual environment."""
    out = []
    if shutil.which("cosign"):
        out.append(("cosign", ["cosign", "verify-blob", "--bundle", bundle, "--certificate-identity", identity,
                               "--certificate-oidc-issuer", issuer, attestation]))
    sig = ["verify", "identity", "--bundle", bundle, "--cert-identity", identity, "--cert-oidc-issuer", issuer, attestation]
    if shutil.which("uv"):
        out.append((f"uv run {SIGSTORE_PIN}", ["uv", "run", "--quiet", "--python", "3.12", "--with", SIGSTORE_PIN,
                                               "python", "-m", "sigstore", *sig]))
    out.append((f"{SIGSTORE_PIN} in a throwaway environment", None))
    return out, sig


def _venv_run(sig):
    tmp = tempfile.mkdtemp(prefix="check-key-")
    try:
        rc, out = _run([sys.executable, "-m", "venv", tmp + "/v"], timeout=120)
        if rc:
            return 3, "could not create a virtual environment: " + out[-200:]
        py = tmp + "/v/bin/python"
        rc, out = _run([py, "-m", "pip", "install", "--quiet", SIGSTORE_PIN], timeout=600)
        if rc:
            return 3, "could not install " + SIGSTORE_PIN + " (it needs Python 3.10 or newer): " + out[-200:]
        return _run([py, "-m", "sigstore", *sig])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    identity, issuer = DEFAULT_IDENTITY, DEFAULT_ISSUER
    pack = Path(__file__).resolve().parent.parent
    while argv:
        a = argv.pop(0)
        if a == "--identity" and argv:
            identity = argv.pop(0)
        elif a == "--issuer" and argv:
            issuer = argv.pop(0)
        elif a == "--pack" and argv:
            pack = Path(argv.pop(0)).resolve()
        else:
            print(__doc__)
            return 3
    att = pack / "trust-anchors" / "publication-key-attestation.json"
    bundle = pack / "trust-anchors" / "publication-key-attestation.bundle"
    if not att.is_file() or not bundle.is_file():
        print("KEY ATTESTATION: COULD NOT RUN - this pack carries no attestation or no bundle in trust-anchors/.")
        print("  That is an absence, not a failure: the key rests on however you obtained it.")
        return 3
    try:
        named = str(json.load(open(att)).get("publication_key") or "").lower()
    except (OSError, ValueError):
        print("KEY ATTESTATION: FAIL - the attestation file is unreadable.")
        return 1
    print(f"attestation names the publication key {named[:16]}...; expected identity {identity} via {issuer}")
    ref = pack / "trust-anchors" / "reference.json"
    if ref.is_file():
        try:
            rk = str(json.load(open(ref)).get("publication_key") or "").lower()
            print("  the reference in this pack names " + ("the SAME key" if rk == named else f"a DIFFERENT key ({rk[:16]}...): a finding"))
        except (OSError, ValueError):
            pass
    cmds, sig = _tool_commands(str(bundle), str(att), identity, issuer)
    last = ""
    for name, cmd in cmds:
        try:
            rc, out = _run(cmd) if cmd else _venv_run(sig)
        except (OSError, subprocess.TimeoutExpired) as exc:
            rc, out = 3, f"{type(exc).__name__}: {exc}"
        if rc == 0:
            print(f"KEY ATTESTATION: PASS - verified with {name}: the identity {identity} signed a statement naming this key, "
                  "recorded in the public Rekor log.")
            print("  This does not make the key independent of its owner, and does not authenticate earlier records.")
            return 0
        last = f"{name}: {out[-400:]}"
        if rc == 1 or "mismatch" in out.lower() or "identity" in out.lower():
            print(f"KEY ATTESTATION: FAIL - {name} refused it.\n  {out[-400:]}")
            return 1
    print("KEY ATTESTATION: COULD NOT RUN - no tool succeeded; nothing was decided. Last: " + last[-300:])
    print("  Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) or uv and run this again.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
