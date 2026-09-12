#!/usr/bin/env python3
"""Sign an enclave build so the client will treat it as InferRoute's own record.

Why this exists
---------------
The client ships a list of enclave builds it recognises, and refuses a session on anything
else. To recognise a genuine new operator build without waiting for a client release, the
relay can serve additions at run time — which is convenient, and is also the one seam an
attacker holding the relay could use: point a client at an enclave they control, then supply
the row that legitimises it. Every other check would pass truthfully.

A signature closes that, provided the private key never goes near the relay. It does not live
on a server. It lives wherever you keep it, and signing a build is a deliberate act.

    sign_build.py keygen --key build-signing.key
        Make a keypair. Prints the PUBLIC key to paste into builds.SIGNING_KEYS.
        The private key is written 0600 and must never be deployed.

    sign_build.py sign --key build-signing.key --build builds.json
        Sign every entry in a build list, in place, adding a "sig" field.

    sign_build.py verify --build builds.json
        Check a list against the public keys the client ships. No private key needed —
        this is what anyone auditing us can run.

The signature covers only the identity and the four measurements, so a note or a timestamp
can be corrected without re-signing, while the thing that must not be forgeable — WHICH
ENCLAVE this row blesses — cannot be changed without invalidating it.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inferroute_local.confidential import builds  # noqa: E402


def _private(path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit(f"{path} is readable by others (mode {oct(mode & 0o777)}); chmod 600 it first")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def keygen(a) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    p = Path(a.key)
    if p.exists():
        raise SystemExit(f"{p} already exists — refusing to overwrite a signing key")
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    p.write_text(raw.hex() + "\n")
    os.chmod(p, 0o600)
    pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    print(f"private key → {p} (0600). Keep it off every server, including the relay.\n")
    print("Add the public half to inferroute_local/confidential/builds.py:\n")
    print(f'    SIGNING_KEYS: tuple[str, ...] = (\n        "{pub}",\n    )')
    return 0


def sign(a) -> int:
    key = _private(Path(a.key))
    rows = json.loads(Path(a.build).read_text())
    rows = rows if isinstance(rows, list) else [rows]
    for r in rows:
        if not r.get("mrtd"):
            raise SystemExit(f"entry {r.get('id', '?')} has no measurements to sign")
        r["sig"] = key.sign(builds.signed_bytes(r)).hex()
        print(f"  signed {r.get('id', '?')}  mrtd {str(r['mrtd'])[:16]}…")
    Path(a.build).write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\n{len(rows)} entr{'y' if len(rows) == 1 else 'ies'} written to {a.build}")
    if not builds.SIGNING_KEYS:
        print("NOTE: builds.SIGNING_KEYS is empty, so a client will not yet accept these.")
    return 0


def verify(a) -> int:
    rows = json.loads(Path(a.build).read_text())
    rows = rows if isinstance(rows, list) else [rows]
    if not builds.SIGNING_KEYS:
        print("no signing keys are shipped in this client; every entry will be treated as pending")
    bad = 0
    for r in rows:
        ok = builds.verify_signature(r)
        bad += not ok
        print(f"  {'OK      ' if ok else 'UNSIGNED'}  {r.get('id', '?')}")
    print(f"\n{len(rows) - bad}/{len(rows)} verify against the shipped keys")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen"); g.add_argument("--key", required=True); g.set_defaults(fn=keygen)
    s = sub.add_parser("sign")
    s.add_argument("--key", required=True); s.add_argument("--build", required=True)
    s.set_defaults(fn=sign)
    v = sub.add_parser("verify"); v.add_argument("--build", required=True); v.set_defaults(fn=verify)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
