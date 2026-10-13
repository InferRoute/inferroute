#!/usr/bin/env python3
"""Sign enclave-build records with InferRoute's offline publication key, for the relay to serve.

A signed record is what lets a new operator image be recognised — or an old one retired — without a client
release, while a compromised relay still cannot add or retire anything: the client accepts a run-time record
as InferRoute's only if it carries a valid signature under a key it ships (builds.SIGNING_KEYS), over bytes
that name their purpose (builds.signed_bytes), so the signature is valid for nothing else.

    sign_enclave_builds.py --key /media/$USER/IR-PUBKEY/inferroute-publication.key --passphrase-prompt \\
        --in records.json --out signed.json

`records.json` is a list of rows (or {"builds": [...]}) with id, mrtd, rtmr1, rtmr2, rtmr3 and status
(`observed`, or `refused` with `refused_because`). Rows are printed and confirmed before anything is signed.
Nothing is uploaded: commit `signed.json` to the relay's config and deploy it as usual.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from inferroute_local.confidential import builds  # noqa: E402
from sign_macos_runtime import _private, _public_hex  # noqa: E402

HEX96 = set("0123456789abcdef")


def _check(row: dict) -> str | None:
    for k in ("mrtd", "rtmr1", "rtmr2", "rtmr3"):
        v = str(row.get(k, "")).lower()
        if len(v) != 96 or set(v) - HEX96:
            return f"{row.get('id', '?')}: {k} is not 48 bytes of hex"
    if not row.get("id"):
        return "a row has no id"
    st = str(row.get("status", "")).lower()
    if st not in ("observed", "refused"):
        return f"{row['id']}: status must be 'observed' or 'refused' (a run-time record is never 'reviewed')"
    if st == "refused" and not row.get("refused_because"):
        return f"{row['id']}: a refusal must say why (refused_because)"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True, type=Path)
    ap.add_argument("--passphrase-prompt", action="store_true")
    ap.add_argument("--passphrase-env")
    ap.add_argument("--in", dest="src", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()

    doc = json.loads(a.src.read_text())
    rows = doc.get("builds") if isinstance(doc, dict) else doc
    if not isinstance(rows, list) or not rows:
        raise SystemExit("no rows to sign")
    problems = [p for p in (_check(r) for r in rows) if p]
    if problems:
        raise SystemExit("refusing to sign:\n  " + "\n  ".join(problems))

    key = _private(a.key, a.passphrase_env, a.passphrase_prompt)
    pub = _public_hex(key)
    if pub not in builds.SIGNING_KEYS:
        raise SystemExit(f"this key ({pub[:16]}…) is not one the client ships; its signatures would verify nowhere")

    print(f"\n  signing with {pub[:16]}…  purpose {builds.SIGNED_PURPOSE}\n")
    for r in rows:
        print(f"  {r['id']:<24} {str(r['status']).lower():<9} mrtd {r['mrtd'][:12]}…  rtmr1 {r['rtmr1'][:12]}…  "
              f"rtmr2 {r['rtmr2'][:12]}…  rtmr3 {r['rtmr3'][:12]}…" + (f"  ({r['refused_because']})" if r.get("refused_because") else ""))
    print("\n  Signing an 'observed' record asserts that this build measures the operating system's programs,"
          "\n  libraries and configuration (RTMR3 over the file list in its initramfs), as guest 1.4.x does: every"
          "\n  receipt's limitation text says so of the builds InferRoute accepts. Check that before signing.")
    print("\n  Type YES to sign these records: ", end="", flush=True)
    if sys.stdin.readline().strip() != "YES":
        raise SystemExit("not signed")

    out = []
    for r in rows:
        r = {**r, "status": str(r["status"]).lower()}
        r["sig"] = key.sign(builds.signed_bytes(r)).hex()
        if not builds.verify_signature(r):
            raise SystemExit(f"{r['id']}: the signature does not verify against the shipped key; nothing written")
        out.append(r)
    a.out.write_text(json.dumps(out, indent=2) + "\n")
    print(f"\n  wrote {len(out)} signed record(s) to {a.out}; every one verified against the shipped key.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
