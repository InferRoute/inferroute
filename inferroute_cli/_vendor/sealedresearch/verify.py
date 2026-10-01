"""sealed-verify — standalone verifier for a sealed-research export bundle.

Deliberately self-contained (stdlib only, no imports from the research engine): this file is meant to be
handed to the client firm — or their expert, or a rival — so they can check an export without trusting us.

What it checks, per ledger file (the egress ledger `egress.jsonl` and, if present, the decision ledger
`ledger.jsonl` share the same chain scheme):

  1. CHAIN    every row's `hash` = sha256(prev_hash + canonical-JSON(row-without-hash)), linked from the
              all-zero genesis. Any edit, reorder, insertion, deletion, or truncation breaks the replay.
  2. HEAD     the recomputed head equals the head named in the certificate (when given via --expect-head).
  3. POLICY   every egress row carries the same policy sha256 (no mid-run policy swap), equal to
              --expect-policy when given.
  4. TOTALS   bytes out, request counts, recipients, decisions — recomputed from rows, never trusted.

Exit code 0 = PASS, 1 = FAIL, 2 = usage. Output is one JSON object on stdout plus a human PASS/FAIL line
on stderr, so it can be piped or read.

Usage:
  sealed-verify --egress egress.jsonl [--ledger ledger.jsonl]
                [--expect-head HEX] [--expect-policy HEX]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64


def chain_hash(prev_hash: str, row_without_hash: Dict[str, Any]) -> str:
    body = json.dumps(row_without_hash, sort_keys=True)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def replay(path: str) -> Tuple[bool, str, List[Dict[str, Any]], Optional[int]]:
    """Returns (chain_ok, head, rows, first_bad_line). Rows are returned even on failure, up to the break."""
    prev = GENESIS
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                return False, prev, rows, i
            stored = row.pop("hash", None)
            sig = row.pop("sig", None)                 # signatures live outside the chain hash
            if row.get("prev_hash") != prev or stored != chain_hash(prev, row):
                return False, prev, rows, i
            prev = stored
            row["hash"] = stored
            if sig is not None:
                row["sig"] = sig
            rows.append(row)
    return True, prev, rows, None


def egress_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    s: Dict[str, Any] = {"rows": len(rows), "allow": 0, "deny": 0, "held": 0, "responses": 0,
                         "bytes_out": 0, "recipients": {}, "providers": {}, "policy_sha256": set(),
                         "first_ts": rows[0].get("ts") if rows else None,
                         "last_ts": rows[-1].get("ts") if rows else None}
    for r in rows:
        d = r.get("decision")
        if d == "response":
            s["responses"] += 1
        elif d in ("allow", "deny", "held"):
            s[d] += 1
        if r.get("policy_sha256"):
            s["policy_sha256"].add(r["policy_sha256"])
        if d == "allow":
            s["bytes_out"] += int(r.get("bytes_out", 0))
            host = r.get("host", "?")
            s["recipients"][host] = s["recipients"].get(host, 0) + 1
            p = r.get("provider", "?")
            s["providers"][p] = s["providers"].get(p, 0) + 1
    s["policy_sha256"] = sorted(s["policy_sha256"])
    return s


def check_signatures(rows: List[Dict[str, Any]], pubkey_pem: str) -> Dict[str, Any]:
    """Verify each row's Ed25519 `sig` over its hash against the gateway's PUBLIC key, using the openssl CLI
    (keeps this verifier stdlib-only). A row without `sig` counts as unsigned, not as a failure — the check
    reports coverage so a certificate can require 100%."""
    import base64 as b64
    import subprocess
    import tempfile
    signed = bad = 0
    for r in rows:
        sig = r.get("sig")
        if not sig:
            continue
        signed += 1
        with tempfile.TemporaryDirectory() as td:
            mp, sp = os.path.join(td, "m"), os.path.join(td, "s")
            open(mp, "wb").write(r["hash"].encode("ascii"))
            open(sp, "wb").write(b64.b64decode(sig))
            rc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pubkey_pem,
                                 "-rawin", "-in", mp, "-sigfile", sp],
                                capture_output=True).returncode
        if rc != 0:
            bad += 1
    return {"signed": signed, "unsigned": len(rows) - signed, "bad": bad}


def verify_bundle(egress: str, ledger: Optional[str] = None,
                  expect_head: Optional[str] = None, expect_policy: Optional[str] = None,
                  pubkey: Optional[str] = None) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    ok, head, rows, bad = replay(egress)
    checks.append({"check": "egress-chain", "ok": ok,
                   "detail": f"{len(rows)} rows replayed" + ("" if ok else f"; chain breaks at line {bad}")})
    summ = egress_summary(rows)
    if expect_head:
        checks.append({"check": "egress-head", "ok": head == expect_head,
                       "detail": f"recomputed {head[:16]}… vs expected {expect_head[:16]}…"})
    pol_ok = len(summ["policy_sha256"]) <= 1
    checks.append({"check": "single-policy", "ok": pol_ok,
                   "detail": f"{len(summ['policy_sha256'])} distinct policy hashes in egress rows"})
    if expect_policy:
        checks.append({"check": "policy-match", "ok": summ["policy_sha256"] == [expect_policy],
                       "detail": f"rows carry {summ['policy_sha256']} vs expected {expect_policy[:16]}…"})
    if pubkey:
        sigs = check_signatures(rows, pubkey)
        checks.append({"check": "row-signatures", "ok": sigs["bad"] == 0 and sigs["unsigned"] == 0,
                       "detail": f"{sigs['signed']} signed OK, {sigs['bad']} bad, {sigs['unsigned']} unsigned"})
    if ledger:
        lok, lhead, lrows, lbad = replay(ledger)
        checks.append({"check": "decision-ledger-chain", "ok": lok,
                       "detail": f"{len(lrows)} rows replayed" + ("" if lok else f"; chain breaks at line {lbad}")})
    result = {"pass": all(c["ok"] for c in checks), "checks": checks,
              "egress_head": head, "summary": summ}
    if ledger:
        result["decision_ledger_head"] = lhead
    return result


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="sealed-verify", description=__doc__.split("\n\n")[0])
    p.add_argument("--egress", required=True, help="egress.jsonl (the outbound record)")
    p.add_argument("--ledger", default=None, help="optional decision ledger (same chain scheme)")
    p.add_argument("--expect-head", default=None, help="head hash named in the certificate")
    p.add_argument("--expect-policy", default=None, help="policy sha256 named in the certificate")
    p.add_argument("--pubkey", default=None, help="gateway public key PEM: require every row Ed25519-signed")
    a = p.parse_args(argv)
    result = verify_bundle(a.egress, a.ledger, a.expect_head, a.expect_policy, pubkey=a.pubkey)
    print(json.dumps(result, indent=2))
    n_bytes = result["summary"]["bytes_out"]
    rec = ", ".join(f"{h} ({n})" for h, n in sorted(result["summary"]["recipients"].items())) or "none"
    print(f"[sealed-verify] {'PASS' if result['pass'] else 'FAIL'} — "
          f"{result['summary']['allow']} sent ({n_bytes} bytes) to: {rec}; "
          f"{result['summary']['deny']} denied, {result['summary']['held']} held for approval; "
          f"head {result['egress_head'][:16]}…", file=sys.stderr)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
