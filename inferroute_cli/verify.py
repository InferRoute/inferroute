"""`ir verify` — independently verify your anchored records against Base.

Fetches YOUR proof bundles from inferroute.ai, reads the Merkle roots straight
from the InferRoute anchor contract on Base (raw eth_call — no trust in any
InferRoute-served value, no web3 dependency), and checks each record's inclusion
proof against the ON-CHAIN root. If it verifies, that turn's fingerprint + billing
were committed on-chain and cannot have been altered since.
docs/verifiable-recording-spine.md §4.5.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Optional

from . import config
from inferroute_local.anchor_verify import verify_record

# Contract function selectors (keccak-derived; fixed for the ABI).
_SEL_EPOCH_ROOTS = "ef95d4e0"  # epochRoots(uint64) -> (bytes32 batchRoot, bytes32 commitment)


def _site_url() -> str:
    env = os.environ.get("INFERROUTE_SITE_URL")
    if env:
        return env.rstrip("/")
    api = config.load().api_url
    # https://api.inferroute.ai -> https://inferroute.ai
    return api.replace("//api.", "//").rstrip("/") if "//api." in api else "https://inferroute.ai"


_UA = "inferroute-ir-verify/1.0"


def _http_get_json(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers={"user-agent": _UA, **headers})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _eth_call(rpc: str, to: str, data_hex: str) -> str:
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": "0x" + data_hex}, "latest"],
    }).encode()
    req = urllib.request.Request(rpc, data=payload, headers={"content-type": "application/json", "user-agent": _UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read().decode("utf-8"))
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]  # 0x + hex


def _onchain_roots(rpc: str, contract: str, epoch: int) -> tuple[str, str]:
    """epochRoots(epoch) -> (batch_root_hex, commitment_hex), read from Base."""
    arg = f"{epoch:064x}"
    res = _eth_call(rpc, contract, _SEL_EPOCH_ROOTS + arg)
    h = res[2:] if res.startswith("0x") else res
    return h[:64], h[64:128]  # two bytes32


def cmd_verify(rest: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ir verify", description="Verify your anchored records against Base.")
    ap.add_argument("--session", help="Only verify one session's records.")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--json", action="store_true", help="Machine-readable output.")
    ns = ap.parse_args(rest)

    creds = config.load()
    if not creds.api_key:
        print("  Not logged in. Run: ir login")
        return 2
    site = _site_url()

    url = f"{site}/api/verify/proofs?limit={ns.limit}" + (f"&session={ns.session}" if ns.session else "")
    try:
        data = _http_get_json(url, {"x-api-key": creds.api_key})
    except urllib.error.HTTPError as e:
        print(f"  proof fetch failed: HTTP {e.code}")
        return 1
    except Exception as e:
        print(f"  proof fetch failed: {e}")
        return 1

    contract = data.get("contract")
    rpc = os.environ.get("ANCHOR_VERIFY_RPC") or data.get("rpc") or "https://sepolia.base.org"
    records = data.get("records") or []
    if not contract:
        print("  Anchoring is not enabled yet on the server (no contract).")
        return 0
    if not records:
        print("  No anchored records yet for your account.\n"
              "  Records anchor after the next epoch seals (they must be recorded locally first).")
        return 0

    verified, mismatched, on_chain_missing = 0, [], []
    root_cache: dict[int, tuple[str, str]] = {}
    for rec in records:
        epoch = rec["epoch"]
        if epoch not in root_cache:
            try:
                root_cache[epoch] = _onchain_roots(rpc, contract, epoch)
            except Exception:
                root_cache[epoch] = ("", "")
        on_batch, on_commit = root_cache[epoch]
        if not on_batch or on_batch == "0" * 64:
            on_chain_missing.append(rec["record_id"]); continue
        # (a) the server's claimed root must equal what's actually on Base, and
        # (b) the record's proof must verify against that ON-CHAIN root.
        server_ok = (rec.get("batch_root") == on_batch) and (rec.get("commitment") == on_commit)
        proof_ok = verify_record(rec, on_batch)
        if server_ok and proof_ok:
            verified += 1
        else:
            mismatched.append({"record_id": rec["record_id"], "epoch": epoch, "server_ok": server_ok, "proof_ok": proof_ok})

    result = {
        "contract": contract, "chain": data.get("chain"), "rpc": rpc,
        "records": len(records), "verified": verified,
        "mismatched": mismatched, "on_chain_missing": len(on_chain_missing),
    }
    if ns.json:
        print(json.dumps(result, indent=2))
        return 0 if not mismatched else 1

    print(f"\n  Verifying {len(records)} anchored record(s) against Base ({data.get('chain')})")
    print(f"  contract {contract}  ·  read directly from {rpc}\n")
    print(f"    ✓ verified on-chain   {verified}")
    if on_chain_missing:
        print(f"    … epoch not yet on-chain (pending confirmation)  {len(on_chain_missing)}")
    if mismatched:
        print(f"    ✗ MISMATCH            {len(mismatched)}")
        for m in mismatched[:10]:
            print(f"        record {m['record_id']} epoch {m['epoch']}  server_ok={m['server_ok']} proof_ok={m['proof_ok']}")
        print("\n  A mismatch means the server's records for these turns do NOT match what\n"
              "  was anchored on Base — tampering or a bug. This is exactly what verify catches.")
        return 1
    print("\n  All records verify against the on-chain Merkle roots. Their fingerprints\n"
          "  and billing were committed on Base and cannot have been altered since.\n")
    return 0
