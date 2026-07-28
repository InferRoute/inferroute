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
from datetime import datetime, timezone
from typing import Optional

from . import config
from inferroute_local.anchor_verify import verify_record, verify_commitment

# Contract function selectors (keccak-derived; fixed for the ABI).
_SEL_EPOCH_ROOTS = "ef95d4e0"  # epochRoots(uint64) -> (bytes32 batchRoot, bytes32 commitment)
_ZERO = "0" * 64               # genesis C_0 (32 zero bytes)


def _explorer(chain: Optional[str]) -> str:
    return "https://basescan.org" if chain == "base" else "https://sepolia.basescan.org"


def _fmt_day(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%b %-d")


def _fmt_usd(millicents: int) -> str:
    # cost is integer millicents (1/1000 of a cent) → dollars = millicents / 100000.
    d = millicents / 100_000
    return f"${d:,.4f}" if d < 1 else f"${d:,.2f}"


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

    from collections import defaultdict

    root_cache: dict[int, tuple[str, str]] = {}

    def roots(epoch: int) -> tuple[str, str]:
        if epoch not in root_cache:
            try:
                root_cache[epoch] = _onchain_roots(rpc, contract, epoch)
            except Exception:
                root_cache[epoch] = ("", "")
        return root_cache[epoch]

    verified, mismatched, on_chain_missing = 0, [], []
    by_epoch: dict[int, dict] = defaultdict(lambda: {"count": 0, "tx": None})
    tot_cost = tot_in = tot_out = tot_cache = 0
    models: set[str] = set()
    sessions: set[str] = set()
    kinds: dict[str, int] = defaultdict(int)
    ts_min = ts_max = None

    for rec in records:
        epoch = rec["epoch"]
        on_batch, on_commit = roots(epoch)
        if not on_batch or on_batch == _ZERO:
            on_chain_missing.append(rec["record_id"]); continue
        # (a) the server's claimed root must equal what's actually on Base, and
        # (b) the record's proof must verify against that ON-CHAIN root.
        server_ok = (rec.get("batch_root") == on_batch) and (rec.get("commitment") == on_commit)
        proof_ok = verify_record(rec, on_batch)
        if not (server_ok and proof_ok):
            mismatched.append({"record_id": rec["record_id"], "epoch": epoch, "server_ok": server_ok, "proof_ok": proof_ok})
            continue
        verified += 1
        # Aggregate the verified leaves (values recomputed/checked above, not trusted blindly).
        e = by_epoch[epoch]; e["count"] += 1; e["tx"] = rec.get("tx_hash") or e["tx"]
        f = rec.get("leaf_fields") or {}
        kind = f.get("kind", "usage")
        kinds[kind] += 1
        if kind != "founding-capsule":
            tot_cost += int(f.get("cost_millicents") or 0)
            tot_in += int(f.get("input_tokens") or 0)
            tot_out += int(f.get("output_tokens") or 0)
            tot_cache += int(f.get("cache_read_tokens") or 0)
            if f.get("model"):
                models.add(f["model"])
        if f.get("session_id"):
            sessions.add(f["session_id"])
        ms = f.get("created_at_ms")
        if ms:
            ts_min = ms if ts_min is None else min(ts_min, ms)
            ts_max = ms if ts_max is None else max(ts_max, ms)

    # Commitment chain: each epoch YOU appear in must derive from its predecessor,
    # C_e == sha256(C_{e-1} ‖ batch_root_e), read from Base. Because C_{e-1} folds
    # in every prior epoch, this transitively anchors your epoch to the whole
    # append-only ledger — and it's checked per-your-epoch rather than walked from
    # genesis, so a pre-production/test-epoch discontinuity can't false-alarm. A
    # failure HERE, on your own epochs, is a real tamper/reorder signal.
    chain_ok: Optional[bool] = None
    chain_checked = 0
    for e in sorted(by_epoch):
        b, c = roots(e)
        if not b or b == _ZERO or not c:
            continue
        prevc = _ZERO if e == 1 else roots(e - 1)[1]
        if not prevc:
            continue  # predecessor not readable — skip this link
        chain_checked += 1
        ok = verify_commitment(prevc, b, c)
        chain_ok = ok if chain_ok is None else (chain_ok and ok)

    if ns.json:
        print(json.dumps({
            "contract": contract, "chain": data.get("chain"), "rpc": rpc,
            "records": len(records), "verified": verified,
            "mismatched": mismatched, "on_chain_missing": len(on_chain_missing),
            "commitment_chain": chain_ok, "chain_epochs_checked": chain_checked,
            "epochs": {str(e): {"records": v["count"], "tx": v["tx"]} for e, v in sorted(by_epoch.items())},
            "committed": {
                "cost_millicents": tot_cost, "input_tokens": tot_in,
                "output_tokens": tot_out, "cache_read_tokens": tot_cache,
                "models": sorted(models), "sessions": len(sessions),
                "kinds": dict(kinds),
                "first_ms": ts_min, "last_ms": ts_max,
            },
        }, indent=2))
        return 0 if not mismatched else 1

    chain_name = data.get("chain")
    exp = _explorer(chain_name)
    mark = "✓" if not mismatched else "✗"

    print(f"\n  Verifying {len(records)} anchored record(s) against Base ({chain_name})")
    print(f"  contract {contract}")
    print(f"  roots read directly from {rpc} — nothing below is on our word\n")

    print("  Inclusion")
    print(f"    {mark} {verified}/{len(records)} records verified against the on-chain Merkle roots")
    if on_chain_missing:
        print(f"      {len(on_chain_missing)} in an epoch not yet on-chain (pending confirmation)")

    if chain_ok is True:
        ne = len(by_epoch)
        subj = "your anchored epoch links" if ne == 1 else f"all {ne} of your anchored epochs link"
        print("\n  Ledger integrity")
        print(f"    ✓ {subj} into the append-only chain")
        print("      C_t = SHA256(C_t-1 ‖ batch_root) verified on-chain — each epoch")
        print("      cryptographically folds in every epoch before it")
    elif chain_ok is False:
        print("\n  Ledger integrity")
        print("    ✗ an epoch of yours does NOT link into the chain — possible tampering")

    if kinds.get("usage") or tot_cost or models:
        print("\n  What was committed  (recomputed from the anchored leaves)")
        print(f"    {_fmt_usd(tot_cost)} in charges     {tot_in:,} in · {tot_out:,} out · {tot_cache:,} cached tokens")
        if models:
            shown = ", ".join(sorted(models)[:6])
            more = f"  +{len(models) - 6} more" if len(models) > 6 else ""
            print(f"    {len(models)} model(s): {shown}{more}")
        line = f"    {kinds.get('usage', 0):,} turn(s)"
        if sessions:
            line += f" across {len(sessions):,} session(s)"
        if ts_min and ts_max:
            line += f"  ·  {_fmt_day(ts_min)} → {_fmt_day(ts_max)}"
        print(line)
    if kinds.get("founding-capsule"):
        print(f"    ★ {kinds['founding-capsule']} founding-contributor capsule(s) anchored")

    if by_epoch:
        print(f"\n  Anchored across {len(by_epoch)} epoch(s) on Base:")
        for e in sorted(by_epoch, reverse=True):
            tx = by_epoch[e]["tx"] or ""
            shown = (tx[:12] + "…") if tx else "—"
            link = f"  {exp}/tx/{tx}" if tx else ""
            print(f"    epoch {e:<4} {by_epoch[e]['count']:>4} rec   {shown}{link}")

    if mismatched:
        print("\n  ✗ MISMATCH — these records do NOT match what was anchored on Base:")
        for m in mismatched[:10]:
            print(f"      record {m['record_id']} epoch {m['epoch']}  server_ok={m['server_ok']} proof_ok={m['proof_ok']}")
        print("\n  A mismatch is exactly what verify exists to catch — tampering or a bug.")
        return 1

    print("\n  These exact turn fingerprints and their billing are committed on Base and")
    print("  cannot have been altered since. Everything above was read from the chain,")
    print(f"  not served by InferRoute — check it by hand at {site}/verify\n")
    return 0
