"""The firm's client. Verify, THEN encrypt — never the other way round.

    sealed-client verify-offer OFFER_DIR --job J --expect-index SNAP [--certs DIR]
    sealed-client seal         OFFER_DIR --job J --disclosure FILE --out BLOB
    sealed-client keygen       --out-priv FILE --out-pub FILE
    sealed-client open-result  OUTBOX --job J --firm-priv FILE --out DIR

`seal` refuses to produce a ciphertext unless `verify-offer` passes in the same invocation. That is
the whole point: the disclosure is held locally until a report from genuine hardware, signed by AMD's
chain, commits to the exact public key we are about to encrypt to. A bad attestation means the
plaintext never leaves this machine.

What verify-offer checks, in order — each one a distinct way to be lied to:
  1. the SNP report parses, is a hardware report (version ≥ 2, non-zero signature), DEBUG off;
  2. the report's signature verifies under the VCEK, and the VCEK chains to AMD's ARK
     (certs fetched once from AMD KDS and cached; verification is then offline);
  3. REPORT_DATA equals binding(pubkeys ‖ measurement ‖ policy ‖ index ‖ model ‖ job) recomputed
     from the offer's own stated fields — so the offer cannot describe one corpus and commit to
     another;
  4. the job id and index snapshot are the ones the firm expects.
Measurement is printed, never judged, until an expected image measurement exists to compare it to.
That gap is stated in the output rather than hidden.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from typing import Dict, List, Optional

from . import envelope, snp, statement

KDS_CHAIN = "https://kdsintf.amd.com/vcek/v1/{product}/cert_chain"


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as fh:
        return fh.read()


def get_certs(report: bytes, certs_dir: str, product: str = "Turin") -> Dict[str, Optional[bytes]]:
    """VCEK + ASK/ARK for this report's chip and TCB. Cached per chip so verification is offline
    after the first fetch. Returns None entries rather than raising — the verifier decides."""
    os.makedirs(certs_dir, exist_ok=True)
    p = snp.parse(report)
    hw = snp.hwid_hex(p["chip_id"])
    vcek_path = os.path.join(certs_dir, f"vcek-{hw}-{p['reported_tcb'].hex()}.der")
    chain_path = os.path.join(certs_dir, f"ask-ark-{product}.pem")
    out: Dict[str, Optional[bytes]] = {"vcek": None, "chain": None}
    for path, url, key in ((vcek_path, snp.vcek_url(report, product=product), "vcek"),
                           (chain_path, KDS_CHAIN.format(product=product), "chain")):
        if not os.path.exists(path):
            try:
                data = _fetch(url)
                if len(data) > 200:
                    with open(path, "wb") as fh:
                        fh.write(data)
            except Exception as exc:          # noqa: BLE001
                print(f"[client] could not fetch {key}: {exc}", file=sys.stderr)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                out[key] = fh.read()
    return out


def verify_offer(offer_dir: str, job: str, expect_index: Optional[str], certs_dir: str) -> List[str]:
    """Returns the list of problems. Empty list == the offer is safe to encrypt to."""
    problems: List[str] = []
    with open(os.path.join(offer_dir, "offer.json")) as fh:
        offer = json.load(fh)
    with open(os.path.join(offer_dir, "snp-report.bin"), "rb") as fh:
        report = fh.read()
    if hashlib.sha256(report).hexdigest() != offer.get("snp_report_sha256"):
        problems.append("offer.json does not describe the report file beside it")
    if offer.get("job_id") != job:
        problems.append(f"offer is for job {offer.get('job_id')!r}, expected {job!r}")
    if expect_index and offer.get("index_snapshot") != expect_index:
        problems.append(f"offer searches {offer.get('index_snapshot')!r}, expected {expect_index!r}")
    if offer.get("attestation") == "FAKE":
        problems.append("offer declares FAKE attestation — phase-test artifact, never encrypt to it")

    # 1: structural check BEFORE any network — a report that is not even a hardware report gets no
    # KDS lookup (which would also leak a garbage chip id to AMD and stall on two timeouts).
    pre = snp.verify_chain(report, vcek_der=None, ask_ark_pem=None)
    structural = [q for q in pre["problems"] if "no VCEK" not in q and "ASK/ARK" not in q]
    if structural:
        problems += structural
        return problems
    # 2: signed by silicon, chained to AMD (certs fetched once, then offline).
    certs = get_certs(report, certs_dir)
    res = snp.verify_chain(report, vcek_der=certs["vcek"], ask_ark_pem=certs["chain"])
    problems += res["problems"]

    # 3: the commitment matches what the offer claims. Recomputed here from the offer's fields — if
    # the enclave bound a different index or policy than it advertises, this is where it shows.
    try:
        expected = snp.binding(
            enclave_pubkey=bytes.fromhex(offer["enclave_x25519_pub"]) + bytes.fromhex(offer["statement_signer_pub"]),
            image_measurement=bytes.fromhex(offer["measurement"]),
            policy_hash=bytes.fromhex(offer["policy_sha256"]),
            index_manifest_hash=bytes.fromhex(offer["index_manifest_sha256"]),
            model_weights_hash=bytes.fromhex(offer["model_manifest_sha256"] or "00" * 32),
            job_id=offer["job_id"].encode())
        if not snp.check_binding(report, expected):
            problems.append("REPORT_DATA does not match the offer's stated key/policy/index/model/job")
        if snp.parse(report)["measurement"] != bytes.fromhex(offer["measurement"]):
            problems.append("offer's stated measurement differs from the report's")
    except (KeyError, ValueError) as exc:
        problems.append(f"offer malformed: {exc}")
    return problems


def _print_verdict(offer_dir: str, problems: List[str]) -> None:
    with open(os.path.join(offer_dir, "offer.json")) as fh:
        offer = json.load(fh)
    print(f"offer       {offer.get('job_id')}  attestation={offer.get('attestation')}")
    print(f"index       {offer.get('index_snapshot')}")
    print(f"measurement {offer.get('measurement')}")
    print("            (printed, not judged: no published expected measurement exists yet — that is the"
          " open item with the provider, and until it closes this proves genuine hardware, not our software)")
    if problems:
        print("REFUSED — will not encrypt to this offer:")
        for p in problems:
            print(f"  ✗ {p}")
    else:
        print("VERIFIED — report signed by silicon, chained to AMD, committing to exactly this key, index, policy and job.")


def cmd_verify(a) -> int:
    problems = verify_offer(a.offer_dir, a.job, a.expect_index, a.certs)
    _print_verdict(a.offer_dir, problems)
    return 1 if problems else 0


def cmd_seal(a) -> int:
    problems = verify_offer(a.offer_dir, a.job, a.expect_index, a.certs)
    _print_verdict(a.offer_dir, problems)
    if problems:
        print("no ciphertext produced.", file=sys.stderr)
        return 1
    with open(os.path.join(a.offer_dir, "offer.json")) as fh:
        offer = json.load(fh)
    with open(a.disclosure, "rb") as fh:
        text = fh.read().decode("utf-8")
    # The priority date travels INSIDE the envelope. The first hardware run dropped it in transit and
    # the engine, given no bound, rated 2013-2016 papers as "high" prior art for a 2013 priority —
    # post-dated art is not prior art, and a search without a date is not a prior-art search.
    meta = {"ref": a.job, "priority_year": a.priority_year}
    if a.directions:
        with open(a.directions) as fh:
            meta["directions"] = json.load(fh)          # Phase A: [{"label","text"}, ...], compared in-enclave
    plain = json.dumps({"disclosure": text, "meta": meta}).encode()
    blob = envelope.seal(bytes.fromhex(offer["enclave_x25519_pub"]), plain, aad=a.job.encode())
    with open(a.out, "wb") as fh:
        fh.write(blob)
    print(f"sealed {len(plain)} bytes → {a.out} ({len(blob)} bytes). The plaintext stays here.")
    return 0


def cmd_keygen(a) -> int:
    priv, pub = envelope.gen_keypair()
    fd = os.open(a.out_priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv)
    with open(a.out_pub, "w") as fh:
        fh.write(pub.hex() + "\n")
    print(f"firm key written: {a.out_priv} (private, 0600)  {a.out_pub} (public, give this to the enclave)")
    return 0


def cmd_open(a) -> int:
    """Decrypt the result, verify the statement with the key bound in the attested offer, and check
    the report we decrypted is the one the enclave signed over."""
    with open(os.path.join(a.outbox, "offer.json")) as fh:
        offer = json.load(fh)
    with open(os.path.join(a.outbox, "statement.json")) as fh:
        signed = json.load(fh)
    signer = bytes.fromhex(offer["statement_signer_pub"])
    if not statement.verify_statement(signer, signed):
        print("REFUSED: statement signature does not verify under the key bound in the attested offer")
        return 1
    if signed["job_id"] != a.job:
        print(f"REFUSED: statement is for job {signed['job_id']!r}")
        return 1
    with open(a.firm_priv, "rb") as fh:
        priv = fh.read()
    with open(os.path.join(a.outbox, "result.sealed"), "rb") as fh:
        blob = fh.read()
    if hashlib.sha256(blob).hexdigest() != signed["result_blob_sha256"]:
        print("REFUSED: result blob is not the one the statement signs over")
        return 1
    try:
        bundle = json.loads(envelope.open_(priv, blob, aad=(a.job + "/result").encode()))
    except envelope.EnvelopeError as exc:
        print(f"REFUSED: {exc}")
        return 1
    os.makedirs(a.out, exist_ok=True)
    for name, text in bundle.items():
        with open(os.path.join(a.out, name), "w") as fh:
            fh.write(text)
    rep = hashlib.sha256(bundle["report.md"].encode()).hexdigest()
    if rep != signed["report_sha256"]:
        print("REFUSED: decrypted report does not match the hash the enclave signed")
        return 1
    print(f"OK — statement verified under the attested key; report matches its signed hash.")
    print(f"     interfaces during the run: {signed['netns_interfaces']}   ledger rows: {signed['ledger_rows']}"
          f"   bytes through gateway: {signed['egress_bytes']}   index: {signed['index_snapshot']}")
    print(f"     written to {a.out}/")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="sealed-client", description=__doc__.split("\n\n")[0])
    p.add_argument("--certs", default=os.path.expanduser("~/.cache/sealed-research/amd-certs"))
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify-offer"); v.add_argument("offer_dir"); v.add_argument("--job", required=True)
    v.add_argument("--expect-index", default=None); v.set_defaults(fn=cmd_verify)
    s = sub.add_parser("seal"); s.add_argument("offer_dir"); s.add_argument("--job", required=True)
    s.add_argument("--expect-index", default=None); s.add_argument("--disclosure", required=True)
    s.add_argument("--priority-year", type=int, required=True,
                   help="art published after this year is excluded; a search without it is refused")
    s.add_argument("--directions", default=None,
                   help="JSON list of {label, text} candidate directions — switches the run to a comparative "
                        "direction assessment (Phase A of the IP extension)")
    s.add_argument("--out", required=True); s.set_defaults(fn=cmd_seal)
    k = sub.add_parser("keygen"); k.add_argument("--out-priv", required=True); k.add_argument("--out-pub", required=True)
    k.set_defaults(fn=cmd_keygen)
    o = sub.add_parser("open-result"); o.add_argument("outbox"); o.add_argument("--job", required=True)
    o.add_argument("--firm-priv", required=True); o.add_argument("--out", required=True); o.set_defaults(fn=cmd_open)
    # --- reflection: the deferred, private thinking-partner session (sealedresearch/reflect_client.py)
    from . import reflect_client as rc
    r = sub.add_parser("reflect", help="a private reflection turn, deferred; verification narrated step by step")
    r.add_argument("message", nargs="?", default=None)
    r.add_argument("--session", required=True); r.add_argument("--firm-priv", default=None)
    r.add_argument("--relay", default=os.environ.get("SEALED_RELAY", "https://relay.inferroute.ai"))
    r.add_argument("--token", default=os.environ.get("SEALED_RELAY_TOKEN", ""))
    r.add_argument("--seed-report", default=None, help="turn 1 only: a prior report to start from (its hash is recorded as lineage)")
    r.add_argument("--async", dest="async_", action="store_true", help="request and return; collect later")
    r.add_argument("--collect", action="store_true", help="advance the pending turn without a new message")
    r.add_argument("--cancel", action="store_true", help="withdraw the pending turn (only before an enclave starts it)")
    r.add_argument("--show", action="store_true"); r.add_argument("--poll-seconds", type=int, default=15)
    r.add_argument("--timeout-min", type=int, default=0)
    r.add_argument("--explain", action="store_true", help="a sentence more per verification step")
    r.add_argument("--quiet", action="store_true", help="verdicts only")
    r.set_defaults(fn=rc.cmd_reflect)
    sc = sub.add_parser("search", help="a sealed prior-art search; verification narrated step by step")
    sc.add_argument("text", nargs="?"); sc.add_argument("--cutoff", type=int, default=None, help="YYYYMMDD: exclude art on/after")
    sc.add_argument("-k", type=int, default=50); sc.add_argument("--legs", default=None)
    sc.add_argument("--firm-priv", default=None); sc.add_argument("--firm", default="the firm")
    sc.add_argument("--offer-dir", default=None); sc.add_argument("--inbox", default=None); sc.add_argument("--expect-index", default=None)
    sc.add_argument("--collect", action="store_true"); sc.add_argument("--job", default=None); sc.add_argument("--outbox", default=None)
    sc.add_argument("--out", default=None); sc.add_argument("--show", type=int, default=None)
    sc.add_argument("--matter", default=None, help="the firm's own reference for this matter; appears on the report")
    sc.add_argument("--applicant", default="")
    sc.add_argument("--relay", default=None); sc.add_argument("--token", default=None)
    sc.add_argument("--certs", default=os.path.expanduser("~/.cache/sealed-research/amd-certs"))
    sc.add_argument("--quiet", action="store_true"); sc.add_argument("--explain", action="store_true")
    from . import search_client as scl
    sc.set_defaults(fn=scl.cmd_search)
    e = sub.add_parser("explain", help="narrate a past offer or outbox, field by field, offline")
    e.add_argument("dir"); e.set_defaults(fn=rc.cmd_explain)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
