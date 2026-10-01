"""`sealed-client search` — a sealed prior-art search, verification narrated step by step.

    sealed-client search "disclosure text" [--cutoff YYYYMMDD] [-k N] --firm-priv KEY --offer-dir DIR --inbox FILE
    sealed-client search --collect --job J --firm-priv KEY --outbox DIR [--out DIR]
    sealed-client search "..." --relay URL --token T --firm-priv KEY          (deferred, via the relay)

Verify, THEN encrypt. The disclosure stays on this machine until a hardware report, signed by AMD's
chain, commits to the exact key it is about to be sealed to AND to the exact index that will be
searched. On return: the statement is checked against the signer bound in that report, the sealed
result against the hash the statement carries, and the index manifest shipped back against the hash
bound in REPORT_DATA — so the scope printed on the certificate is the scope that was committed to
hardware, not a claim in a PDF.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from . import envelope, search, snp, statement
from .reflect_client import Narrator, _short

SEARCH_HOME = os.path.expanduser("~/.local/share/sealed-research/searches")


def narrated_verify_search(offer_dir: str, certs_dir: str, nar: Narrator, expect_index: Optional[str] = None) -> List[str]:
    """Same hardware checks as the reflection client; the kind check is the opposite — a search offer
    MUST commit to a real index (non-sentinel) and to the encoders it will use."""
    from .client import get_certs
    problems: List[str] = []
    offer = json.load(open(os.path.join(offer_dir, "offer.json")))
    if offer.get("runtime_data"):
        # The confidential-container lane. Its offer carries runtime_data and binds REPORT_DATA as
        # sha256(runtime_data) || zeros, which is a different scheme from the self-hosted lane below.
        # It is verified by the SAME file a stranger runs against the exported record, so the client
        # cannot accept an enclave that the record's verifier would later reject.
        return _narrate_checks(nar, _verify_aci_offer(offer_dir, offer, expect_index))

    report = open(os.path.join(offer_dir, "snp-report.bin"), "rb").read()
    ok = hashlib.sha256(report).hexdigest() == offer.get("snp_report_sha256")
    nar.step(ok, f"offer.json describes the report beside it (sha256 {_short(offer.get('snp_report_sha256'))}).")
    if not ok:
        problems.append("offer.json does not describe the report file beside it")
    kind_ok = offer.get("kind", "search") == "search" and offer.get("index_snapshot") not in (None, "", "none") \
        and offer.get("index_manifest_sha256") not in (None, "", "00" * 32) and bool(offer.get("model_manifest_sha256"))
    nar.step(kind_ok, f"Offer is a search offer over index {offer.get('index_snapshot')!r} (manifest "
                      f"{_short(offer.get('index_manifest_sha256'))}), encoders {_short(offer.get('model_manifest_sha256'))}.",
             "A search commits to the exact bytes it will search. An all-zero index field here would mean nothing was committed.")
    if not kind_ok:
        problems.append("offer is not a search offer committing to an index and encoders")
    if expect_index and offer.get("index_snapshot") != expect_index:
        nar.step(False, f"REFUSED — offer searches {offer.get('index_snapshot')!r}, expected {expect_index!r}.")
        problems.append("unexpected index snapshot")
    if offer.get("attestation") == "FAKE":
        problems.append("offer declares FAKE attestation — phase-test artifact, never encrypt to it")
    p = snp.parse(report)
    pre = snp.verify_chain(report, vcek_der=None, ask_ark_pem=None)
    structural = [q for q in pre["problems"] if "no VCEK" not in q and "ASK/ARK" not in q]
    if structural:
        nar.step(False, f"REFUSED — the report is not a hardware report: version {p['version']}, "
                        f"{'unsigned' if p['signature'] == b'\\x00' * 512 else 'signed'}{', DEBUG allowed' if p['debug_allowed'] else ''}.")
        return problems + structural
    nar.step(True, f"Report is a hardware report: version {p['version']}, signed by {p['signing_key']}, DEBUG off.")
    certs = get_certs(report, certs_dir)
    nar.step(certs["vcek"] is not None, f"Fetching AMD's certificate for this exact chip (hwid {snp.hwid_hex(p['chip_id'])})"
                                         f"{' (cached)' if certs['vcek'] else ' — NOT obtained'}.")
    res = snp.verify_chain(report, vcek_der=certs["vcek"], ask_ark_pem=certs["chain"])
    nar.step(res["verified"], "Report signature verifies under that certificate: this came from silicon, not from a server we control."
             if res["verified"] else "REFUSED — the report does not verify under AMD's chain: " + "; ".join(res["problems"]))
    problems += res["problems"]
    try:
        expected = snp.binding(
            enclave_pubkey=bytes.fromhex(offer["enclave_x25519_pub"]) + bytes.fromhex(offer["statement_signer_pub"]),
            image_measurement=bytes.fromhex(offer["measurement"]), policy_hash=bytes.fromhex(offer["policy_sha256"]),
            index_manifest_hash=bytes.fromhex(offer["index_manifest_sha256"]),
            model_weights_hash=bytes.fromhex(offer["model_manifest_sha256"] or "00" * 32), job_id=offer["job_id"].encode())
        bound = snp.check_binding(report, expected)
    except (KeyError, ValueError) as exc:
        bound = False; problems.append(f"offer malformed: {exc}")
    nar.step(bound, f"The report commits to enclave key {_short(offer.get('enclave_x25519_pub'))}, policy {_short(offer.get('policy_sha256'))}, "
                    f"index manifest {_short(offer.get('index_manifest_sha256'))}, encoders {_short(offer.get('model_manifest_sha256'))}, "
                    f"job {offer.get('job_id')}: nothing we could swap after the fact.")
    if not bound:
        problems.append("REPORT_DATA does not match the offer's stated key/policy/index/model/job")
    nar.step(True, f"Measurement {_short(offer.get('measurement'), 12)} (printed, not judged: no published expected value yet).")
    return problems


def _verify_aci_offer(offer_dir: str, offer: dict, expect_index: Optional[str]):
    """Everything checkable BEFORE anything is sealed, via the vendored verifier.

    Pre-seal is the security-critical direction: a sealed query cannot be recalled, so a retired policy
    or an unusable enclave key has to stop the disclosure from leaving this machine, not fail the record
    afterwards.
    """
    from . import verify_record as V
    ref = None
    ref_path = os.path.join(offer_dir, "reference.json")
    if os.path.exists(ref_path):
        ref = json.load(open(ref_path))
    policy_b64 = None
    pol_path = os.path.join(offer_dir, "policy.base64")
    if os.path.exists(pol_path):
        policy_b64 = open(pol_path).read().strip()
    # The key that says the reference is OURS. Optional and read from beside the offer, so a firm given
    # InferRoute's publication key can close the "reference authenticated" row outright; without it the
    # verifier still reports that identity rests on a file nobody verified, rather than staying silent.
    ref_key = None
    key_path = os.path.join(offer_dir, "reference-key.txt")
    if os.path.exists(key_path):
        import re as _re
        m = _re.search(r"[0-9a-fA-F]{64}", open(key_path).read())
        ref_key = m.group(0).lower() if m else None
    c = V.verify_offer(offer, reference=ref, policy_b64=policy_b64, reference_key=ref_key)
    if expect_index:
        import base64 as _b64
        try:
            rd = json.loads(_b64.b64decode(offer["runtime_data"], validate=True))
        except Exception:                                      # noqa: BLE001
            rd = {}
        c.add(rd.get("index_snapshot") == expect_index, "the index you asked for",
              f"offer searches {rd.get('index_snapshot')!r}, you expected {expect_index!r}")
    if ref is None:
        c.add(None, "enclave identity",
              "no reference beside the offer: this proves a confidential container, NOT that it is "
              "InferRoute's. Put the reference you were given next to offer.json as reference.json.")
    return c


def _narrate_checks(nar: "Narrator", c) -> List[str]:
    """One verdict, said once. The narration reads the rows rather than describing them, so the words
    cannot promise a check the code did not run — which is exactly how "Fetching AMD's certificate for
    this exact chip" outlived a chain check that was never performed (fixed 2026-09-16)."""
    problems: List[str] = []
    for status, name, detail in c.rows:
        if status == "PASS":
            nar.step(True, f"{name}: {detail}")
        elif status == "FAIL":
            nar.step(False, f"REFUSED — {name}: {detail}")
            problems.append(f"{name}: {detail}")
        else:
            nar.say(f"  not checked — {name}: {detail}")
    return problems


def seal_query(offer: Dict[str, Any], query: str, k: int, cutoff_date: Optional[int], legs: Optional[List[str]] = None,
               session_id: Optional[str] = None, from_date: Optional[int] = None,
               offices: Optional[List[str]] = None) -> bytes:
    payload = {"kind": "search", "query": query, "k": k, "cutoff_date": cutoff_date, "legs": legs,
               "from_date": from_date, "offices": offices, "session_id": session_id or os.urandom(16).hex(),
               "meta": {"client": "sealed-client 0.1"}}
    search.validate(json.dumps(payload).encode())          # refuse locally what the enclave would refuse
    return envelope.seal(bytes.fromhex(offer["enclave_x25519_pub"]), json.dumps(payload).encode(), aad=offer["job_id"].encode())


def open_search_result(outbox: str, job: str, firm_priv_path: str, nar: Narrator) -> Dict[str, Any]:
    """Verify, then open. Raises SystemExit(1) on any refusal, narrated. Returns {result, statement, manifest}."""
    offer = json.load(open(os.path.join(outbox, "offer.json")))
    signed = json.load(open(os.path.join(outbox, "statement.json")))
    ok = statement.verify_statement(bytes.fromhex(offer["statement_signer_pub"]), signed)
    nar.step(ok, f"Statement signature verifies under the key bound in the attestation ({_short(offer['statement_signer_pub'])}).")
    if not ok:
        raise SystemExit(1)
    if signed.get("job_id") != job or signed.get("kind") != "search":
        nar.step(False, f"REFUSED — statement is for {signed.get('job_id')!r}/{signed.get('kind')!r}, expected {job!r}/search."); raise SystemExit(1)
    same = all(signed.get(f) == offer.get(f) for f in ("index_manifest_sha256", "model_manifest_sha256", "policy_sha256", "enclave_x25519_pub"))
    nar.step(same, "The statement names the same index manifest, encoders, policy and enclave key as the offer that was verified.")
    if not same:
        raise SystemExit(1)
    manifest = None
    mp = os.path.join(outbox, "index-manifest.json")
    if os.path.exists(mp):
        mh = hashlib.sha256(open(mp, "rb").read()).hexdigest(); m_ok = mh == signed["index_manifest_sha256"]
        nar.step(m_ok, f"The index manifest shipped back hashes to {_short(mh)}, the value committed in REPORT_DATA"
                       f"{'' if m_ok else ' — MISMATCH'}.",
                 "The manifest lists every file that was searchable: paths, sizes, hashes. Its own hash is what the hardware signed.")
        if not m_ok:
            raise SystemExit(1)
        manifest = json.load(open(mp))
    if signed.get("outcome") == "refused":
        nar.step(False, f"The enclave refused this search: category {signed.get('refusal')!r}. No result was produced.")
        return {"refused": signed.get("refusal"), "statement": signed, "manifest": manifest}
    blob = open(os.path.join(outbox, "result.sealed"), "rb").read()
    h_ok = hashlib.sha256(blob).hexdigest() == signed.get("result_blob_sha256")
    nar.step(h_ok, f"The sealed result's hash matches what the enclave signed ({_short(signed.get('result_blob_sha256'))}).")
    if not h_ok:
        raise SystemExit(1)
    try:
        res = json.loads(envelope.open_(open(firm_priv_path, "rb").read(), blob, aad=(job + "/result").encode()))
    except envelope.EnvelopeError as exc:
        nar.step(False, f"REFUSED — {exc}"); raise SystemExit(1)
    r_ok = search.sha256(res) == signed.get("result_sha256") and len(res.get("hits", [])) == signed.get("hits_n")
    nar.step(r_ok, f"Decrypted result hashes to the signed result hash ({_short(signed.get('result_sha256'))}); {signed.get('hits_n')} hits.")
    if not r_ok:
        raise SystemExit(1)
    can = signed.get("canary") or []
    nar.step(True, f"Control lane: {len(can)} public canary queries ran in the same process just before yours; "
                   f"{sum(c['found_100'] for c in can)}/{sum(c['gold_n'] for c in can)} of their known examiner-cited art in the top 100, "
                   f"{sum(c['found_1000'] for c in can)}/{sum(c['gold_n'] for c in can)} in the top 1000.",
             "The canaries have known answers. Their yield in this run is evidence the machinery was healthy when your query ran.")
    nar.step(True, f"Interfaces during the search: {signed.get('netns_interfaces')}; egress probe: {signed.get('egress_probe')}; "
                   f"legs and candidate counts: {signed.get('legs')}; cutoff {signed.get('cutoff_date') or 'none'}.")
    return {"result": res, "statement": signed, "manifest": manifest}


def print_hits(res: Dict[str, Any], nar: Narrator, n: Optional[int] = None) -> None:
    hits = res["hits"][: n or len(res["hits"])]
    cal = res.get("calibration")
    nar.say(f"\nCPC {' '.join(res.get('cpc', []))}   candidates {res.get('candidates')}   legs {res.get('legs')}")
    if cal:
        nar.say(f"calibrated yield for area {cal.get('area')}: {cal.get('recall_100'):.0%} of examiner-cited art within the top 100, "
                f"{cal.get('recall_1000'):.0%} within the top 1000 (n={cal.get('n')}, public benchmark, this pipeline version)")
    for i, h in enumerate(hits, 1):
        nar.say(f"{i:3d}  {h['score']:.3f}  [{','.join(h['legs'])}] {h.get('source','paper'):<6} {h.get('year') or '----'}  {(h.get('title') or '')[:80]}  {h['key']}")
    nar.say(f"\n{res.get('claim_boundary')}")


def _jdir(job: str) -> str:
    d = os.path.join(SEARCH_HOME, job); os.makedirs(d, exist_ok=True); return d


def cmd_search(a) -> int:
    nar = Narrator("quiet" if a.quiet else "explain" if a.explain else "default")
    if a.collect:
        got = open_search_result(a.outbox, a.job, a.firm_priv, nar)
        if "refused" in got:
            return 1
        res = got["result"]; print_hits(res, nar, a.show)
        out = a.out or _jdir(a.job); os.makedirs(out, exist_ok=True)
        json.dump(res, open(os.path.join(out, "result.json"), "w"), indent=1)
        from .search_certificate import render_search
        html = render_search(got["statement"], json.load(open(os.path.join(a.outbox, "offer.json"))), got["manifest"], firm=a.firm)
        open(os.path.join(out, "certificate.html"), "w").write(html)
        from .search_report import render_report
        rpt = render_report(got["statement"], res, matter=(getattr(a, "matter", None) or a.job),
                            firm=a.firm, manifest=got.get("manifest"), applicant=getattr(a, "applicant", "") or "")
        open(os.path.join(out, "search-report.html"), "w").write(rpt)
        nar.say(f"result, search report and certificate written to {out}")
        return 0
    if not a.text:
        nar.say("give the disclosure text (or --collect)"); return 2
    if a.offer_dir:
        offer = json.load(open(os.path.join(a.offer_dir, "offer.json")))
        nar.say(f"an enclave is offering for job {offer['job_id']}. Verifying before anything is sent:")
        problems = narrated_verify_search(a.offer_dir, a.certs, nar, a.expect_index)
        if problems:
            nar.say("REFUSED — no ciphertext produced; your disclosure has not left this machine.")
            for p in problems:
                nar.say(f"  ✗ {p}")
            return 1
        blob = seal_query(offer, a.text, a.k, a.cutoff, a.legs.split(",") if a.legs else None)
        nar.step(True, "Sealing your disclosure to that key. The plaintext stays on this machine.")
        open(a.inbox, "wb").write(blob)
        d = _jdir(offer["job_id"]); open(os.path.join(d, "query.sealed"), "wb").write(blob)
        nar.say(f"sealed — {len(blob)} bytes at {a.inbox}; collect with: sealed-client search --collect --job {offer['job_id']} --outbox <OUTBOX> --firm-priv ...")
        return 0
    nar.say("relay mode is not wired in this build; use --offer-dir/--inbox with a running enclave")
    return 2
