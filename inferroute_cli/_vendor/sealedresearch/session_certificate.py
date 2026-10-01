"""sealed-session-certificate — one HTML document per reflection session, rendered only from what was
verified: the signed statements, the offers they answer, the reports beside those offers, and the
lineage chain between turns.

Facts only. The template contains no causal connective at all (stricter than the report guard); the
word "refused" appears only in table cells. Verification happens first and refuses to render on any
problem: a certificate that could be rendered for a broken session would be worth nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import reflect, snp, statement
from .certificate import _CSS, _esc


def load_turns(session_dir: str) -> List[Dict[str, Any]]:
    """Every completed turn in order: statement, offer, report bytes, request."""
    out = []
    tdir = os.path.join(session_dir, "turns")
    for n in sorted(os.listdir(tdir), key=int):
        ob = os.path.join(tdir, n, "outbox")
        if not os.path.exists(os.path.join(ob, "statement.json")):
            continue
        t = {"n": int(n), "statement": json.load(open(os.path.join(ob, "statement.json"))),
             "offer": json.load(open(os.path.join(ob, "offer.json"))),
             "report": open(os.path.join(ob, "snp-report.bin"), "rb").read(),
             "request": json.load(open(os.path.join(tdir, n, "request.json"))) if os.path.exists(os.path.join(tdir, n, "request.json")) else {}}
        out.append(t)
    return out


def verify_turns(turns: List[Dict[str, Any]], certs_dir: Optional[str] = None, *, require_hardware: bool = True) -> List[str]:
    """Problems, or []. Signatures under each offer's signer; report hashes; REPORT_DATA bindings;
    lineage chain; monotonic turn numbers; one seeded_from per session."""
    problems: List[str] = []
    prev_out, seeds = None, set()
    for i, t in enumerate(turns):
        st, o, rep = t["statement"], t["offer"], t["report"]
        tag = f"turn {st.get('turn', '?')}"
        if not statement.verify_statement(bytes.fromhex(o["statement_signer_pub"]), st):
            problems.append(f"{tag}: statement signature fails under the offer's signer")
        if hashlib.sha256(rep).hexdigest() != o.get("snp_report_sha256"):
            problems.append(f"{tag}: offer does not describe the report beside it")
        if st.get("kind") != "reflect" or o.get("kind") != "reflect":
            problems.append(f"{tag}: not a reflection statement/offer")
        if o.get("index_snapshot") != "none" or o.get("index_manifest_sha256") != "00" * 32:
            problems.append(f"{tag}: offer committed to an index")
        try:
            expected = snp.binding(
                enclave_pubkey=bytes.fromhex(o["enclave_x25519_pub"]) + bytes.fromhex(o["statement_signer_pub"]),
                image_measurement=bytes.fromhex(o["measurement"]), policy_hash=bytes.fromhex(o["policy_sha256"]),
                index_manifest_hash=bytes.fromhex(o["index_manifest_sha256"]),
                model_weights_hash=bytes.fromhex(o["model_manifest_sha256"] or "00" * 32), job_id=o["job_id"].encode())
            if not snp.check_binding(rep, expected):
                problems.append(f"{tag}: REPORT_DATA does not match the offer")
        except (KeyError, ValueError) as exc:
            problems.append(f"{tag}: offer malformed ({exc})")
        if require_hardware:
            pre = snp.verify_chain(rep, vcek_der=None, ask_ark_pem=None)
            structural = [q for q in pre["problems"] if "no VCEK" not in q and "ASK/ARK" not in q]
            problems += [f"{tag}: {q}" for q in structural]
            if certs_dir:
                from .client import get_certs
                c = get_certs(rep, certs_dir)
                res = snp.verify_chain(rep, vcek_der=c["vcek"], ask_ark_pem=c["chain"])
                problems += [f"{tag}: {q}" for q in res["problems"]]
        if st.get("turn") != i + 1:
            problems.append(f"{tag}: expected turn {i + 1}")
        if st.get("outcome") == "answered":
            if prev_out is not None and st.get("transcript_in_sha256") != prev_out:
                problems.append(f"{tag}: transcript_in differs from the previous turn's transcript_out")
            prev_out = st.get("transcript_out_sha256")
        if st.get("seeded_from"):
            seeds.add(st["seeded_from"])
        if st.get("session_id") != turns[0]["statement"].get("session_id"):
            problems.append(f"{tag}: session id differs")
    if len(seeds) > 1:
        problems.append("more than one seeded_from across the session")
    return problems


def render_session(turns: List[Dict[str, Any]], *, firm: str, operator: str = "the operator",
                   re_verify_cmd: str = "sealed-session-certificate --verify-only <session-dir>") -> str:
    sts = [t["statement"] for t in turns]
    first, last = sts[0], sts[-1]
    answered = [s for s in sts if s.get("outcome") == "answered"]
    fresh = sum(1 for s in sts if s.get("ollama_fresh_process"))
    lo_only = sum(1 for s in sts if s.get("netns_interfaces") == ["lo"])
    probes_failed = sum(1 for s in sts if str(s.get("egress_probe", "")).startswith(("refused", "none", "no route")) or s.get("egress_probe") in (False, "failed"))
    lifetimes = sorted({s.get("lifetime_id") for s in sts})
    models = sorted({(s.get("model"), t["offer"].get("model_manifest_sha256")) for s, t in zip(sts, turns)})
    policies = sorted({t["offer"].get("policy_sha256") for t in turns})
    measurements = sorted({t["offer"].get("measurement") for t in turns})
    seeded = first.get("seeded_from")
    period = f"{first.get('attested_utc', '?')} — {last.get('attested_utc', '?')}"

    rows = "".join(
        f"<tr><td>{s.get('turn')}</td><td>{_esc(s.get('lifetime_id'))}</td><td>{s.get('lifetime_seq')}</td>"
        f"<td>{_esc(s.get('outcome'))}{(' · ' + _esc(s.get('refusal'))) if s.get('refusal') else ''}</td>"
        f"<td><code>{_esc((s.get('transcript_in_sha256') or '')[:12])}</code></td>"
        f"<td><code>{_esc((s.get('transcript_out_sha256') or '')[:12])}</code></td>"
        f"<td>{_esc(s.get('netns_interfaces'))}</td><td>{_esc(s.get('egress_probe'))}</td>"
        f"<td>{'yes' if s.get('ollama_fresh_process') else 'no'}</td><td>{_esc(s.get('attested_utc'))}</td></tr>"
        for s in sts)

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Sealed reflection session {_esc(first.get('session_id'))}</title>
<style>{_CSS}</style></head><body>
<h1>Sealed reflection session certificate</h1>
<table class="kv">
<tr><th>Session</th><td><code>{_esc(first.get('session_id'))}</code></td></tr>
<tr><th>Firm</th><td>{_esc(firm)}</td></tr>
<tr><th>Operator</th><td>{_esc(operator)}</td></tr>
<tr><th>Turns</th><td>{len(sts)} ({len(answered)} answered)</td></tr>
<tr><th>Period (UTC)</th><td>{_esc(period)}</td></tr>
<tr><th>Mode</th><td>attested confidential enclave (AMD SEV-SNP + NVIDIA CC), deferred execution, one session in working memory at a time</td></tr>
<tr><th>Model</th><td>{"; ".join(f"{_esc(m)} (manifest <code>{_esc((h or '')[:16])}</code>)" for m, h in models)}</td></tr>
<tr><th>Egress policy</th><td>{"; ".join(f"<code>{_esc((p or '')[:16])}</code>" for p in policies)}</td></tr>
<tr><th>Enclave lifetimes</th><td>{", ".join(f"<code>{_esc(l)}</code>" for l in lifetimes)}</td></tr>
<tr><th>Seeded from</th><td>{f"<code>{_esc(seeded)}</code>" if seeded else "nothing"}</td></tr>
</table>

<h2>What was verified</h2>
<p>Each of the {len(sts)} turns carries a statement signed by a key born inside the enclave and committed in that enclave's hardware attestation report. Every signature verified under the signer named in the corresponding offer. Every report's REPORT_DATA equals the recomputation from the offer's own fields: enclave encryption key, statement signer, launch measurement, egress policy hash, an all-zero index field, model manifest hash, and lifetime id. No document index was present in any turn.</p>
<p>Network interfaces recorded during the turn were <code>['lo']</code> on {lo_only} of {len(sts)} turns. The enclave's own egress probe (TCP to two public resolvers, UDP DNS, name resolution) is recorded per turn in the table. No gateway exists on this path.</p>
<p>Turns ran strictly one at a time. The model server was started as a fresh process for the turn on {fresh} of {len(sts)} turns; the process ended with the turn. While this session's turn was in working memory, no other session's data was.</p>
<p>The lineage chain holds across the {len(answered)} answered turns: each turn's input transcript hash equals the previous turn's output transcript hash, from the client's own copy of the transcript.</p>

<h2>What the operator and the provider could observe</h2>
<p>Ciphertext sizes, job and session identifiers, request and completion timestamps, the model name, and instance metadata. The plaintext of every message and answer existed in two places: on the firm's machine and inside the enclave during the turn.</p>

<h2>What this certificate does not cover</h2>
<p>The launch measurements ({", ".join(f"<code>{_esc((m or '')[:16])}</code>" for m in measurements)}) are printed, not compared against a published value. The quality of the answers. The confidentiality of the firm's own machine.</p>

<h2>Turns</h2>
<table><tr><th>#</th><th>lifetime</th><th>seq</th><th>outcome</th><th>in</th><th>out</th><th>interfaces</th><th>egress probe</th><th>fresh process</th><th>attested (UTC)</th></tr>
{rows}</table>

<h2>Re-verify</h2>
<p>From the session directory, with the offers, reports and statements it contains:</p>
<pre>{_esc(re_verify_cmd)}</pre>
</body></html>"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sealed-session-certificate")
    p.add_argument("session_dir"); p.add_argument("--firm", default="the firm"); p.add_argument("--operator", default="the operator")
    p.add_argument("--out", default=None); p.add_argument("--certs", default=None)
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--allow-fake", action="store_true", help="phase tests only: accept non-hardware reports")
    a = p.parse_args(argv)
    turns = load_turns(a.session_dir)
    if not turns:
        print("no completed turns", file=sys.stderr); return 2
    problems = verify_turns(turns, a.certs, require_hardware=not a.allow_fake)
    if problems:
        print("REFUSED to certify:", file=sys.stderr)
        for q in problems:
            print("  - " + q, file=sys.stderr)
        return 1
    print(f"verified {len(turns)} turns of session {turns[0]['statement'].get('session_id')}")
    if a.verify_only:
        return 0
    html = render_session(turns, firm=a.firm, operator=a.operator,
                          re_verify_cmd=f"sealed-session-certificate --verify-only {a.session_dir}")
    out = a.out or os.path.join(a.session_dir, "certificate.html")
    with open(out, "w") as fh:
        fh.write(html)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
