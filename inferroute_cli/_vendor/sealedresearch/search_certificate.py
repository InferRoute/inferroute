"""sealed-search-certificate — one HTML document per sealed search, rendered only from what was verified:
the signed statement, the offer it answers, the report beside that offer, and the index manifest whose
hash the hardware committed to.

Facts only. No sentence explains why a limit exists; each limit is stated. The claim boundary appears
verbatim. The words "coverage" and "absence" appear only where the corresponding fact is stated, and
never within reach of a causal clause (tests/test_report_prose.py guards this)."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .certificate import _CSS, _esc


def _comp_rows(manifest: Optional[Dict[str, Any]]) -> str:
    if not manifest:
        return "<tr><td colspan=3>manifest not shipped with this result</td></tr>"
    by: Dict[str, Dict[str, int]] = {}
    for s in manifest.get("shards", []):
        c = s["path"].split("/")[0] if not s["path"].startswith("models/") else "/".join(s["path"].split("/")[:2])
        d = by.setdefault(c, {"files": 0, "bytes": 0}); d["files"] += 1; d["bytes"] += s.get("bytes", 0)
    return "".join(f"<tr><td><code>{_esc(c)}</code></td><td>{v['files']}</td><td>{v['bytes']/2**30:.1f} GB</td></tr>" for c, v in sorted(by.items()))


def render_search(st: Dict[str, Any], offer: Dict[str, Any], manifest: Optional[Dict[str, Any]], *, firm: str,
                  operator: str = "the operator", re_verify_cmd: str = "sealed-client search --collect --job <job> --outbox <dir> --firm-priv <key>") -> str:
    can = st.get("canary") or []
    g = sum(c["gold_n"] for c in can); f100 = sum(c["found_100"] for c in can); f1000 = sum(c["found_1000"] for c in can)
    cal = st.get("calibration") or {}
    legs = st.get("legs") or {}
    leg_rows = "".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in legs.items())
    can_rows = "".join(f"<tr><td><code>{_esc(c['id'])}</code></td><td>{c['gold_n']}</td><td>{c['found_100']}</td><td>{c['found_1000']}</td></tr>" for c in can)
    cutoff = st.get("cutoff_date")
    cutoff_s = f"{str(cutoff)[:4]}-{str(cutoff)[4:6]}-{str(cutoff)[6:]}" if cutoff else "none given"
    pap = st.get("calibration_papers") or {}
    cal_s = (f"In the public examiner-citation benchmark for this pipeline version, area <b>{_esc(cal.get('area'))}</b> "
             f"(n={cal.get('n')}): {cal.get('recall_100', 0):.0%} of examiner-cited patents appear within the top 100 and "
             f"{cal.get('recall_1000', 0):.0%} within the top 1000.") if cal else "No calibration table was present for the predicted area."
    if pap:
        cal_s += (f" For the scientific-literature leg, measured on held-out queries with each query's own citations removed "
                  f"(n={pap.get('n')}): {pap.get('recall_100', 0):.1%} within the top 100 and {pap.get('recall_1000', 0):.1%} within the top 1000.")
    outcome = st.get("outcome"); pc = st.get("paper_coverage") or {}
    und = st.get("undated_hits") or 0
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Sealed search {_esc(st.get('job_id'))}</title>
<style>{_CSS}</style></head><body>
<h1>Sealed prior-art search certificate</h1>
<table class="kv">
<tr><th>Job</th><td><code>{_esc(st.get('job_id'))}</code></td></tr>
<tr><th>Firm</th><td>{_esc(firm)}</td></tr>
<tr><th>Operator</th><td>{_esc(operator)}</td></tr>
<tr><th>Outcome</th><td>{_esc(outcome)}{(' · ' + _esc(st.get('refusal'))) if st.get('refusal') else ''}</td></tr>
<tr><th>Started / finished (UTC)</th><td>{_esc(st.get('started_utc'))} / {_esc(st.get('finished_utc'))}</td></tr>
<tr><th>Mode</th><td>attested confidential enclave (AMD SEV-SNP + NVIDIA CC), network namespace closed, one job in working memory at a time</td></tr>
<tr><th>Index</th><td><code>{_esc(st.get('index_snapshot'))}</code> — manifest <code>{_esc((st.get('index_manifest_sha256') or '')[:16])}</code>, verified in full at offer time</td></tr>
<tr><th>Encoders</th><td>manifest <code>{_esc((st.get('model_manifest_sha256') or '')[:16])}</code></td></tr>
<tr><th>Pipeline</th><td><code>{_esc(st.get('pipeline_version'))}</code></td></tr>
<tr><th>Date cutoff</th><td>{_esc(cutoff_s)}</td></tr>
<tr><th>Query</th><td>sha256 <code>{_esc((st.get('query_sha256') or '')[:16])}</code> (the text exists on the firm's machine and, during the job, inside the enclave)</td></tr>
</table>

<h2>What was verified</h2>
<p>The statement carries a signature by a key born inside the enclave and committed in that enclave's hardware attestation report. The signature verified under the signer named in the offer. The report's REPORT_DATA equals the recomputation from the offer's own fields: enclave encryption key, statement signer, launch measurement, egress policy hash, index manifest hash, encoder manifest hash, and job id. The index manifest shipped with the result hashes to the value in REPORT_DATA.</p>
<p>Network interfaces recorded during the job: <code>{_esc(st.get('netns_interfaces'))}</code>. Egress probe (TCP to two public resolvers, UDP DNS, name resolution): <code>{_esc(st.get('egress_probe'))}</code>. No gateway exists on this path.</p>

<h2>What was searched</h2>
<table><tr><th>component</th><th>files</th><th>size</th></tr>{_comp_rows(manifest)}</table>
<p>Every file above is listed by path, size and hash in the manifest; the manifest's own hash is the one committed in hardware. A re-run of <code>sealed-index-verify</code> against the volume reproduces that hash or lists what changed.</p>
{f"<p>The corpus-wide paper leg holds vectors for {pc.get('dense_rows', 0):,} of {pc.get('corpus_rows', 0):,} works ({pc.get('dense_coverage', 0):.1%}); the remainder is reachable through the curated store and the classification pool only.</p>" if pc else ""}

<h2>How it was searched</h2>
<table><tr><th>leg</th><th>candidates</th></tr>{leg_rows}<tr><td>total distinct</td><td>{st.get('candidates_total')}</td></tr></table>
<p>Predicted classification: <code>{_esc(' '.join(st.get('cpc_predicted') or []))}</code>. Documents dated on or after the cutoff were excluded where the index holds a date: patents by publication date, papers in the curated store by year. Papers surfaced from the corpus-wide leg carry no date in this index and are marked as undated in the result ({und} of the {st.get('hits_n')} hits returned). Hits are returned per source — up to {st.get('k')} papers and up to {st.get('k')} patents, interleaved by rank — so the calibrated yield below applies at the depth shown for that source. Each hit carries the legs that surfaced it.</p>

<h2>Control lane</h2>
<p>{len(can)} public queries with known examiner-cited art ran in the same process, on the same index, immediately before the firm's query. Of their {g} known citations, {f100} appeared within the top 100 and {f1000} within the top 1000 in this run.</p>
<table><tr><th>canary</th><th>known citations</th><th>in top 100</th><th>in top 1000</th></tr>{can_rows}</table>

<h2>Calibrated yield</h2>
<p>{cal_s} The benchmark set, the harness and the expected numbers are published; the table's hash in this run is <code>{_esc((st.get('calibration_sha256') or '')[:16])}</code>.</p>

<h2>What is returned</h2>
<p>Each hit carries its identifier, title, date where the index holds one, score, and the legs that surfaced it. Patent abstracts are reproduced; they are government publications. For scientific papers this search returned identifier, title and date. The ranking was computed over the full abstract text in both cases, and each identifier resolves to the publisher's own copy.</p>

<h2>Claim boundary</h2>
<p>This search <b>{_esc(st.get('claim_boundary'))}</b>.</p>

<h2>What the operator and the provider could observe</h2>
<p>Ciphertext sizes, the job identifier, request and completion timestamps, candidate counts, and instance metadata. The disclosure and the hit list existed in two places: on the firm's machine and inside the enclave during the job.</p>

<h2>What this certificate does not cover</h2>
<p>The launch measurement (<code>{_esc((st.get('measurement') or '')[:16])}</code>) is printed, not compared against a published value. Relevance of any individual hit. Art outside the components listed above. The confidentiality of the firm's own machine.</p>

<h2>Re-verify</h2>
<pre>{_esc(re_verify_cmd)}</pre>
</body></html>"""
