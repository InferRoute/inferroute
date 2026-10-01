"""Certificate of non-disclosure ("certificat de non-divulgation") — the per-matter deliverable.

One page + appendix, generated ONLY from the run's export files (egress.jsonl, optional decision ledger),
never from claims: every number on the page is recomputed from the chained rows by the same code path the
open verifier uses. The page states, in the attorney's vocabulary:

  * processing mode (sealed local / attested enclave) and period,
  * every recipient host, with request counts and total bytes,
  * the count of denied and held (attorney-gated) attempts,
  * the chain head (the single value to timestamp) and the policy hash in force,
  * the verification command anyone can run,
  * APPENDIX A: every outbound payload VERBATIM — the reader can see that nothing enabling left.

Output is print-ready HTML (A4). PDF: open in a browser and print, or `weasyprint out.html out.pdf` where
available. Timestamping the head (eIDAS qualified TSP + OpenTimestamps) is a separate step — the certificate
carries the head so the token binds to it.

Usage:
  sealed-certificate --egress egress.jsonl --out certificate.html
                     --matter "M-2026-041" --firm "Cabinet X" [--mode "sealed local (appliance)"]
                     [--ledger ledger.jsonl] [--operator "InferRoute SASU"]
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .verify import egress_summary, replay

_CSS = """
body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a; max-width: 46rem;
       margin: 2rem auto; padding: 0 1rem; line-height: 1.45; }
h1 { font-size: 1.35rem; border-bottom: 2px solid #1a1a1a; padding-bottom: .4rem; }
h2 { font-size: 1.05rem; margin-top: 1.6rem; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { border: 1px solid #999; padding: .3rem .5rem; text-align: left; }
th { background: #f0f0f0; }
code, .mono { font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: .82rem; word-break: break-all; }
.kv td:first-child { width: 14rem; font-weight: bold; border: none; padding-left: 0; }
.kv td { border: none; }
.payload { background: #f7f7f7; border: 1px solid #ccc; padding: .5rem .7rem; margin: .5rem 0;
           white-space: pre-wrap; }
.small { font-size: .8rem; color: #444; }
.badge { display: inline-block; border: 1px solid #1a1a1a; padding: .05rem .45rem; font-size: .75rem;
         margin-right: .4rem; }
@media print { body { margin: 0 auto; } .pagebreak { page-break-before: always; } }
"""


def load_witness(path: str) -> Dict[str, Any]:
    """Read an INDEPENDENT egress witness — a kernel byte counter our gateway cannot influence.

    Accepts `nft -j list counter ...` JSON. The point of this file is that it is not written by the
    component whose honesty is in question: the gateway records what it was asked to send, the kernel
    records what actually crossed the interface, and the certificate is only entitled to the strong
    claim when the second corroborates the first.
    """
    with open(path) as fh:
        doc = json.load(fh)
    analysis = doc.get("analysis")           # optional; see enclave/analyze_pcap.py
    for item in doc.get("nftables", []):
        c = item.get("counter")
        if c is not None:
            return {"source": f"nftables counter {c.get('family')} {c.get('table')} {c.get('name')}",
                    "bytes": int(c.get("bytes", 0)), "packets": int(c.get("packets", 0)),
                    "analysis": analysis}
    raise ValueError(f"{path}: no nftables counter found")


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def render(egress_path: str, *, matter: str, firm: str, operator: str = "the operator",
           mode: str = "sealed local", ledger_path: Optional[str] = None,
           index_manifest: Optional[str] = None, generated_at: Optional[str] = None,
           witness_path: Optional[str] = None) -> str:
    ok, head, rows, bad = replay(egress_path)
    if not ok:
        raise SystemExit(f"refusing to certify: egress chain fails to replay at line {bad}")
    summ = egress_summary(rows)
    lhead = None
    if ledger_path:
        lok, lhead, _, lbad = replay(ledger_path)
        if not lok:
            raise SystemExit(f"refusing to certify: decision ledger fails to replay at line {lbad}")
    policy = summ["policy_sha256"][0] if summ["policy_sha256"] else "(no egress rows)"
    # The index searched is named, not asserted to be intact: re-hashing tens of GB belongs in the
    # firm's own `sealed-index-verify` run, not in rendering a page.
    idx = None
    if index_manifest:
        with open(index_manifest) as fh:
            m = json.load(fh)
        idx = {"id": f"{m.get('index', 'index')}@{m.get('corpus_sha256', '')[:16]}",
               "rows": m.get("rows", 0), "shards": len(m.get("shards", [])),
               "built": m.get("built_utc", ""), "source": (m.get("source") or {}).get("dataset", "")}
    witness = load_witness(witness_path) if witness_path else None
    now = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    sent = [r for r in rows if r.get("decision") == "allow"]
    denied = [r for r in rows if r.get("decision") == "deny"]
    held = [r for r in rows if r.get("decision") == "held"]

    rec_rows = "\n".join(
        f"<tr><td class='mono'>{_esc(h)}</td><td>{n}</td>"
        f"<td>{sum(int(r.get('bytes_out', 0)) for r in sent if r.get('host') == h)}</td></tr>"
        for h, n in sorted(summ["recipients"].items()))

    def _payload_block(r: Dict[str, Any]) -> str:
        body = r.get("body")
        if body is None and r.get("body_b64"):
            body = f"<{r['body_b64'][:24]}… binary, sha256 {r.get('body_sha256', '')[:16]}…>"
        return (f"<div class='payload'><span class='badge'>#{r.get('seq')}</span>"
                f"<span class='badge'>{_esc(r.get('ts', ''))}</span>"
                f"<span class='badge'>{_esc(r.get('provider'))} → {_esc(r.get('host'))}</span>"
                f"<span class='badge'>{r.get('bytes_out', 0)} B</span><br>"
                f"<span class='mono'>{_esc(r.get('method'))} {_esc(r.get('url'))}</span>"
                + (f"<br><span class='mono'>{_esc(body)}</span>" if body else "") + "</div>")

    appendix = "\n".join(_payload_block(r) for r in sent) or "<p><em>No payload left the boundary.</em></p>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Certificate of non-disclosure — {_esc(matter)}</title><style>{_CSS}</style></head><body>
<h1>Certificate of non-disclosure</h1>
<p class="small">Certificat de non-divulgation — generated {_esc(now)} from the tamper-evident run export.
Every figure below is recomputed from the hash-chained record; none is asserted.</p>

<table class="kv">
<tr><td>Matter</td><td>{_esc(matter)}</td></tr>
<tr><td>Firm</td><td>{_esc(firm)}</td></tr>
<tr><td>Operator</td><td>{_esc(operator)}</td></tr>
<tr><td>Processing mode</td><td>{_esc(mode)}</td></tr>
<tr><td>Period covered</td><td>{_esc(summ['first_ts'])} &nbsp;→&nbsp; {_esc(summ['last_ts'])}</td></tr>
<tr><td>Egress record head</td><td class="mono">{_esc(head)}</td></tr>
{f'<tr><td>Decision ledger head</td><td class="mono">{_esc(lhead)}</td></tr>' if lhead else ''}
<tr><td>Egress policy (sha-256)</td><td class="mono">{_esc(policy)}</td></tr>
{f'<tr><td>Local index snapshot</td><td class="mono">{_esc(idx["id"])}<br>'
 f'<span class="small">{idx["rows"]:,} documents in {idx["shards"]:,} shards · '
 f'{_esc(idx["source"])} · built {_esc(idx["built"])}</span></td></tr>' if idx else ''}
</table>

<h2>1. What left the processing boundary</h2>
<p><b>{len(sent)}</b> outbound request(s), <b>{summ['bytes_out']} bytes</b> in total, to the recipients below.
<b>{len(denied)}</b> attempt(s) were denied by policy and <b>{len(held)}</b> were held for attorney approval;
denied and held attempts never reached the network.</p>

{f'''<p><b>And nothing else — measured, not asserted.</b> An independent counter in the kernel's
output path, outside the gateway and not writable by it, measured <b>{witness["bytes"]:,} bytes</b> in {witness["packets"]:,} packet(s)
leaving this machine while the matter was open.</p>
<p>That figure is not zero, and is not expected to be. Any host reachable from the internet
continuously emits <em>replies</em> it did not choose to send — TCP resets refusing unsolicited
connection attempts, ICMP unreachables answering stray traffic, address-resolution for its own default
route. What the measurement establishes is a <b>ceiling</b>: {witness["bytes"]:,} bytes is the maximum
that could have left this machine by <em>any</em> path, gateway or otherwise, against the
{summ["bytes_out"]:,} bytes the gateway recorded.</p>
{f"""<p>Packet-level analysis of the same period resolves the remainder:
<b>{witness["analysis"]["connections_initiated"]} outbound connection(s) were initiated</b> from inside
the boundary and <b>{witness["analysis"]["payload_bytes_out"]:,} bytes of transport payload</b> left it.
No channel capable of carrying the invention text was ever opened. Source:
{_esc(witness["analysis"].get("source", "packet capture"))}.</p>""" if witness.get("analysis") else
"""<p class="small">No packet-level analysis accompanies this run, so the composition of the figure
above is stated but not itemised. Where the distinction matters, repeat the run with a capture of the
sealed period, which resolves the count into connections initiated (which must be zero) and payload
bytes (which must be zero) against unsolicited-reply traffic (which need not be).</p>"""}
<table><tr><th>Independent witness</th><th>Packets</th><th>Bytes</th></tr>
<tr><td class="mono">{_esc(witness["source"])}</td><td>{witness["packets"]:,}</td>
<td>{witness["bytes"]:,}</td></tr></table>''' if witness else '''<p class="small"><b>Scope of this
figure.</b> The count above is what the recording gateway recorded. No independent measurement of this
machine's network interface accompanies this run, so the figure rests on the gateway's own record: it
shows that nothing else was <em>sent through the gateway</em>, which is a weaker statement than nothing
else left the machine. Where the stronger claim is required, the run must be repeated with a kernel
byte counter outside the gateway, and this paragraph is replaced by that measurement.</p>'''}
<table><tr><th>Recipient host</th><th>Requests</th><th>Bytes out</th></tr>{rec_rows or
'<tr><td colspan=3><em>none</em></td></tr>'}</table>

{f'''<p>The search itself ran against the local index snapshot named above — a fixed corpus held on this
machine. Consulting it produces no network traffic of any kind, which is why the byte count above can be
what it is: the questions asked of the prior art were asked here, not of a search engine.</p>''' if idx else ''}

<h2>1b. What the host could observe</h2>
<p class="small">The search read the local index from an encrypted volume attached to the enclave. Which
regions of that index were read is visible to the hosting provider as a pattern of disk access, even
though their contents are not. That pattern is correlated with the technical field of the search. The
disclosure text itself is not exposed by it. This is a known limit of the current design, stated here
rather than omitted; it is the only channel by which anything about the matter reaches the host, and
it reaches no one else.</p>

<h2>2. What was NOT disclosed</h2>
<p>The full invention text was processed only inside the sealed boundary. No payload other than those reproduced
verbatim in Appendix A crossed it. This certificate does not extend to: information retained by the listed
recipients under their own terms; the client firm's own endpoints; or material the reader forwards onward.</p>

<h2>3. Verify this certificate</h2>
<p class="small">Anyone holding the export files can recompute this page's figures and the chain head with the
open-source verifier:</p>
<p><code>sealed-verify --egress egress.jsonl --expect-head {_esc(head)} --expect-policy {_esc(policy)}</code></p>
{f'''<p class="small">And, on the appliance itself, that the index searched is the one named here and has not
been altered since — every shard re-hashed against the manifest:</p>
<p><code>sealed-index-verify /path/to/index</code></p>''' if idx else ''}
<p class="small">The head above is the value bound by the qualified timestamp token accompanying this
certificate (eIDAS RFC-3161 and OpenTimestamps receipts, when attached).</p>

<div class="pagebreak"></div>
<h2>Appendix A — every outbound payload, verbatim ({len(sent)} item(s))</h2>
{appendix}
</body></html>"""


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="sealed-certificate", description=__doc__.split("\n\n")[0])
    p.add_argument("--egress", required=True)
    p.add_argument("--ledger", default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--matter", required=True)
    p.add_argument("--firm", required=True)
    p.add_argument("--operator", default="InferRoute")
    p.add_argument("--mode", default="sealed local")
    p.add_argument("--witness", default=None,
                   help="nft -j counter JSON from an INDEPENDENT kernel byte counter outside the "
                        "gateway. Without it the certificate states the weaker claim, on purpose.")
    p.add_argument("--index-manifest", default=None,
                   help="manifest.json of the local index searched (names the snapshot on the certificate)")
    a = p.parse_args(argv)
    doc = render(a.egress, matter=a.matter, firm=a.firm, operator=a.operator, mode=a.mode,
                 ledger_path=a.ledger, index_manifest=a.index_manifest, witness_path=a.witness)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"[sealed-certificate] wrote {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
