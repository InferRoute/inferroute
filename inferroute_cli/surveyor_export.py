"""`ir surveyor export` — the one-directory record an attorney hands a client, built so that its claims can
be RE-DERIVED by a stranger from the bundle alone, with no InferRoute code and no trust in this machine.

    <matter>-prior-art-record-<stamp>/
      record.html            the human record: matter, disclosure, marks, sessions, reports, statements
      searches.json          the machine record: per sealed search — signed statement, opened result,
                             query text, date bound, and the evidence file it names (by sha256)
      <sha16>.evidence.json  per search: the attestation evidence the local verifier used (SNP report,
                             AMD endorsements, Microsoft UVM endorsement, runtime_data, container policy)
      MANIFEST.json          sha256 of every file above, plus the matter's date bound
      verify_record.py       a single-file independent verifier (stdlib + `cryptography` only)
      VERIFY.md              how to redo every check, here and with AMD's / Google's / Microsoft's own tools
      MANIFEST.json.ots      (optional, --anchor) an OpenTimestamps proof of when this manifest existed

Every claim in record.html that a third party CAN check has its inputs in the bundle; every claim that
cannot be checked from the bundle says so (the device's own confinement is self-reported; the model lane's
limitations are the receipt's own words). An overclaimed proof is a weak proof.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_EXPOSURE_WORD = {
    "this_session": "surfaced by this session's search",
    "earlier_session": "surfaced by an earlier session's search",
    "not_surfaced": "not surfaced by any search on this matter",
    "unknown_prior": "not in this session's results (earlier sessions not consulted)",
}

VERIFY_MD = """# How to verify this record

This bundle is self-contained: nothing below needs InferRoute, this attorney's machine, or the internet,
except the ONE thing that establishes identity (step 3), which by design must come from outside the bundle.
The `verify_record.py` and `sha256sum` commands below are run, in the exporter's own test suite, on a
bundle the exporter produced; `ots` needs the opentimestamps-client and is not exercised there. `python3`
3.9+ and the `cryptography` package (>= 42) are the only requirements for the verifier.

## 1. Run the bundled verifier

    python3 verify_record.py . --reference reference.json

One line per check (PASS / FAIL / SKIP with the reason). Exit 0 only if EVERY check passed under production
roots; 1 if any failed (including "no reference" and "no sealed searches"); 2 if refused (bad flags, old
library); 3 if it passed but under test roots. The file is short on purpose — read it before trusting it.

## 2. Bundle integrity (an index, not a seal)

`MANIFEST.json` lists the SHA-256 of every file and `SHA256SUMS` repeats them in coreutils form:

    sha256sum -c SHA256SUMS

Both are UNSIGNED. They let you see that a file changed after export; they cannot show the export was
honest. The seal is the enclave-signed statement inside each search. If `MANIFEST.json.ots` is present:

    ots verify MANIFEST.json.ots

proves the manifest existed no later than the Bitcoin block it is anchored in (OpenTimestamps, open source).

## 3. IDENTITY — the step that separates InferRoute's enclave from anyone's Azure container

A SEV-SNP report and Microsoft's endorsement prove that SOME confidential container ran on a genuine AMD
chip inside Microsoft's utility VM. Anyone with an Azure account can produce such a bundle with their own
key, their own statement over any text, and their own policy. The MEASUREMENT endorses Microsoft's utility
VM, not our container. What identifies InferRoute's enclave is the container-policy hash (HOST_DATA) and the
index / encoder manifest hashes — and they mean nothing unless compared against values you obtained from
InferRoute INDEPENDENTLY of this bundle:

    reference.json  =  {"policy_sha256": [...], "index_manifest_sha256": [...], "model_manifest_sha256": [...],
                        "source": "<where you got it>", "published_at": "...", "sig": "<optional, see below>"}

Each entry is either a bare hash or `{"value": "...", "valid_from": "YYYY-MM-DDTHH:MM:SSZ",
"valid_to": "...", "retired": false}`. Times are ISO-8601 and compared as times (offsets honoured, a
trailing Z normalised, naive taken as UTC). A record whose search matched an entry that was retired, or
outside its window at the search's signed time, FAILS identity — and so does a windowed match when the
statement carries no parsable time, rather than the window going silent. The verifier says which entry
matched and why.
That is how a policy later withdrawn cannot pass as current, and how the enclave changing over a long
matter is spoken about precisely.

**How to obtain the reference so that it means something.** A page served by InferRoute at the moment you
verify is the weakest form: you would be trusting InferRoute again, just later. Do this instead:
1. Take the reference values (and InferRoute's publication key) from your engagement letter or a signed
   release note, and RECORD them in your own file at first use.
2. Verify every later record against your own first copy: `--reference your-copy.json`.
3. If the reference is signed, pass the publication key you recorded once: `--reference-key <hex>`. Later
   reference updates signed by that key can then be accepted without re-establishing trust.

`MANIFEST.json` → `reference_hint` records what THIS machine was configured to expect at session time. It is
a convenience, not authority: it came from the same machine as the bundle. Until you pass a reference you
obtained independently, the verifier FAILS identity.

## 4. What each check re-derives (the bytes, by file)

`searches.json` holds one entry per sealed search: `statement` (with `sig`), `result`, `query_text`,
`signer_pub`, and `evidence_file`. That evidence file is JSON: `offer.evidence` (base64 of the 1184-byte
SEV-SNP report), `offer.endorsements` (base64 PEM: VCEK, ASK, ARK), `offer.uvm_endorsements` (base64
COSE_Sign1), `offer.runtime_data` (base64 JSON), and `policy_b64` (a sibling of `offer`, when archived).

* **Statement signature** — Ed25519 over the canonical JSON of `statement` (keys sorted, no spaces,
  `sig` removed) under `signer_pub`.
* **Signer is hardware-bound** — `signer_pub` == `statement_signer_pub` inside `runtime_data`, and the
  report's `REPORT_DATA` (bytes 0x50..0x90) == SHA-256(runtime_data bytes) ‖ 32 zero bytes.
* **AMD chain** — report signed (ECDSA P-384, R/S little-endian at 0x2A0) under the VCEK; VCEK ← ASK ← ARK;
  ARK SPKI SHA-256 == AMD's published root for the product (printed with the KDS URL — compare it yourself);
  VCEK hwID and TCB match the report; VMPL 0; debug off; AMD certificate dates enforced.
* **Utility VM** — COSE_Sign1 PS384 under its x5chain; chain root == Microsoft Supply Chain RSA Root CA 2022
  (printed); payload launch measurement == report `MEASUREMENT` (0x90..0xC0).
* **Policy consistency** — SHA-256(base64-decoded `policy_b64`) == report `HOST_DATA` (0xC0..0xE0). This is
  agreement within the bundle; identity is step 3.
* **Query / result** — `query_sha256` == SHA-256(request_id ‖ canonical(query_text)); `result_sha256` ==
  SHA-256(request_id ‖ canonical(result)); `hits_n` == number of hits; the signed `cutoff_date` is the date
  bound the enclave was given (the manifest's value is the record's unsigned claim about the matter).

## 5. Independent tools

    python3 verify_record.py . --extract raw/

writes, per search, `raw/search-N/report.bin`, `vcek.pem`, `ask_ark.pem`, `uvm_endorsement.cose`,
`runtime_data.json`, `policy.rego`, `statement.json` — the exact bytes the checks above consume, as files.
These tools consume the same bytes: AMD's `snpguest` (github.com/virtee/snpguest) and Google's
`go-sev-guest` (github.com/google/go-sev-guest) for the report and certificate chain; `go-cose` or
`pycose` for the COSE endorsement; `az confcom acipolicygen` to regenerate a policy from a container image
and compare its hash. We have NOT run those invocations on this bundle here; we make no claim about their
exact command lines, only that the extracted files are their inputs.

## 6. What this bundle cannot prove

* That this attorney's own machine was confined while the session ran (the device's self-report, stated per
  session in `record.html`).
* Anything about the model lane beyond the receipt's own listed checks and limitations, reproduced verbatim.
* That the record is COMPLETE beyond what it shows: each statement carries a per-enclave sequence number, so
  a search dropped from the middle (or the start) of an enclave's lifetime leaves a visible gap the verifier
  reports — "every search of each enclave SHOWN, in order". A search dropped from the very END of a
  lifetime, or an ENTIRE enclave lifetime dropped from the record, cannot be revealed by any counter; the
  record does not say how many enclaves a matter used.
* Novelty, patentability, or the absence of prior art.
"""


def _e(s: Any) -> str:
    import html
    return html.escape(str(s if s is not None else ""))


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_jsonl(p: Path) -> list:
    rows = []
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows


def _load_sessions(S, client: str, matter: str) -> list:
    rdir = S.records_dir(client, matter)
    sessions = []
    if rdir.is_dir():
        for f in sorted(rdir.glob("*.json")):
            if f.name.endswith(".tmp"):
                continue
            try:
                rec = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            sid = f.stem
            sessions.append({"session_id": sid, "record": rec, "searches": _read_jsonl(rdir / f"{sid}.searches.jsonl")})
    return sessions


# ───────────────────────────── the bundle ─────────────────────────────


def build_bundle(client: str, matter: str) -> Dict[str, Any]:
    """Assemble everything: the HTML, the machine record, and the evidence files, from host-held files.
    Returns {"html": str, "searches": list, "evidence": {sha: json_str}, "matter_cutoff": int|None}."""
    from . import surveyor as S
    rec = S.load_record(client, matter)
    ws = Path(rec["workspace"])
    try:
        state = json.loads(S.state_path(client, matter).read_text())
    except (OSError, ValueError):
        state = {}
    sessions = _load_sessions(S, client, matter)
    disclosure_md, disclosure_sha, disclosure_mtime = "", "", ""
    dp = ws / "disclosure.md"
    if dp.exists():
        try:
            raw = dp.read_bytes()
            disclosure_md = raw.decode("utf-8", "replace")
            disclosure_sha = _sha256_hex(raw)
            disclosure_mtime = dt.datetime.fromtimestamp(dp.stat().st_mtime, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except OSError:
            pass
    usage = [r for r in _read_jsonl(S.usage_ledger_path()) if r.get("matter") == f"{client}/{matter}"]
    matter_hours = round(sum(float(u.get("hours", 0)) for u in usage if u.get("event") == "stop"), 3)
    try:
        matter_cutoff: Optional[int] = S._to_yyyymmdd(rec["date_bound"])
    except Exception:                                          # noqa: BLE001
        matter_cutoff = None

    evidence: Dict[str, str] = {}
    searches: List[Dict[str, Any]] = []
    out: List[str] = []
    A = out.append
    A("<!doctype html><html lang=en><head><meta charset=utf-8>")
    A(f"<title>Prior-art record — {_e(client)}/{_e(matter)}</title>")
    A("<style>"
      "body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
      "h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.15rem;border-bottom:2px solid #eee;padding-bottom:.2rem;margin-top:2rem}"
      ".sub{color:#666}table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}"
      "th{background:#f6f6f6}code,pre{font-family:ui-monospace,Menlo,monospace}pre{background:#f6f8fa;padding:.8rem;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}"
      ".ok{color:#127a2b}.warn{color:#b25000;font-weight:600}.bad{color:#b00020;font-weight:600}"
      ".note{color:#666;font-size:13px}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}"
      "</style></head><body>")
    A("<h1>Prior-art research record</h1>")
    A(f"<div class=sub>{_e(client)} / {_e(matter)}</div>")
    A("<p class=note>Every statement below is a fact this device checked or recorded, not a promise. What a stranger "
      "can re-derive from this bundle alone is marked; what only this device attests is marked too. See "
      "<code>VERIFY.md</code> and run <code>verify_record.py</code>.</p>")

    A("<h2>Matter</h2><table>")
    A(f"<tr><th>Date bound (priority date)</th><td>{_e(rec.get('date_bound'))}"
      f"{' <span class=note>(pre-filing default = creation date; not yet set to a real priority date)</span>' if rec.get('pre_filing_default') else ''}</td></tr>")
    A(f"<tr><th>Created</th><td>{_e(rec.get('created_at'))}</td></tr>")
    if rec.get("changes"):
        rows = "".join(f"<li>{_e(c.get('at'))}: date bound {_e(c.get('old'))} → {_e(c.get('new'))}</li>" for c in rec["changes"])
        A(f"<tr><th>Date-bound changes</th><td><ul>{rows}</ul></td></tr>")
    A("</table>")

    A("<h2>Disclosure</h2>")
    A("<p class=note>The workspace file <code>disclosure.md</code> as it stood at export time — an agent-writable "
      "file, not a sealed record. Its content-hash and modification time are given so a later change is detectable. "
      "The text each sealed search actually received is shown per search below and is bound into that search's "
      "signed statement.</p>")
    if disclosure_md:
        A(f"<p class=note>sha256 <span class=mono>{_e(disclosure_sha)}</span> · last modified {_e(disclosure_mtime)}</p>")
    A(f"<pre>{_e(disclosure_md) or '<span class=note>(no disclosure.md in the workspace)</span>'}</pre>")

    A("<h2>Relevance marks</h2>")
    marks = state.get("marks") or {}
    if not marks:
        A("<p class=note>No relevance marks were recorded for this matter.</p>")
    else:
        A("<table><tr><th>Publication</th><th>Mark</th><th>Exposure</th><th>By</th><th>When</th><th>History</th></tr>")
        for k in sorted(marks):
            latest = (marks[k] or {}).get("latest") or {}
            hist = (marks[k] or {}).get("history") or []
            rank = f" (rank {_e(latest.get('rank'))})" if latest.get("rank") else ""
            hist_s = "; ".join(f"{_e(h.get('value'))} @ {_e(h.get('at'))}" for h in hist)
            A(f"<tr><td class=mono>{_e(k)}</td><td>{_e(latest.get('value'))}</td>"
              f"<td>{_e(_EXPOSURE_WORD.get(latest.get('surfaced'), latest.get('surfaced')))}{rank}</td>"
              f"<td>{_e(latest.get('actor'))}</td><td>{_e(latest.get('at'))}</td><td class=note>{hist_s}</td></tr>")
        A("</table>")
        A("<p class=note>Marks are the attorney's own judgements, typed at this machine; the model cannot make one. "
          "'Exposure' records whether this matter's search actually returned the document.</p>")

    A("<h2>Attested sessions</h2>")
    if matter_hours:
        A(f"<p class=note>Search-enclave container time for this matter, across all sessions: <b>{matter_hours} h</b> (host usage ledger).</p>")
    if not sessions:
        A("<p class=note>No attested sessions were recorded for this matter yet.</p>")
    for s in sessions:
        r = s["record"]
        conf = r.get("confinement")
        if not conf:
            conf, conf_cls = "confinement not recorded", "warn"
        else:
            conf_cls = "bad" if "unconfined" in str(conf) else "ok"
        model = r.get("model_lane") or {}
        contract = r.get("contract") or {}
        A(f"<h3>Session <span class=mono>{_e(s['session_id'])}</span></h3><table>")
        A(f"<tr><th>Started</th><td>{_e(r.get('started_at'))}</td></tr>")
        A(f"<tr><th>Confinement</th><td class={conf_cls}>{_e(conf)} <span class=note>(this device's self-report)</span></td></tr>")
        A(f"<tr><th>Contract governing this session</th><td>contract <span class=mono>{_e((contract.get('contract_sha') or '?')[:16])}</span>, "
          f"preamble <span class=mono>{_e((contract.get('preamble_sha') or '?')[:16])}</span>"
          f"{' <span class=warn>— modified from the pinned version</span>' if contract.get('modified') else ''}</td></tr>")
        # Model lane: every check and every limitation, verbatim from the local receipt — not a pass count.
        checks = model.get("check_list") or []
        lims = model.get("limitations") or []
        head = (f"{'yes' if model.get('verified') else 'no'} — {_e(model.get('checks'))}"
                f"{' · ' + _e(model.get('model')) if model.get('model') else ''}"
                f"{' · ' + _e(model.get('sealing')) if model.get('sealing') else ''}")
        rows = "".join(f"<tr><td class={'ok' if c.get('ok') else 'bad'}>{'✓' if c.get('ok') else '✗'}</td>"
                       f"<td>{_e(c.get('label'))}</td><td class=note>{_e(c.get('why'))}</td></tr>" for c in checks)
        lim_rows = "".join(f"<li>{_e(l)}</li>" for l in lims)
        A(f"<tr><th>Model enclave verified</th><td class={'ok' if model.get('verified') else 'bad'}>{head}"
          f"{('<table>' + rows + '</table>') if rows else ' <span class=note>(no per-check list recorded)</span>'}"
          f"{('<p class=note>Not proven, in the receipt&#39;s own words:</p><ul class=note>' + lim_rows + '</ul>') if lim_rows else ''}"
          f"<p class=note>Verified by this device's local sealed endpoint at session time; the evidence for these checks is "
          f"held in that endpoint's receipt on this device, not reproduced in this bundle.</p></td></tr>")
        surf = r.get("which_surface_saw_what") or {}
        if surf:
            srows = "".join(f"<tr><td>{_e(k.replace('_', ' '))}</td><td>{_e(v)}</td></tr>" for k, v in surf.items())
            A(f"<tr><th>Which surface saw what</th><td><table>{srows}</table></td></tr>")
        A("</table>")

    # Per sealed search: the report (the deliverable), the query text, the signed statement, the evidence.
    A("<h2>Sealed searches</h2>")
    n = 0
    for s in sessions:
        for x in s["searches"]:
            stmt = x.get("statement") or {}
            if not stmt.get("sig"):
                continue
            n += 1
            ev = x.get("evidence")
            ev_sha = ev_file = None
            if ev is not None:
                blob = json.dumps(ev, indent=1, ensure_ascii=False).encode("utf-8")
                ev_sha = _sha256_hex(blob)
                ev_file = f"{ev_sha[:16]}.evidence.json"
                evidence[ev_sha] = blob.decode("utf-8")
            searches.append({"n": n, "session_id": s["session_id"], "at": x.get("at"), "statement": stmt,
                             "result": x.get("result"), "query_text": x.get("query_text"),
                             "signer_pub": x.get("signer_pub"), "cutoff_date": x.get("cutoff_date"),
                             "index_snapshot": x.get("index_snapshot"), "measurement": x.get("measurement"),
                             "host_data": x.get("host_data"), "evidence_file": ev_file, "evidence_sha256": ev_sha})
            A(f"<h3>Search {n} — session <span class=mono>{_e(s['session_id'])}</span>, {_e(x.get('at'))}</h3>")
            A(f"<p class=note>Index <span class=mono>{_e(x.get('index_snapshot'))}</span> · date bound {_e(stmt.get('cutoff_date'))} · "
              f"{_e(stmt.get('hits_n'))} hits · utility VM <span class=mono>{_e((x.get('measurement') or '')[:24])}…</span> · "
              f"policy <span class=mono>{_e((x.get('host_data') or '')[:24])}…</span></p>")
            if x.get("query_text") is not None:
                A("<p class=note>The text this search received (bound into the signed statement as "
                  f"<code>query_sha256</code> = SHA-256(request_id ‖ canonical(text))):</p><pre>{_e(x.get('query_text'))}</pre>")
            rp = x.get("report_html")
            if rp:
                A(f'<iframe title="prior-art search report {n}" style="width:100%;height:640px;border:1px solid #ccc;border-radius:6px" '
                  f'sandbox srcdoc="{_e(rp)}"></iframe>')
            else:
                A("<p class=note>No report was rendered for this search.</p>")
            A(f"<p class=note>Enclave-signed statement (Ed25519 over the canonical JSON minus <code>sig</code>, under "
              f"<span class=mono>{_e(x.get('signer_pub'))}</span>, a key the hardware report binds):</p>")
            A(f"<pre>{_e(json.dumps(stmt, indent=1, ensure_ascii=False))}</pre>")
            if ev_file:
                A(f"<p class=note>Attestation evidence: <code>{_e(ev_file)}</code> (sha256 <span class=mono>{_e(ev_sha)}</span>). "
                  "From it alone, without trusting this device: recompute REPORT_DATA = SHA-256(runtime_data) and find "
                  "the signing key committed in it; verify the SEV-SNP report chains to AMD's root and the utility-VM "
                  "endorsement to Microsoft's; check HOST_DATA = SHA-256(the container policy). "
                  "<code>verify_record.py</code> does all of this; <code>VERIFY.md</code> names independent tools that do too.</p>")
            else:
                A("<p class=warn>No attestation evidence was recorded for this search — the signature can be checked but "
                  "not bound to an enclave from this bundle.</p>")
    if n == 0:
        A("<p class=note>No sealed search completed for this matter.</p>")

    A("<h2>What this record does and does not prove</h2>")
    any_policy = any(x.get("evidence", {}).get("policy_b64") for s in sessions for x in s["searches"] if isinstance(x.get("evidence"), dict))
    A("<p class=note><b>Re-derivable by anyone from this bundle</b> (run <code>verify_record.py</code>): that each search "
      "result was signed by a key bound into an AMD SEV-SNP hardware report; that the report chains to AMD's published "
      "root and the utility VM to Microsoft's"
      + ("; that the archived container policy agrees with the report's HOST_DATA" if any_policy else "")
      + "; that each signed statement is about exactly the query text and result shown, on the index and date bound shown.</p>")
    A("<p class=note><b>What that does NOT establish on its own</b>: that the container was InferRoute's. A SEV-SNP "
      "report and Microsoft's endorsement prove a genuine confidential container inside Microsoft's utility VM — the "
      "MEASUREMENT endorses that utility VM, not our container. Only comparing the policy hash and the index / encoder "
      "manifest hashes against values obtained from InferRoute <i>independently of this bundle</i> shows our code and our "
      "index ran (<code>verify_record.py --reference</code>; see VERIFY.md §3). Trust rests on two root pins plus "
      "signature links: no revocation checking, no certificate-path constraints. The MANIFEST is an unsigned index; the "
      "enclave-signed statements are the seal. The record proves what it shows, never that it shows every search.</p>")
    A("<p class=note><b>This device's own attestation only</b>: that its agent ran confined (per session above), that the "
      "date bound and marks were held outside the agent's reach, and that the model-lane checks passed as listed. "
      "A reader who does not trust this device should weigh those lines accordingly.</p>")
    A("<p class=note><b>Not claimed</b>: novelty, patentability, or the absence of prior art. A sealed search lists what a "
      "bounded corpus surfaced under a stated date bound; the corpus is named by its index manifest hash in each statement.</p>")
    reach = [f"{s['session_id']}: {_reach_note(str((s['record'] or {}).get('confinement') or ''))}" for s in sessions]
    if reach:
        A("<p class=note>Per session: " + "; ".join(_e(x) for x in reach) + ".</p>")
    A(f"<p class=note>Generated {_e(dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))} on the attorney's machine.</p>")
    A("</body></html>")
    return {"html": "".join(out), "searches": searches, "evidence": evidence, "matter_cutoff": matter_cutoff}


def _reach_note(recorded: str) -> str:
    """What one session's RECORDED confinement line entitles the bundle to say about these records. Read off
    the stamped line itself rather than assumed from the mode: a best-effort session and a required one both
    write-deny the record directory, but only the required one would have refused to run without it, and only
    the address-level bind made the directory invisible rather than unwritable. Saying "require-mode" for a
    session that ran best-effort would be the bundle claiming a guarantee nobody made."""
    low = recorded.lower()
    if not recorded:
        return "confinement not recorded — cannot claim these records were out of reach"
    if "unconfined" in low or low.startswith("not confined"):
        return "UNCONFINED (developer override) — the agent could have altered these records"
    # NOT "address-level": require mode has confined EGRESS by address since before the matter-dir bind
    # existed, and those sessions left the filesystem merely write-denied. Only the line that itself says
    # the files were absent earns the stronger sentence.
    if "absent rather than unwritable" in low:
        return ("not present in the agent's filesystem at all (address-level confinement: an empty network "
                "namespace with only the matter directory bound in)")
    if low.startswith("require"):
        return "held outside the agent's write access (require-mode confinement)"
    return ("held outside the agent's write access, but confinement was best-effort — had it been unavailable "
            "this session would still have run, so weigh this line by the mode, not by the mode's name")


def _reference_hint() -> Dict[str, Any]:
    """What THIS machine was configured to expect (search.json pins). A convenience for the reader — it comes
    from the same machine as the bundle, so it is NOT the out-of-band reference the verifier needs."""
    hint: Dict[str, Any] = {"note": "values this machine was configured to expect at session time; NOT authoritative — "
                                    "obtain InferRoute's published reference independently and pass it with --reference"}
    try:
        from .pi_attested import search_config_path
        cfg = json.loads(search_config_path().read_text())
        for k in ("expect_host_data", "expect_index", "reference_url"):
            if cfg.get(k):
                hint[k] = cfg[k]
    except Exception:                                          # noqa: BLE001
        pass
    return hint


def _is_within(child: Path, parent: Path) -> bool:
    c, p = os.path.abspath(child), os.path.abspath(parent)
    return c == p or c.startswith(p.rstrip("/") + "/")


def write_bundle(client: str, matter: str, out_dir: Optional[str], *, anchor: bool = False) -> Path:
    """Write the bundle directory (0700, files 0600). Refuses the matter workspace and cloud-sync roots: the
    bundle holds the invention in plain text. Returns the directory."""
    from . import surveyor as S
    rec = S.load_record(client, matter)
    ws = Path(rec["workspace"])
    b = build_bundle(client, matter)
    if out_dir:
        dest = Path(out_dir)
        if _is_within(dest, ws):
            raise S.SurveyorError("refusing to write the export inside the matter workspace, where a later session "
                                  "could alter it before it is filed. Choose a directory outside the workspace.")
        sync = S._under_sync_root(dest)
        if sync:
            raise S.SurveyorError(f"refusing to write the export under a cloud-sync folder ({sync}): it holds the "
                                  "invention in plain text. Choose a local directory outside any synced folder.")
    else:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = S.surveyor_root() / client / "exports" / f"{matter}-prior-art-record-{stamp}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest, 0o700)
    except OSError:
        pass

    files: Dict[str, bytes] = {"record.html": b["html"].encode("utf-8"),
                               "searches.json": json.dumps(b["searches"], indent=1, ensure_ascii=False).encode("utf-8"),
                               "VERIFY.md": VERIFY_MD.encode("utf-8")}
    for sha, content in b["evidence"].items():
        files[f"{sha[:16]}.evidence.json"] = content.encode("utf-8")
    verifier_src = Path(__file__).resolve().parent / "pi_attested" / "verify_record.py"
    if not verifier_src.exists():
        raise S.SurveyorError("the independent verifier (pi_attested/verify_record.py) is missing from this installation; "
                              "refusing to write a record that VERIFY.md tells the reader to verify with it")
    files["verify_record.py"] = verifier_src.read_bytes()
    manifest = {"schema": "inferroute.prior-art-record/1", "client": client, "matter": matter,
                "matter_cutoff": b["matter_cutoff"], "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "note": "an unsigned index of this bundle, not a seal; the enclave-signed statements in searches.json are the seal",
                "reference_hint": _reference_hint(),
                "files": {name: _sha256_hex(data) for name, data in sorted(files.items())}}
    files["MANIFEST.json"] = json.dumps(manifest, indent=1).encode("utf-8")
    files["SHA256SUMS"] = "".join(f"{sha}  {name}\n" for name, sha in sorted(manifest["files"].items())).encode("utf-8")
    for name, data in files.items():
        p = dest / name
        p.write_bytes(data)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    print(f"wrote {dest}")
    print(f"  {len(b['searches'])} sealed search(es), {len(b['evidence'])} evidence bundle(s); verify with: python3 verify_record.py .")
    print("  contains the disclosure in plain text — store it accordingly")
    if anchor:
        _anchor(dest / "MANIFEST.json")
    else:
        print("  to timestamp this record (open source, publishes only a hash): ir surveyor export ... --anchor, or `ots stamp MANIFEST.json`")
    return dest


def _anchor(manifest_path: Path) -> None:
    """OpenTimestamps: publishes ONLY the manifest's hash to public calendar servers, later anchored in Bitcoin.
    Proves the record existed by a date. Opt-in because it contacts external servers."""
    ots = shutil.which("ots")
    if not ots:
        print("  --anchor: `ots` (opentimestamps-client) is not installed; run `ots stamp MANIFEST.json` later to anchor.")
        return
    try:
        r = subprocess.run([ots, "stamp", str(manifest_path)], capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and (manifest_path.parent / "MANIFEST.json.ots").exists():
            print("  anchored: MANIFEST.json.ots written (upgrade later with `ots upgrade MANIFEST.json.ots`; verify with `ots verify`)")
        else:
            print(f"  --anchor: ots stamp did not complete ({(r.stderr or r.stdout).strip()[:200]})")
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  --anchor: ots stamp failed ({e})")


def verify_bundle(bundle_dir: str, extra_args: Optional[List[str]] = None) -> int:
    """Run the bundle's own verify_record.py (or this package's copy) over the bundle. Convenience only —
    the point of the bundled verifier is that it needs no `ir` at all."""
    d = Path(bundle_dir)
    script = d / "verify_record.py"
    if not script.exists():
        script = Path(__file__).resolve().parent / "pi_attested" / "verify_record.py"
    import sys
    r = subprocess.run([sys.executable, str(script), str(d), *(extra_args or [])])
    return r.returncode
