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

This bundle is self-contained. Nothing below needs InferRoute, this attorney's machine, or the internet,
except where marked. Do the checks in any order; each is independent.

## 1. Quick: run the bundled verifier (stdlib + `cryptography`)

    python3 verify_record.py .

It prints one line per check (PASS / FAIL / SKIP with the reason) and exits 0 only if every applicable
check passed. It is one short file: read it before you trust it — it is meant to be audited in minutes.

## 2. Bundle integrity

`MANIFEST.json` lists the SHA-256 of every file. Recompute them (`sha256sum *`) and compare. If
`MANIFEST.json.ots` is present, `ots verify MANIFEST.json` (OpenTimestamps, open source) proves the
manifest existed no later than the Bitcoin block it is anchored in — evidence of the date of this record.

## 3. What each check re-derives

* **Statement signature** — Ed25519 over the canonical JSON of the statement (sort_keys, no spaces,
  minus `sig`), under `signer_pub`. Any Ed25519 implementation can redo this.
* **Signer key is hardware-bound** — `signer_pub` appears as `statement_signer_pub` inside
  `offer.runtime_data` (base64 JSON), and the SEV-SNP report's `REPORT_DATA` (bytes 0x50..0x90) equals
  SHA-256(runtime_data) followed by 32 zero bytes. So the AMD chip signed over that key.
* **AMD chain** — the report (1184 bytes at `offer.evidence`) is ECDSA-P384-signed under the VCEK in
  `offer.endorsements`; VCEK is signed by the ASK, ASK by the ARK, ARK self-signed; the ARK's public key
  hashes to AMD's published root for the product line (the verifier prints the hash and the AMD KDS URL to
  compare). Fully independent redo: `snpguest verify` (AMD, github.com/virtee/snpguest) or
  `go-sev-guest` (Google, github.com/google/go-sev-guest) on the same report and certificates.
* **Utility VM** — `offer.uvm_endorsements` is a COSE_Sign1 (PS384) signed by Microsoft; its x5chain
  roots at "Microsoft Supply Chain RSA Root CA 2022" (fingerprint printed); its payload's launch
  measurement equals the report's `MEASUREMENT` (bytes 0x90..0xC0). Independent redo: `go-cose`,
  `pycose`.
* **Container policy** — the report's `HOST_DATA` (bytes 0xC0..0xE0) equals SHA-256 of the
  base64-decoded policy in `policy_b64`. To tie the policy to a container image, regenerate it with
  `az confcom acipolicygen` from the image and compare. (If `policy_b64` is absent the verifier prints
  the HOST_DATA to compare against the policy the operator publishes.)
* **Query and result** — `query_sha256` = SHA-256(request_id ‖ canonical(query_text)) and
  `result_sha256` = SHA-256(request_id ‖ canonical(result)), with `hits_n` = number of hits, and
  `cutoff_date` = the matter's date bound in `MANIFEST.json`.

## 4. What this bundle cannot prove

* That this attorney's own machine was confined while the session ran. That is the device's self-report
  (`record.html` says, per session, whether it was run confined or under a developer override).
* Anything about the model lane beyond the receipt's own listed checks and limitations, reproduced verbatim
  in `record.html`.
* Novelty, patentability, or the absence of prior art. The report lists what a bounded corpus surfaced.
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
    A("<p class=note><b>Re-derivable by anyone from this bundle</b> (run <code>verify_record.py</code>): that each search "
      "result was signed by a key bound into an AMD SEV-SNP hardware report; that the report chains to AMD's published "
      "root and the utility VM to Microsoft's; that the report commits to the container policy in force; that each "
      "signed statement is about exactly the query text and result shown, on the index and date bound shown.</p>")
    A("<p class=note><b>This device's own attestation only</b>: that its agent ran confined (per session above), that the "
      "date bound and marks were held outside the agent's reach, and that the model-lane checks passed as listed. "
      "A reader who does not trust this device should weigh those lines accordingly.</p>")
    A("<p class=note><b>Not claimed</b>: novelty, patentability, or the absence of prior art. A sealed search lists what a "
      "bounded corpus surfaced under a stated date bound; the corpus is named by its index manifest hash in each statement.</p>")
    reach = []
    for s in sessions:
        c0 = str((s["record"] or {}).get("confinement") or "")
        if not c0:
            reach.append(f"{s['session_id']}: confinement not recorded — cannot claim these records were out of reach")
        elif "unconfined" in c0:
            reach.append(f"{s['session_id']}: UNCONFINED (developer override) — the agent could have altered these records")
        else:
            reach.append(f"{s['session_id']}: held outside the agent's write access (require-mode confinement)")
    if reach:
        A("<p class=note>Per session: " + "; ".join(_e(x) for x in reach) + ".</p>")
    A(f"<p class=note>Generated {_e(dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))} on the attorney's machine.</p>")
    A("</body></html>")
    return {"html": "".join(out), "searches": searches, "evidence": evidence, "matter_cutoff": matter_cutoff}


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
    if verifier_src.exists():
        files["verify_record.py"] = verifier_src.read_bytes()
    manifest = {"schema": "inferroute.prior-art-record/1", "client": client, "matter": matter,
                "matter_cutoff": b["matter_cutoff"], "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "files": {name: _sha256_hex(data) for name, data in sorted(files.items())}}
    files["MANIFEST.json"] = json.dumps(manifest, indent=1).encode("utf-8")
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
