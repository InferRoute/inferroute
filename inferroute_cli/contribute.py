"""`ir data calls/offer/submit/submissions` — CRE data-contribution v0 client.

The CLI is THE submitting surface by design (docs/cre-data-contribution-v0.md §3):
the corpus, the scrubber, and the record key live on this machine, so the egress
decision happens here. The website only observes and settles.

Trust properties enforced client-side:
  - nothing leaves the machine on `calls`/`offer` (local-only preview);
  - `submit` runs the LOCAL scrubber over every blob before packaging and shows
    the redaction summary before asking for consent;
  - blobs with ZERO redactions ship byte-identical, so the server (at evaluation
    time) can re-hash them against the content fingerprint recorded at request
    time — the Tier-A provenance the anchored spine enables.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import config


def _base() -> Path:
    d = os.environ.get("INFERROUTE_RECORD_DIR")
    return Path(d) if d else Path.home() / ".inferroute"


def _api(path: str, payload: Optional[dict] = None) -> dict:
    creds = config.load()
    if not creds.api_key:
        raise SystemExit("  Not logged in. Run: ir login")
    url = creds.api_url.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"x-api-key": creds.api_key, "content-type": "application/json",
                 "user-agent": "inferroute-ir-data/1.0"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", "")
        except Exception:
            detail = ""
        raise SystemExit(f"  server said HTTP {e.code}: {detail}")


def _iter_choice_events(since: Optional[float], until: Optional[float],
                        model: Optional[str], session: Optional[str]):
    events = _base() / "events"
    if not events.is_dir():
        return
    for f in sorted(events.glob("events-*.jsonl")):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("kind") != "choice" or not e.get("new_user_block_hash"):
                continue
            if since and (e.get("ts") or 0) < since:
                continue
            if until and (e.get("ts") or 0) > until:
                continue
            if model and model.lower() not in str(e.get("chosen_model", "")).lower():
                continue
            if session and e.get("session_id") != session:
                continue
            yield e


def _blob_path(sha: str) -> Path:
    return _base() / "blobs" / sha[:2] / f"{sha}.gz"


def _collect(ns) -> list[dict]:
    """Candidate turns: choice events whose last-user-block blob exists locally
    (full-recording turns — content is what a submission ships)."""
    since = datetime.fromisoformat(ns.from_).replace(tzinfo=timezone.utc).timestamp() if ns.from_ else None
    until = datetime.fromisoformat(ns.to).replace(tzinfo=timezone.utc).timestamp() if ns.to else None
    out, seen = [], set()
    for e in _iter_choice_events(since, until, ns.model, ns.session):
        sha = e["new_user_block_hash"]
        key = (e.get("session_id"), e.get("turn_seq"), sha)
        if key in seen or not _blob_path(sha).exists():
            continue
        seen.add(key)
        out.append(e)
    return out


def cmd_calls(rest: list[str]) -> int:
    data = _api("/v1/data/calls")
    calls = data.get("calls") or []
    if not calls:
        print("  No open data calls right now. (Calls open when we're taking data.)")
        return 0
    print(f"\n  {len(calls)} open call(s):\n")
    for c in calls:
        print(f"  [{c['id'][:8]}]  {c['title']}")
        print(f"      closes {c['closes_at']}  ·  max {c['max_submission_bytes'] // 1_048_576} MB  ·  {c['max_submissions_per_user']}/user")
        for ln in c["description"].splitlines():
            print(f"      {ln}")
        print(f"      preview yours:  ir data offer {c['id'][:8]}")
        print()
    return 0


def _resolve_call(prefix: str) -> dict:
    calls = _api("/v1/data/calls").get("calls") or []
    hits = [c for c in calls if c["id"].startswith(prefix)]
    if len(hits) != 1:
        raise SystemExit(f"  call '{prefix}' does not match exactly one open call (run: ir data calls)")
    return hits[0]


def cmd_offer(ns) -> int:
    _resolve_call(ns.call)  # confirm the call is open; nothing is uploaded
    turns = _collect(ns)
    if not turns:
        print("  0 matching turns with local content on this machine (full recording only).")
        return 0
    sessions = {t.get("session_id") for t in turns}
    models = {t.get("chosen_model") for t in turns}
    size = sum(_blob_path(t["new_user_block_hash"]).stat().st_size for t in turns)
    ts = sorted(t.get("ts") or 0 for t in turns)
    def day(x): return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d")
    print(f"\n  LOCAL preview (nothing was uploaded):")
    print(f"    {len(turns)} turn(s) across {len(sessions)} session(s)  ·  {day(ts[0])} → {day(ts[-1])}")
    print(f"    ~{size / 1_048_576:.1f} MB of content  ·  models: {', '.join(sorted(m for m in models if m))[:80]}")
    print(f"\n  Submit with:  ir data submit {ns.call}" +
          (f" --from {ns.from_}" if ns.from_ else "") + (f" --to {ns.to}" if ns.to else "") +
          (f" --model {ns.model}" if ns.model else "") + (f" --session {ns.session}" if ns.session else ""))
    return 0


def cmd_submit(ns) -> int:
    call = _resolve_call(ns.call)
    turns = _collect(ns)
    if not turns:
        print("  Nothing to submit (no matching full-recording turns on this machine).")
        return 1

    # Mandatory scrub pass — every blob, before anything is packaged.
    try:
        from inferroute_local.scrubber import Scrubber
        scrubber = Scrubber()
    except Exception as e:
        raise SystemExit(f"  scrubber unavailable ({e}) — refusing to submit unscrubbed content")

    manifest_turns, files, total_red = [], {}, 0
    for e in turns:
        sha = e["new_user_block_hash"]
        raw = gzip.decompress(_blob_path(sha).read_bytes())
        text = raw.decode("utf-8", "replace")
        res = scrubber.scrub(text)
        # redaction_report = {total: <this-call redactions>, distinct: <machine-wide
        # map size>, by_category: {...}} — only `total` describes THIS text.
        red = int((res.redaction_report or {}).get("total") or 0)
        # Byte-identity decides verifiability (the scrubber may re-apply
        # previously-known tokens without counting new redactions).
        if res.scrubbed_text == text:
            shipped = raw  # byte-identical → server can re-hash to the recorded fingerprint
            red = 0
        else:
            shipped = res.scrubbed_text.encode("utf-8")
            red = max(red, 1)
            total_red += red
        blob_sha = hashlib.sha256(shipped).hexdigest()
        if blob_sha not in files:
            files[blob_sha] = gzip.compress(shipped)
        manifest_turns.append({
            "session_id": e.get("session_id"), "turn_seq": e.get("turn_seq"),
            "ts": e.get("ts"), "model": e.get("chosen_model"),
            "v1": sha, "v2": e.get("turn_hash"), "hash_v": e.get("hash_v"),
            "blob_sha": blob_sha, "redactions": red,
        })

    manifest = {
        "v": 1, "call_id": call["id"], "turns": manifest_turns,
        "scrubber": "inferroute-local", "built_by": "ir-data-submit/1.0",
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    manifest_hash = hashlib.sha256(canonical).hexdigest()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("manifest.json"); info.size = len(canonical)
        tar.addfile(info, io.BytesIO(canonical))
        for blob_sha, gz in files.items():
            info = tarfile.TarInfo(f"blobs/{blob_sha}.gz"); info.size = len(gz)
            tar.addfile(info, io.BytesIO(gz))
    payload = buf.getvalue()

    sessions = {t["session_id"] for t in manifest_turns}
    print(f"\n  Ready to submit to “{call['title']}”:")
    print(f"    {len(manifest_turns)} turn(s) · {len(sessions)} session(s) · {len(payload) / 1_048_576:.1f} MB archive")
    print(f"    scrub: {total_red} redaction(s) across {sum(1 for t in manifest_turns if t['redactions'])} turn(s); "
          f"{sum(1 for t in manifest_turns if not t['redactions'])} turn(s) ship byte-identical (verifiable)")
    print(f"    manifest {manifest_hash[:16]}…")

    if ns.preview:
        out = Path(ns.preview)
        out.write_text(json.dumps(manifest, indent=2))
        print(f"\n  --preview: manifest written to {out}. Nothing was uploaded.")
        return 0
    if not ns.yes:
        try:
            ok = input("\n  Upload this to InferRoute for evaluation? [y/N] ").strip().lower()
        except EOFError:
            ok = ""
        if ok != "y":
            print("  Cancelled. Nothing was uploaded.")
            return 1

    reg = _api("/v1/data/submissions", {
        "call_id": call["id"], "manifest": manifest, "manifest_hash": manifest_hash,
        "payload_bytes": len(payload),
        "scrub_summary": {"redactions": total_red,
                          "turns_scrubbed": sum(1 for t in manifest_turns if t["redactions"])},
    })
    put = urllib.request.Request(reg["upload_url"], data=payload, method="PUT",
                                 headers={"content-type": "application/gzip",
                                          "content-length": str(len(payload))})
    with urllib.request.urlopen(put, timeout=600) as r:
        if r.status not in (200, 201):
            raise SystemExit(f"  upload failed: HTTP {r.status}")
    _api(f"/v1/data/submissions/{reg['submission_id']}/complete", {})

    it = reg.get("intake") or {}
    print(f"\n  ✓ submitted — id {reg['submission_id']}")
    print(f"    server intake: {it.get('hash_claim_matched', 0)} fingerprint-matched · "
          f"{it.get('turn_matched', 0)} turn-matched · {it.get('unmatched', 0)} unmatched")
    print("    You'll see the evaluation + any credit award at inferroute.ai/contribute")
    print(f"    (withdraw before it's decided:  ir data withdraw {reg['submission_id'][:8]})")
    return 0


def cmd_submissions(rest: list[str]) -> int:
    subs = _api("/v1/data/submissions").get("submissions") or []
    if not subs:
        print("  No submissions yet.")
        return 0
    print()
    for s in subs:
        award = ""
        if s.get("awarded_millicredits"):
            award = f"  →  ${s['awarded_millicredits'] / 100_000:.2f} credits"
        reasons = (s.get("decision") or {}).get("reasons")
        print(f"  {s['id'][:8]}  {s['status']:<9}  {s['turn_count']:>5} turns  “{s['call']}”{award}")
        if reasons:
            print(f"            “{reasons}”")
    print()
    return 0


def cmd_withdraw(ns) -> int:
    subs = _api("/v1/data/submissions").get("submissions") or []
    hits = [s for s in subs if s["id"].startswith(ns.submission)]
    if len(hits) != 1:
        raise SystemExit("  does not match exactly one submission (run: ir data submissions)")
    _api(f"/v1/data/submissions/{hits[0]['id']}/withdraw", {})
    print("  ✓ withdrawn — the quarantined payload was deleted server-side.")
    return 0
