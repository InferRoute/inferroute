"""Recover readings written BEFORE they were persisted, from the conversations that are.

One-off. The live capture attaches the first assistant turn after a read; the conversation log holds the
same sequence — a `user` row "Open <key>: read that document…" followed by the assistant's reply — so the
same rule can be applied backwards. Only fills keys that have no reading; never overwrites a live one.
"""
import json, os, re, sys
from pathlib import Path

OPEN_PUB = re.compile(r"\b([A-Z]{2}-[0-9A-Z]{3,}-[A-Z0-9]{1,3})\b")
OPEN = re.compile(r"^Open ([A-Z]{2}-[0-9A-Z]+-[A-Z0-9]{1,3})\s*:\s*read that document", re.I)
base = Path("/home/henry/.inferroute/confidential/attested-records")
total = 0
for matter_dir in sorted(base.glob("*/*")):
    if not matter_dir.is_dir():
        continue
    found = {}
    for conv in sorted(matter_dir.glob("*.conversation.jsonl")):
        try:
            rows = [json.loads(l) for l in conv.read_text(encoding="utf-8").splitlines() if l.strip()]
        except (OSError, ValueError):
            continue
        for i, r in enumerate(rows):
            if r.get("kind") != "user":
                continue
            m = OPEN.match(str(r.get("text") or "").strip())
            if not m:
                continue
            key = m.group(1).upper()
            for nxt in rows[i + 1:]:
                if nxt.get("kind") == "user":
                    break                        # the next question began; nothing was written about it
                txt = str(nxt.get("text") or "").strip()
                if nxt.get("kind") == "assistant" and txt:
                    # Only if it is demonstrably about THIS document. Without this the rule attached a
                    # survey summary to US-12446781-B2 and a reading of US-6445938-B1 to US-6421548-B1 —
                    # the assistant's next words are not always its answer to the question just asked.
                    first = OPEN_PUB.search(txt.upper())
                    if first and first.group(1) == key.upper():
                        found.setdefault(key, {"text": txt[:6000], "at": nxt.get("at")})
                    break
    if not found:
        continue
    path = matter_dir / "readings.json"
    existing = {}
    if path.exists():
        try:
            existing = (json.loads(path.read_text(encoding="utf-8")) or {}).get("readings") or {}
        except (OSError, ValueError):
            existing = {}
    added = {k: v for k, v in found.items() if k not in existing}
    if not added:
        continue
    merged = {**existing, **added}
    payload = {"schema": "inferroute.probant-readings/1",
               "matter": "/".join(matter_dir.parts[-2:]), "readings": merged}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    total += len(added)
    print("  %-34s recovered %d: %s" % ("/".join(matter_dir.parts[-2:]), len(added), ", ".join(sorted(added))))
print("total recovered:", total)
