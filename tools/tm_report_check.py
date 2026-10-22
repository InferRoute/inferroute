"""Check a name-check report against the searches that produced it. Usage:
    tm_report_check.py NAME_CHECK_MD TRADEMARK_SEARCHES_JSONL [--json]

The report is written by the model; the search log (trademark-searches.jsonl, kept on the host, write-denied to the
agent) is what the searches returned. This reads both and says, without judgement calls:
- every register number the report cites, and whether a logged search returned it (a number no search returned
  was made up or mistyped);
- whether the status and classes written next to a cited number agree with the search;
- wording the report must never use (a verdict on a name);
- whether the sections the prompt asks for are there, and the word count against the 450-word cap.
Meant for comparing models on the same names: run it on each run's report and log."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# A verdict on a name is a legal judgement; names.md forbids these. Matched as words, case-insensitively.
FORBIDDEN = [r"\bis available\b", r"\bare available\b", r"\bfree to use\b", r"\bname is free\b", r"\bcleared?\b",
             r"\bsafe\b", r"\blow[- ]risk\b", r"\bhigh[- ]risk\b", r"\brisky\b", r"\blikely to be confused\b",
             r"\bunlikely to be confused\b", r"\bno conflict\b", r"\bgo ahead\b"]
SECTIONS = ["At a glance", "What you can do next", "Questions for a trademark professional"]
CITE = re.compile(r"\b(US|FR)\s*(?:No\.?\s*)?(\d{5,9})\b")
STATUS = re.compile(r"\b(registered|pending|filed|expired|dead|abandoned|cancelled)\b", re.I)
CLASSES = re.compile(r"\bclass(?:es)?\s+((?:\d{1,2}(?:\s*(?:,|and|&)\s*)?)+)", re.I)


def logged_hits(log: Path) -> Dict[tuple, Dict[str, Any]]:
    out: Dict[tuple, Dict[str, Any]] = {}
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        for h in entry.get("hits", []):
            out[(h["register"], str(h["number"]))] = h
    return out


def check(report: str, hits: Dict[tuple, Dict[str, Any]]) -> Dict[str, Any]:
    cited: List[Dict[str, Any]] = []
    found = list(CITE.finditer(report))
    for i, m in enumerate(found):
        key = (m.group(1), m.group(2))
        # What is written right after this number, up to the next cited number: "(US 1, US 2) … in class 21"
        # says class 21 of the marks named after them, not of US 2.
        end = found[i + 1].start() if i + 1 < len(found) else len(report)
        near = report[m.end():min(end, m.end() + 80)].split("\n")[0]
        said_status = STATUS.search(near)
        said_classes = CLASSES.search(near)
        h = hits.get(key)
        row = {"cite": f"{key[0]} {key[1]}", "returned": h is not None}
        if h is not None:
            if said_status:
                row["status_ok"] = said_status.group(1).lower() == h["status"].lower()
            if said_classes:
                said = set(re.findall(r"\d{1,2}", said_classes.group(1)))
                row["classes_ok"] = said <= {str(int(c)) for c in h.get("classes", [])}
        cited.append(row)
    low = report.lower()
    words = len(re.findall(r"\b\w[\w'-]*\b", report))
    return {
        "cited": len(cited),
        "not_returned": [c["cite"] for c in cited if not c["returned"]],
        "status_wrong": [c["cite"] for c in cited if c.get("status_ok") is False],
        "classes_wrong": [c["cite"] for c in cited if c.get("classes_ok") is False],
        "forbidden": sorted({m.group(0) for p in FORBIDDEN for m in re.finditer(p, low)}),
        "sections_missing": [s for s in SECTIONS if s.lower() not in low],
        "says_not_searched": "not searched" in low,
        "words": words,
        "over_cap": words > 450,
    }


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    got = check(Path(argv[0]).read_text(encoding="utf-8"), logged_hits(Path(argv[1])))
    if "--json" in argv:
        print(json.dumps(got))
    else:
        for k, v in got.items():
            print(f"{k:18} {v}")
    bad = got["not_returned"] or got["status_wrong"] or got["classes_wrong"] or got["forbidden"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
