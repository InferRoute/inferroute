"""`Check this record` — the exported record checked on this computer, in words a professional can use.

The check itself is NOT reimplemented here. It runs the bundle's own `verify_record.py`, the one
implementation of the verdict, and takes its EXIT CODE as the verdict; the printed lines are read only to
say which part of the record a failure touches. A second opinion that could disagree with the verifier would
be worse than none — so when the two could differ, the exit code wins and this module says so.

What this adds is the sentence the exit code does not carry. A red `FAIL completeness` told a patent
user nothing about whether they could still put the record in front of a client; every failure here says
what it means for that decision, and what to do about it.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROW = re.compile(r"^\s*(PASS|FAIL|SKIP)\s+(.+?):\s*(.*)$")
RESULT = re.compile(r"^RESULT:\s*(.*)$")

# The five questions a professional actually has, and which of the verifier's checks answer each. Matched on
# the check's name; anything unmatched is kept and shown under "other checks" rather than silently dropped.
GROUPS: Tuple[Tuple[str, str, str, Tuple[str, ...]], ...] = (
    ("intact", "Is the record whole and unaltered?",
     "Every file is present and matches the hashes written when the record was made.",
     ("manifest", "bundle integrity", "searches.json", "evidence file", "malformed")),
    ("machine", "Was this really a sealed machine?",
     "The hardware signed its own report, under AMD's and Microsoft's roots, with debugging off.",
     ("amd", "vcek", "snp report", "hardware report", "debug", "chip key", "vmpl", "report signature",
      "certificates parse", "chain present", "product line", "firmware tcb", "uvm", "measurement",
      "report_data", "runtime data", "ark self-signed", "signed by ark")),
    ("identity", "Was it InferRoute's machine, and not merely someone's?",
     "The sealed machine ran the software named in InferRoute's published reference.",
     ("enclave identity", "reference", "archived policy")),
    ("truthful", "Does the record tell the truth about your search?",
     "The query, the results, the recorded recipient key and the date bound match what the machine signed.",
     ("query text", "signed recipient matches recorded key", "result is the signed result", "hit count", "statement",
      "sealing key", "signer key", "document", "date bound", "predates")),
    ("complete", "Could a search have been taken out of it?",
     "The searches are numbered without a gap, so none was removed.",
     ("completeness",)),
)

# What a failure in each group costs the person holding the record, and what to do next. Never a diagnosis
# we cannot support: "tell InferRoute" is the honest end of most of these.
CONSEQUENCE: Dict[str, Tuple[str, str]] = {
    "intact": ("The record has been changed, or a file is missing, since it was made. What it says about "
               "the search can no longer be relied on.",
               "Export the record again from the matter. If a fresh export fails the same way, tell us "
               "before using it for anything."),
    "machine": ("The hardware evidence does not hold up, so nothing here shows the search ran inside a "
                "sealed machine at all.",
                "Do not rely on this record. Send it to us with this result — this is ours to explain."),
    "identity": ("The machine was sealed, but this record does not show it was running InferRoute's "
                 "software. It could have been a confidential machine belonging to anyone.",
                 "Check that you passed InferRoute's published reference and the publication key from your "
                 "engagement letter. If you did, tell us: the reference may need to be reissued."),
    "truthful": ("What the record shows on screen is not what the machine signed. The results, the query "
                 "or the date bound do not match the signature.",
                 "Do not rely on this record, and tell us. A mismatch here is never something you caused."),
    "complete": ("A search could have been removed from this record without it showing. The searches that "
                 "ARE here are still properly signed.",
                 "Usable as evidence of the searches it contains, but not as evidence that these were all "
                 "of them. Tell us if you need the stronger claim."),
    "other": ("A check that this summary has no name for did not pass.",
              "Read the technical lines below, and send them to us."),
}

# The verifier's exit codes, said once, here. The code is the verdict; these only put it into words.
VERDICTS: Dict[int, Tuple[str, str, str]] = {
    0: ("passed", "Everything checked out.",
        "This record is what it says it is: a sealed search, run inside a machine that proved what software "
        "it was running, and unchanged since."),
    1: ("failed", "Something did not check out.",
        "One or more checks failed. What that means for you depends on which — see below."),
    2: ("refused", "The check could not be run.",
        "The verifier refused to start — usually a missing file or an option it would not accept. Nothing "
        "about the record itself is claimed either way."),
    3: ("test", "This was a test run, not a verification.",
        "Test roots were used, so this says nothing about whether a real Azure machine was involved. Run it "
        "again without the test options."),
    4: ("unauthenticated", "Everything passed, but the reference was not authenticated.",
        "The checks passed against a reference file nobody's signature vouched for. Pass the publication key "
        "from your engagement letter (--reference-key) to close that gap."),
}


def group_of(name: str) -> str:
    low = name.lower()
    for key, _, _, words in GROUPS:
        if any(w in low for w in words):
            return key
    return "other"


def parse(text: str, code: int) -> Dict[str, Any]:
    """Turn the verifier's output and exit code into the page's shape. Pure: the tests drive it with
    recorded output, so a change in the verifier's wording shows up as a failing test, not as a page that
    quietly stops grouping anything."""
    rows: List[Dict[str, str]] = []
    result = ""
    for line in text.splitlines():
        m = ROW.match(line)
        if m:
            rows.append({"status": m.group(1), "name": m.group(2).strip(), "detail": m.group(3).strip(),
                         "group": group_of(m.group(2))})
            continue
        r = RESULT.match(line.strip())
        if r:
            result = r.group(1).strip()
    verdict, headline, explainer = VERDICTS.get(code, ("failed", f"The check ended with code {code}.",
                                                       "That is not a code this version knows. Tell us."))
    groups = []
    for key, question, ok_text, _ in (*GROUPS, ("other", "Other checks", "Everything else passed.", ())):
        mine = [r for r in rows if r["group"] == key]
        if not mine:
            continue
        failed = [r for r in mine if r["status"] == "FAIL"]
        skipped = [r for r in mine if r["status"] == "SKIP"]
        entry: Dict[str, Any] = {"key": key, "question": question, "rows": mine,
                                 "status": "fail" if failed else "skip" if skipped and not any(
                                     r["status"] == "PASS" for r in mine) else "pass",
                                 "answer": ok_text}
        if failed:
            means, todo = CONSEQUENCE.get(key, CONSEQUENCE["other"])
            entry["answer"] = means
            entry["todo"] = todo
            entry["failed"] = [r["name"] for r in failed]
        elif skipped:
            # One line per distinct skip, not one per search: a 68-search record said the same sentence 68
            # times and buried the answer (19 Sep). The count keeps how often it applied.
            seen: Dict[str, int] = {}
            for r in skipped:
                line = f"{r['name']}: {r['detail']}"
                seen[line] = seen.get(line, 0) + 1
            entry["not_checked"] = [line if n == 1 else f"{line} (in {n} searches)" for line, n in seen.items()]
        groups.append(entry)
    return {"code": code, "verdict": verdict, "headline": headline, "explainer": explainer,
            "result_line": result, "groups": groups, "checks": len(rows),
            "failed": [r["name"] for r in rows if r["status"] == "FAIL"], "output": text,
            "plain": plain_block(text)}


PLAIN_HEADING = "In plain words, for a reader who will not read the table above"


def plain_block(text: str) -> List[str]:
    """The verifier's OWN plain statement for this record, lifted verbatim from its output.

    Not re-derived and not written beside it. The statement is computed from `confidentiality_reach`, which is
    gated on the evidence, and five rounds of naive-reader testing went into its wording (a940a98). A second
    copy maintained by the page would be a sentence about a record that no code checks — and this session has
    already watched one artifact claim a version another artifact contradicted. One function, one answer, and
    when the record's posture changes the page changes with it because it is reading the same bytes.

    Returns the paragraphs, outdented, or [] when the verifier printed none (which it does deliberately for a
    reach level that has no sentence written — the nearest available one would overclaim).
    """
    if PLAIN_HEADING not in text:
        return []
    body = text[text.index(PLAIN_HEADING) + len(PLAIN_HEADING):]
    out: List[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        # The block runs to the next thing that is not an indented paragraph of it. The verifier prints its
        # rows with a PASS/FAIL/SKIP prefix and its sections at a shallower indent, so either ends it.
        if ROW.match(raw) or not raw.startswith("    "):
            break
        out.append(line)
    return out


def published_reference() -> Tuple[Optional[str], Optional[str]]:
    """InferRoute's published reference and publication key as this computer was configured for searching —
    the same two files the session itself pins, so the record is checked against what it was made under.
    Missing is not an error: the check then runs without them and says identity could not be established."""
    from . import pi_attested
    try:
        cfg = json.loads(pi_attested.search_config_path().read_text())
    except (OSError, ValueError):
        return None, None
    ref, key = cfg.get("reference"), cfg.get("reference_key")
    return (str(ref) if ref and Path(str(ref)).exists() else None), (str(key) if key else None)


def check(bundle_dir: str | Path, *, reference: Optional[str] = None, reference_key: Optional[str] = None,
          timeout: float = 300.0) -> Dict[str, Any]:
    """Run the bundle's own verifier over it and report what it found. `reference`/`reference_key` default
    to this computer's configured ones."""
    d = Path(bundle_dir)
    script = d / "verify_record.py"
    if not script.exists():
        script = Path(__file__).resolve().parent / "pi_attested" / "verify_record.py"
    if reference is None and reference_key is None:
        reference, reference_key = published_reference()
    argv = [sys.executable, str(script), str(d)]
    if reference:
        argv += ["--reference", reference]
    if reference_key:
        argv += ["--reference-key", reference_key]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    except subprocess.TimeoutExpired:
        out = parse("", 2)
        out.update(headline="The check did not finish.",
                   explainer=f"It was still running after {int(timeout)} seconds and was stopped. Tell us.")
        return out
    except OSError as e:
        out = parse("", 2)
        out.update(headline="The check could not be started.", explainer=f"{type(e).__name__}: {e}")
        return out
    out = parse((r.stdout or "") + (r.stderr or ""), r.returncode)
    out["reference_used"] = bool(reference)
    out["key_used"] = bool(reference_key)
    if not reference:
        # Said plainly rather than left for the person to work out from a FAIL they did not cause.
        out["note"] = ("This computer has no published reference configured, so the check could not "
                       "establish whose machine it was. Everything else was still checked.")
    return out
