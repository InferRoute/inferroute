#!/usr/bin/env python3
"""check_report.py — check your audit report and its result file, and make the result file FROM the report.

Run it from anywhere; it finds the pack it ships in. Python 3.8+, standard library only, no network.

    python3 stationery/check_report.py ../REPORT-<this folder>.md
        Checks the report against this pack: every claim heading present, in order, with its exact title;
        every section present; a Verdict and a Covered-by line under each claim; and that each verdict is
        what its own numbers say (the rule is in REPORT-TEMPLATE.md). Prints what to fix, line by line.

    python3 stationery/check_report.py --make-json ../REPORT-<this folder>.md --name "<who you are>" \\
            --model "<your model>" > ../AUDIT-RESULT-<this folder>.json
        Builds the structured result FROM the report, with the pack's hashes and the key names exactly as the
        professional's client expects them. Do not write that file by hand: on 3 Oct an auditor did, renamed
        three keys, left the numbers null, and the client would have refused it five different ways.

    python3 stationery/check_report.py ../REPORT-<this folder>.md ../AUDIT-RESULT-<this folder>.json
        Checks both, and that they agree with each other.

Exit 0 means the client will accept the result. It does not mean your conclusions are right — nothing here
reads your reasoning — only that the shape, the numbers and the pack binding are.

This file is stationery: it is not evidence, it is not in SHA256SUMS, and nothing about the record depends on it.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys

SCHEMA = "inferroute.audit-results/1"
VERDICTS = ("VERIFIED", "VERIFIED IN PART", "NOT VERIFIED", "COULD NOT CHECK")
SECTIONS = ("About this audit",
            "The verifier, and an independent copy of it",
            "One plain statement about confidentiality",
            "Exact statement established, and its limits",
            "Results for the client")
NONE_WORDS = {"", "none", "nothing", "n/a", "na", "-", "—", "no", "nil", "0"}
UNIFORM_WORDS = re.compile(r"\b(uniform|identical|all (?:eight|8)|same verdict|every claim)\b", re.I)


# ── the pack ────────────────────────────────────────────────────────────────────────────────────────────────
def find_pack(explicit):
    if explicit:
        return os.path.abspath(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (here, os.path.dirname(here), os.getcwd()):
        if os.path.isfile(os.path.join(cand, "MANIFEST.json")):
            return cand
    sys.exit("check_report.py: cannot find the pack (MANIFEST.json). Run it from inside the pack, or pass --pack DIR.")


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def pack_identity(pack):
    return {"manifest_sha256": sha(os.path.join(pack, "MANIFEST.json")),
            "evidence_list_sha256": sha(os.path.join(pack, "SHA256SUMS"))}


def totals(manifest):
    c = manifest["contents"]
    return {6: c["searches"], 7: c["session_receipts"], 8: c["document_reads"]}, c["statements"]


def claim_total(manifest, cid):
    special, default = totals(manifest)
    return special.get(cid, default)


# ── the report ──────────────────────────────────────────────────────────────────────────────────────────────
def sections_of(text):
    """{heading: body} for every '## ' heading, in file order, plus the ordered list of headings."""
    parts = re.split(r"(?m)^## +(.+?)\s*$", text)
    heads = parts[1::2]
    bodies = parts[2::2]
    return heads, dict(zip(heads, bodies))


def _num(word):
    word = (word or "").strip().lower()
    return 0 if word in ("none", "nil", "nothing", "") else int(word)


def parse_covered(line):
    """(tool, own, N, neither_text) from a Covered-by line, or None when it cannot be read."""
    tool = re.search(r"tool\s*:\s*(none|\d+)(?:\s*of\s*(\d+))?", line, re.I)
    own = re.search(r"(?:my own recomputation|own recomputation|independent)\s*:\s*(none|\d+)(?:\s*of\s*(\d+))?", line, re.I)
    neither = re.search(r"neither\s*:\s*(.*)$", line, re.I)
    if not (tool and own and neither):
        return None
    ns = [int(x) for x in (tool.group(2), own.group(2)) if x]
    return {"tool": _num(tool.group(1)), "own": _num(own.group(1)),
            "N": ns[0] if ns else None, "N_agree": len(set(ns)) <= 1,
            "neither": neither.group(1).strip().strip("_*").strip()}


def neither_is_none(text):
    t = re.sub(r"[\s.·*_`]+", " ", text.lower()).strip()
    return t in NONE_WORDS or t.startswith("none ")


def claim_blocks(heads, bodies, claims):
    out = {}
    for h in heads:
        m = re.match(r"Claim\s+(\d+)\s+[—–-]\s+(.*)$", h)
        if m:
            out.setdefault(int(m.group(1)), []).append((h, m.group(2).strip(), bodies[h]))
    return out


def verdict_of(body):
    m = re.search(r"(?m)^\*\*Verdict:?\*\*:?\s*(.*)$", body)
    if not m:
        return None, "missing"
    raw = re.sub(r"[_*`]", "", m.group(1)).strip()
    if "/" in raw and "VERIFIED" in raw and raw.count("VERIFIED") > 1:
        return None, "placeholder"
    for v in sorted(VERDICTS, key=len, reverse=True):
        if raw.upper().startswith(v):
            return v, raw
    return None, raw


def covered_of(body):
    m = re.search(r"(?m)^\*\*Covered by:?\*\*:?\s*(.*)$", body)
    if not m:
        return None, None
    line = m.group(1).strip()
    if line.startswith("_(") or "N of N" in line and "M of N" in line:
        return None, "placeholder"
    return parse_covered(line), line


def labelled(body, *labels):
    """The text after the first bold label that starts with any of `labels`, up to the next bold label."""
    for label in labels:
        m = re.search(r"(?ims)^\*\*" + re.escape(label) + r"[^*]*\*\*:?\s*(.*?)(?=^\*\*[A-Z]|\Z)", body)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return ""


def check_report(pack, report_path):
    """List of (where, what's wrong, how to fix it)."""
    problems = []
    manifest = json.load(open(os.path.join(pack, "MANIFEST.json")))
    wanted = [(c["id"], c["title"]) for c in manifest["audit_claims"]]
    try:
        text = open(report_path, encoding="utf-8").read()
    except OSError as e:
        return [("report", f"cannot read {report_path}: {e.strerror}", "pass the path of your report")], {}
    heads, bodies = sections_of(text)
    blocks = claim_blocks(heads, bodies, wanted)

    first = text.strip().splitlines()[0] if text.strip() else ""
    if "<pack folder name>" in first:
        problems.append(("title", "the title still says <pack folder name>", "replace it with this folder's name"))
    preface = text.split("\n## ", 1)[0]                  # the header line lives above the first section
    if re.search(r"<who you are>|<date>|<code>", preface):
        problems.append(("header line", "the 'Auditor: · Date: · Verifier exit code:' line still has its placeholders",
                         "fill in who you are, today's date and the verifier's exit code"))

    claim_heads = [h for h in heads if re.match(r"Claim\s+\d+", h)]
    expected_heads = [f"Claim {n} — {t}" for n, t in wanted]
    if claim_heads != expected_heads:
        for exp in expected_heads:
            if exp not in claim_heads:
                problems.append(("headings", f"missing or retitled: '## {exp}'",
                                 f"the heading must be exactly '## {exp}' — copy it, do not rephrase it"))
        for got in claim_heads:
            if got not in expected_heads:
                problems.append(("headings", f"'## {got}' is not one of the claims",
                                 "remove it or restore the claim's exact title; do not add or retitle claims"))
        if sorted(claim_heads) == sorted(expected_heads):
            problems.append(("headings", "the claims are not in order 1..8", "put them back in the order of the template"))

    for sec in SECTIONS:
        if sec not in heads:
            problems.append(("sections", f"missing section '## {sec}'",
                             f"add '## {sec}' exactly as REPORT-TEMPLATE.md has it (the text under it is yours)"))

    verdicts = {}
    covered = {}
    for n, title in wanted:
        rows = blocks.get(n) or []
        if not rows:
            continue
        body = rows[0][2]
        v, raw = verdict_of(body)
        where = f"claim {n}"
        if v is None:
            why = {"missing": "no '**Verdict:**' line", "placeholder": "the verdict is still the template's list of options"}.get(
                raw, f"'{raw}' is not one of the four verdicts")
            problems.append((where, why, "write exactly one of: VERIFIED, VERIFIED IN PART, NOT VERIFIED, COULD NOT CHECK"))
        else:
            verdicts[n] = v
        cov, line = covered_of(body)
        if cov is None:
            why = "the 'Covered by' line is still the template's placeholder" if line == "placeholder" else (
                "no '**Covered by:**' line" if line is None else f"cannot read the 'Covered by' line: {line[:90]}")
            problems.append((where, why, "write: **Covered by:** tool: N of M · my own recomputation: K of M · neither: <what, or none>"))
            continue
        covered[n] = cov
        total = claim_total(manifest, n)
        if cov["N"] is not None and cov["N"] != total:
            problems.append((where, f"your 'Covered by' says {cov['N']} operations; this pack has {total} for this claim",
                             f"use 'of {total}'"))
        if cov["tool"] > total or cov["own"] > total:
            problems.append((where, "a count is larger than the number of operations", f"counts cannot exceed {total}"))
        reached = max(cov["tool"], cov["own"])
        none_left = neither_is_none(cov["neither"])
        if total == 0 and v in ("VERIFIED", "VERIFIED IN PART"):
            problems.append((where, f"{v}, but this pack holds 0 operations for this claim — there is nothing to have verified",
                             "COULD NOT CHECK, with 'tool: 0 of 0 · my own recomputation: 0 of 0' and what is missing after 'neither:'"))
            continue
        if v == "VERIFIED" and (not none_left or reached != total):
            problems.append((where, f"VERIFIED, but your numbers leave something out (tool {cov['tool']}, own {cov['own']} of {total}; neither: {cov['neither'][:60] or 'blank'})",
                             "VERIFIED needs one of tool/own to equal the total and 'neither: none'; otherwise it is VERIFIED IN PART"))
        if v == "VERIFIED IN PART" and not reached:
            problems.append((where, "VERIFIED IN PART, but tool and own are both 0",
                             "you reached none of it: that is NOT VERIFIED or COULD NOT CHECK — or fill in what the tool read"))
        if v == "VERIFIED IN PART" and none_left and cov["tool"] == total:
            problems.append((where, f"VERIFIED IN PART, but your own line says the tool read {total} of {total} and nothing was left out",
                             "by the template's rule this is VERIFIED. If a part of the claim truly has no evidence here, name it after 'neither:'"))

    if len(verdicts) == len(wanted) and len(set(verdicts.values())) == 1 and not UNIFORM_WORDS.search(text.split("## One plain statement", 1)[-1]):
        problems.append(("verdicts", f"all {len(wanted)} verdicts are '{next(iter(verdicts.values()))}' and the report never says why the evidence is uniform",
                         "re-read each Covered by line against the rule, or say in the closing why every claim really has the same verdict"))
    return problems, {"verdicts": verdicts, "covered": covered, "sections": bodies}


# ── the result file ─────────────────────────────────────────────────────────────────────────────────────────
def _s(value, name, required=True, limit=8000):
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"{name} is missing or too long")
    return value.strip()


def check_result(pack, data):
    """The same rules the professional's client applies (inferroute_cli/probant_audit_results.validate), phrased
    for the person who has to fix them. Returns a list of (where, what's wrong, how to fix it)."""
    problems = []
    manifest = json.load(open(os.path.join(pack, "MANIFEST.json")))
    expect = pack_identity(pack)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return [("result", f"'schema' must be exactly \"{SCHEMA}\"", "build the file with --make-json")]
    p = data.get("pack")
    if not isinstance(p, dict) or set(p) != set(expect):
        problems.append(("pack", f"the pack block has the keys {sorted(p) if isinstance(p, dict) else p!r}; it must have exactly {sorted(expect)}",
                         "copy the block exactly — do not rename the keys; --make-json writes it"))
    elif p != expect:
        problems.append(("pack", "the hashes do not match this folder", "--make-json computes them from MANIFEST.json and SHA256SUMS"))
    claims = data.get("claims")
    wanted = manifest["audit_claims"]
    if not isinstance(claims, list) or len(claims) != len(wanted):
        problems.append(("claims", f"the result must answer all {len(wanted)} claims exactly once", "one entry per claim, in order"))
        return problems
    for w, c in zip(wanted, claims):
        where = f"claim {w['id']}"
        if not isinstance(c, dict) or c.get("id") != w["id"] or c.get("title") != w["title"]:
            problems.append((where, "omitted, reordered or retitled", f"id {w['id']}, title exactly: {w['title']}"))
            continue
        v = c.get("verdict")
        if v not in VERDICTS:
            problems.append((where, f"verdict {v!r} is not one of the four", "VERIFIED / VERIFIED IN PART / NOT VERIFIED / COULD NOT CHECK"))
            continue
        cov = c.get("coverage")
        if not isinstance(cov, dict):
            problems.append((where, "coverage is missing", "coverage: {tool, independent, total, unchecked}"))
            continue
        total = claim_total(manifest, w["id"])
        if type(cov.get("total")) is not int or cov["total"] != total:
            problems.append((where, f"coverage.total must be {total}", f"set total to {total}"))
        for k in ("tool", "independent"):
            if type(cov.get(k)) is not int or not 0 <= cov[k] <= total:
                problems.append((where, f"coverage.{k} is {cov.get(k)!r}; it must be a number from 0 to {total}",
                                 "use 0 for a check you did not perform — null is refused"))
        unchecked = cov.get("unchecked")
        if not isinstance(unchecked, str):
            problems.append((where, "coverage.unchecked must be text (empty only when nothing is left unexamined)", "use \"\" or describe what is left"))
            unchecked = ""
        if all(type(cov.get(k)) is int for k in ("tool", "independent")):
            if v == "VERIFIED" and (unchecked.strip() or max(cov["tool"], cov["independent"]) != total):
                problems.append((where, "VERIFIED, but coverage leaves something unchecked", "full coverage and an empty 'unchecked', or a different verdict"))
            if v == "VERIFIED IN PART" and not max(cov["tool"], cov["independent"]):
                problems.append((where, "VERIFIED IN PART, but tool and independent are both 0", "a partial verification must have checked something"))
        if v in ("VERIFIED", "VERIFIED IN PART") and not str(c.get("verified_statement") or "").strip():
            problems.append((where, "verified_statement is empty", "one sentence of what this verdict supports"))
        if not str(c.get("evidence") or "").strip():
            problems.append((where, "evidence is empty", "what you looked at"))
        lims = c.get("limitations")
        if not isinstance(lims, list) or (v != "VERIFIED" and not lims):
            problems.append((where, "limitations must be a list, and non-empty unless the verdict is VERIFIED", "name what the verdict does not cover"))
    a = data.get("auditor")
    if not isinstance(a, dict) or any(not str((a or {}).get(k) or "").strip() for k in ("name", "model")):
        problems.append(("auditor", f"auditor must be {{\"name\": ..., \"model\": ...}} — you wrote {sorted(a) if isinstance(a, dict) else a!r}",
                         "name = who you are, model = your actual model name"))
    ca = data.get("completed_at")
    try:
        d = dt.datetime.fromisoformat(str(ca).replace("Z", "+00:00"))
        if d.tzinfo is None:
            raise ValueError
    except (ValueError, TypeError):
        problems.append(("completed_at", f"{ca!r} is not an ISO timestamp with a timezone", "e.g. 2026-10-02T12:09:00Z — top level, not inside auditor"))
    if not str(data.get("verified_statement") or "").strip():
        problems.append(("verified_statement", "the overall verified_statement (top level) is empty", "the exact positive statement your audit supports"))
    lims = data.get("limitations")
    if not isinstance(lims, list) or not lims:
        problems.append(("limitations", "the overall limitations list (top level) is missing or empty", "name what the audit does not establish"))
    return problems


def cross_check(report_info, data):
    problems = []
    for c in data.get("claims", []):
        n = c.get("id")
        if n in report_info["verdicts"] and c.get("verdict") != report_info["verdicts"][n]:
            problems.append((f"claim {n}", f"the report says {report_info['verdicts'][n]}, the result says {c.get('verdict')}", "they must agree"))
        cov = report_info["covered"].get(n)
        if cov and isinstance(c.get("coverage"), dict):
            if (c["coverage"].get("tool"), c["coverage"].get("independent")) != (cov["tool"], cov["own"]):
                problems.append((f"claim {n}", "the numbers in the result differ from the report's 'Covered by' line", "regenerate with --make-json"))
    return problems


# ── making the result from the report ───────────────────────────────────────────────────────────────────────
def _bullets(text):
    items = [re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", ln).strip() for ln in text.splitlines()]
    items = [i for i in items if i]
    return items or ([text.strip()] if text.strip() else [])


def make_json(pack, report_path, name, model):
    manifest = json.load(open(os.path.join(pack, "MANIFEST.json")))
    text = open(report_path, encoding="utf-8").read()
    heads, bodies = sections_of(text)
    blocks = claim_blocks(heads, bodies, manifest["audit_claims"])
    claims = []
    for w in manifest["audit_claims"]:
        n = w["id"]
        body = (blocks.get(n) or [("", "", "")])[0][2]
        v, _ = verdict_of(body)
        cov, _ = covered_of(body)
        cov = cov or {"tool": 0, "own": 0, "neither": ""}
        done = labelled(body, "What I computed myself", "What I computed") or labelled(body, "Evidence")
        miss = labelled(body, "What I could not reach", "What I could not")
        evidence = labelled(body, "Evidence") or done or "see the report"
        unchecked = "" if neither_is_none(cov.get("neither", "")) else cov["neither"]
        claims.append({
            "id": n, "title": w["title"], "verdict": v,
            "verified_statement": (done or evidence)[:1000] if v in ("VERIFIED", "VERIFIED IN PART") else "",
            "evidence": evidence[:1800],
            "limitations": [] if v == "VERIFIED" else (_bullets(miss) or ([unchecked] if unchecked else ["see the report"]))[:12],
            "coverage": {"tool": cov["tool"], "independent": cov["own"], "total": claim_total(manifest, n), "unchecked": unchecked[:1800]},
        })
    stated = bodies.get("Exact statement established, and its limits", "").strip()
    first = re.split(r"\n\s*\n", stated)[0].strip() if stated else ""
    limits = [l for c in claims for l in c["limitations"]][:10]
    return {"schema": SCHEMA, "pack": pack_identity(pack),
            "auditor": {"name": name, "model": model},
            "completed_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verified_statement": first[:1500] or "see the report",
            "limitations": limits or ["see the report"],
            "claims": claims}


# ── main ────────────────────────────────────────────────────────────────────────────────────────────────────
def show(problems, label):
    for where, what, fix in problems:
        print(f"  ✗ {label} · {where}: {what}\n      fix: {fix}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check your audit report and result file, or make the result file from the report.")
    ap.add_argument("report")
    ap.add_argument("result", nargs="?")
    ap.add_argument("--make-json", action="store_true", help="print the result file built from REPORT")
    ap.add_argument("--name", default="")
    ap.add_argument("--model", default="")
    ap.add_argument("--pack", default="")
    a = ap.parse_args(argv)
    pack = find_pack(a.pack)
    if a.make_json:
        if not a.name.strip() or not a.model.strip():
            sys.exit("--make-json needs --name \"<who you are>\" and --model \"<your actual model name>\"")
        json.dump(make_json(pack, a.report, a.name.strip(), a.model.strip()), sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0
    problems, info = check_report(pack, a.report)
    show(problems, "report")
    if a.result:
        try:
            data = json.load(open(a.result, encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"  ✗ result · cannot read {a.result}: {e}")
            return 1
        rp = check_result(pack, data)
        show(rp, "result")
        problems += rp
        if not rp and info:
            cp = cross_check(info, data)
            show(cp, "report vs result")
            problems += cp
    if problems:
        print(f"\n{len(problems)} thing(s) to fix. Fix them and run this again; it prints nothing but OK when it is clean.")
        return 1
    print("OK — " + ("report and result agree, and the client will accept the result." if a.result
                     else "the report has every heading, section, verdict and Covered-by line, and its verdicts match its numbers."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
