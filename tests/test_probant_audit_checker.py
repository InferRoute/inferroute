"""check_report.py, shipped in every audit pack: what it accepts, what it refuses, and that it agrees with the client.

Written after the first audit run on ADE (3 Oct): an agent completed a thorough audit, copied the template and
then wrote its own file over it — headings rewritten, the Covered-by lines gone, eight identical verdicts —
and hand-wrote a result file the professional's client would have refused five ways. The brief already said all
of this, at length. These tests are the enforcement that prose was not.
"""
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from inferroute_cli import probant_audit_results as R
from inferroute_cli import probant_check
from inferroute_cli import probant_export as E
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "check_report", Path(__file__).resolve().parents[1] / "inferroute_cli" / "pi_attested" / "check_report.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

from tests.test_verify_record import V, _synthetic_bundle, kms  # noqa: F401  (fixtures)


@pytest.fixture
def pack(tmp_path, V, kms, monkeypatch):
    monkeypatch.setattr(probant_check, "published_reference", lambda: (None, None))
    return E.write_audit_pack(_synthetic_bundle(tmp_path, V, kms), tmp_path / "pack")


def manifest(pack):
    return json.loads((pack / "MANIFEST.json").read_text())


def filled_report(pack, verdicts=None, covered=None, closing="Seven operations were read; claims differ in what could be reached."):
    """The template, completed the way an auditor should: verdict and numbers per claim, prose, closing sections."""
    m = manifest(pack)
    text = (pack / "REPORT-TEMPLATE.md").read_text()
    text = text.replace("# Audit report — <pack folder name>", f"# Audit report — {pack.name}")
    text = text.replace("Auditor: <who you are> · Date: <date> · Verifier exit code: <code>", "Auditor: a model · Date: 2026-10-03 · Verifier exit code: 0")
    verdicts = verdicts or {}
    covered = covered or {}
    for c in m["audit_claims"]:
        n = c["id"]
        total = C.claim_total(m, n)
        # A claim the pack holds nothing for (no receipts, no document reads in the synthetic pack) cannot be
        # verified: COULD NOT CHECK is the honest answer, and the client refuses anything else.
        v = verdicts.get(n, "VERIFIED" if total else "COULD NOT CHECK")
        cov = covered.get(n, f"tool: {total} of {total} operations · my own recomputation: {1 if total else 0} of {total} · neither: "
                             f"{'none' if total else 'the pack holds none'}")
        block = re.compile(rf"(## Claim {n} — .*?)\*\*Verdict:\*\* _\(.*?\)_\n\n\*\*Covered by:\*\* _\(.*?\)_\n\n"
                           r"\*\*What I computed myself:\*\* \n\n\*\*What I could not reach, and why:\*\* \n", re.S)
        assert block.search(text), n
        text = block.sub(lambda mo: f"{mo.group(1)}**Verdict:** {v}\n\n**Covered by:** {cov}\n\n"
                                    f"**What I computed myself:** Re-derived one operation; it agreed with the tool.\n\n"
                                    f"**What I could not reach, and why:** nothing for this claim.\n", text, count=1)
    for heading, body in (("About this audit", "A model on a laptop."),
                          ("The verifier, and an independent copy of it", "Exit 0."),
                          ("One plain statement about confidentiality", closing),
                          ("Exact statement established, and its limits", "The seven operations ran in the machine described.\n\nIt does not establish exclusivity.")):
        text = re.sub(rf"(## {re.escape(heading)}\n\n)<.*?>\n", lambda mo: mo.group(1) + body + "\n", text, count=1, flags=re.S)
    return text


def write(tmp, name, text):
    p = tmp / name
    p.write_text(text)
    return p


def test_a_correctly_filled_report_and_the_result_made_from_it_pass_and_the_client_accepts_them(pack, tmp_path):
    report = write(tmp_path, "REPORT.md", filled_report(pack))
    problems, info = C.check_report(str(pack), str(report))
    assert problems == [], problems
    data = C.make_json(str(pack), str(report), "an auditor", "kimi-k2.6")
    assert C.check_result(str(pack), data) == [] and C.cross_check(info, data) == []
    accepted = R.validate(copy.deepcopy(data), pack, R.identity(pack))               # the PROFESSIONAL's client agrees
    assert accepted["auditor"] == {"name": "an auditor", "model": "kimi-k2.6"}
    assert [c["verdict"] for c in accepted["claims"]] == ["VERIFIED"] * 6 + ["COULD NOT CHECK"] * 2


def test_the_unfilled_template_is_refused_with_what_to_fix(pack):
    problems, _ = C.check_report(str(pack), str(pack / "REPORT-TEMPLATE.md"))
    said = " | ".join(f"{w}: {what}" for w, what, _ in problems)
    assert "<pack folder name>" in said and "placeholders" in said
    assert said.count("still the template's list of options") == 8
    assert said.count("placeholder") >= 8 and all(fix for _, _, fix in problems)


def test_the_shape_the_first_audit_actually_produced_is_refused_for_each_of_its_faults(pack, tmp_path):
    """Headings kept, but no Covered-by lines, a section renamed, one dropped, eight identical verdicts."""
    m = manifest(pack)
    lines = ["# Audit — whatever", "", "**Auditor position.** I am a language model.", ""]
    for c in m["audit_claims"]:
        lines += [f"## Claim {c['id']} — {c['title']}", "**Verdict:** VERIFIED IN PART", "", "**Evidence:** I looked.", ""]
    lines += ["## Statement about confidentiality", "fine.", "## JSON results form", "x"]
    problems, _ = C.check_report(str(pack), str(write(tmp_path, "r.md", "\n".join(lines))))
    said = " | ".join(f"{w}: {what}" for w, what, _ in problems)
    assert said.count("no '**Covered by:**' line") == 8
    assert "missing section '## One plain statement about confidentiality'" in said
    assert "missing section '## Exact statement established, and its limits'" in said
    assert "missing section '## The verifier, and an independent copy of it'" in said


def test_a_retitled_or_dropped_claim_is_named_exactly(pack, tmp_path):
    text = filled_report(pack)
    title = manifest(pack)["audit_claims"][7]["title"]
    text = text.replace(f"## Claim 8 — {title}", "## Claim 8 — A different question entirely")
    problems, _ = C.check_report(str(pack), str(write(tmp_path, "r.md", text)))
    assert any("missing or retitled" in w and title in w for _, w, _ in problems) or \
        any(title in fix for _, _, fix in problems)
    assert any("not one of the claims" in w for _, w, _ in problems)


@pytest.mark.parametrize("verdict,cov,expect", [
    ("VERIFIED IN PART", "tool: {t} of {t} operations · my own recomputation: 1 of {t} · neither: none", "this is VERIFIED"),
    ("VERIFIED", "tool: {t} of {t} operations · my own recomputation: 1 of {t} · neither: the withheld texts", "VERIFIED, but your numbers leave something out"),
    ("VERIFIED", "tool: 0 of {t} operations · my own recomputation: 0 of {t} · neither: none", "VERIFIED, but your numbers leave something out"),
    ("VERIFIED IN PART", "tool: 0 of {t} operations · my own recomputation: 0 of {t} · neither: everything", "both 0"),
    ("VERIFIED", "tool: 99 of 99 operations · my own recomputation: 1 of 99 · neither: none", "this pack has"),
])
def test_a_verdict_must_be_what_its_own_numbers_say(pack, tmp_path, verdict, cov, expect):
    t = C.claim_total(manifest(pack), 1)
    report = write(tmp_path, "r.md", filled_report(pack, {1: verdict}, {1: cov.format(t=t)}))
    problems, _ = C.check_report(str(pack), str(report))
    assert any(expect in what + " " + fix for where, what, fix in problems if where == "claim 1"), problems


def test_a_genuinely_partial_verdict_is_accepted(pack, tmp_path):
    t = C.claim_total(manifest(pack), 4)
    report = write(tmp_path, "r.md", filled_report(pack, {4: "VERIFIED IN PART"},
                   {4: f"tool: {t} of {t} operations · my own recomputation: 1 of {t} · neither: the withheld query and result texts"}))
    assert C.check_report(str(pack), str(report))[0] == []


def test_eight_identical_verdicts_need_a_reason_in_the_closing(pack, tmp_path):
    m = manifest(pack)
    allpart = {c["id"]: "VERIFIED IN PART" for c in m["audit_claims"]}
    cov = {c["id"]: f"tool: 0 of {C.claim_total(m, c['id'])} operations · my own recomputation: 1 of {C.claim_total(m, c['id'])} · neither: the rest"
           for c in m["audit_claims"]}
    bad = C.check_report(str(pack), str(write(tmp_path, "a.md", filled_report(pack, allpart, cov))))[0]
    assert any(w == "verdicts" for w, _, _ in bad)
    good = C.check_report(str(pack), str(write(tmp_path, "b.md", filled_report(
        pack, allpart, cov, closing="The verdicts are uniform because every claim has a part with no evidence here."))))[0]
    assert not any(w == "verdicts" for w, _, _ in good)


def hand_written_like_the_audit(pack):
    """The result file as the audit wrote it: three keys renamed, counts null, a field moved, one dropped."""
    m = manifest(pack)
    ident = R.identity(pack)
    return {"schema": R.SCHEMA,
            "pack": {"manifest_sha256": ident["manifest_sha256"], "searches_json_sha256": "ab" * 32},
            "auditor": {"identity": "kimi-k2.6", "completed_at": "2026-10-03T21:55:00Z"},
            "claims": [{"id": c["id"], "title": c["title"], "verdict": "VERIFIED IN PART", "verified_statement": "x",
                        "evidence": "y", "coverage": {"tool": None, "independent": "2 of 7", "total": 7, "unchecked": "z"}}
                       for c in m["audit_claims"]]}


def test_the_hand_written_result_is_refused_for_every_fault_and_the_client_refuses_it_too(pack):
    data = hand_written_like_the_audit(pack)
    problems = C.check_result(str(pack), data)
    said = " | ".join(f"{w}: {what}" for w, what, _ in problems)
    assert "the pack block has the keys" in said and "evidence_list_sha256" in said      # the renamed key, named
    assert "auditor must be" in said and "completed_at" in said                           # moved fields
    assert "coverage.tool is None" in said and "null is refused" in " ".join(f for _, _, f in problems)
    assert "overall limitations" in said and "overall verified_statement" in said
    with pytest.raises(ValueError):
        R.validate(data, pack, R.identity(pack))                                        # the client agrees it is bad


def test_the_checker_and_the_clients_validator_agree_on_a_range_of_mutations(pack, tmp_path):
    report = write(tmp_path, "r.md", filled_report(pack))
    good = C.make_json(str(pack), str(report), "an auditor", "kimi-k2.6")

    def mutate(fn):
        d = copy.deepcopy(good)
        fn(d)
        return d

    cases = [
        lambda d: d.__setitem__("schema", "other"),
        lambda d: d["pack"].__setitem__("manifest_sha256", "0" * 64),
        lambda d: d["claims"].pop(),
        lambda d: d["claims"][0].__setitem__("title", "renamed"),
        lambda d: d["claims"][0].__setitem__("verdict", "CONDITIONALLY VERIFIED"),
        lambda d: d["claims"][0]["coverage"].__setitem__("tool", None),
        lambda d: d["claims"][0]["coverage"].__setitem__("tool", 10 ** 6),
        lambda d: d["claims"][0]["coverage"].__setitem__("total", 3),
        lambda d: d["claims"][0]["coverage"].__setitem__("unchecked", "something left"),
        lambda d: d["claims"][0].__setitem__("evidence", ""),
        lambda d: d.__setitem__("completed_at", "2026-10-03"),
        lambda d: d["auditor"].__setitem__("model", ""),
        lambda d: d.__setitem__("limitations", []),
        lambda d: d.__setitem__("verified_statement", " "),
        lambda d: None,                                                                  # unchanged: both must accept
    ]
    for i, fn in enumerate(cases):
        d = mutate(fn)
        mine = bool(C.check_result(str(pack), d))
        try:
            R.validate(copy.deepcopy(d), pack, R.identity(pack))
            theirs = False
        except (ValueError, TypeError, KeyError):
            theirs = True
        assert mine == theirs, (i, mine, theirs, C.check_result(str(pack), d))


def test_make_json_needs_a_name_and_a_model_and_the_script_runs_alone_on_the_standard_library(pack, tmp_path):
    report = write(tmp_path, "r.md", filled_report(pack))
    script = pack / "stationery" / "check_report.py"
    assert script.is_file() and oct(script.stat().st_mode & 0o777) == "0o500"
    run = lambda *a: subprocess.run([sys.executable, "-I", str(script), *a], capture_output=True, text=True, cwd=pack)
    assert run("--make-json", str(report)).returncode != 0                               # no name, no model
    made = run("--make-json", str(report), "--name", "an auditor", "--model", "kimi-k2.6")
    assert made.returncode == 0
    result = tmp_path / "result.json"
    result.write_text(made.stdout)
    checked = run(str(report), str(result))
    assert checked.returncode == 0 and checked.stdout.startswith("OK"), checked.stdout + checked.stderr
    bad = run(str(pack / "REPORT-TEMPLATE.md"))
    assert bad.returncode == 1 and "fix:" in bad.stdout


def test_the_brief_and_template_send_the_auditor_to_the_checker_and_the_checker_is_accounted_for(pack):
    brief = E.AUDIT_MD
    assert "stationery/check_report.py --make-json" in brief and "do not hand-write the result file" in brief.lower()
    assert "Do not write this by hand" in (pack / "REPORT-TEMPLATE.md").read_text()
    m = manifest(pack)
    assert "stationery/check_report.py" in m["stationery"]
    assert "stationery/check_report.py" not in m["files"] and "check_report" not in (pack / "SHA256SUMS").read_text()


def test_the_checker_in_the_pack_is_the_one_in_the_client(pack):
    assert (pack / "stationery" / "check_report.py").read_bytes() == Path(C.__file__).read_bytes()


def test_verified_on_a_claim_the_pack_holds_nothing_for_is_named_for_what_it_is(pack, tmp_path):
    m = manifest(pack)
    assert C.claim_total(m, 7) == 0
    report = write(tmp_path, "r.md", filled_report(pack, {7: "VERIFIED"}, {7: "tool: 0 of 0 operations · my own recomputation: 0 of 0 · neither: none"}))
    problems, _ = C.check_report(str(pack), str(report))
    assert any(w == "claim 7" and "0 operations" in what for w, what, _ in problems)


def test_the_client_says_what_is_wrong_with_a_malformed_result_not_that_the_pack_changed(pack):
    data = hand_written_like_the_audit(pack)
    with pytest.raises(ValueError, match="pack block is not the one this pack gave") as e:
        R.validate(copy.deepcopy(data), pack, R.identity(pack))
    assert "evidence_list_sha256" in str(e.value) and "check_report.py --make-json" in str(e.value)
    data["pack"] = R.identity(pack)
    for c in data["claims"]:
        c["coverage"]["total"] = C.claim_total(manifest(pack), c["id"])
        c["limitations"] = ["x"]
    with pytest.raises(ValueError, match="claim 1: coverage 'tool' is None"):
        R.validate(copy.deepcopy(data), pack, R.identity(pack))
    data["claims"][0]["coverage"]["total"] = 7
    with pytest.raises(ValueError, match="claim 1: coverage total is 7; this pack holds"):
        R.validate(copy.deepcopy(data), pack, R.identity(pack))
    data["claims"][0]["coverage"]["total"] = C.claim_total(manifest(pack), 1)
    for c in data["claims"]:
        c["coverage"].update(tool=min(1, c["coverage"]["total"]), independent=min(1, c["coverage"]["total"]))
        if not c["coverage"]["total"]:
            c["verdict"] = "COULD NOT CHECK"                          # nothing in this pack to verify
    with pytest.raises(ValueError, match='"name": ..., "model": ...'):
        R.validate(copy.deepcopy(data), pack, R.identity(pack))


def test_the_brief_tells_the_auditor_to_start_the_report_early_and_to_budget_its_effort():
    """3 Oct, the second audit run on ADE: 50 minutes, about $12, 183 turns, no report. Its last message was a
    tool call written out as text, which ended the session; nothing had been written because the report was
    planned for the end. The first run took 22 minutes and $3.25 and finished."""
    brief = E.AUDIT_MD
    head = brief[:brief.index("## What this folder is")]
    assert "## How to work" in head and "Start the report in your first minutes" in head
    assert "About eight tool calls a claim" in head and "Intel quote chain" in head and "Finish with the checker" in head
    assert head.index("## How to work") < brief.index("## Write your report")          # said before the work, not after


def test_the_brief_warns_against_reading_an_exit_code_from_the_end_of_a_pipe():
    """3 Oct: `verifier | grep | head | echo "EXIT:$?"` printed EXIT:0 on a tampered pack, and the auditor reported
    that about the verifier. The verifier had caught both tampers; the shell had hidden its exit code."""
    head = E.AUDIT_MD[:E.AUDIT_MD.index("## What this folder is")]
    assert "never from the end of a pipe" in head and 'echo "exit $?"' in head
