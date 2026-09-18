"""`ir probant export` — the one-directory record the attorney hands a client, built so a stranger can
re-derive its claims from the bundle alone. Checks the bundle's shape (record.html, searches.json, evidence
files, MANIFEST.json, VERIFY.md, the standalone verify_record.py), the honest per-session reach note, the
model lane's full check list and limitations, the query-text binding, and the output-path safety.
"""
import hashlib
import json
from pathlib import Path

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_export as E


@pytest.fixture
def matter(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR", "IR_PROBANT_DEV_UNCONFINED",
              "IR_REPORT_MATTER", "IR_REPORT_FIRM"):
        monkeypatch.delenv(k, raising=False)
    assert S.main(["new", "AcmeCorp", "battery-cooling", "--priority-date", "2020-01-15"]) == 0
    (Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"]) / "disclosure.md").write_text(
        "# Disclosure\n\nA battery housing with COOLANT-MARKER channels between cells.\n")
    return tmp_path


def _write_session(sid, record, searches=None):
    rdir = S.records_dir("AcmeCorp", "battery-cooling")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / f"{sid}.json").write_text(json.dumps(record))
    if searches:
        (rdir / f"{sid}.searches.jsonl").write_text("".join(json.dumps(s) + "\n" for s in searches))


def _write_state(marks):
    S.state_path("AcmeCorp", "battery-cooling").write_text(json.dumps({"approved": [], "marks": marks, "surfaced": {}}))


def _full_session():
    _write_session("sess-1", {
        "started_at": "2026-09-14T10:00:00Z",
        "confinement": "require (address-level egress enforced or the session does not start)",
        "model_lane": {"verified": True, "checks": "2/2", "model": "kimi-k2.6", "sealing": "ML-KEM-768 + ChaCha20-Poly1305",
                       "check_list": [{"label": "Genuine TDX, debug off", "ok": True, "why": "quote verified"},
                                      {"label": "GPUs verified by NVIDIA", "ok": True, "why": "NRAS ok"}],
                       "limitations": ["GPU-to-CPU binding is not proven by this receipt"]},
        "search_lane": {"searches": [{"at": "2026-09-14T10:05:00Z", "hits": 1}]},
        "which_surface_saw_what": {"model_enclave": "saw the conversation, inside a verified enclave"},
        "contract": {"contract_sha": "c0ffee1234567890abcdef", "preamble_sha": "beadfeed1234567890", "modified": False},
    }, searches=[{"at": "2026-09-14T10:05:01Z", "signer_pub": "ed25519-pub-hex", "cutoff_date": 20200115,
                  "index_snapshot": "us-2026-09", "measurement": "m" * 40, "host_data": "h" * 40,
                  "query_text": "A battery housing with QUERY-MARKER channels.",
                  "statement": {"hits_n": 1, "cutoff_date": 20200115, "request_id": "r1", "sig": "SIGNATUREHEX"},
                  "result": {"hits": [{"key": "US-7000-B2"}]},
                  "report_html": "<!doctype html><html><body>REPORT-BODY-MARKER: US-7000-B2</body></html>",
                  "evidence": {"offer": {"runtime_data": "b64rd", "evidence": "snp-report-b64"}, "policy_b64": "cG9saWN5"}}])
    _write_state({"US-7000-B2": {"latest": {"value": "relevant", "actor": "human", "at": "2026-09-14T10:06:00Z",
                                            "surfaced": "this_session", "rank": 1},
                                 "history": [{"value": "relevant", "at": "2026-09-14T10:06:00Z"}]}})


def test_export_writes_a_verifiable_bundle(matter):
    _full_session()
    out = matter / "bundle"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    names = sorted(p.name for p in out.iterdir())
    assert "record.html" in names and "searches.json" in names and "MANIFEST.json" in names
    assert "VERIFY.md" in names and "verify_record.py" in names
    assert any(n.endswith(".evidence.json") for n in names)
    # the bundle's own verifier is the real standalone file, unmodified
    src = (Path(S.__file__).resolve().parent / "pi_attested" / "verify_record.py").read_bytes()
    assert (out / "verify_record.py").read_bytes() == src
    # MANIFEST covers every file and carries the matter's date bound
    m = json.loads((out / "MANIFEST.json").read_text())
    assert m["matter_cutoff"] == 20200115
    for name, sha in m["files"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == sha
    assert set(m["files"]) == set(names) - {"MANIFEST.json", "SHA256SUMS"}
    assert "SHA256SUMS" in names and m["note"].startswith("an unsigned index")
    assert "reference_hint" in m and "NOT authoritative" in m["reference_hint"]["note"]
    # VERIFY.md is the honest version: identity via --reference, extract step, tools named as consumers only
    v = (out / "VERIFY.md").read_text()
    assert "--reference" in v and "--extract" in v and "sha256sum -c SHA256SUMS" in v and "ots verify MANIFEST.json.ots" in v
    assert "have NOT run those invocations" in v
    # searches.json binds statement, result, query text and names the evidence file by sha
    rows = json.loads((out / "searches.json").read_text())
    assert rows[0]["query_text"].startswith("A battery housing with QUERY-MARKER")
    assert rows[0]["statement"]["sig"] == "SIGNATUREHEX" and rows[0]["result"]["hits"][0]["key"] == "US-7000-B2"
    assert (out / rows[0]["evidence_file"]).exists()
    assert hashlib.sha256((out / rows[0]["evidence_file"]).read_bytes()).hexdigest() == rows[0]["evidence_sha256"]
    # the evidence file carries the policy so HOST_DATA = sha256(policy) is redoable
    assert json.loads((out / rows[0]["evidence_file"]).read_text())["policy_b64"] == "cG9saWN5"
    # permissions: 0700 dir, 0600 files
    assert (out.stat().st_mode & 0o777) == 0o700
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in out.iterdir())


def test_record_html_shows_report_query_statement_model_checks_and_honest_reach(matter):
    _full_session()
    out = matter / "b2"
    S.cmd_export("AcmeCorp/battery-cooling", str(out))
    h = (out / "record.html").read_text()
    assert "COOLANT-MARKER" in h and "sha256" in h                                  # disclosure, hashed
    assert "QUERY-MARKER" in h and "query_sha256" in h                              # the text actually searched
    assert "REPORT-BODY-MARKER" in h and "srcdoc=" in h                             # the report, isolated
    assert "SIGNATUREHEX" in h and "ed25519-pub-hex" in h                           # statement verbatim
    assert ".evidence.json" in h and "REPORT_DATA = SHA-256(runtime_data)" in h    # evidence + redo sentence
    assert "Genuine TDX, debug off" in h and "GPU-to-CPU binding is not proven" in h  # model lane, verbatim
    assert "c0ffee1234567890" in h                                                  # governing contract
    assert "held outside the agent" in h and "self-report" in h                     # honest reach
    assert "does and does not prove" in h and "Not claimed" in h
    assert "not InferRoute" in h or "NOT establish" in h                           # the identity caveat is stated
    assert "archived container policy agrees" in h                                 # policy sentence conditional (policy archived here)
    assert "<script" not in h and 'src="http' not in h and "<link " not in h


def test_export_is_honest_about_a_dev_unconfined_session(matter):
    _write_session("sess-dev", {"started_at": "t", "confinement": "unconfined (developer override)",
                                "model_lane": {"verified": True, "checks": "1/1"}, "search_lane": {"searches": []},
                                "contract": {"contract_sha": "c0ffee", "preamble_sha": "beadfeed"}})
    out = matter / "b3"
    S.cmd_export("AcmeCorp/battery-cooling", str(out))
    h = (out / "record.html").read_text()
    assert "class=bad>unconfined (developer override)" in h and "the agent could have altered these records" in h


def test_export_flags_a_missing_confinement_stamp_as_warn(matter):
    _write_session("sess-x", {"started_at": "t", "model_lane": {"verified": True}, "search_lane": {"searches": []}})
    out = matter / "b4"
    S.cmd_export("AcmeCorp/battery-cooling", str(out))
    assert "class=warn>confinement not recorded" in (out / "record.html").read_text()


def test_export_refuses_workspace_and_sync_root(matter):
    ws = Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"])
    assert S.main(["export", "AcmeCorp/battery-cooling", "-o", str(ws / "rec")]) == 2
    assert S.main(["export", "AcmeCorp/battery-cooling", "-o", str(matter / "OneDrive" / "rec")]) == 2


def test_export_default_path_is_outside_the_workspace_and_warns_plaintext(matter, capsys):
    assert S.main(["export", "AcmeCorp/battery-cooling"]) == 0
    dirs = list((S.probant_root() / "AcmeCorp" / "exports").iterdir())
    assert dirs and (dirs[0] / "record.html").exists()
    assert "plain text" in capsys.readouterr().out


def test_verify_export_runs_the_bundled_verifier_and_an_empty_record_is_not_a_pass(matter):
    out = matter / "b5"
    S.cmd_export("AcmeCorp/battery-cooling", str(out))
    assert S.main(["verify-export", str(out)]) == 1               # no sealed searches → FAIL, never a clean exit


def test_export_of_a_matter_with_no_sessions_still_renders(matter):
    out = matter / "empty"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    h = (out / "record.html").read_text()
    assert "No attested sessions" in h and "No relevance marks" in h and "No sealed search completed" in h


def test_export_of_unknown_matter_refuses(matter):
    assert S.main(["export", "Nobody/none"]) == 2


def test_disclosure_content_gates_prewarm(matter):
    ws = Path(S.load_record("AcmeCorp", "battery-cooling")["workspace"])
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE)
    assert S.disclosure_has_content(ws) is False
    ws.joinpath("disclosure.md").write_text(S.TEMPLATE_DISCLOSURE + "\nThe invention is a phase-change cooling loop.\n")
    assert S.disclosure_has_content(ws) is True


# ── the record's first screen ──

def _sess(conf="require, address-level (empty network namespace)", verified=True):
    return {"record": {"confinement": conf, "model_lane": {"verified": verified}}}


def test_glance_never_asserts_the_search_machine_was_inferroutes():
    from inferroute_cli import probant_export as X
    html = X._glance([_sess()], 2, {}, {"date_bound": "2020-01-01"})
    assert "Whether the search machine was InferRoute's" in html and "does not assert it" in html
    assert "was InferRoute's</b> is checked" in html


def test_glance_says_who_stands_behind_each_line():
    from inferroute_cli import probant_export as X
    html = X._glance([_sess()], 1, {"US-1-B2": {}}, {"date_bound": "2020-01-01"})
    assert html.count("As reported by this computer") == 2 and "Anyone can check these from this folder alone" in html
    assert "the start of the session." in html


def test_glance_reports_an_unboxed_or_unverified_session_as_a_problem():
    from inferroute_cli import probant_export as X
    html = X._glance([_sess(), _sess(conf="unconfined (developer override)", verified=False)], 1, {}, {"date_bound": "x"})
    assert "WITHOUT its box" in html and "not verified in 1 of 2" in html
    assert "worked in a closed box" not in html and "ran in a sealed machine" not in html


def test_glance_claims_no_date_bound_search_when_nothing_was_searched():
    from inferroute_cli import probant_export as X
    html = X._glance([_sess()], 0, {}, {"date_bound": "2020-01-01"})
    assert "No sealed search completed" in html and "were searched" not in html


# ── how much of each document was read ──
#
# The record used to promise that "each report states how many of the documents it examined most closely it
# was able to read in full" and that "the signed result records the shortfall". Measured against a real
# bundle on 2026-09-18: text_coverage is null on every statement, because the deployed sealed lane runs the
# dense pass alone. The record was describing evidence it did not carry, in the one document that leaves the
# firm. The paragraph is now derived from the statements.

def _sessions(*coverages):
    return [{"session_id": "s1", "record": {},
             "searches": [{"statement": {"sig": "aa", "text_coverage": c}} for c in coverages]}]


def test_the_record_says_nothing_was_read_in_full_when_nothing_says_it_was():
    note = E._coverage_note(_sessions(None, None, None, None))
    assert "none of the 4 sealed searches" in note
    assert "title and the start of its abstract" in note
    # It must not read as a hole in the record: the sealed machine has no full text to hold.
    assert "not a gap in the record" in note


def test_an_unsigned_row_is_not_counted_as_a_search_that_read_nothing():
    s = _sessions(None)
    s[0]["searches"].append({"statement": {"text_coverage": None}})      # no sig: not an enclave statement
    assert "none of the 1 sealed search in this record" in E._coverage_note(s)
    assert E._coverage_note([{"session_id": "s", "record": {}, "searches": []}]) == ""


def test_a_signed_coverage_figure_is_reported_as_the_engine_counter_it_is():
    note = E._coverage_note(_sessions({"rescoring": {"examined": 300}}, None))
    assert "1 of the 2 sealed searches carry a signed" in note
    # The figure is the engine's own counter over rescored candidates. Calling it a count of documents read
    # in full is the overclaim this replaced.
    assert "NOT a count of documents read in full" in note


def test_the_record_makes_no_comparative_claim_about_reading_more(matter):
    """The record may say what the sealed search READ. It may not say what reading more would or would not
    have done — in either direction. The measurement we have is conditional (full-text rescoring pays when
    most of the window is readable; the +0.002 everyone reaches for was taken at 12.5% coverage, and the
    same mechanism gave +0.060 at full coverage), and a conditional quoted flat becomes "we proved it would
    not help" — the error that flatters the lane we sell and is easy to make while sounding candid."""
    out = matter / "claims"
    assert S.cmd_export("AcmeCorp/battery-cooling", str(out)) == 0
    html = (out / "record.html").read_text()                          # what the client actually reads
    for claim in ("percentage point", "does not pay"):
        assert claim not in html, f"the record must not carry the comparative claim {claim!r}"
    # "cannot tell you THAT X" reads as "X is not so"; only "whether" leaves it open.
    assert "we cannot tell you whether reading more" in html
    assert "we cannot tell you that reading more" not in html
    assert "the title and the opening of the abstract" in html
