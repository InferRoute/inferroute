"""verify_ai_receipt.py: an AI-session receipt is re-checked OFFLINE from the record alone.

Two real receipts are the fixtures (tests/fixtures/ai-receipt/):
  fresh/   written by this client (0.9.125 + this change) on 2026-11-02: one machine, 16/16 checks, with Intel's
           signed collateral and NVIDIA's EAT tokens kept verbatim — every online row re-checks.
  legacy/  written by 0.9.114 on 2026-10-31: two machines, twelve pins, eleven switches, no collateral — the
           offline rows re-check, the online rows SKIP, and the receipt is INCOMPLETE, never PASS.
Neither holds a prompt, a reply or a path (checked below). Every mutant below parses AND changes the
verdict, by the row's name; a mutant the verifier did not notice would be a hole, not a pass.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PI = ROOT / "inferroute_cli" / "pi_attested"
FIX = ROOT / "tests" / "fixtures" / "ai-receipt"
if str(PI) not in sys.path:
    sys.path.insert(0, str(PI))
import verify_ai_receipt as V  # noqa: E402

FRESH, LEGACY = "session-fixture-fresh.receipt.json", "session-fixture-legacy.receipt.json"


def _bundle(tmp_path: Path, which: str) -> Path:
    d = tmp_path / which
    shutil.copytree(FIX / which, d)
    return d


def _rows(c) -> dict:
    return {n: s for s, n, _ in c.rows}


def _detail(c, name: str) -> str:
    return next(d for s, n, d in c.rows if n == name)


def _mutate(bundle: Path, name: str, fn) -> None:
    """Apply `fn(att)` to the receipt's attestation row AND its content-addressed file, re-hashing both: the shape a
    device would produce if it had recorded that evidence. (A mismatched hash is a different, earlier, FAIL.)"""
    p = bundle / name
    r = json.loads(p.read_text())
    att = r["attestation"]
    old_sha = r["served_by"][-1]["attestation_sha256"]
    fn(att)
    blob = json.dumps(att, sort_keys=True).encode()
    sha = hashlib.sha256(blob).hexdigest()
    for e in r["served_by"]:
        if e["attestation_sha256"] == old_sha:
            e["attestation_sha256"], e["attestation_file"] = sha, f"{sha[:16]}.attestation.json"
    (bundle / f"{old_sha[:16]}.attestation.json").unlink(missing_ok=True)
    (bundle / f"{sha[:16]}.attestation.json").write_bytes(blob)
    p.write_text(json.dumps(r, indent=1))


def _edit_quote(att: dict, fn) -> None:
    """Change the TDX quote INSIDE the signed body (and the loose copy, so the two still agree)."""
    body = json.loads(base64.b64decode(att["attested_body"]))
    q = bytearray(base64.b64decode(body["evidence"]["tdx_quote"]))
    fn(q)
    body["evidence"]["tdx_quote"] = base64.b64encode(bytes(q)).decode()
    att["attested_body"] = base64.b64encode(json.dumps(body).encode()).decode()
    att["quote"] = body["evidence"]["tdx_quote"]


# ───────────────────────── the fixtures themselves ─────────────────────────

def test_fixtures_hold_no_text_and_no_path():
    for which, name in (("fresh", FRESH), ("legacy", LEGACY)):
        r = json.loads((FIX / which / name).read_text())
        assert "path" not in r and r.get("withheld") == ["path"]
        text = (FIX / which / name).read_text()
        assert "/home/" not in text and "messages" not in r and "content" not in r
        for e in r["served_by"]:
            blob = json.loads((FIX / which / e["attestation_file"]).read_text())
            assert set(blob) <= {"tee_type", "quote", "gpu_evidence", "instance_id", "certificate", "signature", "attested_body",
                                 "checked_with", "collateral", "build"}


def test_fresh_receipt_is_fully_rechecked_offline(tmp_path):
    b = _bundle(tmp_path, "fresh")
    [(name, c, ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert name == FRESH and not c.failed, c.failed
    assert ok, V.blocking_skips(c)
    for n in ("Intel TCB info", "Intel QE identity", "Intel revocation lists", "Intel TCB status (platform)",
              "Intel Quoting Enclave identity and status", "GPU certificate chains", "NVIDIA verdict token signatures",
              "NVIDIA verdict (challenge, overall result)", "NVIDIA verdict per GPU", "recorded build"):
        assert rows[n] == "PASS", n
    assert "Intermediate 004 (pinned)" in _detail(c, "NVIDIA verdict token signatures")
    assert "O=chutes" in _detail(c, "machine 1 (in_csa26tchk) signature over the evidence"), "the operator is named from its own CA"
    assert "tee-vm-2026-09-20" in _detail(c, "recorded build") and "RTMR1+RTMR2+RTMR3 recomputed" in _detail(c, "recorded build")
    # The permanent limits are SKIP rows, printed every time, and never make the receipt 'incomplete'.
    assert rows["GPU confidential-computing mode"] == "SKIP" and rows["not recomputed"] == "SKIP"
    # The fixture predates preamble_path, so the older-client rows follow the permanent ones (Kimi round 22).
    assert [d for s, n, d in c.rows if n == "not recomputed"] == list(V.NOT_RECOMPUTED) + list(V.OLDER_CLIENT_NOT_RECORDED)


def test_legacy_receipt_rechecks_offline_rows_and_is_incomplete_not_failed(tmp_path):
    b = _bundle(tmp_path, "legacy")
    searches = [{"session_id": "fixture-legacy", "at": "2026-10-31T13:58:30Z"}, {"session_id": "fixture-legacy", "at": "2026-10-31T14:00:10Z"},
                {"session_id": "another-session", "at": "2026-10-31T10:00:00Z"}]
    [(name, c, ok)] = V.verify_bundle(str(b), searches)
    rows = _rows(c)
    assert name == LEGACY and not c.failed, c.failed
    assert not ok, "a receipt that kept no collateral is not fully re-checked"
    assert set(V.blocking_skips(c)) == {"Intel collateral (TCB info, QE identity, CRLs)", "NVIDIA verdict tokens"}
    assert rows["instance switches vs pins"] == "PASS" and "11 switch(es) = 12 pin(s)" in _detail(c, "instance switches vs pins")
    assert "2 distinct machine(s)" in _detail(c, "every pinned machine has an evidence row")
    assert rows["searches inside the session's verified window"] == "PASS" and "2 search(es)" in _detail(c, "searches inside the session's verified window")
    assert rows["GPU certificate chains"] == "PASS" and "GB100" in _detail(c, "GPU certificate chains")
    assert sum(1 for s, n, _ in c.rows if n.startswith("machine ") and "quote signed by Intel" in n and s == "PASS") == 2


# ───────────────────────── mutants ─────────────────────────

def test_wrong_nonce_fails_the_challenge_and_everything_bound_to_it(tmp_path):
    b = _bundle(tmp_path, "fresh")
    _mutate(b, FRESH, lambda att: att["checked_with"].__setitem__("challenge", "cd" * 32))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert not ok and rows["machine 1 (in_csa26tchk) fresh challenge answered"] == "FAIL"
    assert rows["machine 1 (in_csa26tchk) sealing key bound to the enclave"] == "FAIL"
    assert rows["NVIDIA verdict (challenge, overall result)"] == "FAIL" and "DIFFERENT challenge" in _detail(c, "NVIDIA verdict (challenge, overall result)")


def test_debug_bit_set_fails_tdx_shape(tmp_path):
    b = _bundle(tmp_path, "fresh")
    _mutate(b, FRESH, lambda att: _edit_quote(att, lambda q: q.__setitem__(48 + 120, q[48 + 120] | 0x01)))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert not ok and rows["machine 1 (in_csa26tchk) genuine TDX, debug off"] == "FAIL"
    assert "DEBUG bit is SET" in _detail(c, "machine 1 (in_csa26tchk) genuine TDX, debug off")
    # editing the signed body also breaks the enclave's signature over it, as it must
    assert rows["machine 1 (in_csa26tchk) signature over the evidence"] == "FAIL"


def test_tampered_quote_fails_intel_signature_and_build(tmp_path):
    b = _bundle(tmp_path, "fresh")
    _mutate(b, FRESH, lambda att: _edit_quote(att, lambda q: q.__setitem__(48 + 136, q[48 + 136] ^ 0xFF)))   # MRTD byte
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert not ok and rows["machine 1 (in_csa26tchk) quote signed by Intel's Quoting Enclave"] == "FAIL"
    # the quote now names measurements nobody recorded: not this file's list, and not the row the receipt carries
    assert rows["recorded build"] == "FAIL" and "DIFFERENT measurements" in _detail(c, "recorded build")


def test_unrecorded_refused_pending_and_signed_builds(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    b = _bundle(tmp_path, "fresh")
    r = json.loads((b / FRESH).read_text())
    m = r["attestation"]["build"]
    key = {k: m[k] for k in ("mrtd", "rtmr1", "rtmr2", "rtmr3")}
    # 1. not recorded anywhere, and the receipt carries no row
    monkeypatch.setattr(V, "RECORDED_BUILDS", [])
    _mutate(b, FRESH, lambda att: att.__setitem__("build", {}))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and _rows(c)["recorded build"] == "FAIL" and "no signed row" in _detail(c, "recorded build")
    # 2. refused by InferRoute
    monkeypatch.setattr(V, "RECORDED_BUILDS", [{"id": "x", "status": "refused", "refused_on": "2026-11-01", "refused_because": "test", **key}])
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and "REFUSED by InferRoute" in _detail(c, "recorded build")
    # 3. an unsigned run-time row in the receipt is not InferRoute's record
    monkeypatch.setattr(V, "RECORDED_BUILDS", [])
    _mutate(b, FRESH, lambda att: att.__setitem__("build", {"id": "rt-1", "status": "pending", "origin": "relay", **key}))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and "UNSIGNED run-time row" in _detail(c, "recorded build")
    # 4. the same row signed by the (test-pinned) offline key passes, named as such
    sk = Ed25519PrivateKey.generate()
    pub_hex = sk.public_key().public_bytes_raw().hex()
    row = {"id": "rt-1", "status": "signed", **key}
    row["sig"] = sk.sign(V._signed_bytes(row)).hex()
    monkeypatch.setattr(V, "SIGNING_KEYS", (pub_hex,))
    _mutate(b, FRESH, lambda att: att.__setitem__("build", dict(row)))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert ok and "signed by InferRoute's offline publication key" in _detail(c, "recorded build")
    # 5. ... and a signature under some OTHER key does not
    monkeypatch.setattr(V, "SIGNING_KEYS", (Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and "UNSIGNED" in _detail(c, "recorded build")


def test_bad_gpu_token_fails_nvidia_signature(tmp_path):
    b = _bundle(tmp_path, "fresh")

    def tamper(att):
        per = att["collateral"]["nvidia"]["response"][1]
        h, p, s = per["GPU-0"].split(".")
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        claims["dbgstat"] = "enabled"
        p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        per["GPU-0"] = f"{h}.{p2}.{s}"
    _mutate(b, FRESH, tamper)
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert not ok and rows["NVIDIA verdict token signatures"] == "FAIL" and "GPU-0" in _detail(c, "NVIDIA verdict token signatures")
    assert rows["NVIDIA verdict per GPU"] == "FAIL"


def test_token_signed_under_an_unpinned_intermediate_fails(tmp_path, monkeypatch):
    b = _bundle(tmp_path, "fresh")
    monkeypatch.setattr(V, "NVIDIA_NRAS_SIGNING_SPKI_SHA256", {"00" * 32: "nobody"})
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and "not a pinned NVIDIA Attestation Service intermediate" in _detail(c, "NVIDIA verdict token signatures")


def test_gpu_chain_to_an_unpinned_root_fails(tmp_path, monkeypatch):
    b = _bundle(tmp_path, "fresh")
    monkeypatch.setattr(V, "NVIDIA_DEVICE_ROOT_SPKI_SHA256", "00" * 32)
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and _rows(c)["GPU certificate chains"] == "FAIL"


def test_collateral_fetched_long_after_the_pin_fails(tmp_path):
    b = _bundle(tmp_path, "fresh")
    _mutate(b, FRESH, lambda att: att["collateral"]["nvidia"].__setitem__("fetched_at", "2026-11-02T12:31:51Z"))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and _rows(c)["machine 1 (in_csa26tchk) collateral fetched at the pin"] == "FAIL"


def test_intel_collateral_tampering_fails(tmp_path):
    b = _bundle(tmp_path, "fresh")

    def tamper(att):
        t = att["collateral"]["intel"]["tcb_info"]
        att["collateral"]["intel"]["tcb_info"] = t.replace('"tcbStatus":"UpToDate"', '"tcbStatus":"UpToDATE"', 1)
    _mutate(b, FRESH, tamper)
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and _rows(c)["Intel TCB info"] == "FAIL"


def test_missing_evidence_file_fails_unless_the_receipt_itself_carries_the_same_bytes(tmp_path):
    b = _bundle(tmp_path, "fresh")
    r = json.loads((b / FRESH).read_text())
    (b / r["served_by"][0]["attestation_file"]).unlink()
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert ok and "the receipt's own attestation row" in _detail(c, "evidence row 1 (in_csa26tchk)"), "same sha256, same evidence"
    r["attestation"]["certificate"] = r["attestation"]["certificate"][:-8] + "AAAAAAAA"
    (b / FRESH).write_text(json.dumps(r))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and _rows(c)["evidence row 1 (in_csa26tchk)"] == "FAIL"


def test_evidence_file_that_does_not_hash_to_the_receipt_fails(tmp_path):
    b = _bundle(tmp_path, "fresh")
    r = json.loads((b / FRESH).read_text())
    f = b / r["served_by"][0]["attestation_file"]
    f.write_bytes(f.read_bytes().replace(b'"tee_type"', b'"tee_typo"', 1))
    [(_, c, ok)] = V.verify_bundle(str(b), [])
    assert not ok and "does not hash to the sha256" in _detail(c, "evidence row 1 (in_csa26tchk)")


def test_searches_outside_the_window_or_in_a_refused_session_fail(tmp_path):
    b = _bundle(tmp_path, "legacy")
    [(_, c, _ok)] = V.verify_bundle(str(b), [{"session_id": "fixture-legacy", "at": "2026-10-31T13:57:00Z"}])
    assert _rows(c)["searches inside the session's verified window"] == "FAIL", "a search before the first verified machine"
    [(_, c, _ok)] = V.verify_bundle(str(b), [{"session_id": "fixture-legacy", "at": "2026-10-31T15:00:00Z"}])
    assert _rows(c)["searches inside the session's verified window"] == "FAIL", "a search after the session"
    r = json.loads((b / LEGACY).read_text())
    r["verdict"], r["refusal"] = "refused", "test"
    (b / LEGACY).write_text(json.dumps(r))
    [(_, c, _ok)] = V.verify_bundle(str(b), [{"session_id": "fixture-legacy", "at": "2026-10-31T13:58:30Z"}])
    assert "never verified" in _detail(c, "searches inside the session's verified window")


def test_counters_that_contradict_the_pins_fail(tmp_path):
    b = _bundle(tmp_path, "legacy")
    r = json.loads((b / LEGACY).read_text())
    r["counters"]["instance_switches"] = 40
    r["counters"]["requests"] = 1000
    (b / LEGACY).write_text(json.dumps(r))
    [(_, c, _ok)] = V.verify_bundle(str(b), [])
    rows = _rows(c)
    assert rows["instance switches vs pins"] == "FAIL" and rows["requests credited per machine"] == "FAIL"


def test_a_receipt_of_another_schema_or_a_broken_file_never_passes(tmp_path):
    b = tmp_path / "x"
    b.mkdir()
    (b / "session-a.receipt.json").write_text(json.dumps({"schema": "something/else", "session_id": "a"}))
    (b / "session-b.receipt.json").write_text("{not json")
    out = V.verify_bundle(str(b), [])
    assert [ok for _, _, ok in out] == [False, False] and all(c.failed for _, c, _ in out)


# ───────────────────────── the copies this file carries ─────────────────────────

def test_pins_and_recorded_builds_match_the_client():
    from inferroute_local.confidential import attest_intel, attest_nvidia, builds
    ident = ("id", "status", "mrtd", "rtmr1", "rtmr2", "rtmr3")
    assert [{k: b.get(k) for k in ident} for b in V.RECORDED_BUILDS] == [{k: b.get(k) for k in ident} for b in builds.BUNDLED], \
        "verify_ai_receipt.RECORDED_BUILDS must be updated with builds.BUNDLED"
    assert V.SIGNING_KEYS == builds.SIGNING_KEYS and V.SIGNED_PURPOSE == builds.SIGNED_PURPOSE
    for b in builds.BUNDLED:
        assert V._signed_bytes(b) == builds.signed_bytes(b)
    assert V.INTEL_SGX_ROOT_SPKI_SHA256 == attest_intel.INTEL_ROOT_SPKI_SHA256
    assert V.ACCEPTED_TCB == attest_intel.ACCEPTED_TCB
    assert V.REQUIRED_GPU_CLAIMS == attest_nvidia.REQUIRED_GPU_CLAIMS


def test_verifier_is_standalone_and_imports_nothing_of_ours():
    src = (PI / "verify_ai_receipt.py").read_text()
    assert "inferroute" not in [m.split(".")[0] for m in __import__("re").findall(r"^\s*(?:from|import)\s+([\w.]+)", src, flags=__import__("re").M)]


# ───────────────────────── wired into verify_record.py ─────────────────────────

def test_verify_record_prints_the_optional_section_without_touching_its_verdict(tmp_path, capsys, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("verify_record_under_test", PI / "verify_record.py")
    R = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(R)
    b = _bundle(tmp_path, "fresh")
    out = R.report_ai_receipts(str(b), [])
    text = capsys.readouterr().out
    assert out == {"receipts": 1, "ok": 1, "failed": 0}
    assert "OPTIONAL section" in text and "PASS NVIDIA verdict per GPU" in text and "1 of 1 fully re-checked offline" in text
    assert "remain the device's word" in text
    monkeypatch.setattr(R, "_load_ai_receipt_verifier", lambda: None)
    assert R.report_ai_receipts(str(b), []) is None
    assert "NOT re-checked" in capsys.readouterr().out
    assert R.report_ai_receipts(str(tmp_path / "empty-nonexistent"), []) is None


def test_export_ships_the_receipt_verifier_beside_verify_record():
    from inferroute_cli import probant_export as E
    src = (Path(E.__file__).resolve().parent / "pi_attested" / "verify_ai_receipt.py")
    assert src.exists()
    assert 'files["verify_ai_receipt.py"]' in Path(E.__file__).read_text()


def test_the_plain_ai_paragraph_never_overclaims_what_the_rows_do_not_establish():
    """Reviewed wording (2 Nov): the device's own account is marked as such; NVIDIA's token is not called a check of
    confidential mode; the unmeasured program and its key custody are named; no outcome words."""
    import importlib.util, pathlib
    p = pathlib.Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"
    spec = importlib.util.spec_from_file_location("vr_ai_plain", p); V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    t = V.PLAIN_AI_LANE
    assert "only the app's own claim" in t and "not an independent audit" in t and "nothing in it shows that your text was exposed, and nothing in it shows that it was not" in t and "says nothing about whether the chips were in their confidential-computing mode" in t
    assert "is not among the software the machine's report measures" in t and "holds the key" in t and "the AI operator" in t
    assert "The matched entry does not say how InferRoute obtained the firmware measurement" in t and "the record carries that statement, not the recalculation" in t and "was not compared by this record" in t  and "genuine Intel TDX machine" in t
    low = t.lower()
    assert not [w for w in V.PLAIN_FORBIDDEN if w.lower() in low]
    for bad in ("nvidia's own service checked", "carried only sealed data", "stayed private", "was protected.",
                "is protected", "are protected"):
        assert bad not in low, bad
    # Audit 1102-ai-r2: no corporate "confirmed", the key binding is stated, Chutes is a seller not InferRoute's operator,
    # and the search link is always stated with what it rests on.
    assert "nvidia confirmed" not in low and "confirm nothing" not in low and "runs these machines for inferroute" not in low
    assert "of the public key that messages to it are encrypted to" in t and "necessarily reads every message in plain text" in t and "gateway" in t and "legally responsible" in t and "nothing from the machines that this record can re-check shows that they received yours" in t
    assert "and it is the key the app says it used" not in t  # audit r3: no welding of measurement to the app's word
    assert V.plain_ai_lane(0).endswith(V.PLAIN_AI_SEARCHES_NONE)
    # Independent review (fable, 2 Nov): the paragraph carries this session's own numbers, says where the private key
    # is NOT shown to be, and names Intel's status whenever it is not plainly up to date.
    assert "does not show where the matching private key was made or kept" in t and "which InferRoute account sent them" in t
    f = {"requests": 3, "machines": 2, "start": "2026-11-02T09:00:00Z", "end": "2026-11-02T09:05:00Z", "tcb": ["UpToDate"]}
    up = V.plain_ai_lane(0, f)
    assert "this conversation began sending 3 request(s)" in up and "the app selected 2 distinct machine(s) for it" in up and V.PLAIN_AI_TCB_HARDENING not in up
    # Second code-reading review: no "actually read" for an empty session; refusal surfaced; build sentence from the row;
    # a missing counter is said, not printed as "?"; a run-time signed row claims no recalculation.
    empty = V.plain_ai_lane(0, dict(f, requests=0))
    assert "recorded no request sent in it" in empty and "your text" not in empty and "would have been addressed" in empty and "would have carried" in empty
    ref = V.plain_ai_lane(0, dict(f, refused=True, refused_at="2026-11-02T09:03:00Z"))
    assert "found none it could trust, at 2 Nov 2026, 09:03:00 UTC" in ref and "stopped trusting" not in up
    # Code-reading review 4 (MATERIAL): a non-confidential verdict with no event must not claim a window check.
    bare = V.plain_ai_lane(0, dict(f, refused=True, refused_at=""))
    assert V.PLAIN_AI_VERDICT_ONLY in bare and "lies inside the conversation's time window" not in bare
    assert "on 2 Nov 2026, from 09:00:00 to 09:05:00 UTC" in up
    # Review 9 (MATERIAL x2): a recorded stop is not the end of sending; the operator's program gets the app's note,
    # with the full home path from clients before 0.9.126.
    assert "does not check whether the app sent further requests after that moment" in V.plain_ai_lane(0, dict(f, refused=True, refused_at="2026-11-02T09:03:00Z"))
    # Review 11: the receipt's own 'preamble_path' field decides, not the version number.
    assert "account name" in V.plain_ai_lane(0, dict(f, writer="ir 0.9.126")) and "account name" not in V.plain_ai_lane(0, dict(f, preamble_path="home-relative"))
    assert "would also have sent it a note" in V.plain_ai_lane(0, dict(f, requests=0))
    # Review 8 (MATERIAL x2): no relay billing sentence on the direct carrier; the stop time is the stop event's.
    d8 = V.plain_ai_lane(0, dict(f, transport="direct to the enclave operator (your own key — InferRoute is not in the path)"))
    assert "billing report" not in d8 and "billing report" in up
    both = V.ai_session_facts({"verdict": "degraded", "refusal": "no verified alternative", "events": [
        {"kind": "reverify-failed", "ts": "2026-11-02T10:05:00Z"}, {"kind": "no-eligible-instance", "ts": "2026-11-02T10:09:00Z"}]}, [])
    assert both["stopped_at"] == "2026-11-02T10:09:00Z"
    # Review 7 (MATERIAL x2): credited machines are distinct instances, never more than selected.
    re_pin = V.ai_session_facts({"counters": {"requests": 4}, "served_by": [{"instance": {"id": "i-a"}, "attestation_sha256": "x", "requests": 2},
                                {"instance": {"id": "i-a"}, "attestation_sha256": "y", "requests": 2}], "verdict": "confidential"}, [])
    assert re_pin["machines"] == 1 and re_pin["credited"] == 1
    # Review 6 (MATERIAL x4): credited machines; the app's own stop reason and time; Intel/NVIDIA lookups from the
    # user's computer; the signing key is committed, not shown to be inside.
    cr = V.plain_ai_lane(0, dict(f, machines=3, credited=2))
    assert "selected 3 distinct machine(s) for it and records 2 of them as the machine(s) it addressed those requests to" in cr
    st = V.plain_ai_lane(0, dict(f, refused=True, why="the enclave could not be re-verified 3 times in a row.", stopped_at="2026-11-02T09:04:00Z"))
    assert "at 2 Nov 2026, 09:04:00 UTC because, by its own record, the enclave could not be re-verified 3 times in a row;" in st
    assert V.PLAIN_AI_LOOKUPS in up and "signed from inside the machine" not in up and "where its private half was kept is, again, not shown" in up
    # Review 5 (MATERIAL x2): a direct carrier names no InferRoute relay; a run-time build claims no shipped list.
    direct = V.plain_ai_lane(0, dict(f, transport="direct to the enclave operator (your own key — InferRoute is not in the path)"))
    assert "InferRoute operates a relay" not in direct and "straight to the AI operator's gateway" in direct
    assert "InferRoute operates a relay" in up and "straight to" not in up
    rt2 = V.plain_ai_lane(0, dict(f, builds=[("runtime", ())]))
    assert "as InferRoute's list stood" not in rt2 and "carried in a row InferRoute signed" in rt2
    assert "for every machine" in up and "for at least one machine" in V.plain_ai_lane(0, dict(f, tcb=["UpToDate", "SWHardeningNeeded"], tcb_uniform=False))
    nocount = V.plain_ai_lane(0, dict(f, requests=None))
    assert "carries no count of requests" in nocount and "? request" not in nocount
    rt = V.plain_ai_lane(0, dict(f, builds=[("runtime", ())]))
    assert V.PLAIN_AI_BUILD_RUNTIME in rt and "recalculated them itself" not in rt
    two = V.plain_ai_lane(0, dict(f, builds=[("bundled", ("RTMR1",))]))
    assert "For one of the four measurements InferRoute states that it recalculated it itself" in two and "The matched entry does not say how InferRoute obtained the firmware measurement, measurement three and measurement four" in two
    facts = V.ai_session_facts({"counters": {"requests": 2}, "served_by": [{"attestation_sha256": "a"}, {"attestation_sha256": "b"},
                                {"attestation_sha256": "a"}], "verdict": "confidential", "started_at": "s", "last_activity_at": "e"},
                               [("PASS", "machine 1 (x) recorded build", "build b (current), recorded by InferRoute since d; RTMR1+RTMR2+RTMR3 recomputed by InferRoute from the operator's published artifacts; MRTD 1…"),
                                ("PASS", "Intel TCB status (platform)", "FMSPC f, status SWHardeningNeeded (level d)")])
    assert facts["machines"] == 2 and facts["requests"] == 2 and not facts["refused"] and facts["tcb"] == ["SWHardeningNeeded"]
    assert facts["builds"] == [("bundled", ("RTMR1", "RTMR2", "RTMR3"))]
    assert V.PLAIN_AI_TCB_HARDENING in V.plain_ai_lane(0, dict(f, tcb=["UpToDate", "SWHardeningNeeded"]))
    assert "\n\n" in up and up.endswith(V.PLAIN_AI_SEARCHES_NONE)
    two = V.plain_ai_lane(2)
    assert "links 2 of the patent searches" in two and "not that they came from the conversation" in two
    for tail in (V.PLAIN_AI_SEARCHES_NONE, V.PLAIN_AI_SEARCHES_LINKED):
        assert not [w for w in V.PLAIN_FORBIDDEN if w.lower() in tail.lower()]


def test_a_stop_after_failed_rechecks_bounds_linked_searches():
    """Code-reading audit 7: _reverify stops a session (verdict 'degraded') with 'reverify-failed' events and no
    'refused' event; a search linked after the last of them must FAIL, as the plain words say the app stopped there."""
    receipt = {"verdict": "degraded", "started_at": "2026-11-02T10:00:00Z", "last_activity_at": "2026-11-02T10:20:00Z",
               "events": [{"kind": "pinned", "ts": "2026-11-02T10:00:05Z", "detail": "i-a"},
                          {"kind": "reverify-failed", "ts": "2026-11-02T10:10:00Z", "detail": "x (1 in a row)"},
                          {"kind": "reverify-failed", "ts": "2026-11-02T10:12:00Z", "detail": "x (3 in a row)"}]}
    for at, ok in (("2026-11-02T10:11:00Z", True), ("2026-11-02T10:15:00Z", False)):
        c = V.Checks()
        V.check_receipt_consistency(c, receipt, [], [{"at": at, "session_id": "s"}])
        row = [r for r in c.rows if r[1] == "searches inside the session's verified window"]
        assert row and (row[0][0] == "PASS") is ok, (at, row)


def test_an_exported_receipt_writes_home_as_tilde():
    """Code-reading audit 12: the record goes to third parties; the receipt's 'path' carried the account name."""
    import json as _json, os
    from inferroute_cli.probant_export import _home_relative_receipt_path
    home = os.path.expanduser("~")
    raw = _json.dumps({"path": os.path.join(home, ".inferroute/confidential/receipts/x.json"), "verdict": "confidential"}).encode()
    out = _json.loads(_home_relative_receipt_path(raw))
    assert out["path"] == "~/.inferroute/confidential/receipts/x.json" and out["verdict"] == "confidential"
    assert _home_relative_receipt_path(b'{"path": "/srv/x.json"}') == b'{"path": "/srv/x.json"}'


def test_a_search_after_a_resumed_session_is_inside_the_window():
    """Code-reading audit 13: a session can resume after 'no-eligible-instance' by pinning again; a search after
    that new pin is inside the window, one between the stop and the new pin is not."""
    receipt = {"verdict": "degraded", "started_at": "2026-11-02T10:00:00Z", "last_activity_at": "2026-11-02T10:30:00Z",
               "events": [{"kind": "pinned", "ts": "2026-11-02T10:00:05Z", "detail": "i-a"},
                          {"kind": "no-eligible-instance", "ts": "2026-11-02T10:10:00Z", "detail": "x"},
                          {"kind": "pinned", "ts": "2026-11-02T10:20:00Z", "detail": "i-b"}]}
    for at, ok in (("2026-11-02T10:15:00Z", False), ("2026-11-02T10:25:00Z", True)):
        c = V.Checks()
        V.check_receipt_consistency(c, receipt, [], [{"at": at, "session_id": "s"}])
        row = [r for r in c.rows if r[1] == "searches inside the session's verified window"]
        assert row and (row[0][0] == "PASS") is ok, (at, row)


def test_a_failed_receipt_outranks_an_incomplete_one_in_the_exit_code(tmp_path, capsys):
    """Review of 9eecef6 (3 Nov): the exit code was the numeric maximum over receipts, so a folder holding one
    receipt that FAILED and one that was only INCOMPLETE exited 4 — and the FAIL read as "could not be re-checked".
    A FAIL anywhere is exit 1. The tampered receipt sorts FIRST here, which is the order the old rule got wrong."""
    b = _bundle(tmp_path, "fresh")
    _mutate(b, FRESH, lambda att: att["checked_with"].__setitem__("challenge", "cd" * 32))
    for f in (FIX / "legacy").iterdir():
        shutil.copy(f, b / f.name)
    results = V.verify_bundle(str(b))
    by_name = {n: (c, ok) for n, c, ok in results}
    assert by_name[FRESH][0].failed and not by_name[LEGACY][0].failed and not by_name[LEGACY][1]
    assert sorted(by_name) == [FRESH, LEGACY]
    assert V.exit_code(results) == 1
    assert V.main([str(b)]) == 1
    assert V.exit_code([r for r in results if r[0] == LEGACY]) == 4
    ok_only = V.verify_bundle(str(_bundle(tmp_path / "ok", "fresh")))
    assert V.exit_code(ok_only) == 0


# ───────────────────────── a conversation that moved machines (reviews of 5c26ff3 and 00a6650) ─────────────────────────
#
# Each receipt is judged on its OWN leg. The rows a switch carries into the next leg's receipt are information about
# the earlier leg, never evidence that widens a window; every leg's receipt travels in the record and a search is
# judged on the leg that was serving at its time.

def _chain(n_legs: int = 2, *, leg1_stops_at=None, last_leg_requests: int = 2) -> tuple:
    """Legs of one conversation built by the REAL continuity._record_switch, oldest first, as receipt dicts. Leg k
    opens at -1000+300k s (relative to now, because _record_switch stamps its own note with the current time), pins
    5 s later, and is switched into 200 s after it opened; the last leg's activity runs to +5 s."""
    import dataclasses
    import datetime as _dt
    from types import SimpleNamespace
    from inferroute_local.confidential import continuity as Cont
    from inferroute_local.confidential.receipt import Receipt
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    t = lambda s: (now + _dt.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")     # noqa: E731
    legs = []
    for k in range(n_legs):
        base = -1000 + 300 * k
        r = Receipt(session_id=f"leg{k + 1}:m{k + 1}", model_short=f"m{k + 1}", upstream_model=f"m{k + 1}",
                    fleet_id=f"f{k + 1}", transport="relay", started_at=t(base), verified_at=t(base + 5))
        r.events = [{"ts": t(base), "kind": "continuity-open", "detail": f"serving from m{k + 1}"},
                    {"ts": t(base + 5), "kind": "pinned", "detail": f"in_{k + 1} — session opened"}]
        reqs = last_leg_requests if k == n_legs - 1 else 3
        r.served_by = [{"at": t(base + 5), "instance": {"id": f"in_{k + 1}"}, "attestation_sha256": f"{k + 1:02d}" * 32,
                        "requests": reqs}]
        r.counters["requests"] = reqs
        r.verdict = "confidential"
        if k == 0 and leg1_stops_at is not None:
            r.events.append({"ts": t(leg1_stops_at), "kind": "no-eligible-instance", "detail": "no verified alternative"})
        if k:
            prev = legs[-1]
            r.events.append({"ts": t(base + 200), "kind": "switched", "detail": f"m{k} -> m{k + 1} (timeout)"})
            Cont.Continuity._record_switch(SimpleNamespace(active=SimpleNamespace(receipt=r), switches=k),
                                           SimpleNamespace(receipt=prev, model_short=f"m{k}"))
            prev.last_activity_at = t(base + 199)
        legs.append(r)
    legs[-1].last_activity_at = t(5)
    return [dataclasses.asdict(r) for r in legs], t


def _bundle_of(tmp_path: Path, legs: list) -> Path:
    d = tmp_path / "rec"
    d.mkdir()
    for k, r in enumerate(legs[:-1], 1):
        (d / f"session-S.leg-{k}.receipt.json").write_text(json.dumps(r))
    (d / "session-S.receipt.json").write_text(json.dumps(legs[-1]))
    return d


def _search_row(results, name):
    return next(s for s, n, _ in next(c for f, c, _ in results if f == name).rows
                if n == "searches inside the session's verified window")


def test_a_last_leg_built_by_the_real_switch_passes_its_own_timeline_and_keeps_carried_rows_as_information():
    legs, t = _chain(2)
    d = legs[-1]
    carried = [e for e in d["events"] if e.get("from_previous_session")]
    assert carried and min(e["ts"] for e in carried) < d["started_at"]
    assert not any(e["kind"] == "pinned" for e in carried), "a pin is not carried: it would widen nothing now"
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [])
    rows = _rows(c)
    assert rows["receipt timeline"] == "PASS" and rows["earlier legs carried in"] == "PASS", c.rows
    assert "Information only" in _detail(c, "earlier legs carried in")
    assert rows["continuity switches vs switched events"] == "PASS"
    assert not c.failed


def test_the_last_leg_alone_never_vouches_for_a_search_made_on_an_earlier_leg():
    legs, t = _chain(2)
    c = V.Checks()
    V.check_receipt_consistency(c, legs[-1], [], [{"at": t(-900)}])          # leg 1 served; leg 2 not yet open
    assert _rows(c)["searches inside the session's verified window"] == "FAIL"


def test_a_search_on_leg_one_is_judged_on_leg_one_s_receipt_and_passes(tmp_path):
    legs, t = _chain(2)
    d = _bundle_of(tmp_path, legs)
    given = V.searches_by_receipt(str(d), [{"session_id": "S", "at": t(-900)}, {"session_id": "S", "at": t(-400)}])
    assert [s["at"] for s in given["session-S.leg-1.receipt.json"]] == [t(-900)]
    assert [s["at"] for s in given["session-S.receipt.json"]] == [t(-400)]
    results = V.verify_bundle(str(d), [{"session_id": "S", "at": t(-900)}, {"session_id": "S", "at": t(-400)}])
    assert _search_row(results, "session-S.leg-1.receipt.json") == "PASS"
    assert _search_row(results, "session-S.receipt.json") == "PASS"


def test_a_search_in_the_dead_gap_after_leg_one_stopped_fails(tmp_path):
    """Round 3 (00a6650): leg 1 pinned, then stopped (no eligible instance); the next leg began serving later. A search
    between the two ran while no verified machine served. It falls to leg 1, where it is after the stop: FAIL."""
    legs, t = _chain(2, leg1_stops_at=-950)
    d = _bundle_of(tmp_path, legs)
    results = V.verify_bundle(str(d), [{"session_id": "S", "at": t(-850)}])
    assert _search_row(results, "session-S.leg-1.receipt.json") == "FAIL"
    assert V.exit_code(results) == 1


def test_three_legs_keep_three_distinct_leg_ids():
    legs, _t = _chain(3)
    last = legs[-1]
    rows = {r.get("from_previous_session") for r in last["served_by"]}
    evs = {e.get("from_previous_session") for e in last["events"] if e.get("from_previous_session")}
    assert rows == {"leg1:m1", "leg2:m2", None} and evs == {"leg1:m1", "leg2:m2"}
    c = V.Checks()
    V.check_receipt_consistency(c, last, [], [])
    assert "from 2 earlier leg(s)" in _detail(c, "earlier legs carried in")
    assert _rows(c)["continuity switches vs switched events"] == "PASS"
    assert last["counters"]["continuity_switches"] == 2


def test_a_last_leg_with_no_requests_of_its_own_passes_the_credited_row():
    legs, _t = _chain(2, last_leg_requests=0)
    c = V.Checks()
    V.check_receipt_consistency(c, legs[-1], [], [])
    assert _rows(c)["requests credited per machine"] == "PASS", c.rows
    # and a last leg crediting too few of ITS OWN requests is not hidden by the carried rows' credit
    legs, _t = _chain(2)
    legs[-1]["counters"]["requests"] = 9
    c = V.Checks()
    V.check_receipt_consistency(c, legs[-1], [], [])
    assert _rows(c)["requests credited per machine"] == "FAIL"


def test_the_switch_counter_is_not_judged_on_a_receipt_from_before_events_were_carried():
    legs, _t = _chain(2)
    d = legs[-1]
    d["events"] = [e for e in d["events"] if not e.get("from_previous_session")]
    d["counters"]["continuity_switches"] = 2
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [])
    assert _rows(c)["continuity switches vs switched events"] == "SKIP"
    d["events"].append({"ts": d["events"][-1]["ts"], "kind": "carried", "detail": "x", "from_previous_session": "leg1:m1"})
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [])
    assert _rows(c)["continuity switches vs switched events"] == "FAIL"


def test_carried_events_out_of_order_are_still_caught():
    legs, _t = _chain(3)
    d = legs[-1]
    idx = [i for i, e in enumerate(d["events"]) if e.get("from_previous_session")]
    d["events"][idx[0]]["ts"], d["events"][idx[-1]]["ts"] = d["events"][idx[-1]]["ts"], d["events"][idx[0]]["ts"]
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [])
    assert _rows(c)["earlier legs carried in"] == "FAIL"


# ───────────────────────── review of a14e349 ─────────────────────────

def test_a_missing_leg_cannot_be_stood_in_for_by_the_next_one(tmp_path):
    """The standby pins when it is warmed (-695 here), long before the switch (-500). With leg 1's receipt absent its
    searches fell to leg 2 and passed on leg 2's early pin. Now the last leg's switches say leg 1 served until -500, and a
    search there is given to no receipt: never a PASS. Since review of c5156d2 it is "not re-checked" (SKIP, exit 4), not
    FAIL: the receipt is absent, and nothing present contradicts anything present."""
    legs, t = _chain(2)
    only_last = tmp_path / "last"
    only_last.mkdir()
    (only_last / "session-S.receipt.json").write_text(json.dumps(legs[-1]))
    results = V.verify_bundle(str(only_last), [{"session_id": "S", "at": t(-900)}, {"session_id": "S", "at": t(-600)}])
    c = results[0][1]
    gap = _detail(c, V.SEARCHES_IN_MISSING_LEG)
    assert _rows(c)[V.SEARCHES_IN_MISSING_LEG] == "SKIP" and gap.startswith("not re-checked: 2 search(es) fall in leg 1")
    assert "nothing here shows which machine served them" in gap and t(-600) in gap
    assert _detail(c, "a receipt for every leg") == "not re-checked: leg 1's receipt is not in this record (a record " \
        "exported before receipts were carried for each leg holds one receipt per session)"
    assert not [r for r in c.rows if r[1] == "searches inside the session's verified window" and r[0] == "PASS"]
    assert not [r for r in c.rows if r[1] in V.MISSING_LEG_ROWS and r[0] != "SKIP"]
    assert V.exit_code([r for r in results]) in (1, 4)            # 1 only for the fixture's absent evidence files
    assert not [d for st, n, d in c.rows if st == "FAIL" and n in ("searches inside the session's verified window",)
                + V.MISSING_LEG_ROWS]
    full = V.verify_bundle(str(_bundle_of(tmp_path, legs)), [{"session_id": "S", "at": t(-600)}])
    assert _search_row(full, "session-S.leg-1.receipt.json") == "PASS"
    assert next(c for n, c, _ in full if n == "session-S.receipt.json").rows[-1][:2] == ("PASS", "a receipt for every leg")


def test_a_switched_in_leg_s_window_opens_at_the_switch_not_at_its_standby_pin():
    legs, t = _chain(2)
    c = V.Checks()
    V.check_receipt_consistency(c, legs[-1], [], [{"at": t(-600)}])           # after its pin (-695), before the switch
    assert _rows(c)["searches inside the session's verified window"] == "FAIL"
    c = V.Checks()
    V.check_receipt_consistency(c, legs[-1], [], [{"at": t(-400)}])
    assert _rows(c)["searches inside the session's verified window"] == "PASS"
    assert "the switch that moved the conversation here" in _detail(c, "searches inside the session's verified window")


def test_every_stop_is_honoured_not_only_the_first():
    r = {"verdict": "degraded", "started_at": "2026-11-03T09:00:00Z", "last_activity_at": "2026-11-03T09:06:40Z",
         "events": [{"kind": "pinned", "ts": "2026-11-03T09:00:00Z", "detail": "a"},
                    {"kind": "no-eligible-instance", "ts": "2026-11-03T09:01:40Z", "detail": "gone"},
                    {"kind": "pinned", "ts": "2026-11-03T09:03:20Z", "detail": "b"},
                    {"kind": "no-eligible-instance", "ts": "2026-11-03T09:05:00Z", "detail": "gone again"}]}
    for at, ok in (("2026-11-03T09:00:50Z", True), ("2026-11-03T09:02:30Z", False), ("2026-11-03T09:04:10Z", True),
                   ("2026-11-03T09:05:50Z", False)):
        c = V.Checks()
        V.check_receipt_consistency(c, r, [], [{"at": at}])
        assert (_rows(c)["searches inside the session's verified window"] == "PASS") is ok, at


def test_without_the_last_leg_no_search_can_pass_and_leg_numbers_sort_as_numbers(tmp_path):
    """Earlier legs with no last leg: their serving times are unknown, so no search is placed on one. Not re-checked
    (never PASS, never a FAIL for the absence)."""
    d = tmp_path / "rec"
    d.mkdir()
    for k in (1, 2):
        (d / f"session-S.leg-{k}.receipt.json").write_text(json.dumps({"schema": V.SCHEMA, "session_id": f"x{k}"}))
    results = V.verify_bundle(str(d), [{"session_id": "S", "at": "2026-11-03T09:00:00Z"}])
    rows = [r for _n, c, _ok in results for r in c.rows]
    assert ("SKIP", V.SEARCHES_IN_MISSING_LEG) in [(s_, n) for s_, n, _d in rows]
    assert any(s_ == "SKIP" and n == "a receipt for every leg" and "the last leg's receipt is not in this record" in det
               for s_, n, det in rows)
    assert not any(s_ == "PASS" and n == "searches inside the session's verified window" for s_, n, _d in rows)
    assert V._leg_number("session-S.leg-10.receipt.json") == 10 and V._leg_number("session-S.receipt.json") == 0


def test_the_plain_words_of_a_last_leg_with_no_requests_of_its_own_count_only_that_leg():
    import importlib.util, pathlib
    p = pathlib.Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"
    spec = importlib.util.spec_from_file_location("vr_ai_leg", p)
    VR = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(VR)
    legs, _t = _chain(2, last_leg_requests=0)
    f = VR.ai_session_facts(legs[-1], [])
    assert f["leg"] and f["requests"] == 0 and f["machines"] == 1 and f["credited"] == 0
    txt = VR.plain_ai_lane(1, f)
    assert VR.PLAIN_AI_LEG_INDEX in txt and "the one for this conversation" not in txt
    assert "no text of yours reached any of them in this leg," in txt and "this leg of the conversation's id" not in txt
    assert "this check gave 1 of them to this leg by their times" in txt and "The app's own list links 1 of" not in txt
    low = txt.lower()
    assert not [w for w in VR.PLAIN_FORBIDDEN if w.lower() in low]
    single = VR.plain_ai_lane(1, dict(f, leg=False))
    assert "the one for this conversation" in single and "links 1 of the patent searches" in single


# ───────────────────────── review of 24f5c42 ─────────────────────────

def _vr():
    import importlib.util, pathlib
    p = pathlib.Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"
    spec = importlib.util.spec_from_file_location("vr_r5", p)
    VR = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(VR)
    return VR


def test_leg_one_is_described_as_a_leg_and_its_window_ends_at_the_switch_off_it(tmp_path):
    """Leg 1 has no carried rows and no switch counter, so it read as the whole conversation; and its window ran to its
    last save, which is stamped when the conversation closes. The bundle says it is a leg and when it was moved off."""
    VR = _vr()
    legs, t = _chain(2)
    legs[0]["last_activity_at"] = t(0)                       # stamped at the conversation's close
    d = _bundle_of(tmp_path, legs)
    lf = V.leg_facts(str(d))
    one = lf["session-S.leg-1.receipt.json"]
    assert one["leg"] and one["index"] == 1 and one["of"] == 2 and one["ends"] == V._parse_time(t(-500))
    f = VR.ai_session_facts(legs[0], [], one)
    assert f["leg"] and f["end"] == t(-500)
    txt = VR.plain_ai_lane(0, f)
    assert txt.startswith("About one leg of your conversation") and "this leg of the conversation began sending" in txt
    # the verifier never gives leg 1 a search after the switch, whatever its last save says
    given = V.searches_by_receipt(str(d), [{"session_id": "S", "at": t(-450)}])
    assert given["session-S.leg-1.receipt.json"] == [] and len(given["session-S.receipt.json"]) == 1
    # a single-leg conversation is not called a leg anywhere
    one_only = tmp_path / "single"
    one_only.mkdir()
    (one_only / "session-T.receipt.json").write_text(json.dumps(legs[0] | {"events": [e for e in legs[0]["events"]]}))
    assert V.leg_facts(str(one_only))["session-T.receipt.json"]["leg"] is False


def test_a_run_of_failed_rechecks_is_a_stop_and_a_passing_recheck_resumes():
    r = {"verdict": "degraded", "started_at": "2026-11-03T09:00:00Z", "last_activity_at": "2026-11-03T09:10:00Z",
         "refusal": "the enclave could not be re-verified 3 times in a row — refusing to continue on stale evidence",
         "events": [{"kind": "pinned", "ts": "2026-11-03T09:00:00Z", "detail": "a"},
                    {"kind": "no-eligible-instance", "ts": "2026-11-03T09:01:00Z", "detail": "gone"},
                    {"kind": "pinned", "ts": "2026-11-03T09:02:00Z", "detail": "b"},
                    {"kind": "reverify-failed", "ts": "2026-11-03T09:03:00Z", "detail": "x (1 in a row)"},
                    {"kind": "reverify-failed", "ts": "2026-11-03T09:03:30Z", "detail": "x (2 in a row)"},
                    {"kind": "reverify-failed", "ts": "2026-11-03T09:04:00Z", "detail": "x (3 in a row)"},
                    {"kind": "reverified", "ts": "2026-11-03T09:06:00Z", "detail": "4/4 instances verified"},
                    {"kind": "reverified", "ts": "2026-11-03T09:08:00Z", "detail": "3/4 instances verified"},
                    {"kind": "pinned-failed-reverify", "ts": "2026-11-03T09:08:00Z", "detail": "b"}]}
    stops = V.leg_stops(r)
    assert [s[0] for s in stops] == [V._parse_time("2026-11-03T09:01:00Z"), V._parse_time("2026-11-03T09:04:00Z")]
    assert stops[0][1] == V.NO_ELIGIBLE_WHY and stops[1][1] == r["refusal"]
    for at, ok in (("2026-11-03T09:01:30Z", False), ("2026-11-03T09:02:30Z", True), ("2026-11-03T09:05:00Z", False),
                   ("2026-11-03T09:07:00Z", True),                 # the re-check passed at 09:06: resumed
                   ("2026-11-03T09:09:00Z", False)):               # the 09:08 re-check dropped the pinned machine
        c = V.Checks()
        V.check_receipt_consistency(c, r, [], [{"at": at}])
        assert (_rows(c)["searches inside the session's verified window"] == "PASS") is ok, at
    # the plain words list each stop with ITS OWN reason
    VR = _vr()
    txt = VR.plain_ai_lane(0, VR.ai_session_facts(r, []))
    assert "more than once: at 3 Nov 2026, 09:01:00 UTC, because the verified instance is gone" in txt
    assert "; at 3 Nov 2026, 09:04:00 UTC, because the enclave could not be re-verified 3 times in a row" in txt
    one = dict(r, events=r["events"][:2], refusal="the verified instance is gone and no verified alternative is available")
    f = VR.ai_session_facts(one, [])
    assert f["stopped_at"] == "2026-11-03T09:01:00Z" and f["why"].startswith("the verified instance is gone")


def test_an_old_single_receipt_record_is_not_failed_for_the_leg_it_never_carried(tmp_path, capsys):
    """A record exported before receipts travelled per leg carries one receipt per session. With no search in the leg
    it lacks, that leg is not re-checked (exit 4), not FAILED, and the plain words for the receipt that IS here print."""
    b = _bundle(tmp_path, "fresh")
    p = b / FRESH
    r = json.loads(p.read_text())
    sw = r["started_at"]
    r["events"] = r["events"] + [{"ts": sw, "kind": "switched", "detail": "m1 -> m2 (fleet)"}]
    r["events"].sort(key=lambda e: e["ts"])
    r.setdefault("counters", {})["continuity_switches"] = 1
    p.write_text(json.dumps(r))
    results = V.verify_bundle(str(b), [])
    c = results[0][1]
    assert _rows(c)["a receipt for every leg"] == "SKIP" and not c.failed, c.failed
    assert _detail(c, "a receipt for every leg").startswith("not re-checked: leg 1's receipt is not in this record (a record")
    assert V.exit_code(results) == 4
    VR = _vr()
    VR.report_ai_receipts(str(b), [])
    out = capsys.readouterr().out
    assert "another leg of its conversation was not re-checked" in out and "In plain words" in out
    assert "FAILED" not in out and "contradict" not in out
    # The pack-level line says incomplete too, in the same terms: never VERIFIED, never FAILED.
    assert "AI receipts: incomplete (not re-checked: leg 1's receipt is not in this record)" in out
    assert VR._AI_LANE_VERIFIED is False and VR._AI_LANE_MISSING_LEGS == ["leg 1's receipt is not in this record"]
    VR.report_confidentiality([], reference=None, floor_pinned=False, revocation_checked=False, authenticated=False,
                              record_ok=False)
    agg = capsys.readouterr().out
    assert "AI session receipts: incomplete (not re-checked: leg 1's receipt is not in this record)" in agg
    assert "NOT VERIFIED" not in agg.split("SCOPE", 1)[1].split("\n", 1)[0]
    assert "FAILED" not in agg.split("SCOPE", 1)[1].split("\n", 1)[0]


def test_two_switches_in_the_same_second_stay_two_legs(tmp_path):
    legs, t = _chain(3)
    same = [e for e in legs[1]["events"] if e["kind"] == "switched"][0]["ts"]
    for e in legs[2]["events"]:
        if e["kind"] == "switched" and not e.get("from_previous_session"):
            e["ts"] = same                                     # leg 3 promoted in the very second leg 2 was
    legs[2]["started_at"] = min(legs[2]["started_at"], same)
    d = _bundle_of(tmp_path, legs)
    lf = V.leg_facts(str(d))
    assert [lf[n]["index"] for n in ("session-S.leg-1.receipt.json", "session-S.leg-2.receipt.json",
                                     "session-S.receipt.json")] == [1, 2, 3]
    c = next(c for n, c, _ in V.verify_bundle(str(d), []) if n == "session-S.receipt.json")
    assert _rows(c)["a receipt for every leg"] == "PASS"


# ───────────────────────── review of c5156d2 ─────────────────────────

def _old_single_last_leg(tmp_path):
    """The fresh fixture made into a last leg whose first leg's receipt the record does not carry (a record exported
    before receipts travelled per leg)."""
    b = _bundle(tmp_path, "fresh")
    p = b / FRESH
    r = json.loads(p.read_text())
    r["events"] = sorted(r["events"] + [{"ts": r["started_at"], "kind": "switched", "detail": "m1 -> m2 (fleet)"}],
                         key=lambda e: e["ts"])
    r.setdefault("counters", {})["continuity_switches"] = 1
    p.write_text(json.dumps(r))
    sid = FRESH[len("session-"):-len(".receipt.json")]
    before = (V._parse_time(r["started_at"]) - __import__("datetime").timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return b, sid, before


def test_an_old_single_receipt_record_with_a_search_in_the_missing_leg_is_incomplete_never_failed(tmp_path, capsys):
    b, sid, before = _old_single_last_leg(tmp_path)
    searches = [{"session_id": sid, "at": before}]
    results = V.verify_bundle(str(b), searches)
    c = results[0][1]
    assert not c.failed, c.failed
    assert _rows(c)[V.SEARCHES_IN_MISSING_LEG] == "SKIP" and _rows(c)["a receipt for every leg"] == "SKIP"
    assert V.exit_code(results) == 4
    VR = _vr()
    VR.report_ai_receipts(str(b), searches)
    out = capsys.readouterr().out
    assert "FAILED" not in out and "contradict" not in out and "In plain words" in out
    assert "the searches made during that leg were not re-checked either" in out
    VR.report_confidentiality([], reference=None, floor_pinned=False, revocation_checked=False, authenticated=False,
                              record_ok=False)
    scope = capsys.readouterr().out.split("SCOPE", 1)[1].split("\n", 1)[0]
    assert "incomplete (not re-checked: leg 1's receipt is not in this record)" in scope
    assert "NOT VERIFIED" not in scope and "FAILED" not in scope


def test_a_leg_moved_off_ends_at_the_switch_in_the_verifier_and_the_plain_words(tmp_path):
    VR = _vr()
    legs, t = _chain(2)
    d = _bundle_of(tmp_path, legs)
    res = V.verify_bundle(str(d), [{"session_id": "S", "at": t(-900)}])
    c = next(c for n, c, _ in res if n == "session-S.leg-1.receipt.json")
    assert ") and the switch that moved the conversation off it (" in _detail(c, "searches inside the session's verified window")
    last = next(c for n, c, _ in res if n == "session-S.receipt.json")
    assert _detail(last, "searches inside the session's verified window").endswith("to this leg")
    f = VR.ai_session_facts(legs[0], [], V.leg_facts(str(d))["session-S.leg-1.receipt.json"])
    txt = VR.plain_ai_lane(1, f)
    assert "This leg's end is the moment the app recorded moving the conversation off it." in txt
    assert "writes the end time when it last touched the record" not in txt
    assert "between the time this leg's machine began serving and the switch that moved the conversation off it (" in txt
    lastf = VR.ai_session_facts(legs[-1], [], V.leg_facts(str(d))["session-S.receipt.json"])
    assert "writes the end time when it last touched the record" in VR.plain_ai_lane(0, lastf)


def test_the_not_carried_per_leg_note_appears_only_for_a_single_receipt_session(tmp_path):
    legs, t = _chain(3)
    d = tmp_path / "rec"
    d.mkdir()
    (d / "session-S.leg-1.receipt.json").write_text(json.dumps(legs[0]))
    (d / "session-S.receipt.json").write_text(json.dumps(legs[2]))
    c = next(c for n, c, _ in V.verify_bundle(str(d), []) if n == "session-S.receipt.json")
    assert _detail(c, "a receipt for every leg") == "not re-checked: leg 2's receipt is not in this record"


def test_a_passing_recheck_resumes_only_a_recheck_stop_and_many_stops_name_the_last():
    r = {"verdict": "degraded", "started_at": "2026-11-03T09:00:00Z", "last_activity_at": "2026-11-03T09:10:00Z",
         "events": [{"kind": "pinned", "ts": "2026-11-03T09:00:00Z", "detail": "a"},
                    {"kind": "no-eligible-instance", "ts": "2026-11-03T09:01:00Z", "detail": "gone"},
                    {"kind": "reverified", "ts": "2026-11-03T09:02:00Z", "detail": "4/4 instances verified"}]}
    c = V.Checks()
    V.check_receipt_consistency(c, r, [], [{"at": "2026-11-03T09:03:00Z"}])
    assert _rows(c)["searches inside the session's verified window"] == "FAIL"
    VR = _vr()
    assert "after the last of those stops" in VR.PLAIN_AI_STOPPED_MANY and "after that moment" not in VR.PLAIN_AI_STOPPED_MANY


def test_a_malformed_receipt_is_a_fail_row_not_a_traceback(tmp_path):
    for bad, says in (({"events": 5}, "'events' is a int"),
                      ({"served_by": [{"instance": "in_x", "attestation_sha256": "ab" * 32}]}, "'served_by[0].instance' is a str")):
        r = {"schema": V.SCHEMA, "session_id": "s", "started_at": "2026-11-03T09:00:00Z", **bad}
        c, ok = V.verify_receipt(r)
        assert not ok and _rows(c)["malformed receipt"] == "FAIL" and says in _detail(c, "malformed receipt")
        d = tmp_path / f"b{len(says)}"
        d.mkdir()
        (d / "session-S.receipt.json").write_text(json.dumps(r))
        res = V.verify_bundle(str(d), [{"session_id": "S", "at": "2026-11-03T09:00:00Z"}])
        assert res and V.exit_code(res) == 1
        assert V.main([str(d)]) == 1
