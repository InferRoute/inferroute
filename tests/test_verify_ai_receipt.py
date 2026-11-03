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


# ───────────────────────── a conversation that moved machines (review of 5c26ff3) ─────────────────────────

def _switched_receipt(*, drop_carried_row: bool = False) -> tuple:
    """A last leg built by the REAL continuity._record_switch from two real Receipts: leg 1 opened, pinned and
    warmed a standby; leg 2 (the standby) pinned its own machine; then the lane switched. Times are relative to
    now, because _record_switch stamps its own note with the current time."""
    import dataclasses
    import datetime as _dt
    from types import SimpleNamespace
    from inferroute_local.confidential import continuity as Cont
    from inferroute_local.confidential.receipt import Receipt
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    t = lambda s: (now + _dt.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")     # noqa: E731
    old = Receipt(session_id="leg1:glm-5.2", model_short="glm-5.2", upstream_model="glm-5.2", fleet_id="f1",
                  transport="relay", started_at=t(-600), verified_at=t(-590))
    old.events = [{"ts": t(-600), "kind": "continuity-order", "detail": "glm-5.2 > kimi-k2.6"},
                  {"ts": t(-599), "kind": "continuity-open", "detail": "serving from glm-5.2"},
                  {"ts": t(-590), "kind": "pinned", "detail": "in_first — session opened"},
                  {"ts": t(-560), "kind": "standby-ready", "detail": "kimi-k2.6 verified and held in reserve"}]
    old.served_by = [{"at": t(-590), "instance": {"id": "in_first"}, "attestation_sha256": "11" * 32, "requests": 3}]
    old.counters["requests"] = 3
    new = Receipt(session_id="leg2:kimi-k2.6", model_short="kimi-k2.6", upstream_model="kimi-k2.6", fleet_id="f2",
                  transport="relay", started_at=t(-570), verified_at=t(-565))
    new.events = [{"ts": t(-565), "kind": "pinned", "detail": "in_second — session opened"}]
    new.served_by = [{"at": t(-565), "instance": {"id": "in_second"}, "attestation_sha256": "22" * 32, "requests": 2}]
    new.counters["requests"] = 2
    new.events.append({"ts": t(-1), "kind": "switched", "detail": "glm-5.2 -> kimi-k2.6 (timeout)"})
    Cont.Continuity._record_switch(SimpleNamespace(active=SimpleNamespace(receipt=new), switches=1),
                                   SimpleNamespace(receipt=old, model_short="glm-5.2"))
    new.last_activity_at = t(5)
    d = dataclasses.asdict(new)
    if drop_carried_row:
        d["served_by"] = [r for r in d["served_by"] if not r.get("from_previous_session")]
    return d, t


def test_a_last_leg_built_by_the_real_switch_passes_its_timeline_and_its_first_leg_searches():
    d, t = _switched_receipt()
    carried = [e for e in d["events"] if e.get("from_previous_session")]
    assert {e["kind"] for e in carried} >= {"continuity-order", "continuity-open", "pinned", "standby-ready"}
    # Carried events predate this leg's start: judged as the earlier leg's record, not against this leg's window.
    assert min(e["ts"] for e in carried) < d["started_at"]
    c = V.Checks()
    # A search made on leg 1, after leg 1's pin and BEFORE leg 2 pinned anything.
    V.check_receipt_consistency(c, d, [], [{"at": t(-580)}])
    rows = _rows(c)
    assert rows["receipt timeline"] == "PASS", c.rows
    assert rows["earlier legs carried in"] == "PASS", c.rows
    assert rows["searches inside the session's verified window"] == "PASS", c.rows
    assert rows["every pinned machine has an evidence row"] == "PASS", c.rows
    assert not c.failed


def test_carried_pins_open_the_window_only_when_the_carried_rows_back_them():
    d, t = _switched_receipt(drop_carried_row=True)
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [{"at": t(-580)}])
    rows = _rows(c)
    assert rows["earlier legs carried in"] == "FAIL"
    assert rows["searches inside the session's verified window"] == "FAIL"     # window stays at this leg's own pin


def test_carried_events_out_of_order_are_still_caught():
    d, t = _switched_receipt()
    idx = [i for i, e in enumerate(d["events"]) if e.get("from_previous_session")]
    d["events"][idx[0]]["ts"], d["events"][idx[-1]]["ts"] = d["events"][idx[-1]]["ts"], d["events"][idx[0]]["ts"]
    c = V.Checks()
    V.check_receipt_consistency(c, d, [], [])
    assert _rows(c)["earlier legs carried in"] == "FAIL"
