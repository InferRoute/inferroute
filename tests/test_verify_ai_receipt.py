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
    assert [d for s, n, d in c.rows if n == "not recomputed"] == list(V.NOT_RECOMPUTED)


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
