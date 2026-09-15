"""The bundled independent verifier, proven against REAL Azure evidence (public Microsoft samples in
tests/fixtures/aci, see SOURCE.md) under PRODUCTION pins — and shown to refuse tampering, forged identity,
test roots without consent, empty bundles, and unlisted files. This is the file a stranger runs; if it
passed bad evidence or failed good evidence the whole record would be worthless.

Exit codes under test: 0 production pass; 1 any failure; 2 refused; 3 test-roots pass.
"""
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures" / "aci"
SCRIPT = HERE.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_record", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def V():
    return _load()


@pytest.fixture(scope="module")
def kms():
    return json.load(open(FIX / "kms-snp.json"))


def _pem(certs):
    from cryptography.hazmat.primitives import serialization
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def test_standalone_has_no_inferroute_imports():
    """The verifier must be auditable as a single file with exactly one third-party dependency."""
    import ast
    src = SCRIPT.read_text()
    assert "sealedresearch" not in src and "inferroute_cli" not in src and "inferroute_local" not in src
    allowed = {"base64", "hashlib", "json", "os", "struct", "sys", "typing", "cryptography", "datetime", "argparse",
               "warnings", "__future__"}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_real_amd_chain_and_uvm_verify_under_production_pins(V, kms):
    report = base64.b64decode(kms["evidence"])
    p = V.parse_report(report)
    certs = V.load_certs(base64.b64decode(kms["endorsements"]))
    c = V.Checks()
    V.check_amd(c, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256)
    meas = V.check_uvm(c, base64.b64decode(kms["uvm_endorsements"]), V.MS_UVM_ROOT_SHA256_B64URL, V.UVM_MIN_SVN)
    assert c.failed == [], c.rows
    assert meas is not None and p["measurement"] == meas
    names = {n for _, n, _ in c.rows}
    for must in ("AMD root pinned", "report signature", "VCEK is for this chip", "VCEK is for this firmware",
                 "UVM root is Microsoft's", "UVM endorsement signature", "debug disabled", "report from VMPL 0",
                 "AMD certificates in date"):
        assert must in names
    # a firmware-TCB floor is SKIP when none is pinned, PASS when met, FAIL when not
    assert ("SKIP", "firmware TCB at or above minimum") in {(s, n) for s, n, _ in c.rows}
    c2 = V.Checks()
    V.check_amd(c2, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256, min_tcb={"Milan": {"snpSPL": 8, "ucodeSPL": 115}})
    assert "firmware TCB at or above minimum" not in c2.failed
    c3 = V.Checks()
    V.check_amd(c3, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256, min_tcb={"Milan": {"snpSPL": 99}})
    assert "firmware TCB at or above minimum" in c3.failed


def test_real_host_data_is_the_policy(V):
    p = V.parse_report((FIX / "sidecar-snp_report.bin").read_bytes())
    pol = (FIX / "sidecar-uvm_security_policy.base64").read_text().strip()
    assert hashlib.sha256(base64.b64decode(pol)).hexdigest() == p["host_data"].hex()


def test_tampered_report_and_wrong_pin_are_refused(V, kms):
    report = bytearray(base64.b64decode(kms["evidence"]))
    certs = V.load_certs(base64.b64decode(kms["endorsements"]))
    report[0x90] ^= 1
    c = V.Checks()
    V.check_amd(c, V.parse_report(bytes(report)), _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256)
    assert "report signature" in c.failed
    c2 = V.Checks()
    V.check_amd(c2, V.parse_report(base64.b64decode(kms["evidence"])), _pem(certs[:1]), _pem(certs[1:]),
                {k: "00" * 32 for k in V.AMD_ARK_SPKI_SHA256})
    assert "AMD root pinned" in c2.failed
    c3 = V.Checks()
    V.check_uvm(c3, base64.b64decode(kms["uvm_endorsements"]), "AAAA" * 10 + "AAA", V.UVM_MIN_SVN)
    assert "UVM root is Microsoft's" in c3.failed and "UVM issuer pinned" in c3.failed


# ───────────────────────────── a synthetic bundle over REAL hardware evidence ─────────────────────────────

def _synthetic_bundle(tmp_path, V, kms, *, break_result=False, break_query=False, break_manifest=False,
                      rd_override=None, no_searches=False, extra_unlisted=False, listed_ok=True):
    """Real AMD/UVM evidence (kms sample) with a statement signed by a fresh key committed in a runtime_data we
    control. The REAL report was not produced over our runtime data, so REPORT_DATA must FAIL here — the
    point is every OTHER check, and that a FAIL there is never hidden."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    rd = {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8, "statement_signer_pub": pub,
          "enclave_x25519_pub": "cd" * 32, "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32,
          "index_snapshot": "us-2026-09", "pipeline_version": "t"}
    rd_bytes = json.dumps(rd).encode() if rd_override is None else rd_override
    rid = "0123456789abcdef0123456789abcdef"
    query = "A battery housing with coolant channels between cells."
    result = {"hits": [{"key": "US-7000-B2", "title": "x"}], "candidates": 5}
    st = {"v": 1, "kind": "search", "lifetime_id": rd["lifetime_id"], "request_id": rid,
          "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(), "index_manifest_sha256": rd["index_manifest_sha256"],
          "model_manifest_sha256": rd["model_manifest_sha256"], "cutoff_date": 20200115, "hits_n": 1, "outcome": "answered",
          "query_sha256": V.salted(rid, query), "result_sha256": V.salted(rid, result)}
    st["sig"] = key.sign(V.canonical(st)).hex()
    offer = {"evidence": kms["evidence"], "endorsements": kms["endorsements"], "uvm_endorsements": kms["uvm_endorsements"],
             "runtime_data": base64.b64encode(rd_bytes).decode()}
    ev_bytes = json.dumps({"offer": offer}, indent=1).encode()
    ev_sha = hashlib.sha256(ev_bytes).hexdigest()
    if break_result:
        result = {**result, "candidates": 6}
    if break_query:
        query = query + " (edited)"
    d = tmp_path / "bundle"
    d.mkdir(parents=True)
    (d / f"{ev_sha[:16]}.evidence.json").write_bytes(ev_bytes)
    row = {"n": 1, "session_id": "s1", "at": "t", "statement": st, "result": result, "query_text": query, "signer_pub": pub,
           "evidence_file": f"{ev_sha[:16]}.evidence.json", "evidence_sha256": ev_sha}
    (d / "searches.json").write_text(json.dumps([] if no_searches else [row]))
    (d / "record.html").write_text("<html>record</html>")
    (d / "VERIFY.md").write_text("# verify\n")
    (d / "verify_record.py").write_bytes(SCRIPT.read_bytes())
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    if break_manifest:
        files["record.html"] = "00" * 32
    if extra_unlisted:
        (d / "TAMPERED.html").write_text("TAMPERED RECORD")             # present, not listed
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))
    ref = {"policy_sha256": [V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()],
           "index_manifest_sha256": [rd["index_manifest_sha256"]], "model_manifest_sha256": [rd["model_manifest_sha256"]],
           "source": "test", "published_at": "2026-09-15"}
    (tmp_path / "reference.json").write_text(json.dumps(ref))
    return d


def _run(d, *extra):
    r = subprocess.run([sys.executable, str(SCRIPT), str(d), *extra], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def test_cli_binds_query_result_date_and_identity(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    code, out = _run(d, "--reference", str(tmp_path / "reference.json"))
    for must in ("PASS bundle integrity", "PASS statement signature", "PASS signer key committed in runtime data",
                 "PASS statement matches enclave commitments", "PASS query text is the one searched",
                 "PASS result is the signed result", "PASS hit count as signed", "PASS date bound the enclave was given",
                 "PASS AMD root pinned", "PASS UVM endorsement signature", "PASS report from VMPL 0",
                 "PASS enclave identity"):
        assert must in out, (must, out)
    assert "FAIL REPORT_DATA binds runtime data" in out         # the real report was not made over OUR runtime data
    assert code == 1 and "RESULT: FAILED" in out


def test_identity_fails_without_a_reference_and_with_a_wrong_one(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    code, out = _run(d)
    assert "FAIL enclave identity" in out and "NO REFERENCE SUPPLIED" in out and code == 1
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"policy_sha256": ["00" * 32], "index_manifest_sha256": ["ef" * 32], "model_manifest_sha256": ["12" * 32]}))
    code, out = _run(d, "--reference", str(wrong))
    assert "FAIL enclave identity" in out and "policy: no entry matches" in out and code == 1


def test_cli_refuses_changed_result_query_manifest_and_unlisted_files(tmp_path, V, kms):
    for kw, expect in (({"break_result": True}, "FAIL result is the signed result"),
                       ({"break_query": True}, "FAIL query text is the one searched"),
                       ({"break_manifest": True}, "FAIL bundle integrity"),
                       ({"extra_unlisted": True}, "present-but-unlisted ['TAMPERED.html']")):
        d = _synthetic_bundle(tmp_path / expect.replace(" ", "_").replace("'", "").replace("[", "").replace("]", ""), V, kms, **kw)
        code, out = _run(d, "--reference", str(d.parent / "reference.json"))
        assert expect in out and code == 1, (expect, out)


def test_empty_bundle_is_not_a_pass(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms, no_searches=True)
    code, out = _run(d, "--reference", str(tmp_path / "reference.json"))
    assert "FAIL sealed searches: this record contains NO sealed search" in out and code == 1


def test_binding_rows_never_vanish_on_bad_runtime_data(tmp_path, V, kms):
    # falsy-but-valid object, an array, and garbage: all must produce FAIL rows, never a missing row or a traceback
    for rd in (b"{}", b"[1,2,3]", b"not json"):
        d = _synthetic_bundle(tmp_path / hashlib.sha256(rd).hexdigest()[:8], V, kms, rd_override=rd)
        code, out = _run(d, "--reference", str(d.parent / "reference.json"))
        assert "FAIL signer key committed in runtime data" in out, out
        assert "Traceback" not in out and code == 1


def test_test_roots_require_consent_and_never_exit_zero(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    code, out = _run(d, "--amd-pin", "Milan=" + "00" * 32)
    assert code == 2 and "REFUSED" in out and "--i-am-testing" in out
    code, out = _run(d, "--amd-pin", "Milan=" + "00" * 32, "--i-am-testing", "--reference", str(tmp_path / "reference.json"))
    assert "NON-PRODUCTION ROOTS PINNED" in out and code != 0


def test_extract_writes_raw_files_for_independent_tools(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    _run(d, "--reference", str(tmp_path / "reference.json"), "--extract", str(tmp_path / "raw"))
    sd = tmp_path / "raw" / "search-1"
    assert (sd / "report.bin").stat().st_size == 1184
    assert b"BEGIN CERTIFICATE" in (sd / "vcek.pem").read_bytes() and b"BEGIN CERTIFICATE" in (sd / "ask_ark.pem").read_bytes()
    assert (sd / "uvm_endorsement.cose").stat().st_size > 100 and json.loads((sd / "runtime_data.json").read_text())["v"] == 1


# ───────────────────── reference validity, signed reference, completeness ─────────────────────

def _multi_bundle(tmp_path, V, kms, seqs, started="2026-06-01T12:00:00Z"):
    """Several statements from ONE enclave lifetime (same runtime_data / signer), with given seq numbers."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    rd = {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8, "statement_signer_pub": pub,
          "enclave_x25519_pub": "cd" * 32, "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32}
    rd_bytes = json.dumps(rd).encode()
    offer = {"evidence": kms["evidence"], "endorsements": kms["endorsements"], "uvm_endorsements": kms["uvm_endorsements"],
             "runtime_data": base64.b64encode(rd_bytes).decode()}
    ev_bytes = json.dumps({"offer": offer}, indent=1).encode()
    ev_sha = hashlib.sha256(ev_bytes).hexdigest()
    d = tmp_path / "bundle"
    d.mkdir(parents=True)
    (d / f"{ev_sha[:16]}.evidence.json").write_bytes(ev_bytes)
    rows = []
    for i, seq in enumerate(seqs, 1):
        rid = f"{i:032x}"
        q, res = f"query {i}", {"hits": [{"key": f"US-{i}-A"}]}
        st = {"v": 1, "kind": "search", "lifetime_id": rd["lifetime_id"], "request_id": rid, "started_utc": started,
              "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(), "index_manifest_sha256": rd["index_manifest_sha256"],
              "model_manifest_sha256": rd["model_manifest_sha256"], "cutoff_date": 20200115, "hits_n": 1, "outcome": "answered",
              "query_sha256": V.salted(rid, q), "result_sha256": V.salted(rid, res)}
        if seq is not None:
            st["seq"] = seq
        st["sig"] = key.sign(V.canonical(st)).hex()
        rows.append({"n": i, "session_id": "s1", "at": "t", "statement": st, "result": res, "query_text": q, "signer_pub": pub,
                     "evidence_file": f"{ev_sha[:16]}.evidence.json", "evidence_sha256": ev_sha})
    (d / "searches.json").write_text(json.dumps(rows))
    (d / "record.html").write_text("<html>record</html>")
    (d / "VERIFY.md").write_text("# verify\n")
    (d / "verify_record.py").write_bytes(SCRIPT.read_bytes())
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))
    host = V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()
    return d, host, rd


def _ref(tmp_path, name, policy_entries, idx="ef" * 32, mdl="12" * 32, sign_with=None):
    ref = {"policy_sha256": policy_entries, "index_manifest_sha256": [idx], "model_manifest_sha256": [mdl],
           "source": "test", "published_at": "2026-01-01"}
    if sign_with is not None:
        from importlib import import_module
        V = _load()
        ref["sig"] = sign_with.sign(V.canonical(ref)).hex()
    p = tmp_path / name
    p.write_text(json.dumps(ref))
    return p


def test_reference_validity_windows_and_retired_entries(tmp_path, V, kms):
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1])
    # current entry with a window that contains the search time → identity passes
    ok = _ref(tmp_path, "ok.json", [{"value": host, "valid_from": "2026-01-01T00:00:00Z", "valid_to": "2026-12-31T23:59:59Z"}])
    _, out = _run(d, "--reference", str(ok))
    assert "PASS enclave identity" in out and "policy: current (valid 2026-01-01T00:00:00Z → 2026-12-31T23:59:59Z)" in out
    # retired entry → matches but is not current → FAIL, and it says so
    retired = _ref(tmp_path, "retired.json", [{"value": host, "retired": True}])
    _, out = _run(d, "--reference", str(retired))
    assert "FAIL enclave identity" in out and "matches a RETIRED entry" in out
    # window that ended before the search → FAIL with the reason
    old = _ref(tmp_path, "old.json", [{"value": host, "valid_to": "2026-03-01T00:00:00Z"}])
    _, out = _run(d, "--reference", str(old))
    assert "FAIL enclave identity" in out and "after its valid_to 2026-03-01T00:00:00Z" in out


def test_signed_reference_with_first_use_key(tmp_path, V, kms):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1])
    pubkey = Ed25519PrivateKey.generate()
    pub_hex = pubkey.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    signed = _ref(tmp_path, "signed.json", [host], sign_with=pubkey)
    _, out = _run(d, "--reference", str(signed), "--reference-key", pub_hex)
    assert "PASS reference signature" in out
    _, out = _run(d, "--reference", str(signed))                      # signed, but the reader gave no key
    assert "SKIP reference signature" in out and "no --reference-key" in out
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    code, out = _run(d, "--reference", str(signed), "--reference-key", other)
    assert "FAIL reference signature" in out and code == 1
    unsigned = _ref(tmp_path, "unsigned.json", [host])
    code, out = _run(d, "--reference", str(unsigned), "--reference-key", pub_hex)
    assert "FAIL reference signature" in out and "unsigned" in out and code == 1


def test_completeness_from_sequence_numbers(tmp_path, V, kms):
    host_ref = lambda tp, d_host: _ref(tp, "r.json", [d_host])       # noqa: E731
    d, host, _ = _multi_bundle(tmp_path / "ok", V, kms, seqs=[1, 2, 3])
    _, out = _run(d, "--reference", str(host_ref(tmp_path / "ok", host)))
    assert "PASS completeness (per-enclave sequence)" in out and "seq 1..3 contiguous (3 searches)" in out
    assert "dropped from the END" in out
    d, host, _ = _multi_bundle(tmp_path / "gap", V, kms, seqs=[1, 3])
    code, out = _run(d, "--reference", str(host_ref(tmp_path / "gap", host)))
    assert "FAIL completeness (per-enclave sequence)" in out and "missing [2]" in out and code == 1
    d, host, _ = _multi_bundle(tmp_path / "late", V, kms, seqs=[2, 3])
    _, out = _run(d, "--reference", str(host_ref(tmp_path / "late", host)))
    assert "FAIL completeness" in out and "starts at seq 2" in out
    d, host, _ = _multi_bundle(tmp_path / "none", V, kms, seqs=[None, None])
    _, out = _run(d, "--reference", str(host_ref(tmp_path / "none", host)))
    assert "SKIP completeness (per-enclave sequence)" in out and "no sequence numbers" in out
