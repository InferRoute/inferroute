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

def _multi_bundle(tmp_path, V, kms, seqs, started="2026-06-01T12:00:00Z", omit_recipient=False):
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
        reply_priv = bytes([(i * 7 + j) % 256 for j in range(32)])          # a stand-in one-time reply key
        st = {"v": 1, "kind": "search", "lifetime_id": rd["lifetime_id"], "request_id": rid, "started_utc": started,
              "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(), "index_manifest_sha256": rd["index_manifest_sha256"],
              "model_manifest_sha256": rd["model_manifest_sha256"], "cutoff_date": 20200115, "hits_n": 1, "outcome": "answered",
              "query_sha256": V.salted(rid, q), "result_sha256": V.salted(rid, res)}
        if seq is not None:
            st["seq"] = seq
        if not omit_recipient:                       # an older enclave signed a VALID statement without it
            st["reply_to_sha256"] = hashlib.sha256(reply_priv).hexdigest()
        st["sig"] = key.sign(V.canonical(st)).hex()
        rows.append({"n": i, "session_id": "s1", "at": "t", "statement": st, "result": res, "query_text": q, "signer_pub": pub,
                     **({} if omit_recipient else {"reply_to": reply_priv.hex()}),
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
    # mirrors what `ir probant reference build` writes, schema included — a fixture that drifts from the
    # issuer tests a document nobody issues.
    ref = {"schema": "inferroute.enclave-reference/1",
           "policy_sha256": policy_entries, "index_manifest_sha256": [idx], "model_manifest_sha256": [mdl],
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
    assert "PASS enclave identity" in out
    assert "policy: current (valid 2026-01-01T00:00:00Z → 2026-12-31T23:59:59Z, search at 2026-06-01T12:00:00Z)" in out
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


# ───────────── reviewer's third pass: windows fail closed, real time comparison, completeness never silent ─────────────

def _bundle_with_statement_time(tmp_path, V, kms, started, no_lifetime=False):
    """One statement; `started` None omits started_utc entirely."""
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
    rid = "0" * 32
    q, res = "q", {"hits": [{"key": "US-1-A"}]}
    st = {"v": 1, "kind": "search", "request_id": rid, "seq": 1,
          "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(), "index_manifest_sha256": rd["index_manifest_sha256"],
          "model_manifest_sha256": rd["model_manifest_sha256"], "cutoff_date": 20200115, "hits_n": 1, "outcome": "answered",
          "query_sha256": V.salted(rid, q), "result_sha256": V.salted(rid, res)}
    if not no_lifetime:
        st["lifetime_id"] = rd["lifetime_id"]
    if started is not None:
        st["started_utc"] = started
    st["sig"] = key.sign(V.canonical(st)).hex()
    (d / "searches.json").write_text(json.dumps([{"n": 1, "session_id": "s", "at": "t", "statement": st, "result": res,
                                                  "query_text": q, "signer_pub": pub, "evidence_file": f"{ev_sha[:16]}.evidence.json",
                                                  "evidence_sha256": ev_sha}]))
    for n, body in (("record.html", "<html/>"), ("VERIFY.md", "#")):
        (d / n).write_text(body)
    (d / "verify_record.py").write_bytes(SCRIPT.read_bytes())
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))
    host = V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()
    return d, host


def test_a_windowed_entry_never_reads_current_without_a_statement_time(tmp_path, V, kms):
    d, host = _bundle_with_statement_time(tmp_path, V, kms, started=None)
    expired = _ref(tmp_path, "expired.json", [{"value": host, "valid_to": "2020-01-01T00:00:00Z"}])
    code, out = _run(d, "--reference", str(expired))
    assert "FAIL enclave identity" in out
    # the windowed POLICY entry must not read current; the unwindowed index/encoder entries legitimately do
    assert "policy: matches a windowed entry, but the statement carries no parsable time" in out
    # an unparsable statement time is the same refusal
    d2, host2 = _bundle_with_statement_time(tmp_path / "u", V, kms, started="yesterday-ish")
    _, out = _run(d2, "--reference", str(_ref(tmp_path / "u", "e.json", [{"value": host2, "valid_to": "2099-01-01T00:00:00Z"}])))
    assert "FAIL enclave identity" in out and "no parsable time" in out
    # an unparsable WINDOW is refused too
    d3, host3 = _bundle_with_statement_time(tmp_path / "w", V, kms, started="2026-06-01T12:00:00Z")
    _, out = _run(d3, "--reference", str(_ref(tmp_path / "w", "e.json", [{"value": host3, "valid_to": "not-a-time"}])))
    assert "FAIL enclave identity" in out and "does not parse as ISO-8601" in out


def test_window_comparison_is_a_time_comparison_not_a_string_one(tmp_path, V, kms):
    # 01:00 at +02:00 on the 15th is 23:00Z on the 14th: BEFORE a valid_from of 2026-09-15T00:00:00Z.
    # A string compare would sort it after and call it current.
    d, host = _bundle_with_statement_time(tmp_path, V, kms, started="2026-09-15T01:00:00+02:00")
    ref = _ref(tmp_path, "r.json", [{"value": host, "valid_from": "2026-09-15T00:00:00Z"}])
    _, out = _run(d, "--reference", str(ref))
    assert "FAIL enclave identity" in out and "predates its valid_from" in out
    # fractional seconds inside the window are current
    d2, host2 = _bundle_with_statement_time(tmp_path / "f", V, kms, started="2026-06-01T12:00:00.250Z")
    ref2 = _ref(tmp_path / "f", "r.json", [{"value": host2, "valid_from": "2026-01-01T00:00:00Z", "valid_to": "2026-12-31T00:00:00Z"}])
    _, out = _run(d2, "--reference", str(ref2))
    assert "PASS enclave identity" in out and "current (valid" in out


def test_completeness_is_never_silent_when_grouping_is_impossible(tmp_path, V, kms):
    d, host = _bundle_with_statement_time(tmp_path, V, kms, started="2026-06-01T12:00:00Z", no_lifetime=True)
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "SKIP completeness (per-enclave sequence)" in out and "carry no lifetime_id" in out


def test_completeness_wording_is_per_enclave_shown(tmp_path, V, kms):
    d, host, _ = _multi_bundle(tmp_path, V, kms, seqs=[1, 2])
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "every search of each enclave SHOWN" in out and "entire lifetime dropped" in out


def test_duplicate_values_are_all_evaluated_and_any_current_one_wins(tmp_path, V, kms):
    """A retired (or expired) entry listed before a current one for the SAME hash must not decide the verdict
    by list order — two releases sharing a manifest, or a reinstated policy, make this common."""
    d, host = _bundle_with_statement_time(tmp_path, V, kms, started="2026-06-01T12:00:00Z")
    retired_first = [{"value": host, "retired": True},
                     {"value": host, "valid_from": "2026-01-01T00:00:00Z", "valid_to": "2026-12-31T00:00:00Z"}]
    _, out = _run(d, "--reference", str(_ref(tmp_path, "rf.json", retired_first)))
    assert "PASS enclave identity" in out and "policy: current (valid 2026-01-01T00:00:00Z" in out
    _, out = _run(d, "--reference", str(_ref(tmp_path, "cf.json", list(reversed(retired_first)))))
    assert "PASS enclave identity" in out
    # an expired entry before a current one, both orders
    expired_first = [{"value": host, "valid_to": "2020-01-01T00:00:00Z"},
                     {"value": host, "valid_from": "2026-01-01T00:00:00Z"}]
    for order in (expired_first, list(reversed(expired_first))):
        _, out = _run(d, "--reference", str(_ref(tmp_path, "ef.json", order)))
        assert "PASS enclave identity" in out, out
    # and when NO matching entry is current, every reason is listed
    none_current = [{"value": host, "retired": True}, {"value": host, "valid_to": "2020-01-01T00:00:00Z"}]
    code, out = _run(d, "--reference", str(_ref(tmp_path, "nc.json", none_current)))
    assert code == 1 and "FAIL enclave identity" in out
    assert "matches a RETIRED entry" in out and "after its valid_to 2020-01-01T00:00:00Z" in out and "2 matching entries, none current" in out


def test_a_document_of_another_kind_is_not_a_reference(V):
    """A signature says "InferRoute wrote this", never "InferRoute meant it as a reference". Once the
    publication key signs anything else — a release note, a retrospective benchmark — a document carrying
    the right field names must not be readable as a reference just because the key checks out."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    impostor = {"schema": "inferroute.benchmark-result/1",
                "policy_sha256": "ab" * 32, "index_manifest_sha256": "cd" * 32}
    impostor["sig"] = key.sign(V.canonical(impostor)).hex()

    c = V.Checks()
    V.check_reference_signature(c, impostor, pub)
    assert c.failed, "a benchmark document signed by the publication key must not pass as a reference"
    assert any("another kind" in d for _, _, d in c.rows)

    # and the genuine kind still passes under the same key
    real = {"schema": V.REFERENCE_SCHEMA, "policy_sha256": "ab" * 32}
    real["sig"] = key.sign(V.canonical(real)).hex()
    c2 = V.Checks()
    V.check_reference_signature(c2, real, pub)
    assert not c2.failed


def test_a_hand_typed_unsigned_reference_is_still_usable(V):
    """Three hashes an attorney typed out of an engagement letter carry no schema and no signature. That is
    honest — the verifier already says trust rests on how it was obtained — and must not be refused as
    "the wrong kind of document". Only a SIGNED document needs to prove what kind it is."""
    c = V.Checks()
    V.check_reference_signature(c, {"policy_sha256": "ab" * 32}, None)
    assert not c.failed
    assert any("how you obtained it" in d for _, _, d in c.rows)

    c2 = V.Checks()                                   # signed but kindless: not something we issue
    V.check_reference_signature(c2, {"policy_sha256": "ab" * 32, "sig": "00" * 64}, "ab" * 32)
    assert c2.failed and any("no schema" in d for _, _, d in c2.rows)


def _remanifest(d):
    """Rebuild MANIFEST.json after editing a bundle, so a tamper test exercises the check it means to and
    not the file-hash check standing in front of it."""
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d) if n != "MANIFEST.json"}
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))


def test_the_bundle_shows_whether_a_second_copy_could_have_been_sealed(tmp_path, V, kms):
    """The enclave signs the recipient; the attorney's own proxy recorded the key it made. Equal, and the
    answer went to that one address. This is "only you can open it" as arithmetic rather than our word."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1])
    ref = _ref(tmp_path, "r.json", [host])
    # This fixture's evidence commits to its own runtime data, so the bundle never reaches exit 0 — assert
    # on the ROW, which is what this test is about. A code assertion here would be testing the fixture.
    code, out = _run(d, "--reference", str(ref))
    assert "PASS sealed to one recipient" in out

    rows = json.loads((d / "searches.json").read_text())
    rows[0]["reply_to"] = "aa" * 32                       # as if the answer had gone to a different address
    (d / "searches.json").write_text(json.dumps(rows))
    _remanifest(d)
    code, out = _run(d, "--reference", str(ref))
    assert "FAIL sealed to one recipient" in out and code == 1
    assert "NOT the key this record says was used" in out
    assert "PASS statement signature" in out, "only the recipient check may move; the statement is untouched"


def test_a_record_made_before_the_field_existed_skips_and_says_so(tmp_path, V, kms):
    """A record already made cannot be re-run. Failing it retroactively would punish the attorney for our
    version history — but it must not read as a passed check either. SKIP, naming what is unchecked. The
    LIVE path refuses instead, because there the search is still happening: same fact, different remedy
    (sealed-research tests/test_search_verifier.py)."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1], omit_recipient=True)
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r2.json", [host])))
    assert "SKIP sealed to one recipient" in out
    assert "predates the signed recipient key" in out
    assert "PASS statement signature" in out, "the older statement must still be a VALID statement"


def test_a_gap_the_device_can_explain_is_still_a_failure(tmp_path, V, kms):
    """The enclave takes its sequence number BEFORE it searches, so a request that times out leaves a
    permanent hole. The record may carry this device's account of that attempt — an unexplained gap reads as
    a deleted search, and those are very different things — but the account is the device's word, not proof,
    so the verdict must not move. Explained, still failed."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1, 3])
    ref = _ref(tmp_path, "r.json", [host])

    code, out = _run(d, "--reference", str(ref))
    assert "FAIL completeness" in out and "missing [2]" in out
    assert "never arrived" not in out, "nothing to explain the gap with yet"

    (d / "unanswered.json").write_text(json.dumps([{
        "session_id": "s1", "at": "2026-06-01T12:00:30Z", "request_id": "ab" * 8,
        "lifetime_id": rd["lifetime_id"], "reason": "TimeoutError after 300s"}]))
    _remanifest(d)
    code, out = _run(d, "--reference", str(ref))
    assert "FAIL completeness" in out, "an explanation must never turn a failure into a pass"
    assert "never arrived" in out and "TimeoutError after 300s" in out
    assert "not proof of what the missing search was" in out
    assert code == 1


def test_an_explanation_for_another_enclave_is_not_applied_here(tmp_path, V, kms):
    """An attempt recorded against a different enclave lifetime says nothing about this one's gap."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1, 3])
    (d / "unanswered.json").write_text(json.dumps([{
        "session_id": "s1", "at": "t", "request_id": "cd" * 8,
        "lifetime_id": "ff" * 8, "reason": "TimeoutError after 300s"}]))
    _remanifest(d)
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r2.json", [host])))
    assert "FAIL completeness" in out and "missing [2]" in out
    assert "never arrived" not in out, "an attempt on another enclave must not be offered as this gap's reason"


def _offer(V, kms, rd=None):
    rd = rd if rd is not None else {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8,
                                    "statement_signer_pub": "11" * 32, "enclave_x25519_pub": "22" * 32,
                                    "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32}
    return {"evidence": kms["evidence"], "endorsements": kms["endorsements"],
            "uvm_endorsements": kms["uvm_endorsements"],
            "runtime_data": base64.b64encode(json.dumps(rd).encode()).decode()}


def test_the_live_client_and_the_bundle_verifier_ask_the_same_questions(V, kms):
    """One definition of "verified", shared by the client that is about to seal a query and the stranger
    checking the record afterwards. Two implementations could diverge so that the live client accepts an
    enclave the record's verifier later rejects — and each would look right on its own."""
    c = V.verify_offer(_offer(V, kms))
    names = {n for _, n, _ in c.rows}
    for shared in ("REPORT_DATA binds runtime data", "report signature", "AMD root pinned",
                   "VCEK is for this chip", "report from VMPL 0", "UVM endorsement signature",
                   "UVM root is Microsoft's", "MEASUREMENT is the endorsed utility VM",
                   "enclave identity (InferRoute's policy, index, encoders)"):
        assert shared in names, (shared, sorted(names))
    # and it asks the two questions that only matter BEFORE sealing
    assert "sealing key committed in runtime data" in names


def test_an_offer_with_no_sealing_key_is_refused_before_anything_is_sent(V, kms):
    """There is nothing safe to seal to. This must fail loudly rather than fall through to a default."""
    rd = {"v": 1, "lifetime_id": "ab" * 8, "statement_signer_pub": "11" * 32,
          "enclave_x25519_pub": "00" * 32,                       # all-zero: present but unusable
          "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32}
    c = V.verify_offer(_offer(V, kms, rd))
    assert "sealing key committed in runtime data" in c.failed
    assert any("nothing safe to seal to" in d for _, _, d in c.rows)


def test_a_live_offer_without_a_reference_fails_identity_exactly_as_a_record_does(V, kms):
    c = V.verify_offer(_offer(V, kms))
    assert "enclave identity (InferRoute's policy, index, encoders)" in c.failed
    assert any("NO REFERENCE SUPPLIED" in d for _, _, d in c.rows)
    # with one, the same match logic applies as for a record
    host = V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()
    ref = {"schema": "inferroute.enclave-reference/1", "policy_sha256": [host],
           "index_manifest_sha256": ["ef" * 32], "model_manifest_sha256": ["12" * 32]}
    c2 = V.verify_offer(_offer(V, kms), reference=ref)
    assert "enclave identity (InferRoute's policy, index, encoders)" not in c2.failed


def test_a_retired_enclave_is_refused_before_sealing_not_after(V, kms):
    """The windows are asked about NOW for a live enclave: a retired policy must stop the query being sent,
    not merely fail the record afterwards — by then the invention has already left the machine."""
    host = V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()
    ref = {"schema": "inferroute.enclave-reference/1",
           "policy_sha256": [{"value": host, "retired": True}],
           "index_manifest_sha256": ["ef" * 32], "model_manifest_sha256": ["12" * 32]}
    c = V.verify_offer(_offer(V, kms), reference=ref)
    assert "enclave identity (InferRoute's policy, index, encoders)" in c.failed
    assert any("RETIRED" in d for _, _, d in c.rows)


def test_a_value_beginning_with_a_hyphen_is_explained_not_just_refused(tmp_path):
    """base64url fingerprints start with '-' about 1.3% of the time, so a correct paste fails with argparse's
    "expected one argument" and no clue why. Measured by sealed-research after it made one of their tests
    flaky at a few percent per run; the same shape reaches any user of this CLI."""
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), "--uvm-root", "-Ab3xyz"],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "expected one argument" in r.stderr
    assert "--uvm-root=VALUE" in r.stderr and "starts with '-'" in r.stderr


def test_a_manifest_of_no_files_never_counts_as_identity(V, kms):
    """SHA-256 of b"" is what a manifest builder returns over a root it could not walk. It is the same for
    every index, so an enclave committing to it — even against a reference that pins the same value, which a
    hand-typed unsigned reference could — has said nothing about WHICH index it serves."""
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    rd = {"v": 1, "lifetime_id": "ab" * 8, "statement_signer_pub": "11" * 32, "enclave_x25519_pub": "22" * 32,
          "index_manifest_sha256": empty, "model_manifest_sha256": "12" * 32}
    c = V.verify_offer(_offer(V, kms, rd))
    assert "index manifest names real bytes" in c.failed
    assert any("SHA-256 of nothing" in d for _, _, d in c.rows)


# ───────────── document reads, per-session completeness, an unauthenticated reference ─────────────

def _ops_bundle(tmp_path, V, kms, ops, *, name="bundle"):
    """A record of mixed operations. Each op: {kind, session, seq, ...overrides} — kind "search" or
    "document"; session None puts the old per-enclave seq on the statement instead of a session_seq."""
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
    d = tmp_path / name
    d.mkdir(parents=True)
    (d / f"{ev_sha[:16]}.evidence.json").write_bytes(ev_bytes)
    rows = []
    for i, op in enumerate(ops, 1):
        rid = f"{i:032x}"
        reply_priv = bytes([(i * 7 + j) % 256 for j in range(32)])
        st = {"v": 1, "kind": op.get("kind", "search"), "lifetime_id": rd["lifetime_id"], "request_id": rid,
              "started_utc": "2026-06-01T12:00:00Z", "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(),
              "index_manifest_sha256": rd["index_manifest_sha256"], "model_manifest_sha256": rd["model_manifest_sha256"],
              "cutoff_date": 20200115, "outcome": "answered", "reply_to_sha256": hashlib.sha256(reply_priv).hexdigest()}
        row = {"n": i, "at": "t", "signer_pub": pub, "reply_to": reply_priv.hex(),
               "evidence_file": f"{ev_sha[:16]}.evidence.json", "evidence_sha256": ev_sha}
        if op.get("session"):
            st["session_id"], st["session_seq"] = op["session"], op["seq"]
        else:
            st["seq"] = op["seq"]
        if st["kind"] == "document":
            text = op.get("text", f"Abstract of document {i}.")
            st["key"] = op.get("key", f"US-{i}000-B2")
            st["text_sha256"] = V.salted(rid, op.get("sign_text", text))
            st["coverage"] = {"abstract": "held", "claims": "not_held", "description": "not_held"}
            st["publication_date"] = op.get("publication_date", 19980417)
            row.update({"kind": "document", "key": st["key"], "text": text})
        else:
            q, res = f"query {i}", {"hits": [{"key": f"US-{i}-A"}]}
            st.update({"hits_n": 1, "query_sha256": V.salted(rid, q), "result_sha256": V.salted(rid, res)})
            row.update({"kind": "search", "query_text": q, "result": res})
        st["sig"] = key.sign(V.canonical(st)).hex()
        row["statement"] = st
        rows.append(row)
    (d / "searches.json").write_text(json.dumps(rows))
    (d / "record.html").write_text("<html>record</html>")
    (d / "VERIFY.md").write_text("# verify\n")
    (d / "verify_record.py").write_bytes(SCRIPT.read_bytes())
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))
    host = V.parse_report(base64.b64decode(kms["evidence"]))["host_data"].hex()
    return d, host


def test_a_document_read_is_bound_to_the_text_the_enclave_signed(tmp_path, V, kms):
    d, host = _ops_bundle(tmp_path, V, kms, [{"kind": "document", "session": "s1", "seq": 1}])
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "PASS document text is the one signed" in out
    assert "PASS document is the one signed" in out and "US-1000-B2" in out and "abstract: held" in out
    assert "PASS the document predates the date bound" in out
    assert "SKIP query text is the one searched" not in out    # a read is not a search with a missing query
    assert "result is the signed result" not in out


def test_a_document_whose_text_was_changed_fails_the_record(tmp_path, V, kms):
    d, host = _ops_bundle(tmp_path, V, kms, [{"kind": "document", "session": "s1", "seq": 1,
                                              "text": "Abstract of document 1.", "sign_text": "what the enclave really sent"}])
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "FAIL document text is the one signed" in out and code == 1


def test_a_document_published_on_or_after_the_date_bound_fails_the_record(tmp_path, V, kms):
    # The enclave refuses such a read live; if one ever got through, the record must not pass it.
    d, host = _ops_bundle(tmp_path, V, kms, [{"kind": "document", "session": "s1", "seq": 1, "publication_date": 20200115}])
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "FAIL the document predates the date bound" in out and "NOT before the matter's bound" in out and code == 1


def test_completeness_counts_searches_and_reads_of_one_session(tmp_path, V, kms):
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1},
                                             {"kind": "document", "session": "s1", "seq": 2},
                                             {"session": "s1", "seq": 3}])
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "PASS completeness (per-session sequence)" in out
    assert "seq 1..3 contiguous (2 searches, 1 document read)" in out and "every operation of each session SHOWN" in out


def test_completeness_is_per_session_so_other_clients_are_not_missing(tmp_path, V, kms):
    # The counter the enclave keeps is per session: a record starting at 1 for ITS session is complete, whatever
    # anyone else did on the same enclave — and it says nothing about how much anyone else used it.
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}, {"session": "s1", "seq": 2},
                                             {"session": "s2", "seq": 1}])
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "PASS completeness (per-session sequence)" in out and code == 1  # identity/report still fail on fixtures
    assert "session s1…" in out and "session s2…" in out


def test_a_gap_inside_a_session_still_fails(tmp_path, V, kms):
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}, {"kind": "document", "session": "s1", "seq": 3}])
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "FAIL completeness (per-session sequence)" in out and "missing [2]" in out


def test_records_made_before_session_numbering_verify_exactly_as_before(tmp_path, V, kms):
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": None, "seq": 1}, {"session": None, "seq": 2}])
    _, out = _run(d, "--reference", str(_ref(tmp_path, "r.json", [host])))
    assert "PASS completeness (per-enclave sequence)" in out and "seq 1..2 contiguous (2 searches)" in out
    assert "every search of each enclave SHOWN" in out and "entire lifetime dropped" in out


def _signing_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def test_a_signed_reference_checked_without_its_key_is_not_a_clean_pass(tmp_path, V, kms):
    """Every line can pass while identity rests on a file nobody authenticated. The exit code must say so:
    a reader who reads only the number would otherwise be told the strongest verdict."""
    key, pub = _signing_key()
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = _ref(tmp_path, "signed.json", [host], sign_with=key)
    code_without, out_without = _run(d, "--reference", str(ref))
    assert "SKIP reference signature" in out_without and "no --reference-key was given" in out_without
    code_with, out_with = _run(d, "--reference", str(ref), f"--reference-key={pub}")
    assert "PASS reference signature" in out_with
    # These fixtures fail the hardware binding either way; the verdict difference is what this pins.
    assert (code_without, code_with) == (1, 1)   # these fixtures fail the hardware binding either way


def test_exit_four_is_reserved_for_the_unauthenticated_reference(tmp_path, V, kms, monkeypatch):
    """Exit 4 only when the reference is SIGNED and no key was given: an unsigned reference (three hashes an
    attorney typed) keeps its own verdict, and a key that verifies keeps a clean 0."""
    key, pub = _signing_key()
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    signed, unsigned = _ref(tmp_path, "s.json", [host], sign_with=key), _ref(tmp_path, "u.json", [host])

    def codes(passing):
        # neutralise the fixture's unrelated failures (real report vs synthetic runtime data) to read the verdict
        monkeypatch.setattr(V, "check_hardware", lambda c, *a, **k: {"host_data": host, "product": "Milan"})
        monkeypatch.setattr(V, "check_identity", lambda *a, **k: None)
        return V.main([str(d), f"--reference={passing}"])
    assert codes(signed) == 4
    assert V.main([str(d), f"--reference={signed}", f"--reference-key={pub}"]) == 0
    assert V.main([str(d), f"--reference={unsigned}"]) == 0


def test_a_firmware_floor_can_travel_in_the_reference(tmp_path, V, kms):
    """A firm should not have to know SPL numbers to hold a floor: the reference can carry one, and it is
    covered by the reference's own signature."""
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = json.loads(_ref(tmp_path, "r.json", [host]).read_text())
    ref["min_tcb"] = {"Milan": {"snpSPL": 99, "ucodeSPL": 1}}
    p = tmp_path / "floor.json"
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "FAIL firmware TCB at or above minimum" in out
    ref["min_tcb"] = {"Milan": {"snpSPL": 1, "ucodeSPL": 1}}
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "PASS firmware TCB at or above minimum" in out


# ───────────────── the filters: what was GIVEN, and what the enclave says applying it did ─────────────────

def _filters_statement():
    """A real statement from the search service (sealed-research d7d0fd5), exercising all three filters:
    a legitimate removed=0 on both date bounds, and a real removal on offices."""
    return json.loads((FIX.parent / "statement-filters-applied.json").read_text())


def _filter_rows(V, st):
    c = V.Checks()
    V.check_filters_applied(c, st)
    return {name: (status, detail) for status, name, detail in c.rows}


def test_a_filter_report_is_checked_against_the_filter_the_statement_asked_for(V):
    """A statement carrying only a filter's INPUT attests configuration, never enforcement. An auditor read
    "date bound" as an enforcement claim (19 Sep), and a jurisdiction filter was found matching nothing while
    a statement would have said the search was restricted to it (20 Sep). One rule for every filter."""
    rows = _filter_rows(V, _filters_statement())
    assert rows["date bound was applied"][0] == "PASS"
    assert rows["from-date bound was applied"][0] == "PASS"
    assert rows["offices was applied"][0] == "PASS"
    assert "2 of 5 candidate(s) removed" in rows["offices was applied"][1]
    # A real zero is the common case and must not read as "the filter did nothing".
    assert "no candidate fell outside it" in rows["date bound was applied"][1]
    # k needs no report of its own: k and hits_n are both signed, so the check is arithmetic.
    assert rows["at most k results"][0] == "PASS"


def test_a_filter_report_that_disagrees_with_the_statement_fails(V):
    st = _filters_statement()
    st["offices_applied"]["offices"] = ["EP"]
    rows = _filter_rows(V, st)
    assert rows["offices was applied"][0] == "FAIL"
    assert "is NOT the offices signed in the statement" in rows["offices was applied"][1]
    # A filter reported but never asked for is equally wrong: a bound applied that nobody requested.
    st2 = _filters_statement()
    st2["from_date"] = None
    assert _filter_rows(V, st2)["from-date bound was applied"][0] == "FAIL"
    st3 = _filters_statement()
    st3["hits_n"] = st3["k"] + 4
    assert _filter_rows(V, st3)["at most k results"][0] == "FAIL"


def test_an_older_record_skips_rather_than_rots(V):
    """Every record made before an enclave reported this carries no *_applied. They must not fail: a record
    that verified last week and fails this week is indistinguishable from tampering to the person holding it."""
    st = _filters_statement()
    st.pop("cutoff_applied")
    rows = _filter_rows(V, st)
    assert rows["date bound was applied"][0] == "SKIP"
    assert "not what applying it did" in rows["date bound was applied"][1]
    assert "enforcement is unattested" in rows["date bound was applied"][1]
    # A filter neither requested nor reported says nothing at all — no row, no noise.
    bare = {k: v for k, v in st.items() if k not in ("offices", "offices_applied", "from_date", "from_date_applied")}
    assert "offices was applied" not in _filter_rows(V, bare)


def test_a_record_with_only_a_sealed_session_reads_as_absence_not_failure(tmp_path, V, kms):
    """23 Sep. Making zero-search packs producible (for AUDIT.md claim 7, the CONVERSATION) made this
    branch reachable in normal use for the first time, and it told the auditor "RESULT: FAILED" about a
    record whose only fact is that no search was run. A law firm reads that as the evidence failing.
    It must still not pass — an empty record passed off as verified is the thing this guards — but the
    wording and the verdict line have to separate an ABSENCE from a defect, and name what IS there."""
    import hashlib, json as _json
    d = _synthetic_bundle(tmp_path, V, kms, no_searches=True)
    raw = _json.dumps({"session_id": "f8be46ff", "verdict": "confidential"}).encode()
    name = "session-20260922T191817Z-f8be46ff.receipt.json"
    (d / name).write_bytes(raw)
    man = _json.loads((d / "MANIFEST.json").read_text())
    man["files"][name] = hashlib.sha256(raw).hexdigest()
    (d / "MANIFEST.json").write_text(_json.dumps(man, indent=1))
    code, out = _run(d, "--reference", str(tmp_path / "reference.json"))
    assert "ABSENCE" in out and "not a defect in the evidence" in out
    assert name in out and "claim 7" in out           # the auditor is told what IS here
    assert "RESULT: NOTHING VERIFIED" in out
    assert "RESULT: FAILED" not in out
    assert code == 1, "still not a pass"


def test_a_record_with_neither_searches_nor_a_session_still_says_failed(tmp_path, V, kms):
    """The other side of the same branch: nothing at all in the folder is not an 'absence', it is an
    empty record, and the original wording stands."""
    d = _synthetic_bundle(tmp_path, V, kms, no_searches=True)
    code, out = _run(d, "--reference", str(tmp_path / "reference.json"))
    assert "there is nothing to verify" in out
    assert "RESULT: NOTHING VERIFIED" in out          # still an absence, but nothing to point the auditor at
    assert "session receipt(s) present" not in out
    assert code == 1
