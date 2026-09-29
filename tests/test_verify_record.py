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
    allowed = {"base64", "hashlib", "json", "os", "re", "struct", "sys", "typing", "cryptography", "datetime",
               "argparse", "warnings", "__future__"}
    # `urllib` is allowed ONLY inside a function body. This program's value is that it runs offline and
    # deterministically over a folder; a module-level network import would make that a matter of intent
    # rather than of structure. --check-revocation is the one path that reaches the network, it is off by
    # default, and this test is what keeps that true.
    tree = ast.parse(src)
    fn_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                fn_nodes.add(id(inner))
    for node in ast.walk(tree):
        names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                 else [node.module or ""] if isinstance(node, ast.ImportFrom) else None)
        if names is None:
            continue
        for name in names:
            root = name.split(".")[0]
            if root == "urllib":
                assert id(node) in fn_nodes, "urllib must not be imported at module level"
                continue
            assert root in allowed, name


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
    assert ("SKIP", "configured firmware TCB floor") in {(s, n) for s, n, _ in c.rows}
    c2 = V.Checks()
    V.check_amd(c2, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256, min_tcb={"Milan": {"snpSPL": 8, "ucodeSPL": 115}})
    assert "configured firmware TCB floor" not in c2.failed
    c3 = V.Checks()
    V.check_amd(c3, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256, min_tcb={"Milan": {"snpSPL": 99}})
    assert "configured firmware TCB floor" in c3.failed
    # A floor_skip wins over a pinned floor: if no floor was in force at the search's time, the row
    # must SKIP rather than compare against a threshold that did not apply.
    c4 = V.Checks()
    V.check_amd(c4, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256,
                min_tcb={"Milan": {"snpSPL": 99}}, floor_skip="no floor was active at this search time")
    assert "configured firmware TCB floor" not in c4.failed
    assert ("SKIP", "configured firmware TCB floor") in {(s, n) for s, n, _ in c4.rows}


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


def test_the_bundle_binds_the_signed_recipient_to_the_recorded_key_without_claiming_exclusivity(tmp_path, V, kms):
    """The enclave-signed hash matches the key in the row, but this cannot rule out other disclosure paths."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1])
    ref = _ref(tmp_path, "r.json", [host])
    # This fixture's evidence commits to its own runtime data, so the bundle never reaches exit 0 — assert
    # on the ROW, which is what this test is about. A code assertion here would be testing the fixture.
    code, out = _run(d, "--reference", str(ref))
    assert "PASS signed recipient matches recorded key" in out
    assert "does not rule out another copy or disclosure channel" in out

    rows = json.loads((d / "searches.json").read_text())
    rows[0]["reply_to"] = "aa" * 32                       # as if the answer had gone to a different address
    (d / "searches.json").write_text(json.dumps(rows))
    _remanifest(d)
    code, out = _run(d, "--reference", str(ref))
    assert "FAIL signed recipient matches recorded key" in out and code == 1
    assert "NOT the key this record says was used" in out
    assert "PASS statement signature" in out, "only the recipient check may move; the statement is untouched"


def test_a_record_made_before_the_field_existed_skips_and_says_so(tmp_path, V, kms):
    """A record already made cannot be re-run. Failing it retroactively would punish the attorney for our
    version history — but it must not read as a passed check either. SKIP, naming what is unchecked. The
    LIVE path refuses instead, because there the search is still happening: same fact, different remedy
    (sealed-research tests/test_search_verifier.py)."""
    d, host, rd = _multi_bundle(tmp_path, V, kms, seqs=[1], omit_recipient=True)
    code, out = _run(d, "--reference", str(_ref(tmp_path, "r2.json", [host])))
    assert "SKIP signed recipient matches recorded key" in out
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
    # The floor must be WINDOWED and current at the statement's time to be enforced at all. A flat
    # floor is no longer enforced anywhere (see the SKIP test below): its applicability was never
    # established, so it cannot constrain a search that ran before anyone declared it.
    def _windowed(levels):
        return [{"value": {"Milan": levels}, "valid_from": "2000-01-01T00:00:00Z",
                 "valid_to": None, "retired": False}]
    ref["min_tcb"] = _windowed({"snpSPL": 99, "ucodeSPL": 1})
    p = tmp_path / "floor.json"
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "FAIL configured firmware TCB floor" in out
    ref["min_tcb"] = _windowed({"snpSPL": 1, "ucodeSPL": 1})
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "PASS configured firmware TCB floor" in out


def test_a_FLAT_floor_is_not_enforced_and_says_why(tmp_path, V, kms):
    """The change that matters for already-delivered records. A floor with no validity window cannot
    be shown to have been in force when the search ran, so it SKIPS rather than PASSING. Measured
    2026-09-28: the live signed reference carried a flat floor and all 70 delivered searches predate
    its signing by three days — every one of those rows was a PASS that nothing supported."""
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = json.loads(_ref(tmp_path, "r.json", [host]).read_text())
    ref["min_tcb"] = {"Milan": {"snpSPL": 1, "ucodeSPL": 1}}
    p = tmp_path / "flat.json"
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "SKIP configured firmware TCB floor" in out
    assert "no validity window" in out
    assert "PASS configured firmware TCB floor" not in out


def test_a_floor_whose_window_opens_AFTER_the_search_skips(tmp_path, V, kms):
    """A signature made today cannot establish that a floor was in force last week."""
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = json.loads(_ref(tmp_path, "r.json", [host]).read_text())
    ref["min_tcb"] = [{"value": {"Milan": {"snpSPL": 1, "ucodeSPL": 1}},
                       "valid_from": "2099-01-01T00:00:00Z", "valid_to": None, "retired": False}]
    p = tmp_path / "future.json"
    p.write_text(json.dumps(ref))
    _, out = _run(d, "--reference", str(p))
    assert "SKIP configured firmware TCB floor" in out
    assert "predates floor valid_from" in out


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


def test_the_verifier_compiles_on_every_python_it_claims_to_support():
    """It says "It needs Python 3.9+"; on 24 Sep it did not compile on 3.11 at all, failing at line 836.

    This is the one file we hand a third party and ask them to RUN. It was written and only ever tried on
    3.12, where two constructs are legal that are syntax errors before it: a backslash inside an f-string
    expression, and an f-string expression spanning two lines. Debian 12 ships 3.11 and Ubuntu 22.04 ships
    3.10, so the audit this whole pack exists to invite would have died at the first command on a typical
    firm's laptop — and never on ours.

    The static scan always runs. The real compile runs wherever an older interpreter can be found, because
    a scan for two known shapes cannot promise there is no third."""
    import re
    import shutil
    import subprocess
    src = (Path(V.__file__).resolve() if hasattr(V, "__file__")
           else Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "verify_record.py")
    if src.is_dir() or not src.name.endswith(".py"):
        src = Path(__file__).resolve().parent.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"
    text = src.read_text()

    # (1) No backslash inside an f-string expression.
    for n, line in enumerate(text.split("\n"), 1):
        for m in re.finditer(r'f"[^"\n]*?\{([^{}\n]*)\}', line):
            assert "\\" not in m.group(1), f"line {n}: backslash in an f-string expression"

    # (2) The claimed floor, stated in the file, is what we test against.
    claimed = re.search(r"needs Python (\d)\.(\d+)\+", text)
    assert claimed, "the file no longer states which Python it needs"

    # (3) A real compile on the oldest interpreter this machine can produce.
    older = []
    for name in ("python3.9", "python3.10", "python3.11"):
        found = shutil.which(name)
        if found:
            older.append(found)
    if not older:
        for name in ("3.9", "3.10", "3.11"):
            r = subprocess.run(["uv", "python", "find", name], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                older.append(r.stdout.strip())
    if not older:
        pytest.skip("no interpreter older than this one is available to compile against")
    for exe in older:
        r = subprocess.run([exe, "-c", f"compile(open({str(src)!r}).read(), 'v', 'exec')"],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"{exe} cannot compile the verifier:\n{r.stderr[-400:]}"


def _completeness(V, rows):
    c = V.Checks()
    V.check_completeness(c, rows)
    return c.rows


def _row(lifetime, session, session_seq, seq):
    # A real statement carries BOTH: session_seq numbers the sitting, seq numbers the ENCLAVE. The
    # observation being tested reads the second, and a fixture with only one of them never reaches it.
    return {"statement": {"lifetime_id": lifetime, "session_id": session,
                          "session_seq": session_seq, "seq": seq}}


# ⚠ DO NOT DELETE THE TWO TESTS BELOW WITHOUT REPLACING THEM.
# `verify_record.py` is vendored by sealed-research and pinned there by byte identity against this repo.
# They confirmed on 25 Sep that they have NO behavioural test of this block — deliberately, because a
# second copy of the suite would drift from this one the way the file itself just did. So these inversions
# are the only thing keeping the check honest in either repo.


def test_the_verifier_observes_operations_missing_from_the_record(V):
    """Merged from sealed-research, 25 Sep, after the 09-24 corrupt-session incident: per-session numbering
    can be contiguous while the ENCLAVE's own counter shows operations the record does not contain. That
    day exactly such a gap was a corrupt session of the record's own matter, and only a human noticed.

    Never fatal, because the record genuinely cannot tell whose the missing operations are. On this
    installation the benign answer is the common one — measured the same day, a real pack carried 37 of
    enclave seq 1..65 and all 28 absent ones were other matters — so the wording leads with that. Leading
    with "another client" invites a solo practitioner to report a breach where there is a second matter."""
    with_gap = _completeness(V, [_row("aa" * 16, "s1", 1, 1), _row("aa" * 16, "s1", 2, 2), _row("aa" * 16, "s2", 1, 5)])
    obs = [r for r in with_gap if r[1] == "enclave-wide counter (observation)"]
    assert len(obs) == 1, with_gap
    status, _, detail = obs[0]
    assert status == "SKIP", "an observation the record cannot resolve must never fail the run"
    assert "but not 2 of them (3, 4)" in detail
    assert "another MATTER on the same installation" in detail
    assert "a session of this matter missing from the export looks " in detail
    assert "ask the exporter to account for them" in detail

    # A contiguous enclave counter says nothing: silence is the right output when there is no gap.
    clean = _completeness(V, [_row("bb" * 16, "s1", 1, 1), _row("bb" * 16, "s2", 1, 2)])
    assert not [r for r in clean if r[1] == "enclave-wide counter (observation)"]

    # The list is BOUNDED. `f"{missing}"` on a long-lived enclave prints thousands of numbers into a
    # verifier's output; the count is the fact and the numbers are only the illustration.
    wide = _completeness(V, [_row("cc" * 16, "s1", 1, 1), _row("cc" * 16, "s2", 1, 400)])
    detail = [r for r in wide if r[1] == "enclave-wide counter (observation)"][0][2]
    assert "but not 398 of them" in detail and detail.count(",") <= 12 and "…" in detail
    assert len(detail) < 600, f"unbounded observation: {len(detail)} chars"


def test_the_reference_signature_does_not_claim_what_the_program_cannot_know(V):
    """The old wording said the key was one "you recorded at first use". The program has no way to know
    that — it verifies a signature under a key it was handed. Claiming provenance it cannot check is the
    same defect the brief spends pages warning auditors about, in the tool itself."""
    src = Path(V.__file__).read_text()
    assert "that you supplied" in src
    assert "yours to attest, not this program's" in src
    assert "you recorded at first use\")" not in src


# --- An auditor on 25 Sep read the program and found two rows that said less than their wording implied:
#     the reference's signature "verifies" under a key taken from a file beside it that holds the
#     reference's OWN publication_key, and the identity row claimed a time was tested on a reference whose
#     entries carry no windows at all. Neither is fixable by the program; both are sayable by it.

def _signed_ref(V, sk, *, publication_key, entries=None):
    r = {"schema": V.REFERENCE_SCHEMA, "source": "t", "published_at": "2026-01-01T00:00:00Z",
         "policy_sha256": entries or [{"value": "aa"}],
         "index_manifest_sha256": [{"value": "bb"}], "model_manifest_sha256": [{"value": "cc"}]}
    if publication_key is not None:
        r["publication_key"] = publication_key
    r["sig"] = sk.sign(V.canonical(r)).hex()
    return r


def _sig_why(V, ref, key_hex):
    c = V.Checks()
    V.check_reference_signature(c, ref, key_hex)
    return [row[2] for row in c.rows if row[1] == "reference signature"][0]


def test_a_reference_signed_by_the_key_it_names_is_called_self_consistency(V):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw().hex()
    why = _sig_why(V, _signed_ref(V, sk, publication_key=pub), pub)
    assert "self-consistency, NOT authentication" in why
    assert "engagement letter" in why


def test_a_key_the_reference_does_not_name_is_not_called_self_consistency(V):
    """The inversion. If this passed too, the row would be decoration: it must distinguish the two cases."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw().hex()
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    assert "self-consistency" not in _sig_why(V, _signed_ref(V, sk, publication_key=other), pub)
    assert "self-consistency" not in _sig_why(V, _signed_ref(V, sk, publication_key=None), pub)


def test_a_reference_with_no_windows_is_not_described_as_windowed(V):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw().hex()
    assert V._ref_windowed(_signed_ref(V, sk, publication_key=pub)) is False
    # and the inversion, per entry kind: either a window or a retired flag makes the apparatus live
    for e in ({"value": "aa", "valid_from": "2026-01-01T00:00:00Z"},
              {"value": "aa", "valid_to": "2026-01-01T00:00:00Z"},
              {"value": "aa", "retired": True}):
        assert V._ref_windowed(_signed_ref(V, sk, publication_key=pub, entries=[e])) is True


# --- The policy's PERMISSIONS, and the sentence they license -------------------------------------------
# Until 25 Sep this program hashed the archived policy and never read it, so allow_stdio_access:true in
# every container of a real record was invisible to every check. These rows do not move the exit code --
# a permissive policy is not a damaged record -- so their teeth are that they change what a reader may
# write. Each test below therefore asserts the SENTENCE, not just the row.

def _policy(stdio=False, elevated=False, exec_procs=None, layers=True,
            logging_=False, dumps=False, scratch=False):
    cont = {"allow_elevated": elevated, "allow_stdio_access": stdio,
            "exec_processes": [] if exec_procs is None else exec_procs}
    if layers:
        cont["layers"] = ["aa" * 32, "bb" * 32]
    return base64.b64encode(("package policy\n\n"
                             f"allow_runtime_logging := {str(logging_).lower()}\n"
                             f"allow_dump_stacks := {str(dumps).lower()}\n"
                             f"allow_unencrypted_scratch := {str(scratch).lower()}\n\n"
                             "containers := " + json.dumps([cont, dict(cont)]) + "\n").encode()).decode()


def _posture(V, **kw):
    c = V.Checks()
    return c, V.check_policy_posture(c, _policy(**kw))


def test_a_clean_policy_satisfies_every_posture_condition(V):
    c, out = _posture(V)
    assert [s for s, _, _ in c.rows if s != "PASS"] == [], c.rows
    assert all(out[k] is True for k in out), out


@pytest.mark.parametrize("kw,key", [
    ({"stdio": True}, "allow_stdio_access"),
    ({"elevated": True}, "allow_elevated"),
    ({"logging_": True}, "allow_runtime_logging"),
    ({"dumps": True}, "allow_dump_stacks"),
    ({"scratch": True}, "allow_unencrypted_scratch"),
    ({"layers": False}, "image_pinned"),
    ({"exec_procs": [{"command": ["sh"]}]}, "no_exec"),
])
def test_each_permission_is_detected_on_its_own(V, kw, key):
    """The inversion, one condition at a time: if any of these still came back satisfied, that row would
    be decoration and the licensed sentence would overreach on a policy that permits observation."""
    c, out = _posture(V, **kw)
    assert out[key] is not True, f"{key} not detected: {c.rows}"
    assert any(s == "FAIL" for s, _, _ in c.rows)


def test_a_flag_the_policy_omits_is_not_read_as_denied(V):
    """Absent must not read as false. A document that never mentions a permission denies nothing."""
    pol = base64.b64encode(b'package policy\n\ncontainers := [{"allow_elevated":false,'
                           b'"allow_stdio_access":false,"exec_processes":[],"layers":["aa"]}]\n').decode()
    c = V.Checks()
    out = V.check_policy_posture(c, pol)
    assert out["allow_runtime_logging"] is False
    assert any("does not carry allow_runtime_logging" in d for _, _, d in c.rows)


def _reach(V, posture, **kw):
    opts = {"floor_pinned": True, "revocation_checked": True, "image_published": True, "authenticated": True, "record_ok": True, "policy_committed": True}
    opts.update(kw)
    return V.confidentiality_reach(posture, **opts)


def test_all_configuration_checks_still_do_not_prove_confidentiality(V):
    _, clean = _posture(V)
    assert _reach(V, clean)[0] == 1
    # and the inversion on each condition that is not the policy's
    for missing in ("floor_pinned", "revocation_checked", "image_published", "authenticated"):
        reach, blockers = _reach(V, clean, **{missing: False})
        assert reach < 2, f"{missing} absent still licensed the strongest sentence"
        assert blockers, missing


def test_a_permissive_policy_cannot_reach_even_the_middle_sentence(V):
    _, leaky = _posture(V, stdio=True)
    reach, blockers = _reach(V, leaky)
    assert reach == 0
    assert any("stdio" in b for b in blockers), blockers


def test_configuration_claim_requires_floor_revocation_and_reference_signature(V):
    """Source availability alone cannot establish behavior or authentication."""
    _, clean = _posture(V)
    assert _reach(V, clean, image_published=False)[0] == 1
    assert _reach(V, clean, authenticated=False)[0] == 0
    assert _reach(V, clean, floor_pinned=False)[0] == 0


def test_the_licensed_sentences_are_scoped_to_the_search_lane(V):
    """An auditor on 25 Sep found three things in the session receipts that bear on these sentences and
    that this program cannot see: a session that used four AI instances while attesting one, an unsigned
    receipt-to-search join, and a request served by an instance that later failed re-verification. A
    block that licensed "remained confidential" without naming them would overclaim on the strength of
    the lane it DOES check."""
    assert "NOT ESTABLISHED" in V.STATEMENT_CONFIDENTIAL
    assert "archived SEARCH" in V.STATEMENT_SEALED
    assert "archived SEARCH" in V.STATEMENT_ENCLOSED
    assert len(V.AI_LANE_CONDITIONS) == 3
    joined = " ".join(V.AI_LANE_CONDITIONS)
    # It must NAME the fields to read...
    for field in ("counters.instance_switches", "events", "refusal", "searches.json"):
        assert field in joined, f"the pointer no longer names {field}"
    # ...and must NOT hand over what is found there. An auditor on 25 Sep reported confirming a sentence
    # it had been given rather than computing it, one of the three word for word. A pointer carrying its
    # own answer is a quiz: the auditor agrees instead of checking, and the agreement proves nothing.
    for answer in ("pinned-failed-reverify", "unsigned filename stem", "attests ONE instance",
                   "32-hex", "UUID"):
        assert answer not in joined, f"the pointer still supplies the finding: {answer}"


# --- The licence block must be downstream of whether anything verified ------------------------------
# An auditor on 25 Sep attacked this section as built and got it to license "a genuine, non-debuggable
# confidential machine" over 140 FAIL lines, and "the policy the hardware enforced" over a policy whose
# hash did not match HOST_DATA 70 times. An adversary needed no valid hardware evidence at all, only a
# policy_b64 that read well. A section that tells a reader what they MAY WRITE is the one place in this
# program where being wrong is not a missing check but an active endorsement.

def _clean_posture(V):
    c = V.Checks()
    return V.check_policy_posture(c, _policy())


def test_a_record_that_did_not_verify_licenses_nothing(V):
    posture = _clean_posture(V)
    reach, blockers = V.confidentiality_reach(
        posture, floor_pinned=True, revocation_checked=True, image_published=True,
        authenticated=True, record_ok=False, policy_committed=True)
    assert reach == -1
    assert len(blockers) == 1 and "did not verify" in blockers[0]
    # the inversion: with everything else identical and the record intact, it reaches the top
    assert V.confidentiality_reach(posture, floor_pinned=True, revocation_checked=True,
                                   image_published=True, authenticated=True, record_ok=True, policy_committed=True)[0] == 1


def test_a_policy_the_hardware_did_not_commit_to_licenses_nothing(V):
    """Defence in depth. The per-search row that compares SHA-256(policy) to HOST_DATA already FAILs,
    so record_ok catches this today -- but if that row ever softens to a SKIP, this gate still holds."""
    posture = _clean_posture(V)
    reach, blockers = V.confidentiality_reach(
        posture, floor_pinned=True, revocation_checked=True, image_published=True,
        authenticated=True, record_ok=True, policy_committed=False)
    assert reach == -1
    assert any("HOST_DATA" in b for b in blockers)


def test_a_policy_that_imports_fragments_is_reported_as_a_floor(V):
    """The document lists 3 containers; the fragment it names contributes 10 more, 8 of them allowing
    elevated execution. Counting only what is written here and calling it "the policy the hardware
    enforced" is how the rows became prose."""
    pol = base64.b64encode(('package policy\n\nfragments := [{"feed":"mcr.microsoft.com/aci/x",'
                            '"includes":["containers","fragments"],"minimum_svn":"4"}]\n\n'
                            'allow_runtime_logging := false\nallow_dump_stacks := false\n'
                            'allow_unencrypted_scratch := false\n\n'
                            'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
                            '"exec_processes":[],"layers":["aa"]}]\n').encode()).decode()
    c = V.Checks()
    out = V.check_policy_posture(c, pol)
    assert out["self_contained"] is False
    assert any("unresolved external policy dependency" in d and
               "not the effective policy" in d for _, _, d in c.rows)
    reach, blockers = V.confidentiality_reach(out, floor_pinned=True, revocation_checked=True,
                                              image_published=True, authenticated=True, record_ok=True, policy_committed=True)
    assert reach == 0 and any("fragments" in b for b in blockers)
    # inversion: the same policy without the fragment block reaches the top
    assert _clean_posture(V)["self_contained"] is True


def test_unsigned_reference_is_not_called_authenticated_by_confidentiality_block(tmp_path, V, kms, monkeypatch):
    key, pub = _signing_key()
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    signed = _ref(tmp_path, "signed.json", [host], sign_with=key)
    unsigned = _ref(tmp_path, "unsigned.json", [host])
    monkeypatch.setattr(V, "check_hardware", lambda c, *a, **k: {"host_data": host, "product": "Milan"})
    monkeypatch.setattr(V, "check_identity", lambda *a, **k: None)
    seen = []
    monkeypatch.setattr(V, "report_confidentiality", lambda *a, **k: seen.append(k))
    assert V.main([str(d), f"--reference={unsigned}"]) == 0
    assert not seen[-1]["authenticated"]
    assert V.main([str(d), f"--reference={unsigned}", f"--reference-key={pub}"]) == 1
    assert not seen[-1]["authenticated"]
    assert V.main([str(d), f"--reference={signed}", f"--reference-key={pub}"]) == 0
    assert seen[-1]["authenticated"] and seen[-1]["record_ok"]


# --- Fragment detection must fail CLOSED ---------------------------------------------------------
# The real ACI policy in a live record declares a Microsoft fragment contributing ten further
# containers, eight of them allowing elevated execution. A permission set computed over the three
# containers written in the document is therefore FALSE over the thirteen enforced — and wrong in the
# permissive direction, which is the one direction a fail-closed audit may never be wrong in. The first
# detector keyed on the literal `"feed"` string; probing on 27 Sep walked through it two ways.

@pytest.mark.parametrize("name,rego,expect_self_contained", [
    ("clean policy", 'package policy\nimport future.keywords.every\nallow_runtime_logging := false\n', True),
    ("empty fragments list", 'package policy\nfragments := []\n', True),
    ("standard ACI fragment", 'package policy\nfragments := [{"feed":"mcr/x","includes":["containers"]}]\n', False),
    ("includes omits containers", 'package policy\nfragments := [{"feed":"mcr/x","includes":["fragments"]}]\n', False),
    ("fragment with no feed key", 'package policy\nfragments := [{"source":"mcr/x","includes":["containers"]}]\n', False),
    ("bare import", 'package policy\nimport data.aci.infra\n', False),
])
def test_any_external_import_surface_blocks_policy_assurance(V, name, rego, expect_self_contained):
    body = (rego + 'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
                   '"exec_processes":[],"layers":["aa"]}]\n')
    c = V.Checks()
    out = V.check_policy_posture(c, base64.b64encode(body.encode()).decode())
    assert out["self_contained"] is expect_self_contained, name
    if not expect_self_contained:
        # and it must actually block the strong sentences, not merely note it
        reach, blockers = V.confidentiality_reach(out, floor_pinned=True, revocation_checked=True,
                                                  image_published=True, authenticated=True, record_ok=True, policy_committed=True)
        assert reach == 0 and any("fragment" in b or "import" in b for b in blockers), name


def test_future_keywords_imports_are_not_treated_as_an_import_surface(V):
    """Every real ACI policy opens with `import future.keywords.*`. Treating those as external imports
    would block every policy ever written, which is refusing rather than checking."""
    body = ('package policy\nimport future.keywords.every\nimport future.keywords.in\n'
            'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
            '"exec_processes":[],"layers":["aa"]}]\n')
    c = V.Checks()
    assert V.check_policy_posture(c, base64.b64encode(body.encode()).decode())["self_contained"] is True


def test_prefixed_container_array_cannot_decoy_the_policy_posture(V):
    body = ('package policy\n'
            'sidecar_containers := [{"allow_elevated":false,"allow_stdio_access":false,'
            '"exec_processes":[],"layers":["decoy"]}]\n'
            'allow_runtime_logging := false\nallow_dump_stacks := false\n'
            'allow_unencrypted_scratch := false\n'
            'containers := [{"allow_elevated":true,"allow_stdio_access":false,'
            '"exec_processes":[{"command":["sh"]}],"layers":[]}]\n')
    c = V.Checks()
    out = V.check_policy_posture(c, base64.b64encode(body.encode()).decode())
    statuses = {name: status for status, name, _ in c.rows}
    assert out["self_contained"] is True
    assert out["allow_elevated"] is False
    assert out["no_exec"] is False
    assert out["image_pinned"] is False
    assert statuses["policy denies elevated execution"] == "FAIL"
    assert statuses["policy lists no additional exec processes"] == "FAIL"
    assert statuses["policy lists pinned image layers"] == "FAIL"


def test_duplicate_container_arrays_refuse_to_choose_one(V):
    body = ('package policy\n'
            'allow_runtime_logging := false\nallow_dump_stacks := false\n'
            'allow_unencrypted_scratch := false\n'
            'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
            '"exec_processes":[],"layers":["a"]}]\n'
            'containers := [{"allow_elevated":true,"allow_stdio_access":false,'
            '"exec_processes":[{"command":["sh"]}],"layers":[]}]\n')
    c = V.Checks()
    out = V.check_policy_posture(c, base64.b64encode(body.encode()).decode())
    statuses = {name: status for status, name, _ in c.rows}
    assert out["image_pinned"] is None
    assert statuses["policy permissions"] == "FAIL"
    assert "policy denies elevated execution" not in statuses


def test_defaulted_privacy_flag_is_not_guessed_from_one_rule(V):
    body = ('package policy\n'
            'default allow_runtime_logging := false\nallow_runtime_logging := true\n'
            'allow_dump_stacks := false\nallow_unencrypted_scratch := false\n'
            'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
            '"exec_processes":[],"layers":["a"]}]\n')
    c = V.Checks()
    out = V.check_policy_posture(c, base64.b64encode(body.encode()).decode())
    statuses = {name: status for status, name, _ in c.rows}
    assert out["allow_runtime_logging"] is False
    assert statuses["policy denies runtime logging"] == "FAIL"


@pytest.mark.parametrize("array_rule", ["containers := array.concat(a, b)", "containers := []"])
def test_expression_or_empty_container_array_never_passes(V, array_rule):
    body = ('package policy\nallow_runtime_logging := false\nallow_dump_stacks := false\n'
            'allow_unencrypted_scratch := false\n' + array_rule + '\n')
    c = V.Checks()
    out = V.check_policy_posture(c, base64.b64encode(body.encode()).decode())
    statuses = {name: status for status, name, _ in c.rows}
    assert out["image_pinned"] is not True
    assert out["no_exec"] is not True
    assert statuses.get("policy lists pinned image layers") != "PASS"
    assert statuses.get("policy lists no additional exec processes") != "PASS"


def test_unverified_bundle_prints_no_log_time_or_operation_coverage(V, tmp_path):
    import json
    bundle = tmp_path / "unverified.bundle"
    bundle.write_text(json.dumps({"verificationMaterial":{"tlogEntries":[{"integratedTime":123}]}}))
    att = tmp_path / "attestation.json"
    att.write_text(json.dumps({"publication_key":"ab" * 32}))
    c = V.Checks()

    V.check_key_attestation(c, str(bundle), str(att), "ab" * 32)
    status, _, detail = c.rows[-1]
    assert status == "SKIP"
    assert "Coverage WITHHELD: no authenticated log time, operation count, or historical coverage is reported" in detail
    assert "1970-01-01" not in detail


# --- Attack the mapping from true evidence checks to licensed English ------------------------------

def _report_claims(V, policy=None, **overrides):
    pol = policy or _policy()
    hd = hashlib.sha256(base64.b64decode(pol)).hexdigest()
    options = dict(reference={"image_source": {"url": "https://example.invalid/unverified-source"}},
                   floor_pinned=True, revocation_checked=True, authenticated=True, record_ok=True,
                   committed={hd}, production_roots=True)
    options.update(overrides)
    V.report_confidentiality([(hd, pol)], **options)


def test_pinned_application_can_disclose_with_every_checked_control_true(V, capsys):
    # No attack on signatures/parser: the approved main program itself can send the plaintext.
    # This is a policy/reach reproduction, not a forged hardware report or an executed disclosure.
    body = base64.b64decode(_policy()).decode()
    containers = V._policy_containers(body)
    for cont in containers:
        cont["command"] = ["python", "-c", "send_plaintext_to_operator(query)"]
    body = body[:body.index("containers :=")] + "containers := " + json.dumps(containers) + "\n"
    pol = base64.b64encode(body.encode()).decode()
    c = V.Checks()
    posture = V.check_policy_posture(c, pol)
    assert all(status == "PASS" for status, _, _ in c.rows)
    reach, blockers = _reach(V, posture)
    assert reach == 1 and any("non-disclosure" in b for b in blockers)
    _report_claims(V, pol)
    out = capsys.readouterr().out
    licensed = out.split("You may write:")[1].split("You may NOT write")[0]
    for forbidden in ("POSITIONED", "every channel", "remained confidential", "3.",
                      "text was sealed on the professional's own computer"):
        assert forbidden not in licensed
    assert "Privacy throughout is NOT ESTABLISHED" in out


@pytest.mark.parametrize("image_source", ["nonempty", {"url": "not-a-build-proof"}, None])
def test_source_pointer_never_licenses_confidentiality(V, capsys, image_source):
    _report_claims(V, reference={"image_source": image_source})
    out = capsys.readouterr().out
    assert "    3." not in out
    assert "NOT ESTABLISHED" in out


@pytest.mark.parametrize("overrides", [
    {"record_ok": False}, {"production_roots": False}, {"committed": None},
    {"committed": set()}, {"committed": {"00" * 32}},
])
def test_absent_or_failed_claim_prerequisites_license_nothing(V, capsys, overrides):
    _report_claims(V, **overrides)
    out = capsys.readouterr().out
    assert "REFUSED" in out and "You may write:" not in out


def test_one_archived_policy_cannot_speak_for_another_unarchived_policy(V, capsys):
    pol = _policy()
    hd = hashlib.sha256(base64.b64decode(pol)).hexdigest()
    _report_claims(V, pol, committed={hd, "ff" * 32})
    assert "You may write:" not in capsys.readouterr().out


def test_scope_precedes_every_licensed_sentence_and_ai_conditions_are_not_sufficient(V, capsys):
    _report_claims(V)
    out = capsys.readouterr().out
    assert out.index("AI session receipts are NOT VERIFIED") < out.index("You may write:")
    assert "NOT a sufficient privacy checklist" in out


def test_each_policy_retains_its_own_blockers(V, capsys):
    p1, p2 = _policy(stdio=True), _policy(logging_=True)
    pairs = [(hashlib.sha256(base64.b64decode(p)).hexdigest(), p) for p in (p1, p2)]
    V.report_confidentiality(pairs, reference=None, floor_pinned=True, revocation_checked=True,
                            authenticated=True, record_ok=True, production_roots=True,
                            committed={hd for hd, _ in pairs})
    out = capsys.readouterr().out.split("What is missing:")[1]
    assert "policy denies host access" in out and "policy denies runtime logging" in out


def test_floor_for_another_product_is_not_counted_as_checked(tmp_path, V, kms, monkeypatch):
    # Use real production AMD evidence for the missing-floor check; stub unrelated operation checks
    # so this tests aggregation by main(), not synthetic signatures against the real report.
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = _ref(tmp_path, "reference.json", [host])
    def hardware_only(row, ev, **kw):
        c = V.Checks()
        certs = V.load_certs(base64.b64decode(kms["endorsements"]))
        V.check_amd(c, V.parse_report(base64.b64decode(kms["evidence"])),
                    _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256, kw["min_tcb"])
        assert not c.failed
        return c
    monkeypatch.setattr(V, "verify_search", hardware_only)
    seen = []
    monkeypatch.setattr(V, "report_confidentiality", lambda *a, **kw: seen.append(kw))
    assert V.main([str(d), "--reference", str(ref), "--min-tcb", "Genoa=snpSPL:1"]) == 0
    assert seen[-1]["floor_pinned"] is False
    assert V.main([str(d), "--reference", str(ref), "--min-tcb", "Milan=snpSPL:1"]) == 0
    assert seen[-1]["floor_pinned"] is True


def test_malformed_policy_refuses_instead_of_crashing_or_licensing(V, capsys):
    V.report_confidentiality([('aa', '%%%')], reference=None, floor_pinned=True,
                            revocation_checked=True, authenticated=True, record_ok=True,
                            committed={'aa'}, production_roots=True)
    out = capsys.readouterr().out
    assert "REFUSED" in out and "You may write:" not in out


def test_revocation_failure_precedes_result_and_suppresses_claims(tmp_path, V, kms, monkeypatch, capsys):
    # Isolate main's aggregation/order; no network or fabricated successful hardware verification.
    d, host = _ops_bundle(tmp_path, V, kms, [{"session": "s1", "seq": 1}])
    ref = _ref(tmp_path, "reference.json", [host])
    monkeypatch.setattr(V, "verify_search", lambda *a, **kw: V.Checks())
    def revoked(c, chains):
        c.add(False, "certificate revocation", "test: revoked ASK")
        return False
    monkeypatch.setattr(V, "check_revocation", revoked)
    assert V.main([str(d), "--reference", str(ref), "--check-revocation"]) == 1
    out = capsys.readouterr().out
    assert out.index("test: revoked ASK") < out.index("RESULT: FAILED")
    assert "RESULT: no failing record checks" not in out
    assert "You may write:" not in out


@pytest.mark.parametrize("attestation_present", [False, True])
def test_no_reference_refuses_cleanly_and_reports_actual_attestation_files(tmp_path, V, kms, attestation_present):
    d = _synthetic_bundle(tmp_path, V, kms)
    if attestation_present:
        anchors = d / "trust-anchors"
        anchors.mkdir()
        att = anchors / "publication-key-attestation.json"
        att.write_text(json.dumps({"publication_key": "ab" * 32}))
        bundle = anchors / "publication-key-attestation.bundle"
        bundle.write_text('{}')
        manifest_path = d / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        for path in (att, bundle):
            manifest["files"][str(path.relative_to(d))] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    code, out = _run(d)
    assert code == 1 and "NO REFERENCE SUPPLIED" in out
    assert "Traceback" not in out and "You may write:" not in out
    if attestation_present:
        assert "Coverage WITHHELD" in out
        assert "no attestation in this folder" not in out
    else:
        assert "no attestation in this folder" in out


# A FLAT floor is no longer accepted at sealing time: it cannot be shown to have been in force, so
# the check refuses rather than comparing against a threshold whose applicability is unproven. The
# accepted case is therefore a WINDOWED floor whose window is open now.
_OPEN = [{'value': {'Milan': {'snpSPL': 8}}, 'valid_from': '2000-01-01T00:00:00Z',
          'valid_to': None, 'retired': False}]
_CLOSED = [{'value': {'Milan': {'snpSPL': 8}}, 'valid_from': '2000-01-01T00:00:00Z',
            'valid_to': '2001-01-01T00:00:00Z', 'retired': False}]
_FUTURE = [{'value': {'Milan': {'snpSPL': 8}}, 'valid_from': '2099-01-01T00:00:00Z',
            'valid_to': None, 'retired': False}]


@pytest.mark.parametrize('floors,accepted', [
    (_OPEN, True),
    ({'Milan': {'snpSPL': 8}}, False),   # flat: no window, so sealing refuses
    (_CLOSED, False),                    # window already closed
    (_FUTURE, False),                    # window not yet open
    ([{'value': {'Milan': {'snpSPL': 8}}, 'valid_from': '2000-01-01T00:00:00Z',
       'valid_to': None, 'retired': True}], False),   # retroactively revoked
    ({'Milan': {'snpSPL': 255}}, False),
    ({'Genoa': {'snpSPL': 1}}, False),
    ({}, False), (None, False), ([], False),
    ({'Milan': {'snpSPL': True}}, False),
    ({'Milan': {'snpSPL': '8'}}, False),
    ({'Milan': {'snpSPL': 0}}, False),
    ({'Milan': {'notAnSPL': 8}}, False),
    ({'Milan': {'snpSPL': 256}}, False),
])
def test_declared_reference_firmware_is_enforced_before_sealing(V, kms, floors, accepted):
    c = V.Checks()
    V.check_reference_firmware_before_sealing(c, kms, {'min_tcb': floors})
    assert len(c.rows) == 1
    assert (c.rows[0][0] == 'PASS') is accepted
    assert c.rows[0][1] == 'reference firmware floor before sealing'


def test_absent_floor_creates_no_firmware_pass(V, kms):
    c = V.Checks()
    V.check_reference_firmware_before_sealing(c, kms, {})
    assert c.rows == []


def test_firmware_gate_authenticates_report_not_just_level_bytes(V, kms):
    raw = bytearray(base64.b64decode(kms['evidence']))
    raw[0x90] ^= 1
    c = V.Checks()
    V.check_reference_firmware_before_sealing(c, {**kms, 'evidence': base64.b64encode(raw).decode()},
                                            {'min_tcb': {'Milan': {'snpSPL': 8}}})
    assert c.failed == ['reference firmware floor before sealing']


def test_verify_offer_cannot_ignore_reference_floor_or_weaken_it_with_argument(V, kms):
    c = V.verify_offer(kms, reference={'min_tcb': {'Milan': {'snpSPL': 255}}},
                       min_tcb={'Milan': {'snpSPL': 1}})
    assert 'reference firmware floor before sealing' in c.failed


def test_archive_refuses_malformed_reference_floor_instead_of_dropping_it(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    p = tmp_path / 'reference.json'
    ref = json.loads(p.read_text())
    ref['min_tcb'] = {'Milan': {'snpSPL': '8'}}
    p.write_text(json.dumps(ref))
    code, out = _run(d, '--reference', str(p))
    assert code == 2 and 'invalid reference firmware requirement' in out


_MSFT_FEED = "mcr.microsoft.com/aci/aci-cc-infra-fragment"
_MSFT_ISSUER = ("did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
                "::eku:1.3.6.1.4.1.311.76.59.1.3")


def _policy_with(extra_head: str = "", feed: str = _MSFT_FEED, issuer: str = _MSFT_ISSUER, svn: str = "9"):
    import base64 as _b64
    return _b64.b64encode((
        'package policy\n\n' + extra_head +
        f'fragments := [{{"feed":"{feed}","issuer":"{issuer}",'
        f'"includes":["containers","fragments"],"minimum_svn":"{svn}"}}]\n\n'
        'allow_runtime_logging := false\nallow_dump_stacks := false\n'
        'allow_unencrypted_scratch := false\n\n'
        'containers := [{"allow_elevated":false,"allow_stdio_access":false,'
        '"exec_processes":[],"layers":["aa"]}]\n').encode()).decode()


def test_a_RECOGNISED_platform_fragment_is_not_called_unresolved(V):
    """It is identified, pinned and its contents are disclosed. Calling it 'unresolved' in the same
    run that prints 'every external dependency is identified' tells the reader both at once."""
    c = V.Checks()
    out = V.check_policy_posture(c, _policy_with())
    assert out["self_contained"] is False, "a fragment is still not self-contained"
    detail = " ".join(d for _, step, d in c.rows if step == "policy is self-contained")
    assert "unresolved" not in detail, f"recognised fragment still called unresolved: {detail!r}"
    assert "not constrained by the permission rows" in detail.lower()
    assert "not the effective policy" in detail, "the CONSEQUENCE clause must survive"


def test_a_recognised_fragment_PLUS_a_foreign_import_is_still_unresolved(V):
    """The defect an adversarial review reproduced on 2026-09-29. `dependencies` carries Rego imports
    and parse sentinels; platform_dependency_disclosure only ever examines FRAGMENTS. Softening on it
    alone made the verifier vouch for an import nothing had looked at."""
    c = V.Checks()
    out = V.check_policy_posture(c, _policy_with(extra_head="import data.acme.extra_rules\n\n"))
    detail = " ".join(d for _, step, d in c.rows if step == "policy is self-contained")
    assert "unresolved" in detail, (
        "a dependency nothing examined must NOT be described as identified and disclosed: " + repr(detail))
    assert out["dependencies_identified"] is not True, (
        "the identified row must FAIL when an unexamined dependency is in the same list")


def test_an_unparseable_import_is_never_described_as_disclosed(V):
    c = V.Checks()
    V.check_policy_posture(c, _policy_with(extra_head="import\n\n"))
    detail = " ".join(d for _, step, d in c.rows if step == "policy is self-contained")
    assert "disclosed below" not in detail, f"vouched for an unparseable import: {detail!r}"


def test_the_closed_control_phrases_are_deontic_and_name_the_program(V):
    """'cannot watch' states a fact about the world from a flag in a document. 'may not' fixes that but
    is ambiguous in English between permission and epistemic possibility ('perhaps they do not'), which
    is weaker and vaguer than intended. And the stdio phrase must keep naming THE PROGRAM: the nearest
    noun is the machine, so dropping it widens a claim that is about the container's streams."""
    phrases = dict(V.PLAIN_CLOSED_WORDS)
    for key, phrase in phrases.items():
        assert len(phrase.split()) <= 15, f"{key}: {len(phrase.split())} words"
        assert "cannot" not in phrase, f"{key} states capability, not permission: {phrase!r}"
        assert " may not " not in f" {phrase} ", f"{key} is ambiguously deontic/epistemic: {phrase!r}"
        assert "not permitted" in phrase, f"{key} must be unambiguously deontic: {phrase!r}"
    assert "program" in phrases["allow_stdio_access"], (
        "the stdio phrase must name the program; the flag is about the container's streams, not the "
        "whole machine: " + repr(phrases["allow_stdio_access"]))


def test_the_opening_line_does_not_say_the_containers_PASSED(V):
    """PLAIN_ANSWER[1] is the line the reader reads FIRST. Fixing 'passed the listed protection checks'
    only in the restatement at the bottom of the block leaves the stronger claim at the top."""
    assert "passed" not in V.PLAIN_ANSWER[1].lower(), V.PLAIN_ANSWER[1]


def _render_plain(V, reach, **closed):
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        V.report_plain(reach, closed=closed, blockers=[])
    return buf.getvalue()


def test_the_platform_paragraph_is_gated_on_KNOWING_what_the_dependency_is(V):
    """Every specific in that paragraph -- a CLOUD PLATFORM, containers permitted to attach to stdio,
    most running elevated -- comes from the PLATFORM_DEPENDENCIES census of Microsoft's fragment. Saying
    it because the policy merely is NOT self-contained asserts those specifics about a dependency the
    same run may be reporting as unreadable. That is the defect fixed one row above, mirrored: a
    confident claim about foreign code the instrument never read, in the alarming direction.
    """
    shut = dict(allow_stdio_access=True, allow_elevated=True, allow_runtime_logging=True)

    none = _render_plain(V, 1, self_contained=True, dependencies_identified=True, **shut)
    assert "cloud platform" not in none, "a self-contained policy has no platform containers"

    known = _render_plain(V, 0, self_contained=False, dependencies_identified=True, **shut)
    assert "lets the cloud platform run further containers" in known
    assert "could not fully verify" not in known

    unknown = _render_plain(V, 0, self_contained=False, dependencies_identified=False, **shut)
    assert "could not fully verify" in unknown, (
        "an unidentified dependency must not be described with Microsoft's census: " + unknown)
    assert "lets the cloud platform run further containers" not in unknown
    assert "not a record of what happened" in unknown, "the neutraliser must survive on every branch"

    # Fail-safe: a posture dict missing the keys must take the cautious branch, never the silent one.
    missing = _render_plain(V, 0, **shut)
    assert "could not fully verify" in missing, "an absent key must fall to the honest branch"


def test_the_unresolved_branch_names_only_items_that_are_unresolved(V):
    """With a recognised fragment AND a foreign import, the row correctly says 'unresolved' -- but it
    used to list the recognised fragment under that word, while the DISCLOSED line below printed that
    same fragment's measured census. Name only what is actually unresolved."""
    c = V.Checks()
    V.check_policy_posture(c, _policy_with(extra_head="import data.acme.extra_rules\n\n"))
    detail = " ".join(d for _, step, d in c.rows if step == "policy is self-contained")
    assert "unresolved" in detail
    assert "import data.acme.extra_rules" in detail
    assert _MSFT_FEED not in detail, (
        "the recognised fragment must not be listed under the word 'unresolved': " + detail)


def test_a_truncated_dependency_list_says_how_many_it_hid(V):
    """Hiding dependencies matters MOST where they are unknown: a reader told about unidentified
    foreign code and shown 5 of 12, with nothing saying there are 12."""
    head = "".join(f"import data.acme.m{i}\n" for i in range(12)) + "\n"
    c = V.Checks()
    V.check_policy_posture(c, _policy_with(extra_head=head))
    detail = " ".join(d for _, step, d in c.rows if step == "policy is self-contained")
    assert "more)" in detail, f"silent truncation in the unresolved branch: {detail!r}"


def test_the_dead_plain_constants_are_gone(V):
    """PLAIN_ASK, PLAIN_ASK_TRIGGER, PLAIN_WHAT_IT_BUYS and PLAIN_NO_ASK were defined and referenced
    nowhere. PLAIN_ASK was a near-duplicate of the LIVE PLAIN_ASKS[0] carrying older wording -- exactly
    the string a future editor corrects instead of the one a client reads."""
    for dead in ("PLAIN_ASK", "PLAIN_ASK_TRIGGER", "PLAIN_WHAT_IT_BUYS", "PLAIN_NO_ASK"):
        assert not hasattr(V, dead), f"{dead} is dead client-facing text; delete it, do not keep a twin"
    assert hasattr(V, "PLAIN_ASKS"), "the live one must survive"


def test_a_READ_but_UNVALIDATED_fragment_is_not_called_unreadable(V):
    """Found by an independent Codex review on 2026-09-29, after two same-family reviews missed it.
    platform_dependency_disclosure returns None for a RECOGNISED feed whose issuer mismatches or whose
    minimum_svn is under the floor. That declaration was read and parsed -- we know exactly what it is
    -- so saying the document 'pulls in rules this check could not read' states the wrong defect."""
    import io, contextlib
    shut = dict(allow_stdio_access=True, allow_elevated=True, allow_runtime_logging=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        V.report_plain(0, closed={**shut, "self_contained": False, "dependencies_identified": False},
                       blockers=[])
    out = buf.getvalue()
    assert "could not read" not in out, (
        "an unvalidated-but-parsed dependency must not be described as unreadable: " + out)
    assert "could not fully verify" in out, "say what is actually true: it was named but not verified"


# NOTE: test_the_level_one_sentence_does_not_imply_an_exhaustive_list lived here. It pinned
# "required protection settings", which a later independent round showed ALSO borrows completeness
# (reach 1 gates on image_pinned, no_exec and the floor too, none of which the plain list names).
# Superseded by test_the_level_one_headline_does_not_borrow_completeness, which asserts the same
# "listed above" property plus the stronger one, so this is merged rather than kept as a second
# test of one property that would drift against it.


def test_the_BLOCKER_does_not_call_an_identified_dependency_unresolved(V):
    """The twin I missed. The row detail in check_policy_posture was fixed on 2026-09-29 so a
    recognised fragment is no longer called 'unresolved' -- but confidentiality_reach appends its
    blocker on self_contained alone, so the SAME run still told the reader the SAME dependency was
    unresolved. Found by the independent mac-papa round."""
    posture = {k: True for k, *_ in V.CONFIDENTIALITY_POSTURE}
    posture.update({"image_pinned": True, "no_exec": True,
                    "self_contained": False, "dependencies_identified": True})
    _reach, blockers = V.confidentiality_reach(
        posture, floor_pinned=True, revocation_checked=True, image_published=True,
        authenticated=True, record_ok=True, policy_committed=True)
    joined = " ".join(blockers)
    assert "unresolved external fragments" not in joined, (
        "an identified, disclosed dependency must not be called unresolved: " + joined)
    assert "not constrained by the permission rows" in joined.lower(), \
        "say what is actually true: identified, but outside what the rows cover"
    # inversion: when it genuinely is NOT identified, the honest word must come back
    posture["dependencies_identified"] = False
    _r2, b2 = V.confidentiality_reach(posture, floor_pinned=True, revocation_checked=True,
                                      image_published=True, authenticated=True, record_ok=True,
                                      policy_committed=True)
    assert "unresolved external fragments" in " ".join(b2), "the unidentified case must still say so"


def test_every_verified_control_reaches_the_plain_reader(V):
    """At reach 1 all five CONFIDENTIALITY_POSTURE controls are required True, but only three had
    plain-language phrases, so a reader was never told about stack dumps or unencrypted scratch --
    left less confident than the evidence warrants, and unable to repeat two verified facts."""
    post = [r[0] for r in V.CONFIDENTIALITY_POSTURE]
    plain = [k for k, _ in V.PLAIN_CLOSED_WORDS]
    # allow_unencrypted_scratch is excluded BY RULING, not by oversight: saying scratch is encrypted
    # reassures about the one vector that is open, since the platform's containers share the SEV-SNP
    # key domain. See test_no_reassurance_about_encryption_of_working_storage.
    missing = [k for k in post if k not in plain and k != "allow_unencrypted_scratch"]
    assert not missing, f"controls verified but never said in plain words: {missing}"
    assert "allow_unencrypted_scratch" not in plain, "that omission is deliberate; do not 'fix' it"
    for key, phrase in V.PLAIN_CLOSED_WORDS:
        assert len(phrase.split()) <= 15, f"{key}: {len(phrase.split())} words"
        assert "not permitted" in phrase, f"{key} must stay deontic: {phrase!r}"


def test_the_platform_paragraph_carries_the_census_floor_caveat(V):
    """The specifics in that paragraph come from the hardcoded PLATFORM_DEPENDENCIES census, not from
    anything read out of this record, and that census says the version actually in force may be newer
    than anything measured. The caveat printed in the technical row was absent from the plain one."""
    import io, contextlib
    shut = dict(allow_stdio_access=True, allow_elevated=True, allow_runtime_logging=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        V.report_plain(0, closed={**shut, "self_contained": False, "dependencies_identified": True},
                       blockers=[])
    out = buf.getvalue()
    assert "lets the cloud platform run further containers" in out
    assert "may be newer" in out, "the plain paragraph must carry the census's own floor caveat: " + out


def test_a_SKIPPED_floor_is_not_described_as_a_failure(V):
    """floor_pinned is False for a SKIP as well as a FAIL. 'did not PASS' is literally true and reads
    to a non-technical reader as 'the firmware was below the required level'."""
    posture = {k: True for k, *_ in V.CONFIDENTIALITY_POSTURE}
    posture.update({"image_pinned": True, "no_exec": True, "self_contained": True,
                    "dependencies_identified": True})
    _reach, blockers = V.confidentiality_reach(
        posture, floor_pinned=False, revocation_checked=True, image_published=True,
        authenticated=True, record_ok=True, policy_committed=True)
    joined = " ".join(blockers)
    assert "did not PASS" not in joined, "a SKIP must not be worded as a failure: " + joined
    assert "not established as passing" in joined.lower()


def test_the_platform_warning_survives_the_WORST_posture(V):
    """Found by the independent round on 2026-09-29 and reproduced. The platform paragraph lived
    inside `if shut:`, so a policy with external dependencies and NOT ONE control closed printed no
    plain-language mention of the platform's containers at all. The warning was suppressed exactly
    when the posture was worst, and appeared as soon as any single control was closed."""
    worst = _render_plain(V, 0, self_contained=False, dependencies_identified=True)
    assert "further containers" in worst, (
        "the worst posture must still warn about platform containers: " + worst)
    some = _render_plain(V, 0, self_contained=False, dependencies_identified=True,
                         allow_stdio_access=True)
    assert "further containers" in some, "and it must still warn when a control IS closed"
    # inversion: a self-contained policy has no platform containers, so it must stay silent
    none_ = _render_plain(V, 1, self_contained=True, dependencies_identified=True,
                          allow_stdio_access=True)
    assert "further containers" not in none_


def test_state_C_does_not_claim_the_document_NAMES_its_dependencies(V):
    """State C also covers a declaration that could not be parsed at all, labelled
    '<unparseable fragments assignment>' -- there is no feed, source_uri or uri, so nothing is named.
    'names dependencies' asserts a property the verifier has not established."""
    c = _render_plain(V, 0, self_contained=False, dependencies_identified=False,
                      allow_stdio_access=True)
    assert "could not fully verify" in c
    assert "names dependencies" not in c, "nothing is named when the declaration is unparseable: " + c


def test_the_level_one_headline_does_not_borrow_completeness(V):
    """reach 1 gates on more than the plain list shows -- image_pinned, no_exec, the firmware floor.
    Calling the handful of named items 'the required protection settings' invites a reader to treat
    them as sufficient."""
    one = V.PLAIN_BY_REACH[1][0]
    assert "listed above" not in one
    assert "required protection settings" not in one, one
    assert "this verifier checked" in one, one
