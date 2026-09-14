"""The bundled independent verifier, proven against REAL Azure evidence (public Microsoft samples in
tests/fixtures/aci, see SOURCE.md) under PRODUCTION pins — and shown to refuse tampering. This is the file a
stranger runs; if it passed bad evidence or failed good evidence the whole record would be worthless, so it
is tested against real silicon, not only against our fake.
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
    src = SCRIPT.read_text()
    assert "sealedresearch" not in src and "inferroute_cli" not in src and "inferroute_local" not in src
    # its only third-party dependency is `cryptography`
    for line in src.splitlines():
        if line.startswith(("import ", "from ")) and not line.startswith("from __future__"):
            mod = line.split()[1].split(".")[0]
            assert mod in {"base64", "hashlib", "json", "os", "struct", "sys", "typing", "cryptography", "datetime",
                           "argparse", "warnings"}, line


def test_real_amd_chain_and_uvm_verify_under_production_pins(V, kms):
    report = base64.b64decode(kms["evidence"])
    p = V.parse_report(report)
    certs = V.load_certs(base64.b64decode(kms["endorsements"]))
    c = V.Checks()
    V.check_amd(c, p, _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256)
    meas = V.check_uvm(c, base64.b64decode(kms["uvm_endorsements"]), V.MS_UVM_ROOT_SHA256_B64URL, V.UVM_MIN_SVN)
    assert c.failed == [], c.rows
    assert meas is not None and p["measurement"] == meas           # the endorsed UVM is the one that booted
    names = {n for _, n, _ in c.rows}
    for must in ("AMD root pinned", "report signature", "VCEK is for this chip", "VCEK is for this firmware",
                 "UVM root is Microsoft's", "UVM endorsement signature", "debug disabled"):
        assert must in names


def test_real_host_data_is_the_policy(V):
    p = V.parse_report((FIX / "sidecar-snp_report.bin").read_bytes())
    pol = (FIX / "sidecar-uvm_security_policy.base64").read_text().strip()
    assert hashlib.sha256(base64.b64decode(pol)).hexdigest() == p["host_data"].hex()


def test_tampered_report_and_wrong_pin_are_refused(V, kms):
    report = bytearray(base64.b64decode(kms["evidence"]))
    certs = V.load_certs(base64.b64decode(kms["endorsements"]))
    report[0x90] ^= 1                                               # one bit in MEASUREMENT (signed region)
    c = V.Checks()
    V.check_amd(c, V.parse_report(bytes(report)), _pem(certs[:1]), _pem(certs[1:]), V.AMD_ARK_SPKI_SHA256)
    assert "report signature" in c.failed
    c2 = V.Checks()
    bad_pins = {k: "00" * 32 for k in V.AMD_ARK_SPKI_SHA256}
    V.check_amd(c2, V.parse_report(base64.b64decode(kms["evidence"])), _pem(certs[:1]), _pem(certs[1:]), bad_pins)
    assert "AMD root pinned" in c2.failed
    # a UVM endorsement checked against the wrong Microsoft root is refused
    c3 = V.Checks()
    V.check_uvm(c3, base64.b64decode(kms["uvm_endorsements"]), "AAAA" * 10 + "AAA", V.UVM_MIN_SVN)
    assert "UVM root is Microsoft's" in c3.failed and "UVM issuer pinned" in c3.failed


def _synthetic_bundle(tmp_path, V, kms, *, break_result=False, break_query=False, break_manifest=False):
    """A bundle whose hardware evidence is REAL (kms sample) but whose statement is signed by a fresh test key
    committed in a runtime_data we control — enough to exercise every content/binding check end to end.
    The REPORT_DATA check must SKIP/FAIL (the real report was not made over our runtime data); the point
    here is the statement, query, result, manifest and evidence-hash checks."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    rd = {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8, "statement_signer_pub": pub,
          "enclave_x25519_pub": "cd" * 32, "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32,
          "index_snapshot": "us-2026-09", "pipeline_version": "t"}
    rd_bytes = json.dumps(rd).encode()
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
    ev = {"offer": offer}
    ev_bytes = json.dumps(ev, indent=1).encode()
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
    (d / "searches.json").write_text(json.dumps([row]))
    (d / "record.html").write_text("<html>record</html>")
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    if break_manifest:
        files["record.html"] = "00" * 32
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))
    return d


def _run(d, *extra):
    r = subprocess.run([sys.executable, str(SCRIPT), str(d), *extra], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def test_cli_passes_a_consistent_bundle_and_binds_query_result_and_date(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    code, out = _run(d)
    assert "PASS bundle integrity" in out
    assert "PASS statement signature" in out
    assert "PASS signer key committed in runtime data" in out
    assert "PASS query text is the one searched" in out
    assert "PASS result is the signed result" in out and "PASS hit count as signed" in out
    assert "PASS date bound as recorded" in out
    assert "PASS AMD root pinned" in out and "PASS UVM endorsement signature" in out
    # the REAL report was not produced over OUR runtime data, so this binding must NOT pass silently
    assert "FAIL REPORT_DATA binds runtime data" in out
    assert code == 1                                                # honest: one binding genuinely fails here


def test_cli_refuses_a_changed_result_query_or_manifest(tmp_path, V, kms):
    for kw, expect in (({"break_result": True}, "FAIL result is the signed result"),
                       ({"break_query": True}, "FAIL query text is the one searched"),
                       ({"break_manifest": True}, "FAIL bundle integrity")):
        d = _synthetic_bundle(tmp_path / expect.replace(" ", "_"), V, kms, **kw)
        code, out = _run(d)
        assert expect in out and code == 1


def test_cli_announces_non_production_pins(tmp_path, V, kms):
    d = _synthetic_bundle(tmp_path, V, kms)
    _, out = _run(d, "--amd-pin", "Milan=" + "00" * 32)
    assert "NON-PRODUCTION ROOTS PINNED" in out
