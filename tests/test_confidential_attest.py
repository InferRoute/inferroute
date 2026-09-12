"""Attestation verifier: a synthetic instance shaped like the real evidence (base64-JSON body
signed over the DECODED bytes, quote with an embedded PEM chain, report_data bound to the cert's
SPKI) verifies; each check has a known-negative that REFUSES; the empty fleet never verifies."""
import base64
import datetime as dt
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from inferroute_local.confidential import attest as A

NONCE = "ab" * 32


def _cert(cn="selftest-leaf", key=None, issuer=None, issuer_key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .sign(issuer_key or key, hashes.SHA256()))
    return key, cert


def _quote(report_data: bytes, *, tee=0x81, ver=4, debug=False, mrtd=b"\xAA" * 48, chain=b"") -> bytes:
    body = bytearray(A._BODY)
    body[120:128] = bytes([1 if debug else 0]) + b"\x00" * 7
    body[136:184] = mrtd
    for i, (a, b) in enumerate([(328, 376), (376, 424), (424, 472), (472, 520)]):
        body[a:b] = bytes([0xB0 + i]) * 48
    body[520:584] = report_data
    return ver.to_bytes(2, "little") + b"\x00\x00" + tee.to_bytes(4, "little") + b"\x00" * 40 + bytes(body) + chain


@pytest.fixture
def world():
    key, cert = _cert()
    pem = cert.public_bytes(serialization.Encoding.PEM)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    e2e_pk = base64.b64encode(b"\x42" * 1184).decode()
    rd = hashlib.sha256((NONCE + e2e_pk).encode()).digest() + hashlib.sha256(spki).digest()
    inner = json.dumps({"evidence": {"tdx_quote": "…"}, "nonce": NONCE}).encode()
    sig = base64.b64encode(key.sign(inner, padding.PKCS1v15(), hashes.SHA256())).decode()
    inst = {"instance_id": "i-good", "quote": base64.b64encode(_quote(rd, chain=pem)).decode(),
            "certificate": pem.decode(), "signature": sig,
            "attested_body": base64.b64encode(inner).decode(), "gpu_evidence": [{}] * 8}
    ref = {"configs": [{"name": "h200-x8", "mrtd": "aa" * 48, "rtmrs": ["b0" * 48, "b1" * 48, "b2" * 48, "b3" * 48]},
                       {"name": "other", "mrtd": "cc" * 48, "rtmrs": ["dd" * 48] * 4}]}
    return {"key": key, "cert": cert, "pem": pem.decode(), "rd": rd, "inst": inst, "ref": ref, "inner": inner, "e2e_pk": e2e_pk}


def test_known_positive_verifies_every_check(world):
    r = A.verify_instance(world["inst"], NONCE, world["ref"], world["e2e_pk"])
    assert r.verified, r.failing
    assert r.e2e_pubkey == world["e2e_pk"]
    assert r.gpu_count == 8 and r.mrtd == "aa" * 48 and len(r.rtmrs) == 4
    assert "h200-x8" in r.checks["measurement_ok"].why
    assert r.checks["sig_ok"].why.startswith("verifies over the base64-decoded JSON")


def test_wrong_nonce_is_refused(world):
    r = A.verify_instance(world["inst"], "ff" * 32, world["ref"], world["e2e_pk"])
    assert not r.verified and r.failing == ["nonce_in_body", "e2e_key_bound"], "a foreign nonce breaks both the body and the key binding"


def test_tampered_body_and_wrong_key_signature_are_refused(world):
    inst = dict(world["inst"], attested_body=base64.b64encode(world["inner"] + b" ").decode())
    assert not A.verify_instance(inst, NONCE, world["ref"], world["e2e_pk"]).checks["sig_ok"].ok
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig2 = base64.b64encode(other.sign(world["inner"], padding.PKCS1v15(), hashes.SHA256())).decode()
    assert not A.verify_instance(dict(world["inst"], signature=sig2), NONCE, world["ref"], world["e2e_pk"]).checks["sig_ok"].ok


def test_quote_not_bound_to_the_certificate_is_refused(world):
    q = base64.b64encode(_quote(b"\x22" * 64, chain=world["pem"].encode())).decode()
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["spki_bound"].ok and "MISMATCH" in r.checks["spki_bound"].why


@pytest.mark.parametrize("kw,expect", [
    ({"debug": True}, "DEBUG"), ({"tee": 0x00}, "not TDX"), ({"ver": 3}, "version 3")])
def test_debuggable_non_tdx_and_wrong_version_quotes_are_refused(world, kw, expect):
    q = base64.b64encode(_quote(world["rd"], chain=world["pem"].encode(), **kw)).decode()
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["tdx_shape"].ok and expect in r.checks["tdx_shape"].why


def test_short_buffer_is_refused_not_crashed(world):
    r = A.verify_instance(dict(world["inst"], quote=base64.b64encode(b"\x00" * 10).decode()), NONCE, world["ref"], world["e2e_pk"])
    assert not r.verified and not r.checks["tdx_shape"].ok and not r.checks["spki_bound"].ok


def test_measurements_must_all_sit_in_one_registry_config(world):
    split = {"configs": [{"name": "a", "mrtd": "aa" * 48, "rtmrs": ["b0" * 48, "b1" * 48]},
                         {"name": "b", "rtmrs": ["b2" * 48, "b3" * 48]}]}
    assert not A.verify_instance(world["inst"], NONCE, split).checks["measurement_ok"].ok
    q = base64.b64encode(_quote(world["rd"], mrtd=b"\xCC" * 48, chain=world["pem"].encode())).decode()
    assert not A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"]).checks["measurement_ok"].ok


def test_chain_without_certificates_or_with_a_stranger_is_refused(world):
    q = base64.b64encode(_quote(world["rd"])).decode()          # no embedded PEM
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["chain_ok"].ok and "no certificates" in r.checks["chain_ok"].why
    _, stranger = _cert("stranger")
    leafkey, leaf = _cert("leaf2", issuer=world["cert"].subject, issuer_key=world["key"])
    assert A.check_chain([leaf, world["cert"]]).ok
    assert not A.check_chain([leaf, stranger]).ok
    assert not A.check_chain([]).ok


def test_a_substituted_encryption_key_is_refused_and_an_absent_one_never_passes(world):
    """The join between 'attested' and 'encrypted to': the quote must commit to the key we seal to."""
    other = base64.b64encode(b"\x43" * 1184).decode()
    r = A.verify_instance(world["inst"], NONCE, world["ref"], other)
    assert not r.verified and r.failing == ["e2e_key_bound"] and "MISMATCH" in r.checks["e2e_key_bound"].why
    assert r.e2e_pubkey == ""
    r = A.verify_instance(world["inst"], NONCE, world["ref"], None)
    assert not r.verified and "no encryption key" in r.checks["e2e_key_bound"].why


def test_fleet_report_arithmetic_and_empty_fleet(world):
    doc = {"evidence": [world["inst"], dict(world["inst"], instance_id="i-bad", attested_body=base64.b64encode(b"{}").decode())],
           "failed_instance_ids": ["i-dead"]}
    fr = A.verify_fleet("chute-1", doc, world["ref"], NONCE, {"i-good": world["e2e_pk"], "i-bad": world["e2e_pk"]})
    assert fr.verified_ids == ["i-good"] and fr.failed_instance_ids == ["i-dead"]
    assert fr.as_dict()["verified"] == 1
    assert A.verify_fleet("chute-1", {"evidence": []}, world["ref"], NONCE, {}).verified_ids == []
    assert A.verify_fleet("chute-1", doc, world["ref"], NONCE).verified_ids == [], "no keys supplied → nothing verifies"


def test_labels_cover_every_required_check_and_limitations_name_the_key_gap():
    assert set(A.LABELS) == set(A.REQUIRED)
    assert not any(k == "attributed-key" for k, _ in A.LIMITATIONS), "the key binding is a CHECK now, not a limitation"
    assert "e2e_key_bound" in A.REQUIRED
