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


@pytest.fixture(autouse=True)
def _record_fixture_build(monkeypatch):
    """The synthetic quote's build (MRTD aa…, RTMR1-3 b1/b2/b3…) is a recorded build for these tests."""
    from inferroute_local.confidential import builds
    monkeypatch.setattr(builds, "BUNDLED", [{"id": "fixture", "status": "reviewed", "first_seen": "2026-01-01",
                                            "mrtd": "aa" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}])
    monkeypatch.setattr(builds, "_EXTRA", [])


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
    assert set(A.LABELS) == set(A.REQUIRED) | set(A.REQUIRED_ONLINE)
    assert not any(k == "attributed-key" for k, _ in A.LIMITATIONS), "the key binding is a CHECK now, not a limitation"
    assert "e2e_key_bound" in A.REQUIRED


def test_evidence_fetch_backs_off_on_429_then_succeeds_and_gives_up_after_attempts(monkeypatch):
    import asyncio
    calls = {"n": 0}
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda s: real_sleep(0))

    class R:
        def __init__(self, code):
            self.status_code, self.headers = code, {"Retry-After": "0"}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")
        def json(self):
            return {}

    class Http:
        async def get(self, url, headers=None, timeout=None):
            calls["n"] += 1
            return R(429 if calls["n"] < 3 else 200)
    r = asyncio.run(A._get_retry(Http(), "u", {}, 1.0))
    assert r.status_code == 200 and calls["n"] == 3

    class Dead:
        async def get(self, url, headers=None, timeout=None):
            return R(429)
    with pytest.raises(RuntimeError):
        asyncio.run(A._get_retry(Dead(), "u", {}, 1.0, attempts=2))


def test_an_unrecorded_build_is_refused_unless_explicitly_allowed(world, monkeypatch):
    from inferroute_local.confidential import builds
    q = base64.b64encode(_quote(world["rd"], mrtd=b"\xCC" * 48, chain=world["pem"].encode())).decode()
    ref = {"configs": [{"name": "x", "mrtd": "cc" * 48, "rtmrs": ["b0" * 48, "b1" * 48, "b2" * 48, "b3" * 48]}]}
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    assert r.checks["measurement_ok"].ok, "published by the operator…"
    assert not r.checks["build_recorded"].ok and "not recorded" in r.checks["build_recorded"].why and not r.verified
    monkeypatch.setenv("IR_CONFIDENTIAL_ALLOW_NEW_BUILD", "1")
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    assert r.checks["build_recorded"].ok and "NEW BUILD" in r.checks["build_recorded"].why
    monkeypatch.delenv("IR_CONFIDENTIAL_ALLOW_NEW_BUILD")
    # A build served at run time is accepted so a genuine new operator build can be recorded in
    # minutes — but it is NOT what "recorded by InferRoute" means, and it must not be able to
    # claim that it is. It is the seam a compromised relay would use: every other check would pass
    # truthfully against an enclave the attacker controls, so this row is the whole attack.
    assert builds.absorb_remote([{"id": "later", "status": "reviewed", "mrtd": "cc" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}]) == 1
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    why = r.checks["build_recorded"].why
    assert r.checks["build_recorded"].ok
    assert "PENDING" in why and "run time" in why
    assert "recorded by InferRoute since" not in why and "reviewed by InferRoute" not in why
    assert builds.lookup("cc" * 48, ["", "b1" * 48, "b2" * 48, "b3" * 48])["origin"] == "relay"
    assert builds.absorb_remote([{"id": "dup", "mrtd": "cc" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}]) == 0


def test_a_run_time_build_can_never_displace_our_own_record_of_the_same_measurements(world):
    """The shipped entry must win, whatever the relay says about the same measurements."""
    from inferroute_local.confidential import builds
    b = builds.BUNDLED[0]
    assert builds.absorb_remote([{"id": "impostor", "status": "reviewed", "mrtd": b["mrtd"],
                                  "rtmr1": b["rtmr1"], "rtmr2": b["rtmr2"], "rtmr3": b["rtmr3"]}]) == 0
    got = builds.lookup(b["mrtd"], ["", b["rtmr1"], b["rtmr2"], b["rtmr3"]])
    assert got["id"] == b["id"] and got["origin"] == "bundled"


def test_rtmr0_is_not_part_of_the_build_identity(world):
    """RTMR0 (host boot firmware config) varies across hosts of one fleet; a different RTMR0 with the
    same image is the same recorded build."""
    q = _quote(world["rd"], chain=world["pem"].encode())
    body = bytearray(q[A._HDR:A._HDR + A._BODY])
    body[328:376] = b"\x99" * 48
    q2 = q[:A._HDR] + bytes(body) + q[A._HDR + A._BODY:]
    ref = {"configs": [{"name": "h", "mrtd": "aa" * 48, "rtmrs": ["99" * 48, "b1" * 48, "b2" * 48, "b3" * 48]}]}
    r = A.verify_instance(dict(world["inst"], quote=base64.b64encode(q2).decode()), NONCE, ref, world["e2e_pk"])
    assert r.checks["build_recorded"].ok


def test_measurements_must_be_field_values_not_substrings_of_the_registry(world):
    """The registry is fetched from a URL the relay supplies, so "the hex appears somewhere in
    this JSON" is not a property worth checking. One field holding all five concatenated used to
    pass."""
    q = A.quote_fields(base64.b64decode(world["inst"]["quote"]))
    mine = {k: q[k].hex() for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    honest = {"configs": [{"name": "real", "mrtd": mine["mrtd"],
                           "rtmrs": [mine["rtmr0"], mine["rtmr1"], mine["rtmr2"], mine["rtmr3"]]}]}
    assert A.check_measurements(q, honest).ok
    smuggled = {"configs": [{"name": "x", "notes": "".join(mine.values())}]}
    assert not A.check_measurements(q, smuggled).ok
    # nor may values be borrowed across two different images
    split = {"configs": [{"name": "a", "mrtd": mine["mrtd"], "rtmrs": [mine["rtmr0"], mine["rtmr1"]]},
                         {"name": "b", "rtmrs": [mine["rtmr2"], mine["rtmr3"]]}]}
    assert not A.check_measurements(q, split).ok


def test_a_session_caveat_becomes_a_limitation_so_it_reaches_the_receipt_and_the_model():
    """A caveat that only reaches the screen does not reach the person reading the receipt later,
    nor the assistant answering "is this private?"."""
    def lims(why):
        return dict(A.situational_limitations({"build_recorded": {"why": why}}))
    assert "pending-build" in lims("build x — PENDING — served at run time, not shipped")
    assert "new-build" in lims("NEW BUILD — not yet recorded by InferRoute")
    repro = lims("build x — recorded by InferRoute since 2026-09-12; MRTD+RTMR1 recomputed here from published artifacts")
    assert "reproduced" in repro and "MRTD+RTMR1" in repro["reproduced"]
    # a plain recorded build makes no claim either way
    assert lims("build x — recorded by InferRoute since 2026-09-12") == {}


def test_the_standing_limitation_no_longer_claims_a_reproduction_for_every_build():
    """It is written into every receipt, including sessions where nothing was recomputed."""
    text = dict(A.LIMITATIONS)["build-review"]
    assert "two" not in text and "firmware and the bootloader chain" not in text
    assert "Except where a measurement has been independently recomputed" in text
