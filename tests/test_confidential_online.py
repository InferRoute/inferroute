"""Intel PCS + NVIDIA NRAS checks: synthetic quotes with real ECDSA keys, synthetic collateral
signed by a synthetic 'Intel' root (pinned for the test), a synthetic NRAS JWT signed with a
test ES384 key — every check has a known-positive and a known-negative. No network."""
import base64
import datetime as dt
import hashlib
import json
import struct
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier

from inferroute_local.confidential import attest as A, attest_intel as AI, attest_nvidia as AN

NONCE = "ab" * 32
FMSPC = "90c06f000000"


def _sig64(key, data: bytes, halg=hashes.SHA256()) -> bytes:
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(halg)))
    n = 48 if isinstance(halg, hashes.SHA384) else 32
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")


def _sgx_ext(cpusvn: bytes, pcesvn: int, fmspc: str) -> bytes:
    """Minimal DER for the PCK SGX extension: SEQ { SEQ{oid .2, SEQ{ SEQ{oid .2.17, INT}, SEQ{oid .2.18, OCT} }}, SEQ{oid .3, OCT}, SEQ{oid .4, OCT} }."""
    def der(tag, body):
        ln = len(body)
        return bytes([tag]) + (bytes([ln]) if ln < 128 else b"\x82" + ln.to_bytes(2, "big")) + body
    def oid(s):
        parts = [int(x) for x in s.split(".")]
        out = bytes([parts[0] * 40 + parts[1]])
        for v in parts[2:]:
            enc = [v & 0x7F]
            v >>= 7
            while v:
                enc.insert(0, (v & 0x7F) | 0x80)
                v >>= 7
            out += bytes(enc)
        return der(0x06, out)
    base = "1.2.840.113741.1.13.1"
    tcb = der(0x30, der(0x30, oid(base + ".2.17") + der(0x02, bytes([pcesvn]))) + der(0x30, oid(base + ".2.18") + der(0x04, cpusvn)))
    inner = der(0x30, oid(base + ".2") + tcb) + der(0x30, oid(base + ".3") + der(0x04, b"\x00\x00")) + der(0x30, oid(base + ".4") + der(0x04, bytes.fromhex(fmspc)))
    return der(0x30, inner)


def _cert(cn, key, issuer=None, issuer_key=None, ext_der=None, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30)))
    if ext_der:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(AI._OID_SGX_EXT), ext_der), critical=False)
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key or key, hashes.SHA256())


def _crl(issuer_cert, issuer_key, revoked=()):
    now = dt.datetime.now(dt.timezone.utc)
    b = x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject).last_update(now - dt.timedelta(days=1)).next_update(now + dt.timedelta(days=30))
    for serial in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now - dt.timedelta(hours=1)).build())
    return b.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def intel(monkeypatch):
    """A synthetic Intel PKI: root (pinned for the test) → Platform CA → PCK leaf; a TCB signing
    cert under the root; a v4 TDX quote with real signature data; signed TCB Info and QE Identity."""
    root_k, ca_k, pck_k, tcb_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    root = _cert("Intel SGX Root CA", root_k, ca=True)
    ca = _cert("Intel SGX PCK Platform CA", ca_k, issuer=root.subject, issuer_key=root_k, ca=True)
    cpusvn = bytes.fromhex("04040202040100050000000000000000")
    pck = _cert("Intel SGX PCK Certificate", pck_k, issuer=ca.subject, issuer_key=ca_k, ext_der=_sgx_ext(cpusvn, 13, FMSPC))
    tcbsign = _cert("Intel SGX TCB Signing", tcb_k, issuer=root.subject, issuer_key=root_k)
    monkeypatch.setattr(AI, "INTEL_ROOT_SPKI_SHA256", AI._spki_sha256(root))
    chain_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (pck, ca, root))

    # quote: header(48) + body(584) + sig data
    tee_tcb_svn = bytes.fromhex("0e010400000000000000000000000000")
    body = bytearray(A._BODY)
    body[0:16] = tee_tcb_svn
    body[136:184] = b"\xaa" * 48
    for i, (a, b_) in enumerate([(328, 376), (376, 424), (424, 472), (472, 520)]):
        body[a:b_] = bytes([0xB0 + i]) * 48
    hdr = (4).to_bytes(2, "little") + b"\x00\x00" + (0x81).to_bytes(4, "little") + b"\x00" * 40
    hb = hdr + bytes(body)
    ak = ec.generate_private_key(ec.SECP256R1())
    nums = ak.public_key().public_numbers()
    akey = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    auth = b"\x11" * 32
    qe = bytearray(384)
    qe[16:20] = b"\x00\x00\x00\x00"
    qe[48:64] = bytes.fromhex("1500000000000000e700000000000000")
    qe[128:160] = bytes.fromhex("DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5")
    struct.pack_into("<H", qe, 256, 2)
    struct.pack_into("<H", qe, 258, 8)
    qe[320:352] = hashlib.sha256(akey + auth).digest()
    qe = bytes(qe)
    qe_sig = _sig64(pck_k, qe)
    inner = struct.pack("<HI", 5, len(chain_pem)) + chain_pem
    cd = qe + qe_sig + struct.pack("<H", len(auth)) + auth + inner
    sd = _sig64(ak, hb) + akey + struct.pack("<HI", 6, len(cd)) + cd
    quote = hb + struct.pack("<I", len(sd)) + sd

    def signed(key_name, obj):
        raw = json.dumps(obj, separators=(",", ":"))
        text = '{"' + key_name + '":' + raw + ',"signature":"' + _sig64(tcb_k, raw.encode()).hex() + '"}'
        return text
    nxt = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tcb_info = {"id": "TDX", "version": 3, "fmspc": FMSPC, "nextUpdate": nxt, "tcbLevels": [
        {"tcb": {"sgxtcbcomponents": [{"svn": v} for v in cpusvn], "pcesvn": 13, "tdxtcbcomponents": [{"svn": v} for v in tee_tcb_svn]},
         "tcbDate": "2025-08-13T00:00:00Z", "tcbStatus": "UpToDate"},
        {"tcb": {"sgxtcbcomponents": [{"svn": 0}] * 16, "pcesvn": 0, "tdxtcbcomponents": [{"svn": 0}] * 16},
         "tcbDate": "2020-01-01T00:00:00Z", "tcbStatus": "OutOfDate", "advisoryIDs": ["INTEL-SA-00000"]}]}
    qe_id = {"id": "TD_QE", "nextUpdate": nxt, "mrsigner": "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5", "isvprodid": 2,
             "attributes": "11000000000000000000000000000000", "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
             "miscselect": "00000000", "miscselectMask": "FFFFFFFF",
             "tcbLevels": [{"tcb": {"isvsvn": 8}, "tcbDate": "2025-01-01T00:00:00Z", "tcbStatus": "UpToDate"},
                           {"tcb": {"isvsvn": 1}, "tcbDate": "2020-01-01T00:00:00Z", "tcbStatus": "OutOfDate"}]}
    tcb_text, qe_text = signed("tcbInfo", tcb_info), signed("enclaveIdentity", qe_id)
    col = AI.Collateral(fmspc=FMSPC, tcb_info=tcb_info, tcb_raw=AI._raw_object(tcb_text, "tcbInfo"), tcb_sig=bytes.fromhex(json.loads(tcb_text)["signature"]),
                        tcb_chain=[tcbsign, root], qe_identity=qe_id, qe_raw=AI._raw_object(qe_text, "enclaveIdentity"),
                        qe_sig=bytes.fromhex(json.loads(qe_text)["signature"]), qe_chain=[tcbsign, root],
                        pck_crl=_crl(ca, ca_k), root_crl=_crl(root, root_k))
    return {"quote": quote, "certs": [pck, ca, root], "col": col, "keys": (root_k, ca_k, pck_k, tcb_k), "cpusvn": cpusvn, "tee": tee_tcb_svn, "qe": qe}


def test_intel_known_positive(intel):
    q, certs, col = intel["quote"], intel["certs"], intel["col"]
    assert AI.check_quote_signature(q, certs).ok
    assert AI.check_root_pinned(certs).ok
    ext = AI.pck_extension(certs[0])
    assert ext["fmspc"] == FMSPC and ext["cpusvn"] == intel["cpusvn"] and ext["pcesvn"] == 13
    out = AI.platform_checks(q, certs, col)
    assert all(c.ok for c in out.values()), {k: c.why for k, c in out.items() if not c.ok}
    assert "UpToDate" in out["tcb_current"].why


def test_intel_quote_tampering_and_wrong_keys_are_refused(intel):
    q, certs = intel["quote"], intel["certs"]
    t = bytearray(q)
    t[100] ^= 1                                          # a byte in the TD report body
    assert not AI.check_quote_signature(bytes(t), certs).ok
    other = ec.generate_private_key(ec.SECP256R1())
    stranger = _cert("Intel SGX PCK Certificate", other)
    assert "QE report signature" in AI.check_quote_signature(q, [stranger] + certs[1:]).why
    assert not AI.check_root_pinned([certs[0], certs[1], stranger]).ok
    assert not AI.check_quote_signature(q[: A._HDR + A._BODY + 2], certs).ok


def test_intel_revocation_and_collateral_signature_and_expiry(intel):
    q, certs, col = intel["quote"], intel["certs"], intel["col"]
    root_k, ca_k, pck_k, tcb_k = intel["keys"]
    revoked = _crl(certs[1], ca_k, revoked=[certs[0].serial_number])
    assert "REVOKED" in AI.check_not_revoked(certs, revoked, col.root_crl).why
    assert not AI.check_not_revoked(certs, _crl(certs[1], root_k), col.root_crl).ok, "a CRL not signed by its issuer is refused"
    bad = AI.Collateral(**{**col.__dict__, "tcb_sig": b"\x00" * 64})
    assert not AI.platform_checks(q, certs, bad)["tcb_current"].ok
    stale = AI.Collateral(**{**col.__dict__, "tcb_info": {**col.tcb_info, "nextUpdate": "2020-01-01T00:00:00Z"}})
    assert "expired" in AI.platform_checks(q, certs, stale)["tcb_current"].why


def test_tcb_and_qe_evaluation(intel):
    col, cpusvn, tee, qe = intel["col"], intel["cpusvn"], intel["tee"], intel["qe"]
    assert AI.evaluate_tcb(col.tcb_info, cpusvn, 13, tee)[0] == "UpToDate"
    older = bytes([cpusvn[0] - 1]) + cpusvn[1:]
    assert AI.evaluate_tcb(col.tcb_info, older, 13, tee)[0] == "OutOfDate"
    assert AI.evaluate_tcb(col.tcb_info, cpusvn, 12, tee)[0] == "OutOfDate", "an older PCE SVN drops to the older level"
    assert AI.evaluate_tcb({"tcbLevels": []}, cpusvn, 13, tee)[0] == "Unknown"
    assert AI.evaluate_qe(col.qe_identity, qe)[0] == "UpToDate"
    bad = bytearray(qe)
    bad[16] = 0x01                                       # miscselect bit inside the mask
    assert AI.evaluate_qe(col.qe_identity, bytes(bad))[0] == "Mismatch"
    bad = bytearray(qe)
    bad[48] |= 0x04                                      # an attribute bit OUTSIDE the mask is ignored
    assert AI.evaluate_qe(col.qe_identity, bytes(bad))[0] == "UpToDate"
    old = bytearray(qe)
    struct.pack_into("<H", old, 258, 1)
    assert AI.evaluate_qe(col.qe_identity, bytes(old))[0] == "OutOfDate"


# ───────────────────────── NVIDIA ─────────────────────────

@pytest.fixture
def nras():
    k = ec.generate_private_key(ec.SECP384R1())
    n = k.public_key().public_numbers()
    kid = "nv-eat-kid-test"
    jwks = {"keys": [{"kty": "EC", "crv": "P-384", "kid": kid,
                      "x": base64.urlsafe_b64encode(n.x.to_bytes(48, "big")).decode().rstrip("="),
                      "y": base64.urlsafe_b64encode(n.y.to_bytes(48, "big")).decode().rstrip("=")}]}
    def tok(claims):
        h = base64.urlsafe_b64encode(json.dumps({"kid": kid, "alg": "ES384"}).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        s = base64.urlsafe_b64encode(_sig64(k, f"{h}.{p}".encode(), hashes.SHA384())).decode().rstrip("=")
        return f"{h}.{p}.{s}"
    good = {c: True for c in AN.REQUIRED_GPU_CLAIMS}
    good.update({"measres": "success", "dbgstat": "disabled", "secboot": True, "hwmodel": "GB100", "ueid": "1234567890", "x-nvidia-gpu-driver-version": "595.71.05",
                 "x-nvidia-gpu-vbios-version": "97.00.E4.00.0B", "x-nvidia-attestation-warning": None, "iss": AN.NRAS, "exp": time.time() + 3600})
    def resp(nonce, overall=True, gpu_over=None, n=2):
        oc = {"iss": AN.NRAS, "exp": time.time() + 3600, "eat_nonce": nonce, "x-nvidia-overall-att-result": overall}
        per = {f"GPU-{i}": tok({**good, "eat_nonce": nonce, **(gpu_over or {})}) for i in range(n)}
        return [["JWT", tok(oc)], per]
    return {"jwks": jwks, "tok": tok, "resp": resp, "good": good}


def test_nvidia_known_positive_and_summary(nras):
    exp = AN.challenge(NONCE, "PK")
    v = AN.evaluate(nras["resp"](exp, n=8), nras["jwks"], exp)
    assert v.ok and v.n_gpus == 8 and v.hwmodel == "GB100" and "595.71.05" in v.why and "challenge matched" in v.why
    assert v.per_gpu["GPU-0"]["driver"] == "595.71.05"


def test_nvidia_refusals(nras):
    exp = AN.challenge(NONCE, "PK")
    assert "different challenge" in AN.evaluate(nras["resp"]("00" * 32), nras["jwks"], exp).why
    assert "overall result false" in AN.evaluate(nras["resp"](exp, overall=False), nras["jwks"], exp).why
    assert "nonce-match" in AN.evaluate(nras["resp"](exp, gpu_over={"x-nvidia-gpu-attestation-report-nonce-match": False}), nras["jwks"], exp).why
    assert "debug-enabled" in AN.evaluate(nras["resp"](exp, gpu_over={"dbgstat": "enabled"}), nras["jwks"], exp).why
    assert "measres" in AN.evaluate(nras["resp"](exp, gpu_over={"measres": "fail"}), nras["jwks"], exp).why
    # a token signed by a key NOT in NVIDIA's JWKS
    other = ec.generate_private_key(ec.SECP384R1())
    r = nras["resp"](exp)
    h, p, _ = r[0][1].split(".")
    r[0][1] = f"{h}.{p}." + base64.urlsafe_b64encode(_sig64(other, f"{h}.{p}".encode(), hashes.SHA384())).decode().rstrip("=")
    assert "does not verify" in AN.evaluate(r, nras["jwks"], exp).why
    assert AN.challenge("ab", "cd") == hashlib.sha256(b"abcd").hexdigest()


def test_verify_online_marks_unreachable_services_as_failed_checks_never_raises(intel):
    """Fail-closed: no Intel → Intel checks fail with the reason; no NVIDIA → GPU check fails."""
    import asyncio
    q = intel["quote"]
    rep = A.InstanceReport("i-1", {k: A.Check(True, "x") for k in A.REQUIRED}, 8, "aa", [], True, e2e_pubkey="PK")
    class Dead:
        async def get(self, *a, **k):
            raise ConnectionError("offline")
        async def post(self, *a, **k):
            raise ConnectionError("offline")
    inst = {"quote": base64.b64encode(q).decode(), "gpu_evidence": [{"arch": "BLACKWELL", "evidence": "x", "certificate": "y"}]}
    out = asyncio.run(A.verify_online(rep, inst, NONCE, Dead()))
    assert out.checks["quote_sig"].ok, "the quote's own signature needs no network"
    assert not out.verified
    assert "Intel collateral unavailable" in out.checks["tcb_current"].why
    assert "NVIDIA attestation service unavailable" in out.checks["gpu_verified"].why
    assert set(A.REQUIRED_ONLINE) <= set(out.checks) and out.online_done
    assert out.failing == ["root_pinned", "not_revoked", "tcb_current", "qe_current", "gpu_verified"]
