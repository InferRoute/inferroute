"""Intel side of the attestation: the quote's own signatures, Intel's root of trust, revocation,
and platform TCB currency — checked against Intel's Provisioning Certification Service (PCS).

Everything here is the subset of Intel DCAP quote verification a client needs, written natively:

  quote signature   the ECDSA-P256 signature in the quote's signature data verifies over
                    header+body under the attestation key; the QE report's report_data[0:32]
                    == SHA-256(attestation key ‖ QE auth data); the QE report is signed by the
                    PCK certificate → the quote was produced by Intel's Quoting Enclave on the
                    platform the PCK certificate identifies.
  root pinned       the PCK chain's root SPKI hash equals Intel's published SGX Root CA
                    (fetched once from certificates.trustedservices.intel.com and pinned here).
  not revoked       no certificate in the chain appears on Intel's PCK CRL or Root CA CRL.
  tcb current       the platform's CPU SVN / PCE SVN (from the PCK certificate's SGX extension)
                    and the TD's TEE TCB SVN match a level in Intel's signed TCB Info for the
                    platform's FMSPC whose status is UpToDate or SWHardeningNeeded; the TCB Info
                    signature verifies under Intel's TCB signing certificate, itself chained to
                    the pinned root; the collateral is within its validity window.
  qe current        the Quoting Enclave's MRSIGNER / ISVPRODID / attributes / miscselect match
                    Intel's signed QE Identity and its ISVSVN is at an UpToDate level.

What is sent to Intel: the platform's FMSPC (a 6-byte platform family id) and nothing else.
Collateral is cached per FMSPC for the life of the process.
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
import urllib.parse
from dataclasses import dataclass, field

from .attest import Check, _cn, _HDR, _BODY

PCS = "https://api.trustedservices.intel.com"
INTEL_ROOT_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"
INTEL_ROOT_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
# SHA-256 of the SubjectPublicKeyInfo of Intel's SGX Root CA (fetched from INTEL_ROOT_URL,
# 2026-09-12). The quote's embedded chain must end in exactly this key.
INTEL_ROOT_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
ACCEPTED_TCB = ("UpToDate", "SWHardeningNeeded")
UA = "inferroute-confidential/1 (+native verifier, no SDK)"

_OID_SGX_EXT = "1.2.840.113741.1.13.1"


# ───────────────────────── quote signature data ─────────────────────────

@dataclass
class SigData:
    sig: bytes
    attestation_key: bytes
    qe_report: bytes
    qe_sig: bytes
    qe_auth: bytes
    chain_pem: bytes
    error: str = ""


def parse_sig_data(quote_b: bytes) -> SigData:
    """ECDSA quote signature data (Intel DCAP v4 quote, cert data type 6 = QE report cert data)."""
    empty = SigData(b"", b"", b"", b"", b"", b"")
    off = _HDR + _BODY
    if len(quote_b) < off + 4:
        return SigData(**{**empty.__dict__, "error": "no signature data"})
    sig_len = struct.unpack_from("<I", quote_b, off)[0]
    sd = quote_b[off + 4: off + 4 + sig_len]
    if len(sd) < 134:
        return SigData(**{**empty.__dict__, "error": "signature data truncated"})
    sig, akey = sd[:64], sd[64:128]
    cdt, cds = struct.unpack_from("<H", sd, 128)[0], struct.unpack_from("<I", sd, 130)[0]
    cd = sd[134:134 + cds]
    if cdt != 6:
        return SigData(sig, akey, b"", b"", b"", b"", error=f"certification data type {cdt} is not QE-report (6)")
    if len(cd) < 450:
        return SigData(sig, akey, b"", b"", b"", b"", error="QE certification data truncated")
    qe_report, qe_sig = cd[:384], cd[384:448]
    alen = struct.unpack_from("<H", cd, 448)[0]
    auth = cd[450:450 + alen]
    p = 450 + alen
    if len(cd) < p + 6:
        return SigData(sig, akey, qe_report, qe_sig, auth, b"", error="inner certification data missing")
    ict, ics = struct.unpack_from("<H", cd, p)[0], struct.unpack_from("<I", cd, p + 2)[0]
    inner = cd[p + 6: p + 6 + ics]
    if ict != 5:
        return SigData(sig, akey, qe_report, qe_sig, auth, inner, error=f"inner certification data type {ict} is not PCK chain (5)")
    return SigData(sig, akey, qe_report, qe_sig, auth, inner)


def _p256_verify(pub, sig64: bytes, data: bytes) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    try:
        der = utils.encode_dss_signature(int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big"))
        pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def check_quote_signature(quote_b: bytes, certs: list) -> Check:
    from cryptography.hazmat.primitives.asymmetric import ec
    sd = parse_sig_data(quote_b)
    if sd.error:
        return Check(False, sd.error)
    if not certs:
        return Check(False, "no PCK certificate to verify the QE report against")
    try:
        akey = ec.EllipticCurvePublicNumbers(int.from_bytes(sd.attestation_key[:32], "big"),
                                             int.from_bytes(sd.attestation_key[32:], "big"), ec.SECP256R1()).public_key()
    except Exception:
        return Check(False, "attestation key is not a valid P-256 point")
    if not _p256_verify(akey, sd.sig, quote_b[:_HDR + _BODY]):
        return Check(False, "quote signature does NOT verify under the attestation key")
    if sd.qe_report[320:352] != hashlib.sha256(sd.attestation_key + sd.qe_auth).digest():
        return Check(False, "QE report does not commit to the attestation key")
    if not _p256_verify(certs[0].public_key(), sd.qe_sig, sd.qe_report):
        return Check(False, "QE report signature does NOT verify under the PCK certificate")
    return Check(True, "ECDSA-P256 over header+body by the attestation key; QE report binds that key and is signed by the PCK certificate")


# ───────────────────────── root pin / CRLs ─────────────────────────

def _spki_sha256(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def check_root_pinned(certs: list) -> Check:
    if not certs:
        return Check(False, "no certificates")
    got = _spki_sha256(certs[-1])
    if got != INTEL_ROOT_SPKI_SHA256:
        return Check(False, f"chain root {_cn(certs[-1])} is NOT Intel's SGX Root CA (SPKI {got[:16]}…)")
    return Check(True, "chain ends in Intel's SGX Root CA (pinned public key)")


def check_not_revoked(certs: list, pck_crl, root_crl) -> Check:
    if pck_crl is None or root_crl is None:
        return Check(False, "CRLs not available")
    # the CRLs must themselves be signed by the CA they claim (intermediate / root)
    for crl, issuer, name in ((pck_crl, certs[1] if len(certs) > 1 else None, "PCK CRL"), (root_crl, certs[-1], "Root CRL")):
        if issuer is None or not crl.is_signature_valid(issuer.public_key()):
            return Check(False, f"{name} signature does not verify under its issuer")
        if crl.next_update_utc is not None and crl.next_update_utc.timestamp() < time.time():
            return Check(False, f"{name} is past its next-update time")
    for cert in certs:
        for crl in (pck_crl, root_crl):
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                return Check(False, f"{_cn(cert)} (serial {cert.serial_number:x}) is REVOKED")
    return Check(True, f"no certificate in the chain is on Intel's CRLs ({len(list(pck_crl))} PCK revocations checked)")


# ───────────────────────── PCK SGX extension ─────────────────────────

def _tlv(b: bytes, i: int):
    tag = b[i]
    i += 1
    ln = b[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + ln], i + ln


def _walk(b: bytes) -> list:
    out, i = [], 0
    while i < len(b):
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def _oid(v: bytes) -> str:
    parts, n = [str(v[0] // 40), str(v[0] % 40)], 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def pck_extension(leaf) -> dict:
    """{fmspc, pceid, cpusvn (16 bytes), pcesvn} from the PCK certificate's SGX extension."""
    ext = next((e for e in leaf.extensions if e.oid.dotted_string == _OID_SGX_EXT), None)
    if ext is None:
        return {}
    out: dict = {}
    for _, val in _walk(_walk(ext.value.value)[0][1]):
        items = _walk(val)
        o, v = _oid(items[0][1]), items[1]
        if o == _OID_SGX_EXT + ".4":
            out["fmspc"] = v[1].hex()
        elif o == _OID_SGX_EXT + ".3":
            out["pceid"] = v[1].hex()
        elif o == _OID_SGX_EXT + ".2":
            for _, v2 in _walk(v[1]):
                it = _walk(v2)
                o2, iv = _oid(it[0][1]), it[1][1]
                k = o2.split(".")[-1]
                if k == "18":
                    out["cpusvn"] = iv
                elif k == "17":
                    out["pcesvn"] = int.from_bytes(iv, "big")
    return out


# ───────────────────────── Intel collateral ─────────────────────────

@dataclass
class Collateral:
    fmspc: str
    tcb_info: dict
    tcb_raw: bytes
    tcb_sig: bytes
    tcb_chain: list
    qe_identity: dict
    qe_raw: bytes
    qe_sig: bytes
    qe_chain: list
    pck_crl: object = None
    root_crl: object = None
    fetched_at: float = field(default_factory=time.time)


def _raw_object(text: str, key: str) -> bytes:
    """The exact bytes of the JSON object under `key` — Intel signs those bytes verbatim."""
    i = text.index(f'"{key}":') + len(key) + 3
    depth, j, in_str, esc = 0, i, False, False
    while j < len(text):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1].encode()
        j += 1
    raise ValueError("unbalanced JSON")


def _chain_from_header(h: str) -> list:
    from cryptography import x509
    pem = urllib.parse.unquote(h or "")
    out, beg, end = [], "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    i = pem.find(beg)
    while i != -1:
        j = pem.find(end, i)
        if j == -1:
            break
        j += len(end)
        out.append(x509.load_pem_x509_certificate(pem[i:j].encode()))
        i = pem.find(beg, j)
    return out


_CACHE: dict[str, Collateral] = {}


async def fetch_collateral(http, fmspc: str, ca: str = "platform", timeout: float = 60.0) -> Collateral:
    if fmspc in _CACHE and time.time() - _CACHE[fmspc].fetched_at < 6 * 3600:
        return _CACHE[fmspc]
    from cryptography import x509
    h = {"User-Agent": UA}
    r = await http.get(f"{PCS}/tdx/certification/v4/tcb?fmspc={fmspc}", headers=h, timeout=timeout)
    r.raise_for_status()
    tcb_text = r.text
    tcb = json.loads(tcb_text)
    q = await http.get(f"{PCS}/tdx/certification/v4/qe/identity", headers=h, timeout=timeout)
    q.raise_for_status()
    qe = json.loads(q.text)
    c = await http.get(f"{PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=pem", headers=h, timeout=timeout)
    c.raise_for_status()
    rc = await http.get(INTEL_ROOT_CRL_URL, headers=h, timeout=timeout)
    rc.raise_for_status()
    col = Collateral(
        fmspc=fmspc, tcb_info=tcb["tcbInfo"], tcb_raw=_raw_object(tcb_text, "tcbInfo"), tcb_sig=bytes.fromhex(tcb["signature"]),
        tcb_chain=_chain_from_header(r.headers.get("TCB-Info-Issuer-Chain", "")),
        qe_identity=qe["enclaveIdentity"], qe_raw=_raw_object(q.text, "enclaveIdentity"), qe_sig=bytes.fromhex(qe["signature"]),
        qe_chain=_chain_from_header(q.headers.get("SGX-Enclave-Identity-Issuer-Chain", "")),
        pck_crl=x509.load_pem_x509_crl(c.content), root_crl=x509.load_der_x509_crl(rc.content),
    )
    _CACHE[fmspc] = col
    return col


def _signed_by_intel(raw: bytes, sig: bytes, chain: list) -> tuple[bool, str]:
    """`raw` signed (ECDSA-P256/SHA-256) by chain[0], chain[0] issued by chain[-1] == pinned root."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if not chain:
        return False, "no signing certificate chain"
    if _spki_sha256(chain[-1]) != INTEL_ROOT_SPKI_SHA256:
        return False, "signing chain does not end in Intel's root"
    for a, b in zip(chain, chain[1:]):
        try:
            b.public_key().verify(a.signature, a.tbs_certificate_bytes, ec.ECDSA(a.signature_hash_algorithm))
        except Exception:
            return False, f"signing chain link {_cn(a)} → {_cn(b)} broken"
    if not _p256_verify(chain[0].public_key(), sig, raw):
        return False, "collateral signature does not verify"
    return True, ""


def _fresh(info: dict) -> tuple[bool, str]:
    nxt = info.get("nextUpdate", "")
    try:
        t = time.strptime(nxt, "%Y-%m-%dT%H:%M:%SZ")
        import calendar
        if calendar.timegm(t) < time.time():
            return False, f"collateral expired ({nxt})"
    except ValueError:
        return False, "collateral has no valid nextUpdate"
    return True, ""


def evaluate_tcb(tcb_info: dict, cpusvn: bytes, pcesvn: int, tee_tcb_svn: bytes) -> tuple[str, list, str]:
    """(status, advisoryIDs, tcbDate) of the first level (Intel orders them newest-first) the
    platform satisfies: every SGX component SVN ≥ level's, PCE SVN ≥ level's, every TDX
    component SVN ≥ level's. No level satisfied → 'Unknown'."""
    for lvl in tcb_info.get("tcbLevels", []):
        t = lvl["tcb"]
        sgx = [c["svn"] for c in t.get("sgxtcbcomponents", [])]
        tdx = [c["svn"] for c in t.get("tdxtcbcomponents", [])]
        if len(sgx) != 16 or len(cpusvn) != 16:
            continue
        if all(cpusvn[i] >= sgx[i] for i in range(16)) and pcesvn >= t.get("pcesvn", 0) \
                and all(tee_tcb_svn[i] >= tdx[i] for i in range(min(len(tdx), len(tee_tcb_svn)))):
            return lvl["tcbStatus"], list(lvl.get("advisoryIDs", [])), lvl.get("tcbDate", "")
    return "Unknown", [], ""


def evaluate_qe(qe_identity: dict, qe_report: bytes) -> tuple[str, str]:
    """QE report fields vs Intel's QE Identity → (status, why)."""
    mrsigner = qe_report[128:160].hex()
    isvprodid = struct.unpack_from("<H", qe_report, 256)[0]
    isvsvn = struct.unpack_from("<H", qe_report, 258)[0]
    attrs, misc = qe_report[48:64], qe_report[16:20]   # SGX REPORT: cpusvn 0:16, miscselect 16:20, attributes 48:64
    if mrsigner.lower() != qe_identity.get("mrsigner", "").lower():
        return "Mismatch", "QE MRSIGNER differs from Intel's QE Identity"
    if isvprodid != qe_identity.get("isvprodid"):
        return "Mismatch", "QE ISVPRODID differs from Intel's QE Identity"
    am, av = bytes.fromhex(qe_identity.get("attributesMask", "00" * 16)), bytes.fromhex(qe_identity.get("attributes", "00" * 16))
    if bytes(a & m for a, m in zip(attrs, am)) != bytes(v & m for v, m in zip(av, am)):
        return "Mismatch", "QE attributes differ from Intel's QE Identity"
    mm, mv = bytes.fromhex(qe_identity.get("miscselectMask", "00" * 4)), bytes.fromhex(qe_identity.get("miscselect", "00" * 4))
    if bytes(a & m for a, m in zip(misc, mm)) != bytes(v & m for v, m in zip(mv, mm)):
        return "Mismatch", "QE miscselect differs from Intel's QE Identity"
    for lvl in qe_identity.get("tcbLevels", []):
        if isvsvn >= lvl["tcb"]["isvsvn"]:
            return lvl["tcbStatus"], f"QE ISVSVN {isvsvn} at level dated {lvl.get('tcbDate', '?')}"
    return "Unknown", f"QE ISVSVN {isvsvn} below every published level"


def platform_checks(quote_b: bytes, certs: list, col: Collateral) -> dict[str, Check]:
    """The online-collateral checks, given fetched collateral. Pure."""
    out: dict[str, Check] = {}
    out["root_pinned"] = check_root_pinned(certs)
    out["not_revoked"] = check_not_revoked(certs, col.pck_crl, col.root_crl)
    ok, why = _signed_by_intel(col.tcb_raw, col.tcb_sig, col.tcb_chain)
    fresh, fwhy = _fresh(col.tcb_info)
    if not ok or not fresh:
        out["tcb_current"] = Check(False, why or fwhy)
    else:
        ext = pck_extension(certs[0]) if certs else {}
        if ext.get("fmspc") != col.fmspc or "cpusvn" not in ext:
            out["tcb_current"] = Check(False, "PCK certificate carries no usable SGX extension / FMSPC mismatch")
        else:
            body = quote_b[_HDR:_HDR + _BODY]
            status, advisories, date = evaluate_tcb(col.tcb_info, ext["cpusvn"], ext.get("pcesvn", 0), body[0:16])
            good = status in ACCEPTED_TCB
            adv = f", advisories {', '.join(advisories)}" if advisories else ""
            out["tcb_current"] = Check(good, f"Intel TCB status {status} (level {date[:10]}{adv}, FMSPC {col.fmspc})")
    sd = parse_sig_data(quote_b)
    ok, why = _signed_by_intel(col.qe_raw, col.qe_sig, col.qe_chain)
    fresh, fwhy = _fresh(col.qe_identity)
    if sd.error or not ok or not fresh:
        out["qe_current"] = Check(False, sd.error or why or fwhy)
    else:
        status, why = evaluate_qe(col.qe_identity, sd.qe_report)
        out["qe_current"] = Check(status in ACCEPTED_TCB, f"Quoting Enclave {status}: {why}")
    return out


def ca_kind(certs: list) -> str:
    """Which PCK CRL applies: the intermediate is the 'Platform' or 'Processor' CA."""
    name = _cn(certs[1]).lower() if len(certs) > 1 else ""
    return "processor" if "processor" in name else "platform"
