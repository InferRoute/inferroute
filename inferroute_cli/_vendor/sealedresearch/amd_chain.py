"""AMD SEV-SNP endorsement: verify a report's signing certificate back to AMD's root, and that the
certificate describes the same chip and firmware as the report. Refuses rather than degrades.

Every check is returned as a step {"ok", "step", "detail"}, so a caller can show the user exactly what
was verified and where a refusal came from. `Steps.ok` is true only when every step passed.

The certificates may come from anywhere, including the party being verified: nothing here trusts them
until they chain to a pinned AMD root.

ARK pins are SHA-256 over the SubjectPublicKeyInfo of AMD's root key per product line, read from AMD's
key distribution service (kdsintf.amd.com/vcek/v1/<product>/cert_chain) on 2026-09-14. The Turin value
matches a copy of the same chain cached on 2026-08-28.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import warnings
from typing import Dict, List, Optional, Sequence

from . import snp

ARK_SPKI_SHA256: Dict[str, str] = {
    "Milan": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
    "Genoa": "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
    "Turin": "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
}
_AMD = "1.3.6.1.4.1.3704.1."
OID_PRODUCT = _AMD + "2"
OID_HWID = _AMD + "4"
OID_TCB = {"blSPL": _AMD + "3.1", "teeSPL": _AMD + "3.2", "snpSPL": _AMD + "3.3",
           "ucodeSPL": _AMD + "3.8", "fmcSPL": _AMD + "3.9"}
ZEN5 = frozenset({"Turin"})


class Steps(list):
    def add(self, ok: bool, step: str, detail: str) -> bool:
        self.append({"ok": bool(ok), "step": step, "detail": detail})
        return bool(ok)

    @property
    def ok(self) -> bool:
        return bool(self) and all(s["ok"] for s in self)

    @property
    def problems(self) -> List[str]:
        return [f"{s['step']}: {s['detail']}" for s in self if not s["ok"]]


def load_certs(data: bytes) -> list:
    """One or more PEM certificates, or a single DER certificate."""
    from cryptography import x509
    from cryptography.utils import CryptographyDeprecationWarning
    with warnings.catch_warnings():
        # AMD issues endorsement keys with a non-positive serial; the warning is not a verification fact.
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]


def _ext(cert, oid: str) -> Optional[bytes]:
    for e in cert.extensions:
        if e.oid.dotted_string == oid:
            return getattr(e.value, "value", None)
    return None


def _der_int(b: Optional[bytes]) -> Optional[int]:
    if not b or len(b) < 3 or b[0] != 0x02 or b[1] != len(b) - 2:
        return None
    return int.from_bytes(b[2:], "big")


def _der_ia5(b: Optional[bytes]) -> Optional[str]:
    if not b or len(b) < 2 or b[0] != 0x16 or b[1] != len(b) - 2:
        return None
    return b[2:].decode("ascii", "replace")


def _cn(cert) -> str:
    from cryptography.x509.oid import NameOID
    got = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(got[0].value) if got else ""


def spki_sha256(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _signed_by(child, parent) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            params = child.signature_algorithm_parameters
            pad = params if isinstance(params, padding.PSS) else padding.PKCS1v15()
            pub.verify(child.signature, child.tbs_certificate_bytes, pad, child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:                                   # noqa: BLE001 — any failure is a refusal
        return False


def _report_signature_ok(p: dict, cert) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    sig = p["signature"]
    r = int.from_bytes(sig[0:48][::-1], "big")          # little-endian 72-byte fields, P-384 uses 48
    s = int.from_bytes(sig[72:72 + 48][::-1], "big")
    try:
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(encode_dss_signature(r, s), p["signed_bytes"], ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:                                   # noqa: BLE001
        return False


def verify_report(report: bytes, vcek: bytes, chain: bytes, *, now: Optional[dt.datetime] = None,
                  pins: Optional[Dict[str, str]] = None) -> Steps:
    """Is this report signed by an AMD chip, under AMD's root, for the chip and firmware it describes?

    `vcek` is the endorsement certificate (DER or PEM); `chain` holds the ASK and ARK (PEM). `pins` maps
    product line to the root's SPKI SHA-256 and defaults to AMD's published roots; tests pass their own.
    """
    steps = Steps()
    pins = ARK_SPKI_SHA256 if pins is None else pins
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        p = snp.parse(report)
    except ValueError as exc:
        steps.add(False, "report structure", str(exc))
        return steps
    hardware = p["version"] >= 2 and p["signature"] != b"\x00" * 512
    steps.add(hardware, "hardware report", f"version {p['version']}, "
              f"{'signed' if p['signature'] != b'\x00' * 512 else 'unsigned'}")
    steps.add(not p["debug_allowed"], "debug disabled", "guest policy forbids debugging" if not p["debug_allowed"]
              else "guest policy ALLOWS debugging: the host can inspect this VM")
    if not steps.add(p["signing_key"] == "VCEK", "signed by a chip key",
                     f"report signing key is {p['signing_key']}" + ("" if p["signing_key"] == "VCEK" else "; only VCEK is accepted")):
        return steps
    try:
        vcek_cert = load_certs(vcek)[0]
        chain_certs = load_certs(chain)
    except Exception as exc:                            # noqa: BLE001
        steps.add(False, "certificates parse", f"{type(exc).__name__}")
        return steps
    # The certificate names the product with an optional stepping ("Milan-B0"); roots are per product line.
    product = (_der_ia5(_ext(vcek_cert, OID_PRODUCT)) or "").split("-", 1)[0]
    if not steps.add(product in pins, "product line", f"endorsement key is for {product or 'an unnamed product'}"
                     + ("" if product in pins else f"; pinned roots exist for {', '.join(sorted(pins))}")):
        return steps
    ask = next((c for c in chain_certs if _cn(c) == f"SEV-{product}"), None)
    ark = next((c for c in chain_certs if _cn(c) == f"ARK-{product}"), None)
    if not steps.add(ask is not None and ark is not None, "chain present", f"ASK and ARK for {product}"
                     + ("" if ask is not None and ark is not None else " not both supplied")):
        return steps
    got = spki_sha256(ark)
    steps.add(got == pins[product], "AMD root pinned", f"ARK-{product} key {got[:16]}…"
              + (" is AMD's published root" if got == pins[product] else f" is NOT the pinned root {pins[product][:16]}…"))
    steps.add(_signed_by(ark, ark), "root self-signed", f"ARK-{product}")
    steps.add(_signed_by(ask, ark), "ASK signed by root", f"SEV-{product} under ARK-{product}")
    steps.add(_signed_by(vcek_cert, ask), "VCEK signed by ASK", f"endorsement key under SEV-{product}")
    expired = [_cn(c) or "VCEK" for c in (vcek_cert, ask, ark)
               if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc)]
    steps.add(not expired, "certificates in date", "all three valid now" if not expired else f"outside validity: {expired}")
    hwid = _ext(vcek_cert, OID_HWID) or b""
    chip = p["chip_id"]
    same_chip = bool(hwid) and not p["mask_chip_id"] and chip[:len(hwid)] == hwid and not any(chip[len(hwid):])
    steps.add(same_chip, "VCEK is for this chip", f"hwid {hwid.hex()[:16]}…"
              + (" matches the report's chip id" if same_chip else " does NOT match the report's chip id"
                 + (" (chip id masked)" if p["mask_chip_id"] else "")))
    want = snp.tcb_params(p["reported_tcb"], zen5=product in ZEN5)
    mismatch = [k for k, v in want.items() if _der_int(_ext(vcek_cert, OID_TCB[k])) != v]
    steps.add(not mismatch, "VCEK is for this firmware", f"reported TCB {want}"
              + ("" if not mismatch else f"; certificate differs on {mismatch}"))
    steps.add(_report_signature_ok(p, vcek_cert), "report signature", "the report verifies under the endorsement key"
              if _report_signature_ok(p, vcek_cert) else "the report does NOT verify under the endorsement key")
    return steps


def chain_pem(certs: Sequence) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
