"""The utility-VM endorsement of an Azure confidential container: a COSE_Sign1 statement, signed by
Microsoft, of the launch measurement its utility VM image produces.

Verified here offline: the signature under the certificate chain the statement carries; that chain's
root pinned through the statement's did:x509 issuer; the signing certificate's usage; the feed; a
minimum security version. The endorsed measurement is returned for the caller to compare with the
hardware report. Refuses rather than degrades; every check is a step (see amd_chain.Steps).

Certificate validity dates are NOT checked on this chain: the signing certificates are issued for about
a year and endorsements outlive them, and the reference verifier (microsoft/CCF) also ignores time.
The root pin and the signature are what carry the weight.

The CBOR reader accepts definite-length items only, which is all these statements use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from .amd_chain import Steps, _signed_by

UVM_ROOT_SHA256_B64URL = "I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"   # Microsoft Supply Chain RSA Root CA 2022
UVM_EKU = "1.3.6.1.4.1.311.76.59.1.2"
UVM_FEED = "ContainerPlat-AMD-UVM"
UVM_MIN_SVN = 100

ALG_PS384 = -38
HDR_ALG, HDR_X5CHAIN, HDR_CWT = 1, 33, 15
CWT_ISS, CWT_SUB = 1, 2
MAX_DEPTH = 32


class CBORError(ValueError):
    pass


class Tag(NamedTuple):
    tag: int
    value: Any


def _head(data: bytes, i: int) -> Tuple[int, int, int]:
    if i >= len(data):
        raise CBORError("truncated")
    b = data[i]
    major, info = b >> 5, b & 0x1F
    i += 1
    if info < 24:
        return major, info, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if n is None:
        raise CBORError("indefinite or reserved length")
    if i + n > len(data):
        raise CBORError("truncated")
    return major, int.from_bytes(data[i:i + n], "big"), i + n


def _item(data: bytes, i: int, depth: int) -> Tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CBORError("nesting too deep")
    start = i
    major, arg, i = _head(data, i)
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(data):
            raise CBORError("truncated")
        raw = data[i:i + arg]
        return (raw if major == 2 else raw.decode("utf-8")), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = _item(data, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        m: Dict[Any, Any] = {}
        for _ in range(arg):
            k, i = _item(data, i, depth + 1)
            v, i = _item(data, i, depth + 1)
            if isinstance(k, (list, dict)):
                raise CBORError("unhashable map key")
            m[k] = v
        return m, i
    if major == 6:
        v, i = _item(data, i, depth + 1)
        return Tag(arg, v), i
    info = data[start] & 0x1F
    if info == 20:
        return False, i
    if info == 21:
        return True, i
    if info in (22, 23):
        return None, i
    if info == 25:
        return struct.unpack(">e", data[i - 2:i])[0], i
    if info == 26:
        return struct.unpack(">f", data[i - 4:i])[0], i
    if info == 27:
        return struct.unpack(">d", data[i - 8:i])[0], i
    raise CBORError("unsupported simple value")


def cbor_loads(data: bytes) -> Any:
    v, end = _item(data, 0, 0)
    if end != len(data):
        raise CBORError("trailing bytes")
    return v


def _enc_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * size)):
            return bytes([(major << 5) | info]) + n.to_bytes(size, "big")
    raise CBORError("integer too large")


def cbor_dumps(v: Any) -> bytes:
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _enc_head(0, v) if v >= 0 else _enc_head(1, -1 - v)
    if isinstance(v, bytes):
        return _enc_head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return _enc_head(3, len(raw)) + raw
    if isinstance(v, (list, tuple)) and not isinstance(v, Tag):
        return _enc_head(4, len(v)) + b"".join(cbor_dumps(x) for x in v)
    if isinstance(v, dict):
        return _enc_head(5, len(v)) + b"".join(cbor_dumps(k) + cbor_dumps(x) for k, x in v.items())
    if isinstance(v, Tag):
        return _enc_head(6, v.tag) + cbor_dumps(v.value)
    raise CBORError(f"cannot encode {type(v).__name__}")


def sig_structure(protected_raw: bytes, payload: bytes) -> bytes:
    return cbor_dumps(["Signature1", protected_raw, b"", payload])


def decode_sign1(blob: bytes) -> Dict[str, Any]:
    obj = cbor_loads(blob)
    if isinstance(obj, Tag):
        if obj.tag != 18:
            raise CBORError(f"tag {obj.tag} is not COSE_Sign1")
        obj = obj.value
    if not (isinstance(obj, list) and len(obj) == 4 and isinstance(obj[0], bytes) and isinstance(obj[2], bytes)
            and isinstance(obj[3], bytes)):
        raise CBORError("not a COSE_Sign1 structure")
    protected = cbor_loads(obj[0]) if obj[0] else {}
    if not isinstance(protected, dict):
        raise CBORError("protected header is not a map")
    return {"protected_raw": obj[0], "protected": protected, "unprotected": obj[1] if isinstance(obj[1], dict) else {},
            "payload": obj[2], "signature": obj[3]}


def b64url_sha256(der: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def parse_did_x509(did: str) -> Optional[Dict[str, str]]:
    """did:x509:0:sha256:<fingerprint>::eku:<oid> → {fingerprint, eku}; None for any other shape."""
    parts = did.split("::")
    head = parts[0].split(":")
    if len(head) != 5 or head[:4] != ["did", "x509", "0", "sha256"] or len(parts) != 2:
        return None
    policy = parts[1].split(":", 1)
    if len(policy) != 2 or policy[0] != "eku":
        return None
    return {"fingerprint": head[4], "eku": policy[1]}


def verify_uvm_endorsement(blob: bytes, *, root_sha256_b64url: str = UVM_ROOT_SHA256_B64URL, eku: str = UVM_EKU,
                           feed: str = UVM_FEED, min_svn: int = UVM_MIN_SVN) -> Tuple[Steps, Dict[str, Any]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    steps, info = Steps(), {}
    try:
        cose = decode_sign1(blob)
    except (CBORError, UnicodeDecodeError) as exc:
        steps.add(False, "UVM endorsement structure", str(exc))
        return steps, info
    ph = cose["protected"]
    if not steps.add(ph.get(HDR_ALG) == ALG_PS384, "UVM endorsement structure",
                     "COSE_Sign1, PS384" if ph.get(HDR_ALG) == ALG_PS384 else f"algorithm {ph.get(HDR_ALG)!r} is not PS384"):
        return steps, info
    chain_der = ph.get(HDR_X5CHAIN)
    chain_der = [chain_der] if isinstance(chain_der, bytes) else chain_der
    try:
        certs = [x509.load_der_x509_certificate(d) for d in chain_der or []]
    except Exception as exc:                              # noqa: BLE001
        certs = []
        steps.add(False, "UVM certificate chain", f"does not parse ({type(exc).__name__})")
        return steps, info
    if not steps.add(len(certs) >= 2, "UVM certificate chain", f"{len(certs)} certificate(s) carried"):
        return steps, info
    cwt = ph.get(HDR_CWT) if isinstance(ph.get(HDR_CWT), dict) else {}
    issuer = cwt.get(CWT_ISS) or ph.get("iss") or ""
    did = parse_did_x509(issuer) if isinstance(issuer, str) else None
    steps.add(bool(did) and did["fingerprint"] == root_sha256_b64url and did["eku"] == eku, "UVM issuer pinned",
              f"issuer names root {did['fingerprint'][:12]}… and usage {did['eku']}" if did else "issuer is not a did:x509 name")
    root_fp = b64url_sha256(chain_der[-1])
    steps.add(root_fp == root_sha256_b64url, "UVM root is Microsoft's",
              f"chain root {root_fp[:12]}…" + (" is the pinned root" if root_fp == root_sha256_b64url else " is NOT the pinned root"))
    links = all(_signed_by(certs[k], certs[k + 1]) for k in range(len(certs) - 1)) and _signed_by(certs[-1], certs[-1])
    steps.add(links, "UVM chain signatures", "each certificate is signed by the next, root self-signed (dates not checked)"
              if links else "a certificate in the chain is not signed by the next")
    try:
        leaf_ekus = [o.dotted_string for o in certs[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except Exception:                                     # noqa: BLE001
        leaf_ekus = []
    steps.add(eku in leaf_ekus, "UVM signer usage", f"signing certificate usages {leaf_ekus}")
    pub = certs[0].public_key()
    try:
        if not isinstance(pub, rsa.RSAPublicKey):
            raise TypeError("signing key is not RSA")
        pub.verify(cose["signature"], sig_structure(cose["protected_raw"], cose["payload"]),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
        sig_ok = True
    except Exception:                                     # noqa: BLE001
        sig_ok = False
    steps.add(sig_ok, "UVM endorsement signature", "verifies under the signing certificate" if sig_ok
              else "does NOT verify under the signing certificate")
    got_feed = cwt.get(CWT_SUB) or ph.get("feed")
    steps.add(got_feed == feed, "UVM feed", f"feed {got_feed!r}")
    try:
        body = json.loads(cose["payload"])
        measurement = bytes.fromhex(body["x-ms-sevsnpvm-launchmeasurement"])
        svn = int(cwt.get("svn", body.get("x-ms-sevsnpvm-guestsvn")))
        if len(measurement) != 48:
            raise ValueError("measurement is not 48 bytes")
    except (ValueError, KeyError, TypeError) as exc:
        steps.add(False, "UVM endorsed measurement", f"payload unreadable ({type(exc).__name__})")
        return steps, info
    steps.add(svn >= min_svn, "UVM security version", f"endorsement SVN {svn}, minimum {min_svn}")
    info.update({"measurement": measurement.hex(), "svn": svn, "feed": got_feed, "issuer": issuer})
    return steps, info
