#!/usr/bin/env python3
"""Independent verifier for an attested prior-art record — ONE file, no InferRoute code.

Ships inside every export bundle so that anyone holding the record can re-derive its claims WITHOUT
trusting the tool that produced it. It needs Python 3.9+ and the `cryptography` package; nothing else.
Read it end to end (it is short on purpose): every check below states what it recomputes and from what.

    python3 verify_record.py <export-directory>

What it re-derives, per sealed search, from the bundle alone:

  bundle    every file's SHA-256 matches MANIFEST.json (tamper evidence)
  statement the enclave's Ed25519 signature over the canonical statement verifies under the signer key
  binding   that signer key is the one committed inside the hardware-bound runtime data; the statement's
            runtime_data_sha256 / lifetime / index / model commitments equal the runtime data's
  hardware  REPORT_DATA in the SEV-SNP attestation report == SHA-256(runtime data) ‖ 32 zero bytes,
            so the AMD chip signed a report over exactly that runtime data (hence over that signer key)
  amd       the report's ECDSA P-384 signature verifies under the VCEK; VCEK ← ASK ← ARK (self-signed);
            ARK's public key hashes to AMD's published root for the product line (pin printed for you to
            compare at https://kdsintf.amd.com/vcek/v1/<Product>/cert_chain); VCEK is for this chip and
            this firmware TCB; guest policy forbids debugging
  uvm       Microsoft's COSE_Sign1 (PS384) endorsement of the utility VM verifies under its x5chain, the
            chain roots at Microsoft's Supply Chain RSA Root CA 2022 (pin printed), and the endorsed launch
            measurement equals the report's MEASUREMENT
  policy    HOST_DATA in the report == SHA-256(the container policy), when the policy is in the bundle
  content   query_sha256 == SHA-256(request_id ‖ canonical(query text)); result_sha256 == SHA-256(request_id
            ‖ canonical(result)); hits_n == len(hits); cutoff_date == the matter's date bound

What it does NOT do, and how to redo those parts with independent tools:
  * It does not fetch anything. Certificate validity dates are reported, not enforced (endorsements outlive
    their signing certificates; the reference verifiers behave the same).
  * For a fully independent redo of the AMD chain use AMD's `snpguest verify` (github.com/virtee/snpguest)
    or Google's `go-sev-guest` (github.com/google/go-sev-guest) on <sha>.evidence.json → offer.evidence +
    offer.endorsements; for the COSE endorsement, `go-cose` or `pycose`; to tie the policy to a container
    image, regenerate it with `az confcom acipolicygen` from the image digest and compare its hash.
  * It cannot verify the attorney's OWN machine was confined — that is the device's self-report.

Exit status 0 iff every applicable check passes. Output is plain text: one line per check.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# ───────────────────────────── published roots (pins) ─────────────────────────────
# AMD: SHA-256 over the SubjectPublicKeyInfo of the ARK per product line, as served by AMD's KDS
# (kdsintf.amd.com/vcek/v1/<Product>/cert_chain). Compare these yourself; do not take this file's word.
AMD_ARK_SPKI_SHA256 = {
    "Milan": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
    "Genoa": "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
    "Turin": "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
}
ZEN5 = {"Turin"}
# Microsoft: base64url(SHA-256(DER)) of "Microsoft Supply Chain RSA Root CA 2022", the root named by the
# did:x509 issuer of every utility-VM endorsement.
MS_UVM_ROOT_SHA256_B64URL = "I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
UVM_EKU = "1.3.6.1.4.1.311.76.59.1.2"
UVM_FEED = "ContainerPlat-AMD-UVM"
UVM_MIN_SVN = 100

_AMD = "1.3.6.1.4.1.3704.1."
OID_PRODUCT, OID_HWID = _AMD + "2", _AMD + "4"
OID_TCB = {"blSPL": _AMD + "3.1", "teeSPL": _AMD + "3.2", "snpSPL": _AMD + "3.3", "ucodeSPL": _AMD + "3.8", "fmcSPL": _AMD + "3.9"}

# ───────────────────────────── report of checks ─────────────────────────────


class Checks:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str]] = []      # (status, name, detail)  status ∈ PASS FAIL SKIP

    def add(self, ok: Optional[bool], name: str, detail: str) -> bool:
        self.rows.append(("SKIP" if ok is None else "PASS" if ok else "FAIL", name, detail))
        return bool(ok)

    @property
    def failed(self) -> List[str]:
        return [n for s, n, _ in self.rows if s == "FAIL"]

    def dump(self, indent: str = "  ") -> None:
        for s, n, d in self.rows:
            print(f"{indent}{s:4} {n}: {d}")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def salted(request_id: str, obj: Any) -> str:
    """Exactly how the enclave commits to a query or a result: SHA-256(request_id ‖ canonical JSON)."""
    return sha256_hex(request_id.encode() + canonical(obj))


# ───────────────────────────── minimal CBOR (definite lengths only) ─────────────────────────────


class CBORError(ValueError):
    pass


class Tag:
    def __init__(self, tag: int, value: Any) -> None:
        self.tag, self.value = tag, value


def _cbor_head(data: bytes, i: int) -> Tuple[int, int, int]:
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


def _cbor_item(data: bytes, i: int, depth: int = 0) -> Tuple[Any, int]:
    if depth > 32:
        raise CBORError("nesting too deep")
    start = i
    major, arg, i = _cbor_head(data, i)
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
            v, i = _cbor_item(data, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        m: Dict[Any, Any] = {}
        for _ in range(arg):
            k, i = _cbor_item(data, i, depth + 1)
            v, i = _cbor_item(data, i, depth + 1)
            if isinstance(k, (list, dict)):
                raise CBORError("unhashable map key")
            m[k] = v
        return m, i
    if major == 6:
        v, i = _cbor_item(data, i, depth + 1)
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
    v, end = _cbor_item(data, 0)
    if end != len(data):
        raise CBORError("trailing bytes")
    return v


def _cbor_enc_head(major: int, n: int) -> bytes:
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
        return _cbor_enc_head(0, v) if v >= 0 else _cbor_enc_head(1, -1 - v)
    if isinstance(v, bytes):
        return _cbor_enc_head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return _cbor_enc_head(3, len(raw)) + raw
    if isinstance(v, (list, tuple)):
        return _cbor_enc_head(4, len(v)) + b"".join(cbor_dumps(x) for x in v)
    if isinstance(v, dict):
        return _cbor_enc_head(5, len(v)) + b"".join(cbor_dumps(k) + cbor_dumps(x) for k, x in v.items())
    if isinstance(v, Tag):
        return _cbor_enc_head(6, v.tag) + cbor_dumps(v.value)
    raise CBORError(f"cannot encode {type(v).__name__}")


# ───────────────────────────── SEV-SNP attestation report ─────────────────────────────

REPORT_LEN = 1184
_OFF = {"version": 0x000, "policy": 0x008, "vmpl": 0x030, "flags": 0x048, "report_data": 0x050,
        "measurement": 0x090, "host_data": 0x0C0, "reported_tcb": 0x180, "chip_id": 0x1A0, "signature": 0x2A0}
SIGNING_KEY = {0: "VCEK", 1: "VLEK", 7: "NONE"}


def parse_report(report: bytes) -> Dict[str, Any]:
    if len(report) != REPORT_LEN:
        raise ValueError(f"report must be {REPORT_LEN} bytes, got {len(report)}")
    g = lambda k, n: report[_OFF[k]:_OFF[k] + n]                           # noqa: E731
    flags, = struct.unpack("<I", g("flags", 4))
    policy, = struct.unpack("<Q", g("policy", 8))
    return {"version": struct.unpack("<I", g("version", 4))[0], "policy": policy,
            "debug_allowed": bool((policy >> 19) & 1), "mask_chip_id": bool((flags >> 1) & 1),
            "signing_key": SIGNING_KEY.get((flags >> 2) & 0x7, "reserved"),
            "report_data": g("report_data", 64), "measurement": g("measurement", 48), "host_data": g("host_data", 32),
            "chip_id": g("chip_id", 64), "reported_tcb": g("reported_tcb", 8), "signature": g("signature", 512),
            "signed_bytes": report[:_OFF["signature"]]}


def tcb_params(reported_tcb: bytes, *, zen5: bool) -> Dict[str, int]:
    b = list(reported_tcb)
    if zen5:                                                # Turin reordered TCB_VERSION
        return {"fmcSPL": b[0], "blSPL": b[1], "teeSPL": b[2], "snpSPL": b[3], "ucodeSPL": b[7]}
    return {"blSPL": b[0], "teeSPL": b[1], "snpSPL": b[6], "ucodeSPL": b[7]}


# ───────────────────────────── X.509 helpers (cryptography) ─────────────────────────────


def _x509():
    from cryptography import x509
    return x509


def load_certs(data: bytes) -> list:
    import warnings
    x509 = _x509()
    with warnings.catch_warnings():
        # Some published AMD/Microsoft certificates carry a non-positive serial; the library warns but parses.
        warnings.simplefilter("ignore")
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
    return sha256_hex(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def signed_by(child, parent) -> bool:
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
    except Exception:                                       # noqa: BLE001 — any failure is a refusal
        return False


def report_signature_ok(p: Dict[str, Any], cert) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    sig = p["signature"]
    r = int.from_bytes(sig[0:48][::-1], "big")              # R and S: little-endian 72-byte fields, P-384 uses 48
    s = int.from_bytes(sig[72:72 + 48][::-1], "big")
    try:
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(encode_dss_signature(r, s), p["signed_bytes"], ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:                                       # noqa: BLE001
        return False


# ───────────────────────────── the checks ─────────────────────────────


def check_amd(c: Checks, p: Dict[str, Any], vcek_pem: bytes, chain_pem: bytes, pins: Dict[str, str]) -> None:
    import datetime as dt
    c.add(p["version"] >= 2 and p["signature"] != b"\x00" * 512, "hardware report",
          f"SNP report version {p['version']}, {'signed' if p['signature'] != b'\x00' * 512 else 'UNSIGNED'}")
    c.add(not p["debug_allowed"], "debug disabled", "guest policy forbids debugging" if not p["debug_allowed"]
          else "guest policy ALLOWS debugging — the host could inspect this VM")
    if not c.add(p["signing_key"] == "VCEK", "signed by a chip key", f"signing key is {p['signing_key']} (only VCEK accepted)"):
        return
    try:
        vcek = load_certs(vcek_pem)[0]
        chain = load_certs(chain_pem)
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "certificates parse", type(exc).__name__)
        return
    product = (_der_ia5(_ext(vcek, OID_PRODUCT)) or "").split("-", 1)[0]
    if not c.add(product in pins, "product line", f"VCEK is for {product or 'an unnamed product'}; pinned roots: {', '.join(sorted(pins))}"):
        return
    ask = next((x for x in chain if _cn(x) == f"SEV-{product}"), None)
    ark = next((x for x in chain if _cn(x) == f"ARK-{product}"), None)
    if not c.add(ask is not None and ark is not None, "chain present", f"ASK and ARK for {product}"):
        return
    got = spki_sha256(ark)
    c.add(got == pins[product], "AMD root pinned",
          f"ARK-{product} SPKI sha256 {got} — compare with https://kdsintf.amd.com/vcek/v1/{product}/cert_chain")
    c.add(signed_by(ark, ark), "ARK self-signed", f"ARK-{product}")
    c.add(signed_by(ask, ark), "ASK signed by ARK", f"SEV-{product}")
    c.add(signed_by(vcek, ask), "VCEK signed by ASK", "chip endorsement key under the product signing key")
    now = dt.datetime.now(dt.timezone.utc)
    outside = [_cn(x) or "VCEK" for x in (vcek, ask, ark) if not (x.not_valid_before_utc <= now <= x.not_valid_after_utc)]
    c.add(None if outside else True, "certificate dates", "all valid now" if not outside
          else f"outside validity now: {outside} (reported, not enforced — endorsements outlive certificates)")
    hwid = _ext(vcek, OID_HWID) or b""
    chip = p["chip_id"]
    same = bool(hwid) and not p["mask_chip_id"] and chip[:len(hwid)] == hwid and not any(chip[len(hwid):])
    c.add(same, "VCEK is for this chip", f"hwid {hwid.hex()[:16]}… {'matches' if same else 'does NOT match'} the report's chip id")
    want = tcb_params(p["reported_tcb"], zen5=product in ZEN5)
    mismatch = [k for k, v in want.items() if _der_int(_ext(vcek, OID_TCB[k])) != v]
    c.add(not mismatch, "VCEK is for this firmware", f"reported TCB {want}" + ("" if not mismatch else f"; certificate differs on {mismatch}"))
    ok = report_signature_ok(p, vcek)
    c.add(ok, "report signature", "ECDSA P-384 over the report verifies under the VCEK" if ok else "does NOT verify under the VCEK")


def check_uvm(c: Checks, blob: bytes, root_b64url: str, min_svn: int) -> Optional[bytes]:
    """Returns the endorsed launch measurement (48 bytes) when the endorsement verifies."""
    x509 = _x509()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    try:
        obj = cbor_loads(blob)
        if isinstance(obj, Tag):
            if obj.tag != 18:
                raise CBORError(f"tag {obj.tag} is not COSE_Sign1")
            obj = obj.value
        if not (isinstance(obj, list) and len(obj) == 4 and isinstance(obj[0], bytes) and isinstance(obj[2], bytes) and isinstance(obj[3], bytes)):
            raise CBORError("not a COSE_Sign1 structure")
        protected_raw, unprotected, payload, signature = obj
        ph = cbor_loads(protected_raw) if protected_raw else {}
        if not isinstance(ph, dict):
            raise CBORError("protected header is not a map")
    except (CBORError, UnicodeDecodeError) as exc:
        c.add(False, "UVM endorsement structure", str(exc))
        return None
    if not c.add(ph.get(1) == -38, "UVM endorsement structure", "COSE_Sign1, PS384" if ph.get(1) == -38 else f"alg {ph.get(1)!r} is not PS384"):
        return None
    chain_der = ph.get(33)
    chain_der = [chain_der] if isinstance(chain_der, bytes) else (chain_der or [])
    try:
        certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "UVM certificate chain", f"does not parse ({type(exc).__name__})")
        return None
    if not c.add(len(certs) >= 2, "UVM certificate chain", f"{len(certs)} certificate(s) carried"):
        return None
    cwt = ph.get(15) if isinstance(ph.get(15), dict) else {}
    issuer = cwt.get(1) or ph.get("iss") or ""
    did = None
    if isinstance(issuer, str):
        parts = issuer.split("::")
        head = parts[0].split(":")
        if len(head) == 5 and head[:4] == ["did", "x509", "0", "sha256"] and len(parts) == 2 and parts[1].startswith("eku:"):
            did = {"fingerprint": head[4], "eku": parts[1][4:]}
    c.add(bool(did) and did["fingerprint"] == root_b64url and did["eku"] == UVM_EKU, "UVM issuer pinned",
          f"issuer names root {did['fingerprint']} usage {did['eku']}" if did else "issuer is not a did:x509 name")
    root_fp = base64.urlsafe_b64encode(hashlib.sha256(chain_der[-1]).digest()).rstrip(b"=").decode()
    c.add(root_fp == root_b64url, "UVM root is Microsoft's",
          f"chain root fingerprint {root_fp} (pinned: {root_b64url} = Microsoft Supply Chain RSA Root CA 2022)")
    links = all(signed_by(certs[k], certs[k + 1]) for k in range(len(certs) - 1)) and signed_by(certs[-1], certs[-1])
    c.add(links, "UVM chain signatures", "each certificate signed by the next; root self-signed (dates not enforced)")
    try:
        ekus = [o.dotted_string for o in certs[0].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except Exception:                                       # noqa: BLE001
        ekus = []
    c.add(UVM_EKU in ekus, "UVM signer usage", f"signing certificate usages {ekus}")
    pub = certs[0].public_key()
    try:
        if not isinstance(pub, rsa.RSAPublicKey):
            raise TypeError("not RSA")
        pub.verify(signature, cbor_dumps(["Signature1", protected_raw, b"", payload]),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())
        sig_ok = True
    except Exception:                                       # noqa: BLE001
        sig_ok = False
    c.add(sig_ok, "UVM endorsement signature", "PS384 over Sig_structure verifies under the signing certificate" if sig_ok
          else "does NOT verify")
    feed = cwt.get(2) or ph.get("feed")
    c.add(feed == UVM_FEED, "UVM feed", f"{feed!r}")
    try:
        body = json.loads(payload)
        meas = bytes.fromhex(body["x-ms-sevsnpvm-launchmeasurement"])
        svn = int(cwt.get("svn", body.get("x-ms-sevsnpvm-guestsvn")))
        if len(meas) != 48:
            raise ValueError("measurement is not 48 bytes")
    except (ValueError, KeyError, TypeError) as exc:
        c.add(False, "UVM endorsed measurement", f"payload unreadable ({type(exc).__name__})")
        return None
    c.add(svn >= min_svn, "UVM security version", f"SVN {svn}, minimum {min_svn}")
    return meas


def verify_search(row: Dict[str, Any], evidence: Dict[str, Any], *, pins: Dict[str, str], uvm_root: str,
                  uvm_min_svn: int, matter_cutoff: Optional[int]) -> Checks:
    """All checks for one sealed search. `row` is the searches.json entry; `evidence` the bundle it names."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    c = Checks()
    st = dict(row.get("statement") or {})
    sig_hex = st.pop("sig", None)
    signer = row.get("signer_pub") or ""

    # 1. statement signature
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(sig_hex or ""), canonical(st))
        c.add(True, "statement signature", f"Ed25519 over the canonical statement verifies under {signer[:16]}…")
    except Exception:                                       # noqa: BLE001
        c.add(False, "statement signature", "does NOT verify under the stated signer key")

    # 2. runtime data and its commitments
    offer = (evidence or {}).get("offer") or {}
    try:
        rd_bytes = base64.b64decode(offer["runtime_data"], validate=True)
        rd = json.loads(rd_bytes)
    except Exception:                                       # noqa: BLE001
        c.add(False, "runtime data present", "the evidence bundle carries no readable runtime_data")
        rd, rd_bytes = {}, b""
    if rd:
        c.add(rd.get("statement_signer_pub") == signer, "signer key committed in runtime data",
              "the signing key is the one the hardware report binds" if rd.get("statement_signer_pub") == signer
              else "the signing key is NOT the one in the runtime data")
        c.add(st.get("runtime_data_sha256") == sha256_hex(rd_bytes), "statement names this runtime data",
              f"runtime_data_sha256 {sha256_hex(rd_bytes)[:16]}…")
        same = (st.get("lifetime_id") == rd.get("lifetime_id") and st.get("index_manifest_sha256") == rd.get("index_manifest_sha256")
                and st.get("model_manifest_sha256") == rd.get("model_manifest_sha256"))
        c.add(same, "statement matches enclave commitments",
              f"lifetime {str(rd.get('lifetime_id'))[:12]}…, index manifest {str(rd.get('index_manifest_sha256'))[:12]}…, encoders {str(rd.get('model_manifest_sha256'))[:12]}…")

    # 3. hardware report binds the runtime data; AMD chain; UVM; policy
    p = None
    try:
        report = base64.b64decode(offer["evidence"], validate=True)
        p = parse_report(report)
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "SNP report", f"missing or unparsable ({type(exc).__name__})")
    if p is not None:
        want = hashlib.sha256(rd_bytes).digest() + b"\x00" * 32
        c.add(rd_bytes != b"" and p["report_data"] == want, "REPORT_DATA binds runtime data",
              "REPORT_DATA == SHA-256(runtime data) ‖ zeros: the chip signed over this runtime data" if p["report_data"] == want
              else "REPORT_DATA does NOT equal SHA-256(runtime data) ‖ zeros")
        try:
            certs = load_certs(base64.b64decode(offer["endorsements"], validate=True))
            from cryptography.hazmat.primitives import serialization
            pem = lambda cs: b"".join(x.public_bytes(serialization.Encoding.PEM) for x in cs)  # noqa: E731
            check_amd(c, p, pem(certs[:1]), pem(certs[1:]), pins)
        except Exception as exc:                            # noqa: BLE001
            c.add(False, "AMD endorsements", f"missing or unparsable ({type(exc).__name__})")
        try:
            meas = check_uvm(c, base64.b64decode(offer["uvm_endorsements"], validate=True), uvm_root, uvm_min_svn)
        except Exception as exc:                            # noqa: BLE001
            meas = None
            c.add(False, "UVM endorsement", f"missing or unparsable ({type(exc).__name__})")
        if meas is not None:
            c.add(p["measurement"] == meas, "MEASUREMENT is the endorsed utility VM",
                  f"report MEASUREMENT {p['measurement'].hex()[:16]}… {'==' if p['measurement'] == meas else '!='} endorsed launch measurement")
        pol = (evidence or {}).get("policy_b64")
        if pol:
            try:
                hd = sha256_hex(base64.b64decode(pol))
                c.add(hd == p["host_data"].hex(), "HOST_DATA is the container policy",
                      f"SHA-256(policy) {hd[:16]}… {'==' if hd == p['host_data'].hex() else '!='} HOST_DATA")
            except Exception:                               # noqa: BLE001
                c.add(False, "HOST_DATA is the container policy", "policy in bundle is not valid base64")
        else:
            c.add(None, "HOST_DATA is the container policy",
                  f"policy not in bundle; HOST_DATA is {p['host_data'].hex()} — obtain the deployed policy and compare SHA-256(base64-decoded policy)")

    # 4. content bindings
    rid = str(st.get("request_id") or "")
    q = row.get("query_text")
    if q is not None:
        c.add(salted(rid, q) == st.get("query_sha256"), "query text is the one searched",
              "SHA-256(request_id ‖ canonical(query)) == query_sha256" if salted(rid, q) == st.get("query_sha256") else "query text does NOT match query_sha256")
    else:
        c.add(None, "query text is the one searched", "query text not in bundle; query_sha256 cannot be opened")
    res = row.get("result")
    if isinstance(res, dict):
        ok = salted(rid, res) == st.get("result_sha256")
        c.add(ok, "result is the signed result", "SHA-256(request_id ‖ canonical(result)) == result_sha256" if ok else "result does NOT match result_sha256")
        c.add(len(res.get("hits") or []) == st.get("hits_n"), "hit count as signed", f"{len(res.get('hits') or [])} hits, statement says {st.get('hits_n')}")
    else:
        c.add(None, "result is the signed result", "opened result not in bundle")
    if matter_cutoff is not None:
        c.add(st.get("cutoff_date") == matter_cutoff, "date bound as recorded",
              f"statement cutoff {st.get('cutoff_date')}, matter date bound {matter_cutoff}")
    return c


# ───────────────────────────── bundle-level ─────────────────────────────


def check_manifest(bundle_dir: str) -> Tuple[Checks, Dict[str, Any]]:
    c = Checks()
    mp = os.path.join(bundle_dir, "MANIFEST.json")
    try:
        manifest = json.load(open(mp))
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "MANIFEST.json", f"missing or unreadable ({type(exc).__name__})")
        return c, {}
    bad = []
    for name, want in (manifest.get("files") or {}).items():
        try:
            got = sha256_hex(open(os.path.join(bundle_dir, name), "rb").read())
        except OSError:
            bad.append(f"{name} (missing)")
            continue
        if got != want:
            bad.append(name)
    c.add(not bad, "bundle integrity", f"{len(manifest.get('files') or {})} files match MANIFEST.json" if not bad else f"MISMATCH: {bad}")
    return c, manifest


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Independently verify an attested prior-art record bundle.")
    ap.add_argument("bundle", help="the export directory (holds record.html, searches.json, MANIFEST.json, *.evidence.json)")
    ap.add_argument("--amd-pin", action="append", default=[], metavar="PRODUCT=SPKI_SHA256_HEX",
                    help="override an AMD root pin (TEST ROOTS ONLY — printed loudly)")
    ap.add_argument("--uvm-root", default=None, help="override the Microsoft UVM root fingerprint (TEST ROOTS ONLY)")
    ap.add_argument("--uvm-min-svn", type=int, default=UVM_MIN_SVN)
    a = ap.parse_args(argv)

    pins = dict(AMD_ARK_SPKI_SHA256)
    test_roots = False
    for kv in a.amd_pin:
        k, _, v = kv.partition("=")
        pins[k] = v.lower()
        test_roots = True
    uvm_root = a.uvm_root or MS_UVM_ROOT_SHA256_B64URL
    if a.uvm_root:
        test_roots = True

    print(f"Attested prior-art record: {os.path.abspath(a.bundle)}")
    if test_roots:
        print("!!! NON-PRODUCTION ROOTS PINNED: this run can only verify a TEST enclave, never Azure. !!!")
    c0, manifest = check_manifest(a.bundle)
    c0.dump()
    all_ok = not c0.failed
    try:
        searches = json.load(open(os.path.join(a.bundle, "searches.json")))
    except Exception as exc:                                # noqa: BLE001
        print(f"  FAIL searches.json: missing or unreadable ({type(exc).__name__})")
        return 1
    cutoff = manifest.get("matter_cutoff")
    if not searches:
        print("  (no sealed searches in this record)")
    for i, row in enumerate(searches, 1):
        print(f"\nSearch {i} — session {row.get('session_id')}, recorded {row.get('at')}")
        ev = {}
        ef = row.get("evidence_file")
        if ef:
            try:
                raw = open(os.path.join(a.bundle, ef), "rb").read()
                if row.get("evidence_sha256") and sha256_hex(raw) != row["evidence_sha256"]:
                    print(f"  FAIL evidence file: {ef} sha256 does not match searches.json")
                    all_ok = False
                ev = json.loads(raw)
            except Exception as exc:                        # noqa: BLE001
                print(f"  FAIL evidence file: {ef} unreadable ({type(exc).__name__})")
                all_ok = False
        c = verify_search(row, ev, pins=pins, uvm_root=uvm_root, uvm_min_svn=a.uvm_min_svn, matter_cutoff=cutoff)
        c.dump()
        if c.failed:
            all_ok = False
    print("\nRESULT:", "every applicable check PASSED" if all_ok else f"FAILED — {sum(1 for _ in [1])} or more checks did not pass; see FAIL lines above")
    print("Not redone here: the attorney's own machine confinement (self-reported); fetching anything; enforcing certificate dates.")
    print("Fully independent redo: snpguest / go-sev-guest (AMD chain), go-cose / pycose (UVM), az confcom acipolicygen (policy ↔ image).")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
