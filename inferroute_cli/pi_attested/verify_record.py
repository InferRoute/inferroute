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
  recipient the enclave's signed reply_to_sha256 == SHA-256(the public key recorded in this search row).
            This binds the signed destination to the row; it does NOT establish that no other copy or
            disclosure channel existed, or independently prove how the recorded key was created or used.

  identity  ONLY WITH --reference: HOST_DATA (the container policy hash) and the index / encoder manifest
            hashes equal values obtained from InferRoute OUT OF BAND. Without this the bundle proves a genuine
            Azure confidential container — NOT that it was InferRoute's code or index — and this check FAILS.

READ THIS: a SEV-SNP report plus Microsoft's endorsement prove that SOME confidential container ran on a
genuine AMD chip inside Microsoft's utility VM. Anyone with an Azure account can produce such a bundle with
their own signer key, their own statement over any query and result, and their own policy. The MEASUREMENT
endorses Microsoft's utility VM, not our container. What identifies InferRoute's enclave is the policy hash
(HOST_DATA) and the manifest hashes — and those mean nothing unless you compare them against values you got
from InferRoute independently of this bundle. Pass that file with --reference; until then, treat the record
as "a genuine confidential container searched this text", no more.

What it does NOT do:
  * It does not fetch anything. AMD certificate validity dates ARE enforced (as in the live verifier); the
    Microsoft COSE chain's are not (endorsements outlive their signing certificates; Microsoft's own
    reference verifier behaves the same). No revocation checking; no basicConstraints / keyUsage / path
    length validation — trust is two root pins plus signature links, nothing more.
  * It cannot verify that the machine which made this record was confined — that is the device's self-report.
  * Completeness: each statement carries a per-enclave sequence number; the record is checked for gaps and
    duplicates per enclave lifetime, so a dropped search is visible — except one dropped from the very END
    of a lifetime, and except an ENTIRE lifetime dropped from the record (the check is per enclave shown;
    nothing says how many enclaves a matter used). Statements without sequence numbers or without a
    lifetime_id get a SKIP that says so.
  * The reference may be SIGNED by InferRoute's long-lived publication key: record that key once at first
    use and pass --reference-key; each reference entry may carry a validity window or a retired flag, and a
    match that was not current at the search's time FAILS and says which entry matched.
  * MANIFEST.json is an index, not a seal: it is unsigned. The enclave-signed statements are the seal.
  * `--extract DIR` writes each search's raw evidence (report.bin, vcek.pem, ask_ark.pem,
    uvm_endorsement.cose, runtime_data.json, policy.rego) for independent tools; VERIFY.md names them
    honestly as tools that consume these bytes, without claiming invocations we have run here.

Exit status 0 iff every check passes (a bundle with no sealed searches, or without --reference, does not).
Output is plain text: one line per check.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
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

MIN_CRYPTOGRAPHY = 42            # not_valid_before_utc needs 42+; signature_algorithm_parameters 41+
REQUIRED_FILES = ("record.html", "searches.json", "verify_record.py", "VERIFY.md")
# Present in the folder and deliberately NOT in the manifest's file list. REPORT-TEMPLATE.md is stationery
# — an audit pack invites the auditor to fill it in, so pinning it would fail the integrity check the
# moment they did what they were asked. On 2026-09-25 exactly that happened: one auditor filled it in where
# it lay, and a second auditor running in the same folder found the pack broken and was one step from
# filing evidence tampering that was really a colleague's scratch edit.
UNLISTED_OK = {"MANIFEST.json", "MANIFEST.json.ots", "SHA256SUMS", "REPORT-TEMPLATE.md"}
OPTIONAL_FILES = ("unanswered.json",)            # present only when a sealed search went unanswered

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
            "vmpl": struct.unpack("<I", g("vmpl", 4))[0],
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


def check_amd(c: Checks, p: Dict[str, Any], vcek_pem: bytes, chain_pem: bytes, pins: Dict[str, str],
              min_tcb: Optional[Dict[str, Dict[str, int]]] = None) -> None:
    import datetime as dt
    # The comparison is done before the f-string, not inside it: a backslash in an f-string expression is
    # a syntax error before Python 3.12, and this file has to run wherever the auditor's firm is.
    signed = p["signature"] != b"\x00" * 512
    c.add(p["version"] >= 2 and signed, "hardware report",
          f"SNP report version {p['version']}, {'signed' if signed else 'UNSIGNED'}")
    c.add(not p["debug_allowed"], "debug disabled", "guest policy forbids debugging" if not p["debug_allowed"]
          else "guest policy ALLOWS debugging — the host could inspect this VM")
    if not c.add(p["signing_key"] == "VCEK", "signed by a chip key", f"signing key is {p['signing_key']} (only VCEK accepted)"):
        return
    c.add(p["vmpl"] == 0, "report from VMPL 0", f"VMPL {p['vmpl']}" + ("" if p["vmpl"] == 0 else " — ACI runs the guest at VMPL 0; a higher VMPL is not the container's own report"))
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
    c.add(not outside, "AMD certificates in date", "VCEK, ASK and ARK all valid now" if not outside
          else f"outside validity now: {outside} (enforced for the AMD chain, as in the live verifier; the Microsoft COSE chain is date-exempt by design)")
    hwid = _ext(vcek, OID_HWID) or b""
    chip = p["chip_id"]
    same = bool(hwid) and not p["mask_chip_id"] and chip[:len(hwid)] == hwid and not any(chip[len(hwid):])
    c.add(same, "VCEK is for this chip", f"hwid {hwid.hex()[:16]}… {'matches' if same else 'does NOT match'} the report's chip id")
    want = tcb_params(p["reported_tcb"], zen5=product in ZEN5)
    mismatch = [k for k, v in want.items() if _der_int(_ext(vcek, OID_TCB[k])) != v]
    c.add(not mismatch, "VCEK is for this firmware", f"reported TCB {want}" + ("" if not mismatch else f"; certificate differs on {mismatch}"))
    # A minimum firmware TCB, same shape as the UVM SVN floor: a VCEK that agrees with the report still
    # passes on known-vulnerable firmware unless a floor is pinned.
    floor = (min_tcb or {}).get(product)
    if floor:
        low = {k: (want.get(k), v) for k, v in floor.items() if want.get(k) is None or want[k] < v}
        c.add(not low, "firmware TCB at or above minimum", f"minimum {floor}" + ("" if not low else f"; BELOW on {low}"))
    else:
        c.add(None, "firmware TCB at or above minimum", f"no minimum pinned for {product} (pass --min-tcb {product}=snpSPL:N,ucodeSPL:N); reported {want}")
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


ZERO32 = "0" * 64
# SHA-256 of b"": what a manifest builder returns when it found no files (e.g. over a root whose directories
# are symlinks, which Python 3.12's rglob does not follow). A real-looking digest that names no bytes and is the
# same for every index — a match on it proves nothing about WHICH index ran. Kept in step with the issuer's
# refusal in the reference-issuing tool; duplicated here only because this file must import nothing of ours.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _names_bytes(v: Any) -> bool:
    """A manifest digest that actually identifies something: well-formed, not a placeholder, not empty."""
    return _is_hex32(v) and str(v).lower() not in (ZERO32, EMPTY_SHA256)


def _is_hex32(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(ch in "0123456789abcdef" for ch in v.lower())


# ───────────────────────────── the reference (identity), signed and time-bounded ─────────────────────────────


def _ref_entries(reference: Dict[str, Any], field: str) -> List[Dict[str, Any]]:
    """Entries may be plain hashes or objects {value, valid_from, valid_to, retired}. Times are ISO-8601 UTC
    ('YYYY-MM-DDTHH:MM:SSZ'), compared lexicographically against the statement's started_utc."""
    out: List[Dict[str, Any]] = []
    for e in reference.get(field, []) or []:
        if isinstance(e, str):
            out.append({"value": e.lower(), "valid_from": None, "valid_to": None, "retired": False})
        elif isinstance(e, dict) and isinstance(e.get("value"), str):
            out.append({"value": e["value"].lower(), "valid_from": e.get("valid_from") or None,
                        "valid_to": e.get("valid_to") or None, "retired": bool(e.get("retired"))})
    return out


def _parse_time(s: Any) -> Optional["datetime.datetime"]:
    """ISO-8601 → aware UTC datetime, or None if it does not parse. A trailing Z is normalised; an offset is
    honoured (2026-09-15T01:00:00+02:00 is 23:00Z on the 14th); fractional seconds are accepted; a naive
    time is taken as UTC. A string compare is the wrong instrument for 'was this current at the time'."""
    import datetime
    if not isinstance(s, str) or not s.strip():
        return None
    t = s.strip()
    if t[-1] in "Zz":
        t = t[:-1] + "+00:00"
    try:
        d = datetime.datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc)


# --- What the policy PERMITS, not just what it hashes to -----------------------------------------------
#
# Until 25 Sep this program hashed the archived policy against HOST_DATA and never read it. The hash
# answers "is this the policy the hardware ran"; it says nothing about what that policy ALLOWS. An
# auditor who wanted to know had to read 9.5 KB of Rego by hand, and the one who did found
# allow_stdio_access:true in all three containers — a permission that bears directly on whether anyone
# outside the enclave could observe what it handled, and which no check here would ever have surfaced.
#
# These rows do not change the exit code. The exit code answers "is this record intact", and a permissive
# policy is not a damaged record. What they change is the SENTENCE the evidence licenses, which is
# computed below and printed — so the strongest confidentiality claim a reader may make is mechanical
# rather than a matter of how boldly the report is written.

CONFIDENTIALITY_POSTURE = (
    # (key, per-container, wanted, row name, what it bears on)
    ("allow_stdio_access", True, False, "policy denies host access to the enclave's stdio",
     "with this true, the operator can attach to the container's standard streams"),
    ("allow_elevated", True, False, "policy denies elevated execution",
     "an elevated process can reach outside the container's confinement"),
    ("allow_runtime_logging", False, False, "policy denies runtime logging",
     "runtime logging surfaces container activity to the host"),
    ("allow_dump_stacks", False, False, "policy denies stack dumps",
     "a stack dump can carry live memory contents out of the enclave"),
    ("allow_unencrypted_scratch", False, False, "policy denies unencrypted scratch space",
     "unencrypted scratch writes plaintext to storage the operator can read"),
)


def _policy_containers(text: str) -> Optional[List[Dict[str, Any]]]:
    """Read exactly one top-level containers array; ambiguous policies are not auditable."""
    assignments = list(re.finditer(r"(?m)^[ \t]*containers[ \t]*:=", text))
    if len(assignments) != 1:
        return None
    start = assignments[0].end()
    while start < len(text) and text[start].isspace():
        start += 1
    if start >= len(text) or text[start] != "[":
        return None
    depth, in_str, esc = 0, False, False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                try:
                    out = json.loads(text[start:j + 1])
                except ValueError:
                    return None
                return out if isinstance(out, list) and all(isinstance(x, dict) for x in out) else None
    return None


def _policy_flag(text: str, name: str) -> Optional[bool]:
    """Read one unambiguous simple rule; defaults and duplicate rules are not evaluated here."""
    ident = re.escape(name)
    if re.search(r"(?m)^[ \t]*default[ \t]+" + ident + r"\b", text):
        return None
    matches = re.findall(r"(?m)^[ \t]*" + ident + r"[ \t]*:=[ \t]*(true|false)[ \t]*$", text)
    return (matches[0] == "true") if len(matches) == 1 else None


def _policy_external_dependencies(text: str) -> List[str]:
    """Conservatively find CCE fragment arrays and non-language Rego imports.

    Unknown, malformed, or duplicate fragment declarations block the self-contained claim.
    """
    dependencies: List[str] = []
    assignments = list(re.finditer(r"(?m)^[ \t]*fragments[ \t]*:=", text))
    defaults = list(re.finditer(r"(?m)^[ \t]*default[ \t]+fragments\b", text))
    if len(assignments) > 1 or defaults:
        dependencies.append("<ambiguous fragments assignment>")
    elif assignments:
        start = assignments[0].end()
        while start < len(text) and text[start].isspace():
            start += 1
        if start >= len(text) or text[start] != "[":
            dependencies.append("<unparseable fragments assignment>")
        else:
            depth, in_string, escaped = 0, False, False
            parsed = None
            for end in range(start, len(text)):
                ch = text[end]
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        try:
                            parsed = json.loads(text[start:end + 1])
                        except (TypeError, ValueError):
                            parsed = None
                        break
            if not isinstance(parsed, list):
                dependencies.append("<unparseable fragments assignment>")
            else:
                for i, item in enumerate(parsed):
                    label = None
                    if isinstance(item, dict):
                        label = item.get("feed") or item.get("source_uri") or item.get("uri")
                    dependencies.append(str(label or f"fragment[{i}]"))

    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if not re.match(r"^\s*import\b", code):
            continue
        match = re.match(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_.]*)\b", code)
        if not match:
            dependencies.append("<unparseable import>")
            continue
        module = match.group(1)
        if module != "future.keywords" and not module.startswith("future.keywords."):
            dependencies.append(f"import {module}")
    return sorted(set(dependencies))


def check_policy_posture(c: Checks, policy_b64: Optional[str]) -> Dict[str, Optional[bool]]:
    """Report each permission that bears on whether anything outside the enclave could observe the work.
    Returns {condition: True/False/None}; None is "the document does not say", which is NOT satisfied."""
    out: Dict[str, Optional[bool]] = {k: None for k, *_ in CONFIDENTIALITY_POSTURE}
    out["image_pinned"] = None
    out["no_exec"] = None
    if not policy_b64:
        c.add(None, "policy permissions", "no policy archived in the bundle — nothing to read")
        return out
    try:
        text = base64.b64decode(policy_b64).decode("utf-8", "replace")
    except Exception:                                       # noqa: BLE001
        c.add(False, "policy permissions", "policy in bundle is not valid base64")
        return out
    containers = _policy_containers(text)
    if containers is None:
        c.add(False, "policy permissions", "could not read the containers list out of the policy document")
        return out

    # A policy may PULL IN containers it does not contain. This document declares an external fragment,
    # and counting only the containers written here understates what the hardware actually enforced: an
    # auditor on 25 Sep fetched the fragment this record names and found ten more containers, eight of
    # them allowing elevated execution and one with a non-empty exec_processes. Every row below counts
    # what is IN THIS FILE, so when a fragment can add containers, the rows are a floor and not a census.
    dependencies = _policy_external_dependencies(text)
    out["self_contained"] = not dependencies
    c.add(out["self_contained"], "policy is self-contained",
          "no external fragments or imports found" if out["self_contained"] else
          f"unresolved external policy dependency/dependencies: {', '.join(dependencies[:5])} — "
          "the permission rows below cover only the literal containers in this document, not the effective policy")

    for key, per_container, wanted, name, bears_on in CONFIDENTIALITY_POSTURE:
        if per_container:
            vals = [cont.get(key) for cont in containers]
            got = all(v is wanted for v in vals) if vals else None
            n_bad = sum(1 for v in vals if v is not wanted)
            detail = (f"all {len(vals)} container(s) set {key}={str(wanted).lower()}" if got else
                      f"{n_bad} of {len(vals)} container(s) set {key}={str(not wanted).lower()} — {bears_on}")
        else:
            v = _policy_flag(text, key)
            got = (v is wanted)
            detail = (f"{key}={str(wanted).lower()}" if got else
                      (f"the policy does not carry {key} at all, so nothing denies it" if v is None
                       else f"{key}={str(v).lower()} — {bears_on}"))
        out[key] = got
        c.add(got, name, detail)

    layered = [cont for cont in containers if isinstance(cont.get("layers"), list) and cont["layers"]]
    out["image_pinned"] = len(layered) == len(containers) and bool(containers)
    c.add(out["image_pinned"], "policy lists pinned image layers",
          f"{len(layered)} of {len(containers)} container(s) pin their filesystem layer roots"
          + ("" if out["image_pinned"] else " — an unpinned container can be any image"))

    no_exec = [cont for cont in containers if cont.get("exec_processes") == []]
    out["no_exec"] = len(no_exec) == len(containers) and bool(containers)
    c.add(out["no_exec"], "policy lists no additional exec processes",
          f"{len(no_exec)} of {len(containers)} container(s) set exec_processes: []"
          + ("" if out["no_exec"] else " — a permitted exec can run code the measurement never covered"))
    return out


# --- Claims supported by the archived evidence --------------------------------------------------------
# Passing configuration checks does not prove runtime non-disclosure. In particular, a pinned,
# reproducibly built application can itself send plaintext over the network. None of the flags below
# prohibits that. Keep each licensed sentence bounded by what this program actually checks.

STATEMENT_SEALED = (
    "For the archived SEARCH operations checked here, statement signatures verify under keys bound "
    "to AMD hardware reports with debugging disabled, under the configured production trust roots. "
    "This does not establish encryption on the user's device, secrecy of private keys, or absence "
    "of other plaintext copies.")
STATEMENT_ENCLOSED = (
    "For those archived SEARCH operations, the hardware-committed policy documents list image layer "
    "roots and empty exec_processes, and set stdio access, elevated execution, runtime logging, stack "
    "dumps and unencrypted scratch to false. The configured firmware-floor and ASK-revocation checks "
    "passed. These are checks of specified controls, not proof that every disclosure channel is closed.")
STATEMENT_CONFIDENTIAL = (
    "Privacy throughout is NOT ESTABLISHED: this verifier does not prove client-side sealing, "
    "exclusive key custody, the application's handling of plaintext, all runtime output and retention "
    "channels, or the AI conversation's confidentiality.")

# The scope line matters as much as the sentences. This program checks the SEARCH lane (AMD SEV-SNP).
# The conversation with the AI machine is a different machine on different hardware, attested in the
# session receipts, which this program deliberately does not parse. An auditor on 25 Sep found three
# things there that bear directly on these sentences and that nothing here can see, so they are named
# rather than left to be discovered:
# These NAME the fields and ask the question. They used to print the answers too, and an auditor on
# 25 Sep reported confirming a sentence it had been handed rather than working it out -- one of the three
# word for word. A pointer with the key attached is a quiz, not a pointer.
AI_LANE_CONDITIONS = (
    "that every AI instance a session actually used is attested, not only one of them — read "
    "`counters.instance_switches` and `events` against the `attestation` block, and against the times "
    "of the searches that session covers",
    "what actually BINDS a receipt to the searches it is offered as covering, and whether that binding "
    "is signed — compare the identifiers in the receipt, in searches.json, and in the signed statements",
    "that no request was served by an instance the device itself later stopped trusting — read `events` "
    "and `refusal` against the request timings, and against the receipt's own verdict",
)


def confidentiality_reach(posture: Dict[str, Optional[bool]], *, floor_pinned: bool,
                          revocation_checked: bool, image_published: bool,
                          authenticated: bool, record_ok: bool,
                          policy_committed: bool) -> Tuple[int, List[str]]:
    """Return -1 for invalid evidence, 0 for hardware bindings, 1 for specified controls.

    Level 2 (confidentiality throughout) is deliberately unreachable: even authentic, reproducible
    code and a fully passing policy can intentionally disclose plaintext. Source availability is not
    source-to-image verification or a proof about its behavior. Keep missing evidence visible.
    """
    if record_ok is not True:
        return -1, ["this record did not verify — no sentence is licensed"]
    if policy_committed is not True:
        return -1, ["the archived policy is not established as the hardware-committed policy (HOST_DATA)"]
    blockers: List[str] = []
    for key, _per, _want, name, _bears in CONFIDENTIALITY_POSTURE:
        if posture.get(key) is not True:
            blockers.append(f"the policy does not satisfy: {name}")
    if posture.get("image_pinned") is not True:
        blockers.append("the policy does not pin the image that ran")
    if posture.get("no_exec") is not True:
        blockers.append("the policy does not establish an empty additional-exec allowlist")
    if posture.get("self_contained") is not True:
        blockers.append("the policy has unresolved external fragments/imports, so the permission rows may "
                        "omit effective rules — resolve and verify every dependency")
    if not floor_pinned:
        blockers.append("a configured firmware floor did not PASS for every archived operation")
    if not revocation_checked:
        blockers.append("certificate revocation was not checked successfully (pass --check-revocation)")
    if not authenticated:
        blockers.append("the reference signature was not verified under a supplied key; independently "
                        "establishing who owns that key remains the reader's responsibility")
    controls_checked = not blockers
    blockers.append("image_source is only a reference field; availability, a reproducible build and its "
                    "binding to the measured image were not verified" if image_published else
                    "the reference does not name a source for the image; source-to-image verification is absent")
    blockers.append("client-side sealing, exclusive key custody, runtime egress/retention and application "
                    "non-disclosure were not established; closing the configuration gaps alone is insufficient")
    return (1 if controls_checked else 0), blockers


def report_confidentiality(policies: List[Tuple[str, str]], *, reference: Optional[Dict[str, Any]],
                           floor_pinned: bool, revocation_checked: bool, authenticated: bool,
                           record_ok: bool, committed: Optional[set] = None,
                           production_roots: bool = False) -> None:
    """Describe the archived SEARCH evidence only; never lift it to a session-wide claim."""
    print()
    print("What this evidence licenses you to say about confidentiality")
    print("  SCOPE — archived SEARCH operations only. AI session receipts are NOT VERIFIED here; "
          "no statement below covers the conversation, omitted operations, or future requests.")
    print("  Reference signatures are relative to the supplied key; its independent provenance is not established here.")
    print("  (these rows do NOT affect the exit code above, which is about the record's integrity)")
    if not record_ok:
        print("  REFUSED — this record did not verify; no sentence is licensed.")
        return
    if not production_roots:
        print("  REFUSED — test or unestablished trust roots cannot license production claims.")
        return
    if not policies or committed is None or set(hd for hd, _ in policies) != committed:
        print("  REFUSED — archived policies do not cover every hardware policy commitment in this record.")
        return
    try:
        matched = all(sha256_hex(base64.b64decode(pol, validate=True)) == hd for hd, pol in policies)
    except (ValueError, TypeError):
        matched = False
    if not matched:
        print("  REFUSED — archived policy bytes do not match their supplied commitments.")
        return
    reach, blockers = 1, []
    for hd, pol in policies:
        print(f"  policy {hd[:16]}…")
        c = Checks()
        posture = check_policy_posture(c, pol)
        c.dump(indent="    ")
        r, b = confidentiality_reach(posture, floor_pinned=floor_pinned,
                                     revocation_checked=revocation_checked,
                                     image_published=bool(isinstance(reference, dict) and reference.get("image_source")),
                                     authenticated=authenticated, record_ok=True, policy_committed=True)
        reach = min(reach, r)
        blockers.extend(f"policy {hd[:16]}: {item}" for item in b)
    print()
    print("  You may write:")
    print(f"    1. {STATEMENT_SEALED}")
    if reach >= 1:
        print(f"    2. {STATEMENT_ENCLOSED}")
    print("  You may NOT write that the text was never exposed, could not have been read, or remained "
          "confidential. What is missing:")
    for blocker in dict.fromkeys(blockers):
        print(f"    - {blocker}")
    print(f"  {STATEMENT_CONFIDENTIAL}")
    print("  AI receipts require a separate verification and privacy argument. The following are necessary "
          "binding checks, NOT a sufficient privacy checklist:")
    for cond in AI_LANE_CONDITIONS:
        print(f"    - {cond}")


# --- Revocation ---------------------------------------------------------------------------------------
#
# Listed as a NON-check since this program was written, and every auditor has correctly written it down as
# a limitation: a revoked VCEK passes every other check here. It stays OFF by default, because this
# verifier's value is that it runs offline and deterministically on a folder, and a check that silently
# needs the network would make an air-gapped run look worse than it is. --check-revocation opts in.
#
# A fetch that fails is a SKIP, never a FAIL. "I could not reach AMD" and "this certificate is revoked"
# must not produce the same row -- that is the failure this codebase has been bitten by before.

AMD_CRL_URL = "https://kdsintf.amd.com/vcek/v1/{product}/crl"


def check_revocation(c: Checks, chains: List[Tuple[str, Any, Any]], *, timeout: float = 20.0) -> bool:
    """`chains` is [(product, ask, ark)] deduplicated by the caller. Returns True only if every chain was
    actually CHECKED against a CRL we verified, and none was revoked.

    Read what this can and cannot reach, because a first attempt here got it wrong in the direction that
    flatters us. AMD's CRL for a product line is issued by the ARK and lists ASK-level serials -- the
    Genoa CRL carried exactly one entry when this was written. **VCEKs are not individually revocable
    this way: every VCEK AMD issues carries serial number 0**, so a per-chip CRL lookup is not merely
    unavailable, it silently matches nothing and passes. The first version of this function did exactly
    that and reported "none on AMD's CRL" for 70 certificates it had never really looked up.

    So the honest decomposition is: this checks the ASK, and the control against a chip running
    outdated or broken firmware is NOT a CRL at all -- it is the TCB floor (min_tcb). That is why the
    confidentiality posture treats an unpinned floor as the serious gap and this row as secondary."""
    import urllib.request
    from cryptography import x509
    if not chains:
        c.add(None, "certificate revocation", "no certificate chain to check")
        return False
    all_checked = True
    for product, ask, ark in sorted(chains, key=lambda t: t[0]):
        url = AMD_CRL_URL.format(product=product)
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:      # noqa: S310 — fixed AMD host
                raw = r.read()
            crl = x509.load_der_x509_crl(raw)
        except Exception as exc:                            # noqa: BLE001
            all_checked = False
            c.add(None, "certificate revocation",
                  f"could not obtain AMD's CRL for {product} ({type(exc).__name__}) — NOT a statement that "
                  "the certificates are good, only that this run did not find out")
            continue
        # A CRL nobody authenticated is an attacker's list. It must be signed by the same ARK this record
        # already pinned, or it tells us nothing and must not be allowed to produce a pass.
        if not crl.is_signature_valid(ark.public_key()):
            all_checked = False
            c.add(False, "certificate revocation",
                  f"AMD's CRL for {product} is NOT signed by the ARK this record pins — disregarded")
            continue
        hit = crl.get_revoked_certificate_by_serial_number(ask.serial_number)
        if hit is not None:
            all_checked = False
            c.add(False, "certificate revocation",
                  f"the {product} ASK (serial {ask.serial_number:#x}) is REVOKED in AMD's CRL as of "
                  f"{hit.revocation_date_utc.isoformat()}")
        else:
            c.add(True, "certificate revocation",
                  f"{product} ASK (serial {ask.serial_number:#x}) is not on AMD's ARK-signed CRL "
                  f"({len(list(crl))} entr(y/ies), issued {crl.last_update_utc.isoformat()})")
        c.add(None, "per-chip revocation",
              f"AMD issues every {product} VCEK with serial number 0, so there is no per-chip CRL lookup "
              "to do — a run that reports one is reporting nothing. The control against a chip on outdated "
              "firmware is the TCB floor (min_tcb), not this list.")
    return all_checked


# --- Who says this key is theirs -----------------------------------------------------------------------
#
# Every auditor from 24 Sep on reached the same objection and none of them could get past it: the
# publication key reaches the reader from the audited party, so a reference agreeing with it proves only
# that the party agrees with itself. The row above can name that honestly and no more.
#
# An attestation changes what the row can say. If the pack carries a Sigstore bundle over a document
# naming the key, then a verified identity committed to that key, certified by Fulcio, and the commitment
# sits in Rekor -- an append-only log operated by neither party. That kills SUBSTITUTION and BACK-DATING,
# which is what the objection is actually about. It does NOT make the key independent of the party whose
# key it is, and this program must not imply otherwise.
#
# Deliberately NOT verified here. Checking a Sigstore bundle means Fulcio and Rekor roots, certificate
# transparency and an inclusion proof — a second trust root system inside a program whose whole value is
# that a stranger can read all of it. So this reports the attestation's PRESENCE and prints the exact
# command that checks it, and never claims the check was done. A row that said "attested" on the strength
# of a file in the same folder would be the circularity it exists to break, wearing a better word.

def check_key_attestation(c: Checks, bundle_path: Optional[str], attestation_path: Optional[str],
                          key_hex: Optional[str]) -> None:
    if not bundle_path or not attestation_path:
        c.add(None, "publication key attested out of band",
              "no attestation in this folder — the key rests on however you obtained it, and if that was "
              "from the audited party then agreement with it is self-consistency. See "
              "https://inferroute.ai/trust/ for the published attestation and check it yourself.")
        return
    try:
        att = json.load(open(attestation_path))
        named = str(att.get("publication_key") or "").strip().lower()
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "publication key attested out of band",
              f"attestation present but unreadable ({type(exc).__name__})")
        return
    if key_hex and named != key_hex.strip().lower():
        c.add(False, "publication key attested out of band",
              f"the attestation names {named[:16]}… but the key in use is {key_hex[:16]}… — they are "
              "different keys, and that is a finding, not a formatting difference")
        return
    c.add(None, "publication key attested out of band",
          f"an attestation naming {named[:16]}… and a signature bundle are present, but THIS PROGRAM HAS "
          "NOT VERIFIED THE BUNDLE. Coverage WITHHELD: no authenticated log time, operation count, "
          "or historical coverage is reported. "
          "Verifying it needs Fulcio and Rekor roots this verifier "
          "deliberately does not carry. Run it yourself; it asks the audited party for nothing:\n"
          "         cosign verify-blob --bundle <bundle> --certificate-identity <the identity> \\\n"
          "             --certificate-oidc-issuer https://accounts.google.com <attestation.json>\n"
          "         If it passes, a verified identity committed to this key in a public append-only log, "
          "at the verified log time. It does NOT authenticate earlier records retroactively or make the key "
          "independent of its owner. See VERIFY.md section 4b for the complete command and limits.")


def _ref_windowed(reference: Dict[str, Any]) -> bool:
    """True when ANY reference entry carries a validity window or a retired flag. With none, the whole
    windowing apparatus is inert for this reference and no row may imply a time was checked."""
    for field in ("policy_sha256", "index_manifest_sha256", "model_manifest_sha256"):
        for e in _ref_entries(reference, field):
            if e.get("valid_from") or e.get("valid_to") or e.get("retired"):
                return True
    return False


def _ref_match(entries: List[Dict[str, Any]], value: Any, at_iso: Optional[str]) -> Tuple[bool, str]:
    """(current_match, why). EVERY entry whose value matches is evaluated: the match is current if ANY of
    them is current at the statement's time (that entry is reported); it is refused only when no matching
    entry is current, with every reason listed. So a retired entry listed before a current one for the same
    hash — two releases sharing a manifest, a reinstated policy — cannot decide the verdict by list order.
    A windowed entry can only be called current against a PARSABLE statement time: a missing or unreadable
    started_utc FAILS rather than making the window vacuous."""
    v = str(value or "").lower()
    at = _parse_time(at_iso)
    refusals: List[str] = []
    for e in entries:
        if e["value"] != v:
            continue
        if e["retired"]:
            refusals.append("matches a RETIRED entry")
            continue
        if not (e["valid_from"] or e["valid_to"]):
            return True, "current (entry carries no validity window)"
        vf = _parse_time(e["valid_from"]) if e["valid_from"] else None
        vt = _parse_time(e["valid_to"]) if e["valid_to"] else None
        if (e["valid_from"] and vf is None) or (e["valid_to"] and vt is None):
            refusals.append("matches an entry whose validity window does not parse as ISO-8601")
            continue
        if at is None:
            refusals.append(f"matches a windowed entry, but the statement carries no parsable time "
                            f"(started_utc {at_iso!r}) — cannot say it was current")
            continue
        if vf is not None and at < vf:
            refusals.append(f"matches, but the search ({at_iso}) predates its valid_from {e['valid_from']}")
            continue
        if vt is not None and at > vt:
            refusals.append(f"matches, but the search ({at_iso}) is after its valid_to {e['valid_to']}")
            continue
        return True, f"current (valid {e['valid_from'] or '…'} → {e['valid_to'] or '…'}, search at {at_iso})"
    if refusals:
        return False, "; ".join(dict.fromkeys(refusals)) + (f" ({len(refusals)} matching entries, none current)" if len(refusals) > 1 else "")
    return False, "no entry matches"


REFERENCE_SCHEMA = "inferroute.enclave-reference/1"


def check_reference_signature(c: Checks, reference: Dict[str, Any], key_hex: Optional[str]) -> None:
    """The reference file may be signed (Ed25519 over its canonical JSON minus `sig`) by InferRoute's
    long-lived publication key. Record that key ONCE at first use (engagement letter / signed release note)
    and pass it with --reference-key: later reference updates are then accepted without re-establishing
    trust. Trust-on-first-use, anchored in the firm's own file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    # WHAT KIND OF DOCUMENT IS THIS. A signature says "InferRoute wrote this", never "InferRoute meant it
    # as a reference". The moment that key signs anything else — a release note, a benchmark result — a
    # document carrying the right field names could stand in for a reference unless the kind is checked
    # first. So the kind is checked first, and an unexpected one FAILS rather than being read anyway.
    schema, sig_present = str(reference.get("schema") or ""), bool(reference.get("sig"))
    if schema and schema != REFERENCE_SCHEMA:
        c.add(False, "reference document kind",
              f"expected {REFERENCE_SCHEMA}, this file says {schema} — a document of another kind is not a "
              "reference, even signed by the right key")
        return
    if sig_present and not schema:
        # Every reference the issuer produces stamps its kind. A SIGNED document without one is either not
        # ours or not meant as a reference; an UNSIGNED one may simply be three hashes someone typed
        # out of an engagement letter, and that case is honest — it just carries no authority to confuse.
        c.add(False, "reference document kind",
              f"this file is signed but carries no schema; a reference issued by InferRoute says "
              f"{REFERENCE_SCHEMA}")
        return
    sig = reference.get("sig")
    if key_hex is None:
        c.add(None, "reference signature", "reference carries a signature but no --reference-key was given (record InferRoute's publication key at first use and pass it)"
              if sig else "reference is unsigned; its trust rests entirely on how you obtained it")
        return
    if not sig:
        c.add(False, "reference signature", "a --reference-key was given but this reference is unsigned")
        return
    body = {k: v for k, v in reference.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(str(sig)), canonical(body))
        # An auditor on 25 Sep read this program and found what the row did not say: the key you pass is
        # never compared against anything outside the reference, and the command VERIFY.md recommends takes
        # it from a file beside the reference that holds the reference's OWN publication_key. The signature
        # then verifies under a key the signed file names about itself — self-consistency, which is a real
        # property and not the one the word "verifies" suggests. The program cannot fix that; it can refuse
        # to let it pass unremarked, so the row now says which of the two it is.
        self_named = str(reference.get("publication_key") or "").strip().lower() == key_hex.strip().lower()
        c.add(True, "reference signature", f"verifies under the publication key {key_hex[:16]}… that you supplied "
              + ("— but that key is the one THIS REFERENCE NAMES ABOUT ITSELF (its publication_key field), so "
                 "this is self-consistency, NOT authentication: a substituted reference carrying its own key "
                 "would pass this row identically. Compare the fingerprint against your engagement letter."
                 if self_named else
                 "(whether it was recorded at first use is yours to attest, not this program's)"))
    except Exception:                                       # noqa: BLE001
        c.add(False, "reference signature", "does NOT verify under the given publication key")


def check_completeness(c: Checks, searches: List[Dict[str, Any]], unanswered: Optional[List[Dict[str, Any]]] = None) -> None:
    """The signed sequence numbers must run 1..N with no gaps or duplicates, so the record can claim "every
    operation of this session, in order" — except one dropped from the very END, which no counter can reveal.

    An enclave serves many clients, so a counter per enclave lifetime made every record after the first look
    incomplete, and told each reader how much other people had used it. A statement that carries a session_id
    is therefore counted within its session (session_seq); one that does not falls back to the per-enclave
    seq, so records made before session numbering still verify exactly as they did.

    Both kinds of operation count: a sealed search and a document read each take a number, so a record that
    shows only its searches would show a gap wherever a document was read."""
    groups: Dict[Tuple[str, Optional[str]], List[Tuple[Any, str]]] = {}
    ungrouped, per_session = 0, False
    for row in searches:
        st = row.get("statement") if isinstance(row, dict) else None
        if not isinstance(st, dict):
            continue
        if not st.get("lifetime_id"):
            ungrouped += 1
            continue
        sid = str(st["session_id"]) if st.get("session_id") else None
        per_session = per_session or sid is not None
        seq = st.get("session_seq") if sid is not None else st.get("seq")
        groups.setdefault((str(st["lifetime_id"]), sid), []).append((seq, str(st.get("kind") or "search")))
    name = f"completeness (per-{'session' if per_session else 'enclave'} sequence)"
    if not groups:
        c.add(None, name, f"cannot group: {ungrouped} statement(s) carry no lifetime_id, so sequence gaps cannot be checked")
        return
    if not any(isinstance(seq, int) for rows in groups.values() for seq, _ in rows):
        c.add(None, name, "these statements carry no sequence numbers; a dropped search is undetectable")
        return
    problems, summary = [], []
    for (lid, sid), rows in groups.items():
        tag = f"session {sid[:8]}… of enclave {lid[:8]}…" if sid else f"enclave {lid[:8]}…"
        ints = sorted(seq for seq, _ in rows if isinstance(seq, int))
        if len(ints) != len(rows):
            problems.append(f"{tag}: a statement without a sequence number")
            continue
        present = set(ints)
        gaps = [n for n in range(ints[0], ints[-1] + 1) if n not in present]
        dups = len(ints) != len(present)
        if ints[0] != 1:
            problems.append(f"{tag}: starts at seq {ints[0]} — operations 1..{ints[0] - 1} are not in the record")
        if gaps or dups:
            problems.append(f"{tag}: seq {ints[0]}..{ints[-1]}" + (f" missing {gaps}" if gaps else "") + (" with duplicates" if dups else ""))
        if ints[0] == 1 and not gaps and not dups:
            summary.append(f"{tag}: seq 1..{ints[-1]} contiguous ({_counted(rows)})")
    if ungrouped:
        problems.append(f"{ungrouped} statement(s) carry no lifetime_id and could not be checked")
    # THE DEVICE'S OWN ACCOUNT OF A GAP. The enclave takes its sequence number before it answers, so a
    # request that timed out or dropped leaves a hole for ever. Where the record notes such an attempt, say
    # so — an unexplained gap reads as a deleted search, and those are very different things. It does NOT
    # soften the verdict: this is still a failure, the note is the device's word and not proof, and the
    # missing statement stays missing. Attributed to the same enclave lifetime, or it is not relevant.
    if problems and unanswered:
        for lid, _sid in groups:
            notes = [u for u in unanswered if isinstance(u, dict)
                     and (not u.get("lifetime_id") or u.get("lifetime_id") == lid)]
            for u in notes:
                problems.append(f"enclave {lid[:8]}…: this device recorded a search it sealed at {u.get('at')} "
                                f"whose answer never arrived ({u.get('reason')}) — consistent with a gap here, "
                                "but the device's own account, not proof of what the missing search was")
    shown = ("every operation of each session SHOWN, in order; one dropped from the END, or an entire session "
             "dropped from the record, remains undetectable") if per_session else \
            ("every search of each enclave SHOWN, in order; a search dropped from the END of a lifetime, or an "
             "entire lifetime dropped from the record, remains undetectable")
    c.add(not problems, name, ("; ".join(summary) + f" — covers {shown}") if not problems else "; ".join(problems))
    # ENCLAVE-WIDE COUNTER OBSERVATION (informational, never fatal): when session numbering is in use, the
    # per-enclave `seq` values this record happens to carry can still reveal operations that exist on the
    # enclave but are ABSENT from this record. On 2026-09-24 exactly such a gap was a corrupt/omitted
    # session of THIS record's own matter, and only a human auditor noticed. State the gap where the reader
    # meets it; let the reader judge whose it is. From sealed-research, with two changes:
    #
    #   * The BENIGN case named first, because on real data it is the common one. An enclave serves every
    #     matter on the professional's installation, so a record of one matter is missing the searches of
    #     all the others by construction — measured on a real installation, most of the range was absent
    #     and every absent number belonged to another matter. (The counts were written out here until
    #     25 Sep; the brief sends auditors to read this file before computing anything, so printing the
    #     answer to the one claim whose whole content is a count made recall and arithmetic
    #     indistinguishable.) Leading with "another client" invites a solo practitioner
    #     to report a breach where there is a second matter.
    #   * The list is BOUNDED. `f"{missing}"` on a long-lived enclave prints thousands of numbers into a
    #     verifier's output; the count is the fact, the numbers are the illustration.
    if per_session:
        eseq: Dict[str, set] = {}
        for row in searches:
            st = row.get("statement") if isinstance(row, dict) else None
            if isinstance(st, dict) and st.get("lifetime_id") and isinstance(st.get("seq"), int):
                eseq.setdefault(str(st["lifetime_id"]), set()).add(int(st["seq"]))
        for lid, seen in sorted(eseq.items()):
            lo, hi = min(seen), max(seen)
            missing = [n for n in range(lo, hi + 1) if n not in seen]
            if missing:
                shown_missing = ", ".join(str(n) for n in missing[:12]) + ("…" if len(missing) > 12 else "")
                c.add(None, "enclave-wide counter (observation)",
                      f"enclave {lid[:8]}…: this record carries enclave seq {lo}..{hi} but not {len(missing)} "
                      f"of them ({shown_missing}) — operations that ran on the enclave and are not in this "
                      f"record. Usually another MATTER on the same installation, or another client where the "
                      f"enclave is shared; but a session of this matter missing from the export looks "
                      f"identical here. The record cannot say which; ask the exporter to account for them.")


def _counted(rows: List[Tuple[Any, str]]) -> str:
    """"3 searches, 1 document read" — a reader should not have to infer what was counted."""
    docs = sum(1 for _, kind in rows if kind == "document")
    searches = len(rows) - docs
    parts = []
    if searches:
        parts.append(f"{searches} search{'es' if searches != 1 else ''}")
    if docs:
        parts.append(f"{docs} document read{'s' if docs != 1 else ''}")
    return ", ".join(parts) or "0 operations"


# ── shared by BOTH entry points ───────────────────────────────────────────────────────────────────
# verify_search() checks a record after the fact; verify_offer() checks an enclave BEFORE anything is
# sealed to it. The hardware and identity questions are the same question in both, so they are asked by
# the same code. Two copies would drift, and the drift would be invisible: the live client would accept
# an enclave the bundled verifier later rejects, or the reverse, and each would look right on its own.

def check_hardware(c: "Checks", offer: Dict[str, Any], rd: Dict[str, Any], rd_bytes: bytes, *, pins: Dict[str, str],
                   uvm_root: str, uvm_min_svn: int, policy_b64: Optional[str] = None,
                   min_tcb: Optional[Dict[str, Dict[str, int]]] = None) -> Optional[Dict[str, Any]]:
    """The AMD and Microsoft half: REPORT_DATA binds this runtime data, the report verifies under a VCEK
    that chains to a PINNED AMD root, the utility VM is endorsed by Microsoft and its measurement is the
    one in the report, and any policy shipped alongside hashes to HOST_DATA. Returns the parsed report."""
    p = None
    try:
        report = base64.b64decode(offer["evidence"], validate=True)
        p = parse_report(report)
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "SNP report", f"missing or unparsable ({type(exc).__name__})")
    if p is not None:
        want = hashlib.sha256(rd_bytes).digest() + b"\x00" * 32
        bound = bool(rd) and p["report_data"] == want
        c.add(bound, "REPORT_DATA binds runtime data",
              "REPORT_DATA == SHA-256(runtime data) ‖ zeros: the chip signed over this runtime data" if bound
              else "REPORT_DATA does NOT equal SHA-256(runtime data) ‖ zeros (or no runtime data)")
        try:
            certs = load_certs(base64.b64decode(offer["endorsements"], validate=True))
            from cryptography.hazmat.primitives import serialization
            pem = lambda cs: b"".join(x.public_bytes(serialization.Encoding.PEM) for x in cs)  # noqa: E731
            check_amd(c, p, pem(certs[:1]), pem(certs[1:]), pins, min_tcb)
        except Exception as exc:                            # noqa: BLE001
            c.add(False, "AMD endorsements", f"missing or unparsable ({type(exc).__name__})")
        try:
            meas = check_uvm(c, base64.b64decode(offer["uvm_endorsements"], validate=True), uvm_root, uvm_min_svn)
        except Exception as exc:                            # noqa: BLE001
            meas = None
            c.add(False, "UVM endorsement", f"missing or unparsable ({type(exc).__name__})")
        if meas is not None:
            c.add(p["measurement"] == meas, "MEASUREMENT is the endorsed utility VM",
                  f"report MEASUREMENT {p['measurement'].hex()[:16]}… {'==' if p['measurement'] == meas else '!='} endorsed launch measurement "
                  "(this endorses Microsoft's utility VM, not InferRoute's container)")
        pol = policy_b64
        if pol:
            try:
                hd = sha256_hex(base64.b64decode(pol))
                c.add(hd == p["host_data"].hex(), "archived policy matches the report (consistency)",
                      f"SHA-256(archived policy) {hd[:16]}… {'==' if hd == p['host_data'].hex() else '!='} HOST_DATA — agreement within the bundle, not identity")
            except Exception:                               # noqa: BLE001
                c.add(False, "archived policy matches the report (consistency)", "policy in bundle is not valid base64")
        else:
            c.add(None, "archived policy matches the report (consistency)", "no policy archived in the bundle")
    return p


def check_identity(c: "Checks", rd: Dict[str, Any], p: Optional[Dict[str, Any]],
                   reference: Optional[Dict[str, Any]], at: Optional[str]) -> None:
    """The only check that separates InferRoute's enclave from anyone else's Azure confidential container:
    HOST_DATA and the manifest hashes against values obtained OUT OF BAND. `at` is the moment the claim is
    about — a statement's own time when checking a record, and now when checking a live enclave.

    Mirrors the live verifier's ruling (aci_evidence: an unpinned policy is a FAILING step). Each reference
    entry may carry a validity window or be retired; a match that is not CURRENT at `at` fails, and the row
    says which entry matched and why."""
    if isinstance(reference, dict) and reference.get("development"):
        c.add(False, "enclave identity (InferRoute's policy, index, encoders)",
              "this reference is marked DEVELOPMENT — it was signed by a key that is not the production "
              "publication key, so it cannot establish that the enclave was InferRoute's. Obtain the "
              "production reference from your engagement letter.")
    elif reference is None:
        c.add(False, "enclave identity (InferRoute's policy, index, encoders)",
              "NO REFERENCE SUPPLIED — this bundle proves a genuine Azure confidential container, NOT InferRoute's; "
              "obtain InferRoute's published reference out of band and rerun with --reference")
    else:
        # the manifest hashes come from the runtime data the hardware bound, never from the statement:
        # the question is what the ENCLAVE committed to, not what a record says about it
        idx, mdl = rd.get("index_manifest_sha256"), rd.get("model_manifest_sha256")
        pol_ok, pol_why = (_ref_match(_ref_entries(reference, "policy_sha256"), p["host_data"].hex(), at) if p is not None
                           else (False, "no report"))
        idx_ok, idx_why = _ref_match(_ref_entries(reference, "index_manifest_sha256"), idx, at) if rd else (False, "no runtime data")
        mdl_ok, mdl_why = _ref_match(_ref_entries(reference, "model_manifest_sha256"), mdl, at) if rd else (False, "no runtime data")
        c.add(pol_ok and idx_ok and mdl_ok, "enclave identity (InferRoute's policy, index, encoders)",
              f"policy: {pol_why}; index manifest: {idx_why}; encoder manifest: {mdl_why} — against reference "
              f"{reference.get('source') or '(unnamed)'} published {reference.get('published_at') or '?'}"
              # Only claim a time was tested when some entry actually carries a window. With none, every
              # match is current by default and "at the search's time X" reads as a check that did not
              # happen — flagged by an auditor on 25 Sep as decorative, which on this record it was.
              + (f", at the search's time {at}" if at and _ref_windowed(reference) else ""))



def verify_offer(offer: Dict[str, Any], *, pins: Optional[Dict[str, str]] = None, uvm_root: Optional[str] = None,
                 uvm_min_svn: int = UVM_MIN_SVN, reference: Optional[Dict[str, Any]] = None,
                 policy_b64: Optional[str] = None, at: Optional[str] = None,
                 min_tcb: Optional[Dict[str, Dict[str, int]]] = None) -> Checks:
    """Everything checkable about an enclave BEFORE anything is sealed to it — the check a live client must
    pass before it sends a word of the invention.

    It is the same hardware and identity code the bundled verifier runs after the fact, deliberately: if the
    live client and the record's verifier held two implementations, one could accept an enclave the other
    later rejects, and each would look correct on its own. The difference between them is only WHAT IS
    AVAILABLE — here there is no statement yet, so there is nothing to bind a query or a result to, and the
    reference's validity windows are asked about NOW rather than about a search's own time.

    Returns Checks; `Checks.failed` empty means every question that could be asked was answered yes. The
    caller must treat any failure as "do not seal" — a sealed query cannot be recalled.
    """
    c = Checks()
    rd: Dict[str, Any] = {}
    rd_bytes = b""
    try:
        rd_bytes = base64.b64decode((offer or {}).get("runtime_data", ""), validate=True)
        loaded = json.loads(rd_bytes)
        rd = loaded if isinstance(loaded, dict) else {}
        c.add(bool(rd), "runtime data present", f"{len(rd_bytes)} bytes of readable runtime data")
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "runtime data present", f"no readable runtime_data object in the offer ({type(exc).__name__})")

    # The keys we are about to trust with the invention: the enclave's X25519 key (what the query is sealed
    # to) and its statement signer. Both must be present, non-zero and hardware-bound — the binding is what
    # check_hardware establishes below, via REPORT_DATA over exactly these bytes.
    x_pub, signer = rd.get("enclave_x25519_pub"), rd.get("statement_signer_pub")
    c.add(_is_hex32(x_pub) and str(x_pub).lower() != ZERO32, "sealing key committed in runtime data",
          f"the query would be sealed to {str(x_pub)[:16]}…, which the hardware report commits to"
          if _is_hex32(x_pub) and str(x_pub).lower() != ZERO32
          else "the offer names no usable X25519 key — there is nothing safe to seal to")
    c.add(_is_hex32(signer) and str(signer).lower() != ZERO32, "signer key committed in runtime data",
          f"answers would be signed by {str(signer)[:16]}…" if _is_hex32(signer) and str(signer).lower() != ZERO32
          else "the offer names no usable statement signer key")

    for field, label in (("index_manifest_sha256", "index manifest names real bytes"),
                         ("model_manifest_sha256", "encoder manifest names real bytes")):
        v = rd.get(field)
        # Composed OUTSIDE the f-string: an expression that spans two lines inside one is a syntax error
        # before Python 3.12, and this file is the one artifact a third party is asked to run — on whatever
        # Python their firm happens to have.
        why = ("SHA-256 of nothing — a manifest built over NO files; it is the same for every "
               "index and cannot say which one runs" if str(v).lower() == EMPTY_SHA256
               else "missing, malformed or all zeros")
        c.add(_names_bytes(v), label,
              f"{str(v)[:16]}… identifies the files this enclave serves" if _names_bytes(v)
              else f"{field} is {why}")
    check_hardware(c, offer or {}, rd, rd_bytes, pins=pins or AMD_ARK_SPKI_SHA256,
                   uvm_root=uvm_root or MS_UVM_ROOT_SHA256_B64URL, uvm_min_svn=uvm_min_svn,
                   policy_b64=policy_b64, min_tcb=min_tcb)
    p = None
    try:
        p = parse_report(base64.b64decode((offer or {}).get("evidence", ""), validate=True))
    except Exception:                                       # noqa: BLE001
        p = None
    check_identity(c, rd, p, reference, at)
    return c


def verify_search(row: Dict[str, Any], evidence: Dict[str, Any], *, pins: Dict[str, str], uvm_root: str,
                  uvm_min_svn: int, matter_cutoff: Optional[int], reference: Optional[Dict[str, Any]],
                  min_tcb: Optional[Dict[str, Dict[str, int]]] = None) -> Checks:
    """All checks for one sealed search. `row` is the searches.json entry; `evidence` the bundle it names;
    `reference` the values obtained from InferRoute out of band (None = identity cannot be established)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    c = Checks()
    st = dict(row.get("statement") or {}) if isinstance(row.get("statement"), dict) else {}
    sig_hex = st.pop("sig", None)
    signer = row.get("signer_pub") if isinstance(row.get("signer_pub"), str) else ""

    # 1. statement signature — under the STATED signer; whether that signer is hardware-bound is check 2
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(sig_hex or ""), canonical(st))
        c.add(True, "statement signature", f"Ed25519 over the canonical statement verifies under {signer[:16]}…")
    except Exception:                                       # noqa: BLE001
        c.add(False, "statement signature", "does NOT verify under the stated signer key (or key/signature malformed)")

    # 2. runtime data and its commitments — these rows ALWAYS appear; a missing or malformed runtime data is a FAIL,
    #    never a silent absence, because an unbound signer is exactly what a forger would ship.
    offer = (evidence or {}).get("offer") if isinstance((evidence or {}).get("offer"), dict) else {}
    rd: Dict[str, Any] = {}
    rd_bytes = b""
    try:
        rd_bytes = base64.b64decode(offer["runtime_data"], validate=True)
        parsed = json.loads(rd_bytes)
        if not isinstance(parsed, dict):
            raise ValueError("runtime data is not a JSON object")
        rd = parsed
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "runtime data present", f"no readable runtime_data object in the evidence bundle ({type(exc).__name__})")
    rd_signer = rd.get("statement_signer_pub")
    c.add(bool(rd) and _is_hex32(rd_signer) and rd_signer.lower() != ZERO32 and rd_signer == signer,
          "signer key committed in runtime data",
          "the signing key is the one the hardware report binds" if rd and rd_signer == signer and _is_hex32(rd_signer) and rd_signer.lower() != ZERO32
          else ("runtime data carries no valid, non-zero statement_signer_pub" if not (_is_hex32(rd_signer) and str(rd_signer).lower() != ZERO32)
                else "the signing key is NOT the one in the runtime data"))
    c.add(bool(rd) and st.get("runtime_data_sha256") == sha256_hex(rd_bytes), "statement names this runtime data",
          f"runtime_data_sha256 {sha256_hex(rd_bytes)[:16]}…" if rd else "no runtime data to compare")
    idx, mdl = rd.get("index_manifest_sha256"), rd.get("model_manifest_sha256")
    commits_ok = (bool(rd) and _names_bytes(idx) and _names_bytes(mdl)
                  and st.get("lifetime_id") == rd.get("lifetime_id") and st.get("index_manifest_sha256") == idx
                  and st.get("model_manifest_sha256") == mdl)
    c.add(commits_ok, "statement matches enclave commitments",
          f"lifetime {str(rd.get('lifetime_id'))[:12]}…, index manifest {str(idx)[:12]}…, encoders {str(mdl)[:12]}… (all non-zero)"
          if commits_ok else "lifetime / index manifest / encoder manifest are missing, zero, EMPTY (a manifest of no "
                                 "files), or differ from the statement")

    # 3-4. hardware and identity, asked by the same code the live client asks them with. `at` is this
    # statement's own time: a reference entry's window must have been current WHEN THE SEARCH RAN, not now.
    at = st.get("started_utc") if isinstance(st.get("started_utc"), str) else None
    p = check_hardware(c, offer, rd, rd_bytes, pins=pins, uvm_root=uvm_root, uvm_min_svn=uvm_min_svn,
                       policy_b64=(evidence or {}).get("policy_b64"), min_tcb=min_tcb)
    check_identity(c, rd, p, reference, at)

    # 5. content bindings — what this operation was, and that the record shows exactly what was signed.
    rid = str(st.get("request_id") or "")
    check_recipient(c, st, row)
    if str(st.get("kind") or "search") == "document":
        check_document(c, st, row, rid)
    else:
        check_search_content(c, st, row, rid)
    # The enclave-SIGNED cutoff is the fact; the MANIFEST's is the record's unsigned claim about the matter.
    if matter_cutoff is not None:
        c.add(st.get("cutoff_date") == matter_cutoff, "date bound the enclave was given",
              f"signed statement cutoff_date {st.get('cutoff_date')}; the record claims the matter's date bound was {matter_cutoff} "
              "(consistency with an unsigned value — the signed number is the fact)")
    else:
        c.add(None, "date bound the enclave was given", f"signed statement cutoff_date {st.get('cutoff_date')}; the record states no matter date bound")
    check_filters_applied(c, st)
    return c


# Every filter the enclave accepts, and the report it makes about applying it. A signed statement that
# carries only the filter's INPUT attests configuration, never enforcement: on 2026-09-19 an auditor read
# "date bound" as an enforcement claim when nothing enforced was attested, and on 2026-09-20 a jurisdiction
# filter was found to match nothing while a statement would have said the search was restricted to it. Same
# class, so one rule rather than a privileged case for the date.
FILTERS = (("cutoff_date", "cutoff_applied", "removed_by_cutoff", "date bound"),
           ("from_date", "from_date_applied", "removed_by_from_date", "from-date bound"),
           ("offices", "offices_applied", "removed_by_offices", "offices"))


def check_filters_applied(c: Checks, st: Dict[str, Any]) -> None:
    """The enclave's own signed account of what each filter DID, checked for consistency with what it was
    given. This is not proof of enforcement — enforcement is behaviour, and no attestation of what ran can
    establish it. It is the difference between a filter that reports its work and one that is silent.

    Absent or null is a SKIP, never a failure: records made before an enclave reported this must not rot,
    and an enclave that simply was not asked for a filter has nothing to report.
    """
    for given_key, applied_key, removed_key, label in FILTERS:
        given, applied = st.get(given_key), st.get(applied_key)
        if applied in (None, {}, []):
            if given in (None, "", [], "None"):
                continue                        # filter not requested, nothing reported: nothing to say
            c.add(None, f"{label} was applied",
                  f"this enclave reports only the {label} it was GIVEN ({given!r}), not what applying it did; "
                  "enforcement is unattested here")
            continue
        if not isinstance(applied, dict):
            c.add(False, f"{label} was applied", f"{applied_key} is not an object: {type(applied).__name__}")
            continue
        reported = applied.get(given_key)
        if given in (None, "", [], "None"):
            c.add(False, f"{label} was applied",
                  f"the enclave reports applying {label} {reported!r} that this statement never asked for")
            continue
        considered, removed = applied.get("candidates_considered"), applied.get(removed_key)
        same = reported == given
        detail = (f"{label} {reported!r} as signed; {removed} of {considered} candidate(s) removed by it"
                  if same else f"applied {label} {reported!r} is NOT the {label} signed in the statement ({given!r})")
        if same and removed == 0:
            # A real 0 is the common case and must not read as "the filter did nothing" (sealed-research,
            # 20 Sep): it means no candidate fell outside the bound.
            detail += " — no candidate fell outside it, which is not the same as the filter not running"
        c.add(same, f"{label} was applied", detail)
    # k needs no report of its own: the statement carries both k and hits_n, so the applied-k check is
    # arithmetic on what is already signed.
    k, hits = st.get("k"), st.get("hits_n")
    if isinstance(k, int) and isinstance(hits, int):
        c.add(hits <= k, "at most k results", f"{hits} hit(s) against k={k}"
              if hits <= k else f"{hits} hit(s) exceeds the k={k} this statement asked for")


def check_recipient(c: Checks, st: Dict[str, Any], row: Dict[str, Any]) -> None:
    """Compare the enclave-signed recipient hash with the public key recorded in the search row.

    A match binds the signed destination to that recorded key. It does not prove that the key was the only
    destination, rule out another copy or disclosure channel, or independently establish how the key was
    created or used. Statements from before the field existed get a SKIP that says what is unchecked."""
    rt, want = st.get("reply_to_sha256"), row.get("reply_to")
    if rt is None:
        c.add(None, "signed recipient matches recorded key",
              "this statement predates the signed recipient key; nothing here rules out a second recipient")
    elif not isinstance(want, str) or not want:
        c.add(None, "signed recipient matches recorded key",
              "the statement names a recipient but the record kept no reply key to compare it against")
    else:
        try:
            same = sha256_hex(bytes.fromhex(want)) == rt
        except ValueError:
            same = False
        c.add(same, "signed recipient matches recorded key",
              ("the signed hash matches the public key recorded in this search row; this does not rule out "
               "another copy or disclosure channel, or prove how that key was created or used")
              if same else "the signed recipient is NOT the key this record says was used")


def check_search_content(c: Checks, st: Dict[str, Any], row: Dict[str, Any], rid: str) -> None:
    q = row.get("query_text")
    if isinstance(q, str):
        ok = salted(rid, q) == st.get("query_sha256")
        c.add(ok, "query text is the one searched", "SHA-256(request_id ‖ canonical(query)) == query_sha256" if ok else "query text does NOT match query_sha256")
    else:
        c.add(None, "query text is the one searched", "query text not in bundle; query_sha256 cannot be opened")
    res = row.get("result")
    if isinstance(res, dict):
        ok = salted(rid, res) == st.get("result_sha256")
        c.add(ok, "result is the signed result", "SHA-256(request_id ‖ canonical(result)) == result_sha256" if ok else "result does NOT match result_sha256")
        c.add(len(res.get("hits") or []) == st.get("hits_n"), "hit count as signed", f"{len(res.get('hits') or [])} hits, statement says {st.get('hits_n')}")
    else:
        c.add(None, "result is the signed result", "opened result not in bundle")


def _as_yyyymmdd(value: Any) -> Optional[int]:
    """A date as the enclave may state it: 20180417, "20180417" or "2018-04-17"."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 19000101 <= value <= 20991231 else None
    if isinstance(value, str):
        digits = value.replace("-", "")
        if digits.isdigit() and len(digits) == 8:
            return _as_yyyymmdd(int(digits))
    return None


def check_document(c: Checks, st: Dict[str, Any], row: Dict[str, Any], rid: str) -> None:
    """A document read: the enclave returns the text it holds for one publication number and signs the text,
    the number, how much of the document it held, and the publication date."""
    text = row.get("text")
    if isinstance(text, str):
        ok = salted(rid, text) == st.get("text_sha256")
        c.add(ok, "document text is the one signed",
              "SHA-256(request_id ‖ canonical(text)) == text_sha256" if ok else "the text shown does NOT match text_sha256")
    else:
        c.add(None, "document text is the one signed", "the document's text is not in the bundle; text_sha256 cannot be opened")
    signed_key, shown_key = st.get("key"), row.get("key")
    cov = st.get("coverage") if isinstance(st.get("coverage"), dict) else {}
    held = "; ".join(f"{k}: {v}" for k, v in sorted(cov.items())) or "not stated"
    if shown_key is not None and shown_key != signed_key:
        c.add(False, "document is the one signed", f"the record shows {shown_key}, the enclave signed {signed_key}")
    else:
        c.add(bool(signed_key), "document is the one signed",
              f"{signed_key or '(the statement names no document)'}, published {st.get('publication_date') or 'date not stated'} — "
              f"the enclave signed that it held {held}")
    # THE MATTER'S DATE BOUND APPLIES TO A READ, not only to a search. The enclave refuses a read of art
    # published on or after the bound; the record must fail if one ever got through, or the bound would hold
    # only while someone was watching.
    pub, cut = _as_yyyymmdd(st.get("publication_date")), _as_yyyymmdd(st.get("cutoff_date"))
    if pub is None or cut is None:
        c.add(None, "the document predates the date bound",
              f"publication date {st.get('publication_date')!r} or date bound {st.get('cutoff_date')!r} is not a date this can compare")
    else:
        c.add(pub < cut, "the document predates the date bound",
              f"published {pub}, before the matter's bound {cut}" if pub < cut
              else f"published {pub}, NOT before the matter's bound {cut} — this read went outside the matter's date bound")


# ───────────────────────────── bundle-level ─────────────────────────────


def check_manifest(bundle_dir: str) -> Tuple[Checks, Dict[str, Any]]:
    """MANIFEST.json is an INDEX, not a seal (it is unsigned). It lets a reader detect a file changed after
    export; it cannot prove the export was honest. Membership is enforced both ways: every required file must
    be listed and present, and every file present must be listed."""
    c = Checks()
    mp = os.path.join(bundle_dir, "MANIFEST.json")
    try:
        manifest = json.load(open(mp))
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "MANIFEST.json", f"missing or unreadable ({type(exc).__name__})")
        return c, {}
    listed = manifest.get("files") or {}
    bad, missing = [], [f for f in REQUIRED_FILES if f not in listed]
    for name, want in listed.items():
        try:
            got = sha256_hex(open(os.path.join(bundle_dir, name), "rb").read())
        except OSError:
            bad.append(f"{name} (missing)")
            continue
        if got != want:
            bad.append(name)
    present = {n for n in os.listdir(bundle_dir) if os.path.isfile(os.path.join(bundle_dir, n))}
    unlisted = sorted(present - set(listed) - UNLISTED_OK)
    ok = not bad and not missing and not unlisted
    c.add(ok, "bundle integrity (MANIFEST is an index, not a seal)",
          f"{len(listed)} files match MANIFEST.json; all required files listed; no unlisted files" if ok
          else f"MISMATCH {bad}; required-but-unlisted {missing}; present-but-unlisted {unlisted}")
    return c, manifest


def extract(bundle_dir: str, out_dir: str, searches: List[Dict[str, Any]]) -> None:
    """Write each search's raw evidence as files for independent tools (snpguest, go-sev-guest, go-cose…)."""
    os.makedirs(out_dir, exist_ok=True)
    for i, row in enumerate(searches, 1):
        ef = row.get("evidence_file")
        if not ef:
            continue
        try:
            ev = json.load(open(os.path.join(bundle_dir, ef)))
        except Exception:                                   # noqa: BLE001
            continue
        offer = ev.get("offer") or {}
        d = os.path.join(out_dir, f"search-{i}")
        os.makedirs(d, exist_ok=True)
        try:
            open(os.path.join(d, "report.bin"), "wb").write(base64.b64decode(offer.get("evidence", ""), validate=True))
            certs = load_certs(base64.b64decode(offer.get("endorsements", ""), validate=True))
            from cryptography.hazmat.primitives import serialization
            open(os.path.join(d, "vcek.pem"), "wb").write(certs[0].public_bytes(serialization.Encoding.PEM))
            open(os.path.join(d, "ask_ark.pem"), "wb").write(b"".join(x.public_bytes(serialization.Encoding.PEM) for x in certs[1:]))
            open(os.path.join(d, "uvm_endorsement.cose"), "wb").write(base64.b64decode(offer.get("uvm_endorsements", ""), validate=True))
            open(os.path.join(d, "runtime_data.json"), "wb").write(base64.b64decode(offer.get("runtime_data", ""), validate=True))
            if ev.get("policy_b64"):
                open(os.path.join(d, "policy.rego"), "wb").write(base64.b64decode(ev["policy_b64"]))
            open(os.path.join(d, "statement.json"), "w").write(json.dumps(row.get("statement"), indent=1, sort_keys=True))
        except Exception as exc:                            # noqa: BLE001
            open(os.path.join(d, "EXTRACT-FAILED.txt"), "w").write(f"{type(exc).__name__}: {exc}\n")
    print(f"extracted raw evidence under {out_dir}/search-N/ (report.bin, vcek.pem, ask_ark.pem, uvm_endorsement.cose, runtime_data.json, policy.rego, statement.json)")


def _parse_min_tcb(items: List[str]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for it in items:
        product, _, spec = it.partition("=")
        floor: Dict[str, int] = {}
        for kv in spec.split(","):
            k, _, v = kv.partition(":")
            if k and v.isdigit():
                floor[k] = int(v)
        out[product] = floor
    return out


def main(argv: Optional[List[str]] = None) -> int:
    """Exit codes: 0 every check passed under production roots; 1 one or more checks failed (or nothing to
    verify); 2 usage / refused; 3 every check passed but under TEST roots (never a verification of Azure);
    4 every check passed, but the reference was signed and no --reference-key was given, so the identity
    rests on a file nobody authenticated."""
    import argparse
    class _Parser(argparse.ArgumentParser):
        """argparse cannot tell a VALUE that starts with "-" from a flag, and several of the values here can:
        a base64url fingerprint begins with a hyphen about 1.3% of the time (measured by sealed-research: 51
        of 4,000). The user then sees "expected one argument" and has no idea why a correct paste failed.
        Say what to do instead — the equals form is the only shape immune to it."""

        def error(self, message: str) -> None:                  # type: ignore[override]
            if "expected one argument" in message:
                message += ("\n\nIf the value you pasted starts with '-' (base64url fingerprints often do), "
                            "attach it with '=' so it cannot be read as a flag:\n"
                            "    --uvm-root=VALUE      --reference-key=VALUE      --amd-pin=PRODUCT:VALUE")
            super().error(message)

    ap = _Parser(description="Independently verify an attested prior-art record bundle.")
    ap.add_argument("bundle", help="the export directory (record.html, searches.json, MANIFEST.json, *.evidence.json)")
    ap.add_argument("--reference", default=None, metavar="FILE",
                    help="InferRoute's published reference (policy_sha256, index_manifest_sha256, model_manifest_sha256), obtained OUT OF BAND; without it identity FAILS")
    ap.add_argument("--reference-key", default=None, metavar="ED25519_PUB_HEX",
                    help="InferRoute's long-lived publication key, recorded at first use; verifies the reference file's signature")
    ap.add_argument("--min-tcb", action="append", default=[], metavar="PRODUCT=snpSPL:N,ucodeSPL:N",
                    help="minimum firmware TCB per product line (same shape as the UVM SVN floor)")
    ap.add_argument("--extract", default=None, metavar="DIR", help="also write each search's raw evidence as files for independent tools")
    ap.add_argument("--amd-pin", action="append", default=[], metavar="PRODUCT=SPKI_SHA256_HEX", help="TEST ROOTS ONLY; requires --i-am-testing")
    ap.add_argument("--check-revocation", action="store_true",
                    help="also ask AMD whether the chip certificates are revoked (needs network; off by default "
                         "so an offline run stays deterministic)")
    ap.add_argument("--uvm-root", default=None, help="TEST ROOTS ONLY; requires --i-am-testing")
    ap.add_argument("--uvm-min-svn", type=int, default=UVM_MIN_SVN)
    ap.add_argument("--i-am-testing", action="store_true", help="acknowledge that pin overrides make this a TEST run, never a verification of Azure (exit 3 at best)")
    a = ap.parse_args(argv)

    try:
        import cryptography
        major = int(str(cryptography.__version__).split(".")[0])
    except Exception:                                       # noqa: BLE001
        print("REFUSED: the `cryptography` package is required (pip install cryptography>=42)")
        return 2
    if major < MIN_CRYPTOGRAPHY:
        print(f"REFUSED: cryptography {cryptography.__version__} is too old; this verifier needs >= {MIN_CRYPTOGRAPHY} (pip install -U cryptography). Not a verdict on the record.")
        return 2

    test_roots = bool(a.amd_pin) or a.uvm_root is not None
    if test_roots and not a.i_am_testing:
        print("REFUSED: --amd-pin / --uvm-root replace the production roots; a run with them can never verify an Azure record. "
              "Add --i-am-testing if that is what you mean (the exit code will then be 3, not 0).")
        return 2
    pins = dict(AMD_ARK_SPKI_SHA256)
    for kv in a.amd_pin:
        k, _, v = kv.partition("=")
        pins[k] = v.lower()
    uvm_root = a.uvm_root or MS_UVM_ROOT_SHA256_B64URL
    reference = None
    if a.reference:
        try:
            reference = json.load(open(a.reference))
            if not isinstance(reference, dict):
                raise ValueError("not an object")
        except Exception as exc:                            # noqa: BLE001
            print(f"REFUSED: --reference {a.reference} unreadable ({type(exc).__name__})")
            return 2

    print(f"Attested prior-art record: {os.path.abspath(a.bundle)}")
    print("Trust model: two root pins (AMD ARK per product line, Microsoft Supply Chain RSA Root CA 2022) plus signature links. "
          + ("Revocation: AMD's ARK-signed CRL is fetched and the ASK checked against it (--check-revocation). "
             if a.check_revocation else "No revocation checking (pass --check-revocation to fetch AMD's CRL). ")
          + "No basicConstraints / keyUsage / path-length validation. Identity comes only from --reference.")
    if test_roots:
        print("!!! NON-PRODUCTION ROOTS PINNED (--i-am-testing): this run verifies a TEST enclave, never Azure. Exit code 3 at best. !!!")
    c0, manifest = check_manifest(a.bundle)
    # Looked up unconditionally. Deriving these only when a reference was supplied made the row say "no
    # attestation in this folder" for a folder that plainly contained one — absence and not-having-looked
    # wearing the same words. What is on disk does not depend on which flags were passed.
    _att = os.path.join(a.bundle, "trust-anchors", "publication-key-attestation.json")
    _bun = os.path.join(a.bundle, "trust-anchors", "publication-key-attestation.bundle")
    _att_paths = (_bun if os.path.isfile(_bun) else None,
                  _att if os.path.isfile(_att) else None)
    if reference is not None:
        check_reference_signature(c0, reference, a.reference_key)
    c0.dump()
    fails = len(c0.failed)
    try:
        searches = json.load(open(os.path.join(a.bundle, "searches.json")))
        if not isinstance(searches, list):
            raise ValueError("not a list")
    except Exception as exc:                                # noqa: BLE001
        print(f"  FAIL searches.json: missing or unreadable ({type(exc).__name__})")
        return 1
    cutoff = manifest.get("matter_cutoff") if isinstance(manifest.get("matter_cutoff"), int) else None
    min_tcb = _parse_min_tcb(a.min_tcb)
    # A firmware floor may also travel IN the reference, so a firm does not have to know SPL numbers to hold
    # one. A floor given on the command line wins, and a reference that pins none leaves the check a SKIP.
    if not min_tcb and isinstance(reference, dict) and isinstance(reference.get("min_tcb"), dict):
        from_ref = {str(product): {str(k): int(v) for k, v in levels.items() if isinstance(v, int)}
                    for product, levels in reference["min_tcb"].items() if isinstance(levels, dict)}
        min_tcb = {p: lv for p, lv in from_ref.items() if lv}
    listed = set((manifest.get("files") or {}).keys())
    # A record can legitimately hold no search and still hold evidence: the sealed SESSION with the AI
    # machine (AUDIT.md claim 7). Such a pack became producible on 23 Sep, which made this branch reachable
    # in normal use for the first time. It must still not PASS -- an empty record must never be passed off
    # as verified -- but "FAILED" is read as "the evidence is bad", and the truth is that no search was run.
    absent_searches = False
    try:
        in_folder = sorted(n for n in os.listdir(a.bundle)
                           if n.startswith("session-") and n.endswith(".receipt.json"))
    except OSError:
        in_folder = []
    if not searches:
        absent_searches = True
        if in_folder:
            print("  FAIL sealed searches: this record contains NO sealed search, so this program verified "
                  "nothing about searching. That is an ABSENCE -- no search was run for this matter -- not a "
                  "defect in the evidence. It is still not a pass.")
            print(f"  NOTE sealed session: {len(in_folder)} session receipt(s) present "
                  f"({', '.join(in_folder)}). This program does NOT verify them: they are the professional's "
                  "own device reporting on the AI machine. Audit them by hand -- see claim 7 in AUDIT.md.")
        else:
            print("  FAIL sealed searches: this record contains NO sealed search — there is nothing to verify")
        fails += 1
    seen_policies: Dict[str, str] = {}
    seen_chains: Dict[Tuple[str, bytes], Tuple[str, Any, Any]] = {}
    seen_host_data: set = set()
    firmware_floor_results: List[bool] = []
    for i, row in enumerate(searches, 1):
        if not isinstance(row, dict):
            print(f"\nSearch {i}: FAIL malformed row")
            fails += 1
            continue
        print(f"\nSearch {i} — session {row.get('session_id')}, recorded {row.get('at')}")
        ev: Dict[str, Any] = {}
        ef = row.get("evidence_file")
        if ef:
            if ef not in listed:
                print(f"  FAIL evidence file: {ef} is not listed in MANIFEST.json")
                fails += 1
            try:
                raw = open(os.path.join(a.bundle, ef), "rb").read()
                if row.get("evidence_sha256") and sha256_hex(raw) != row["evidence_sha256"]:
                    print(f"  FAIL evidence file: {ef} sha256 does not match searches.json")
                    fails += 1
                loaded = json.loads(raw)
                ev = loaded if isinstance(loaded, dict) else {}
            except Exception as exc:                        # noqa: BLE001
                print(f"  FAIL evidence file: {ef} unreadable ({type(exc).__name__})")
                fails += 1
        else:
            print("  FAIL evidence file: none named for this search")
            fails += 1
        try:
            # Keyed on the ASK's own bytes, never on a serial: AMD issues every VCEK with serial 0, so a
            # serial is not an identity here and deduplicating on one silently collapses the whole record
            # to a single certificate. An earlier version of this did, and reported "1 distinct VCEK" for
            # a record spanning two chips.
            _rep = base64.b64decode((ev.get("offer") or {}).get("evidence", ""), validate=True)
            if len(_rep) == REPORT_LEN:
                seen_host_data.add(parse_report(_rep)["host_data"].hex())
        except Exception:                                   # noqa: BLE001 — the report is checked per search
            pass
        try:
            _certs = load_certs(base64.b64decode((ev.get("offer") or {}).get("endorsements", ""), validate=True))
            _prod = (_der_ia5(_ext(_certs[0], OID_PRODUCT)) or "").split("-", 1)[0]
            _ask = next((x for x in _certs[1:] if _cn(x) == f"SEV-{_prod}"), None)
            _ark = next((x for x in _certs[1:] if _cn(x) == f"ARK-{_prod}"), None)
            if _prod and _ask is not None and _ark is not None:
                seen_chains.setdefault((_prod, _ask.tbs_certificate_bytes), (_prod, _ask, _ark))
        except Exception:                                   # noqa: BLE001 — the chain is checked per search above
            pass
        if ev.get("policy_b64"):
            try:
                _hd = sha256_hex(base64.b64decode(ev["policy_b64"]))
                if _hd not in seen_policies:
                    seen_policies[_hd] = ev["policy_b64"]
            except Exception:                               # noqa: BLE001 — a malformed policy is reported by the row below
                pass
        try:
            c = verify_search(row, ev, pins=pins, uvm_root=uvm_root, uvm_min_svn=a.uvm_min_svn, matter_cutoff=cutoff,
                              reference=reference, min_tcb=min_tcb)
        except Exception as exc:                            # noqa: BLE001 — a crash must read as a refusal, not a traceback
            print(f"  FAIL verifier error on this search: {type(exc).__name__}: {exc}")
            fails += 1
            continue
        c.dump()
        fails += len(c.failed)
        firmware_floor_results.append(any(status == "PASS" and name == "firmware TCB at or above minimum"
                                          for status, name, _ in c.rows))
    if searches:
        cc = Checks()
        check_key_attestation(cc, _att_paths[0], _att_paths[1], a.reference_key)
        # Read only if the manifest listed it — an attacker-supplied side file must not be able to narrate a
        # gap it created. Membership is already enforced both ways, so an unlisted unanswered.json fails the
        # bundle before we get here.
        unanswered = None
        up = os.path.join(a.bundle, "unanswered.json")
        if os.path.exists(up):
            try:
                loaded = json.load(open(up))
                unanswered = loaded if isinstance(loaded, list) else None
            except (OSError, ValueError):
                unanswered = None
        check_completeness(cc, [r for r in searches if isinstance(r, dict)], unanswered)
        if cc.rows:
            print("\nRecord")
            cc.dump()
            fails += len(cc.failed)
    if a.extract:
        extract(a.bundle, a.extract, [r for r in searches if isinstance(r, dict)])
    revocation_failed = False
    if searches and a.check_revocation:
        rc_checks = Checks()
        revocation_ok = check_revocation(rc_checks, list(seen_chains.values()))
        rc_checks.dump()
        revocation_failed = not revocation_ok
        fails += len(rc_checks.failed)
    print()
    if fails == 1 and absent_searches:
        print("RESULT: NOTHING VERIFIED — this record contains no sealed search, so there was nothing for "
              "this program to check. Not a pass, and not a finding against the evidence.")
    elif fails:
        print(f"RESULT: FAILED — {fails} check(s) did not pass; see FAIL lines above")
    elif test_roots:
        print("RESULT: no failing record checks UNDER TEST ROOTS — this is not a verification of an Azure enclave (exit 3)")
    else:
        if isinstance(reference, dict) and reference.get("sig") and not a.reference_key:
            print("RESULT: no failing record checks, but this reference was NOT authenticated (exit 4); SKIP rows remain unverified")
            print("        The identity above was checked against a signed file nobody verified. Obtain InferRoute's "
                  "publication key from your engagement letter and pass --reference-key to close this.")
        else:
            print("RESULT: no failing record checks under production roots; SKIP rows remain unverified" + ("" if reference else " — but identity FAILED above"))
    print("Completeness: with sequence numbers the record shows every search of each enclave SHOWN, in order — not that every enclave is shown, "
          "and not a search dropped from the very end of a lifetime; without them, only what it shows.")
    print("Not redone here: confinement of the machine that made this record (self-reported); fetching anything"
          + ("" if a.check_revocation else "; certificate revocation") + ".")
    if searches:
        report_confidentiality(
            [(hd, pol) for hd, pol in seen_policies.items()],
            reference=reference,
            floor_pinned=(len(firmware_floor_results) == len(searches) and all(firmware_floor_results)),
            revocation_checked=bool(a.check_revocation and not revocation_failed),
            # An unsigned reference remains usable as manually supplied expected measurements, but
            # this program has not authenticated its provenance. A supplied key alone proves nothing;
            # the signature must exist and the earlier signature check must pass (record_ok below).
            authenticated=bool(isinstance(reference, dict) and reference.get("sig") and a.reference_key),
            record_ok=(fails == 0),
            committed=seen_host_data,
            production_roots=not test_roots)
    # A reference that is signed but was checked against no key: every other line can pass, and the identity
    # still rests on a file nobody authenticated. That is not a clean verification, and the exit code has to
    # say so — a reader who only reads the number would otherwise be told the strongest verdict.
    unauthenticated = bool(isinstance(reference, dict) and reference.get("sig") and not a.reference_key)
    if fails:
        return 1
    if test_roots:
        return 3
    return 4 if unauthenticated else 0


if __name__ == "__main__":
    sys.exit(main())
