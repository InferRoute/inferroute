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
  recipient the enclave's signed reply_to_sha256 == SHA-256(the one-time public key this machine made for
            that search), so the result went to that address and no second copy was sealed to anyone else

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
UNLISTED_OK = {"MANIFEST.json", "MANIFEST.json.ots", "SHA256SUMS"}
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
        c.add(True, "reference signature", f"verifies under the publication key {key_hex[:16]}… that you supplied "
              "(whether it was recorded at first use is yours to attest, not this program's)")
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
    #     all the others by construction. Measured on this machine the same day: 37 of seq 1..65 carried,
    #     28 absent, all of them other matters. Leading with "another client" invites a solo practitioner
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
              + (f", at the search's time {at}" if at else ""))



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
    """WHO ELSE COULD OPEN IT. The enclave signs the recipient key; the user's own proxy recorded the key
    it made. Equal, and the answer went to that one address: a copy sealed to anyone else would have a
    different signed recipient. This is the difference between "only you can open it" as our word and as your
    arithmetic. Statements from before the field existed get a SKIP that says what is therefore unchecked —
    an absent check must never read as a passed one."""
    rt, want = st.get("reply_to_sha256"), row.get("reply_to")
    if rt is None:
        c.add(None, "sealed to one recipient",
              "this statement predates the signed recipient key; nothing here rules out a second recipient")
    elif not isinstance(want, str) or not want:
        c.add(None, "sealed to one recipient",
              "the statement names a recipient but the record kept no reply key to compare it against")
    else:
        try:
            same = sha256_hex(bytes.fromhex(want)) == rt
        except ValueError:
            same = False
        c.add(same, "sealed to one recipient",
              "the signed recipient is the one-time key this machine made for this operation — no second copy"
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
          "No revocation checking; no basicConstraints / keyUsage / path-length validation. Identity comes only from --reference.")
    if test_roots:
        print("!!! NON-PRODUCTION ROOTS PINNED (--i-am-testing): this run verifies a TEST enclave, never Azure. Exit code 3 at best. !!!")
    c0, manifest = check_manifest(a.bundle)
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
            c = verify_search(row, ev, pins=pins, uvm_root=uvm_root, uvm_min_svn=a.uvm_min_svn, matter_cutoff=cutoff,
                              reference=reference, min_tcb=min_tcb)
        except Exception as exc:                            # noqa: BLE001 — a crash must read as a refusal, not a traceback
            print(f"  FAIL verifier error on this search: {type(exc).__name__}: {exc}")
            fails += 1
            continue
        c.dump()
        fails += len(c.failed)
    if searches:
        cc = Checks()
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
    print()
    if fails == 1 and absent_searches:
        print("RESULT: NOTHING VERIFIED — this record contains no sealed search, so there was nothing for "
              "this program to check. Not a pass, and not a finding against the evidence.")
    elif fails:
        print(f"RESULT: FAILED — {fails} check(s) did not pass; see FAIL lines above")
    elif test_roots:
        print("RESULT: all checks passed UNDER TEST ROOTS — this is not a verification of an Azure enclave (exit 3)")
    else:
        if isinstance(reference, dict) and reference.get("sig") and not a.reference_key:
            print("RESULT: every check PASSED, but this reference was NOT authenticated (exit 4)")
            print("        The identity above was checked against a signed file nobody verified. Obtain InferRoute's "
                  "publication key from your engagement letter and pass --reference-key to close this.")
        else:
            print("RESULT: every check PASSED under production roots" + ("" if reference else " — but identity FAILED above"))
    print("Completeness: with sequence numbers the record shows every search of each enclave SHOWN, in order — not that every enclave is shown, "
          "and not a search dropped from the very end of a lifetime; without them, only what it shows.")
    print("Not redone here: confinement of the machine that made this record (self-reported); fetching anything; certificate revocation.")
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
