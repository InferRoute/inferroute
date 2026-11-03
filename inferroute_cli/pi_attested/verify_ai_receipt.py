#!/usr/bin/env python3
"""Re-check an AI-session receipt OFFLINE, from the record alone.

The receipt (`session-<id>.receipt.json` in an exported record, or `~/.inferroute/confidential/receipts/*.json`)
is the professional's own device reporting what it checked about the AI machine before sealing text to it.
Until now that was where it stopped: `verify_record.py` printed "AI receipts are NOT VERIFIED here" and left
the reader to take the device's word. This program recomputes, from the bytes the receipt carries, every
check the device says it made that CAN be recomputed, and says plainly which cannot.

Stdlib + `cryptography` only, like verify_record.py; no network; nothing imported from `ir`. It is shipped
inside the record beside verify_record.py, which calls it when present and prints its rows as an OPTIONAL
section that changes neither verify_record's exit code nor its confidentiality statements.

What is recomputed here, per machine that served (the receipt keeps one evidence row per machine):

  evidence row      the content-addressed attestation file is the one the receipt names (sha256), and the
                    receipt's own `attestation` is the last machine's row
  signed quote      the TDX quote checked is the one INSIDE the enclave-signed body, equal to the loose copy
  challenge         the device's nonce (recorded under `checked_with`) appears verbatim in the signed body
  signature         the body's signature verifies under the certificate the evidence names
  TDX shape         quote v4, tee_type 0x81, TD DEBUG attribute clear
  SPKI binding      report_data[32:64] == SHA-256(SubjectPublicKeyInfo of that certificate)
  key binding       report_data[0:32]  == SHA-256(nonce ‖ the ML-KEM key the device sealed to)
  PCK chain         three certificates, Intel's names, links verify, root public key == pinned Intel SGX Root CA,
                    all valid at the session's time
  quote signature   QE report signed by the PCK key; QE REPORTDATA binds the attestation key; the quote's
                    ECDSA-P256 signature verifies under it
  recorded build    MRTD + RTMR1-3 is a build InferRoute ships in this file (RECORDED_BUILDS, a copy of the
                    client's bundled list), or a run-time row signed by InferRoute's offline key (pinned here)
  Intel collateral  the TCB info and QE identity the device fetched are Intel-signed under the pinned root,
                    were within their validity window at the session's time; the CRLs verify and list nothing
                    in the chain; the platform's TCB status and the Quoting Enclave's status are acceptable
  GPU evidence      the per-GPU reports NVIDIA judged are the ones INSIDE the signed body; each GPU's
                    certificate chain ends in the pinned NVIDIA Device Identity CA
  NVIDIA verdict    the EAT tokens (overall and per GPU) are signed by a key whose x5c chain ends in a pinned
                    NVIDIA Attestation Service intermediate; the tokens name this session's challenge; the
                    overall result is true; per GPU: report parsed/signed/chain-validated/nonce-matched, driver
                    and VBIOS reference manifests fetched, signed and matching, secure boot on, debug off

and per receipt: every machine the events say was pinned has an evidence row; the switch counter agrees
with the pins; requests credited per machine cover the request counter; the searches the record attributes
to this session fall inside the window in which a verified machine was pinned; the timeline is consistent.

What is NOT recomputed, and stays the device's word (printed as SKIP, never PASS):
  * that the requests were sealed to that key and sent — the receipt counts them; nothing signed by the
    machine says "this reply answered that sealed request" (the operator's protocol has no such receipt);
  * what the machine's software did with the text after decrypting it (the measured image does not cover
    the code the model is served with; the receipt's own limitations say so);
  * the GPUs' confidential-computing mode: NVIDIA's verdict carries no such claim;
  * anything a receipt written by a client older than 0.9.126 did not keep: Intel's collateral and NVIDIA's
    tokens were checked online at the time and are not in such a receipt.

Rows are PASS / FAIL / SKIP, in the shape of verify_record.py's Checks. Missing evidence is never a PASS.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "inferroute.confidential.receipt/1"
MIN_CRYPTOGRAPHY = 42

# ───────────────────────── pins (the trust roots this program ships) ─────────────────────────
#
# Intel SGX Root CA — SHA-256 of its SubjectPublicKeyInfo, from
# https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem (2026-09-12).
INTEL_SGX_ROOT_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
# NVIDIA Device Identity CA — the self-signed root every GPU's identity chain ends in. SHA-256 of its SPKI,
# equal to nvtrust's shipped `verifier_device_root.pem`
# (github.com/NVIDIA/nvtrust, guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs, read 2026-11-02)
# and to the root inside live GH100 evidence the same day.
NVIDIA_DEVICE_ROOT_SPKI_SHA256 = "a90c4eb5acfd3e3d03a25db6a26b84f720ad0503196c627c21ddd48dd85b06a4"
# NVIDIA Attestation Service signing intermediates — the last certificate of the x5c chain NVIDIA publishes
# at https://nras.attestation.nvidia.com/.well-known/jwks.json for each short-lived EAT signing key (read
# 2026-11-02: 208 keys, two intermediates, both issued by "NVIDIA Attestation Service CA 001", which NVIDIA
# does not publish in the JWKS, so the pin stops at the intermediates). A token signed under a key that
# chains to neither FAILS here; add the next intermediate when NVIDIA rotates, as a deliberate edit.
NVIDIA_NRAS_SIGNING_SPKI_SHA256 = {
    "fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896": "NVIDIA Attestation Service GPU Intermediate 004 (valid 2025-12-08 → 2029-12-08)",
    "ba14d00377699189b6762c22c744a9dbdc62aa9396097ada7150426c6ff39afc": "NVIDIA Attestation Service GPU Intermediate 005 (valid 2026-10-08 → 2030-10-08)",
}
# InferRoute's offline publication key (Ed25519, hex), which signs run-time build rows. A copy of
# inferroute_local/confidential/builds.py SIGNING_KEYS; a test keeps the two equal.
SIGNING_KEYS: Tuple[str, ...] = (
    "748e4c8e4ca334c5f804ffcdbd85f2dca29713e71c1c7c9c0737e3b898e2e204",
)
SIGNED_PURPOSE = "inferroute-enclave-build/v1"
# A copy of the identity fields of inferroute_local/confidential/builds.py BUNDLED (a test keeps them equal).
# A build is identified by MRTD + RTMR1..3; RTMR0 (the host's boot firmware configuration) varies per host.
RECORDED_BUILDS: List[Dict[str, Any]] = [
    {"id": "tee-vm-2026-09-12", "status": "refused", "first_seen": "2026-09-12", "refused_on": "2026-10-06",
     "refused_because": "guest image 1.3.1 lets the host shadow the root filesystem without changing RTMR3 (overlayroot config disk, fixed by the operator in 1.4.0)",
     "mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
     "rtmr1": "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207",
     "rtmr2": "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968",
     "rtmr3": "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433",
     "reproduced": ["mrtd", "rtmr1", "rtmr2"]},
    {"id": "tee-vm-2026-09-20", "status": "observed", "first_seen": "2026-09-30",
     "mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d",
     "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed",
     "rtmr2": "da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153",
     "rtmr3": "d9dc4c6079fb12a21ad2aa8e329d8bfa61aaa13d3ffd10a93a2c4e82f0e35efbf28f5cf3bed0c0c1b517a7c327a25226",
     "reproduced": ["rtmr1", "rtmr2", "rtmr3"]},
]
# The client accepts these Intel TCB statuses (inferroute_local/confidential/attest_intel.py ACCEPTED_TCB);
# the row names the status it found so a reader can apply a stricter rule.
ACCEPTED_TCB = ("UpToDate", "SWHardeningNeeded")
REQUIRED_GPU_CLAIMS = (
    "x-nvidia-gpu-attestation-report-parsed",
    "x-nvidia-gpu-attestation-report-signature-verified",
    "x-nvidia-gpu-attestation-report-cert-chain-validated",
    "x-nvidia-gpu-attestation-report-nonce-match",
    "x-nvidia-gpu-driver-rim-fetched",
    "x-nvidia-gpu-driver-rim-signature-verified",
    "x-nvidia-gpu-driver-rim-measurements-available",
    "x-nvidia-gpu-vbios-rim-fetched",
    "x-nvidia-gpu-vbios-rim-signature-verified",
    "x-nvidia-gpu-vbios-rim-measurements-available",
)
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
OID_SGX_EXT = "1.2.840.113741.1.13.1"
_HDR, _BODY = 48, 584
_OFF = {"tee_tcb_svn": (0, 16), "mrsignerseam": (64, 112), "seam_attributes": (112, 120), "td_attributes": (120, 128),
        "mrtd": (136, 184), "rtmr0": (328, 376), "rtmr1": (376, 424), "rtmr2": (424, 472), "rtmr3": (472, 520),
        "report_data": (520, 584)}

NOT_RECOMPUTED = (
    "that each request was sealed to the verified key and sent: the receipt COUNTS requests; the operator's protocol "
    "returns nothing signed by the machine that ties a reply to a sealed request, so per-request binding is this "
    "device's word",
    "what the machine's software did with the text after decrypting it: the measured image does not cover the code the "
    "model is served with, and no attestation reaches retention",
    "the GPUs' confidential-computing mode: NVIDIA's verdict carries no claim for it",
    "the machine's boot configuration (RTMR0): supplied by the company running the physical machine and different per "
    "host; this check compares MRTD and RTMR1-3 only (the app compared all five with the operator's published list)",
)
# Rows for receipts written before the client recorded 'preamble_path' (the 2 Nov fixes): what that client did not
# record, stated as rows so the plain words rest on a row rather than on InferRoute's prose (Kimi round 22).
OLDER_CLIENT_NOT_RECORDED = (
    "older app version (no 'preamble_path' field): it saved the request count only after a reply finished, so a "
    "conversation cut off mid-reply can show fewer requests than were sent (InferRoute's account of that version)",
    "older app version: a later change of key on the same machine was not recorded, so requests after such a change "
    "would have been sealed to a key this receipt does not show (InferRoute's account of that version)",
    "older app version: the note sent with every request named this receipt by its full path, normally including the "
    "account name (InferRoute's account of that version)",
)


class Checks:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, str, str]] = []      # (status, name, detail)  status ∈ PASS FAIL SKIP

    def add(self, ok: Optional[bool], name: str, detail: str) -> bool:
        self.rows.append(("SKIP" if ok is None else "PASS" if ok else "FAIL", name, detail))
        return bool(ok)

    @property
    def failed(self) -> List[str]:
        return [n for s, n, _ in self.rows if s == "FAIL"]

    @property
    def skipped(self) -> List[str]:
        return [n for s, n, _ in self.rows if s == "SKIP"]

    def dump(self, indent: str = "  ") -> None:
        for s, n, d in self.rows:
            print(f"{indent}{s:4} {n}: {d}")


# ───────────────────────── small helpers ─────────────────────────

def _b64(s: Any) -> bytes:
    t = (s or "").strip() if isinstance(s, str) else ""
    return base64.b64decode(t + "=" * (-len(t) % 4))


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _parse_time(s: Any) -> Optional[dt.datetime]:
    if not isinstance(s, str) or not s:
        return None
    try:
        t = s.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(t)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _x509():
    import warnings
    from cryptography import x509
    warnings.filterwarnings("ignore", message=".*Attribute's length.*")
    warnings.filterwarnings("ignore", message=".*Country names should be two characters.*")
    return x509


def _spki_sha256(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return _sha256_hex(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def _cn(cert) -> str:
    from cryptography.x509.oid import NameOID
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:                                       # noqa: BLE001
        return cert.subject.rfc4514_string()[:40]


def _org(cert) -> str:
    from cryptography.x509.oid import NameOID
    try:
        return cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except Exception:                                       # noqa: BLE001
        return ""


def _issuer_org(cert) -> str:
    from cryptography.x509.oid import NameOID
    try:
        return cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except Exception:                                       # noqa: BLE001
        return ""


def _issued_by(child, parent) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:                                       # noqa: BLE001
        return False


def _cert_ok_at(cert, at: dt.datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc


def _load_cert(s: str):
    x509 = _x509()
    if not s:
        return None
    try:
        t = s if "BEGIN CERT" in s else ("-----BEGIN CERTIFICATE-----\n" + s.strip() + "\n-----END CERTIFICATE-----\n")
        return x509.load_pem_x509_certificate(t.encode())
    except Exception:                                       # noqa: BLE001
        try:
            return x509.load_der_x509_certificate(_b64(s))
        except Exception:                                   # noqa: BLE001
            return None


def _pem_chain(data: bytes) -> list:
    x509 = _x509()
    out, beg, end = [], b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    i = data.find(beg)
    while i != -1:
        j = data.find(end, i)
        if j == -1:
            break
        j += len(end)
        try:
            out.append(x509.load_pem_x509_certificate(data[i:j]))
        except Exception:                                   # noqa: BLE001
            pass
        i = data.find(beg, j)
    return out


def _p256_raw_ok(pub, sig64: bytes, data: bytes, halg=None) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    n = len(sig64) // 2
    if len(sig64) not in (64, 96):
        return False
    der = encode_dss_signature(int.from_bytes(sig64[:n], "big"), int.from_bytes(sig64[n:], "big"))
    try:
        pub.verify(der, data, ec.ECDSA(halg or hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):                    # noqa: BLE001
        return False


# ───────────────────────── the quote ─────────────────────────

def parse_quote(q: bytes) -> Dict[str, Any]:
    """TDX quote v4 (ECDSA-P256, QE-report certification data): body fields + signature data + PCK chain PEM."""
    if len(q) < _HDR + _BODY + 4:
        raise ValueError("quote shorter than a v4 header + body")
    version, key_type, tee_type = struct.unpack_from("<HHI", q, 0)
    out: Dict[str, Any] = {"version": version, "key_type": key_type, "tee_type": tee_type, "vendor_ok": q[12:28] == INTEL_QE_VENDOR_ID,
                           "signed": q[:_HDR + _BODY]}
    body = q[_HDR:_HDR + _BODY]
    for k, (a, b) in _OFF.items():
        out[k] = body[a:b]
    (sig_len,) = struct.unpack_from("<I", q, _HDR + _BODY)
    sd = q[_HDR + _BODY + 4:_HDR + _BODY + 4 + sig_len]
    if len(sd) != sig_len or sig_len < 134:
        raise ValueError("signature data truncated")
    out["signature"], out["attestation_key"] = sd[0:64], sd[64:128]
    ctype, csize = struct.unpack_from("<HI", sd, 128)
    cd = sd[134:134 + csize]
    if ctype != 6 or len(cd) != csize or len(cd) < 450:
        raise ValueError(f"certification data type {ctype} (expected 6, QE report certification data)")
    out["qe_report_raw"], out["qe_signature"] = cd[0:384], cd[384:448]
    (auth_len,) = struct.unpack_from("<H", cd, 448)
    out["qe_auth_data"] = cd[450:450 + auth_len]
    p = 450 + auth_len
    if len(cd) < p + 6:
        raise ValueError("inner certification data missing")
    itype, isize = struct.unpack_from("<HI", cd, p)
    chain = cd[p + 6:p + 6 + isize]
    if itype != 5 or len(chain) != isize:
        raise ValueError(f"inner certification data type {itype} (expected 5, PCK certificate chain)")
    out["pck_chain_pem"] = chain
    qe = out["qe_report_raw"]
    out["qe"] = {"miscselect": struct.unpack_from("<I", qe, 16)[0], "attributes": qe[48:64], "mrsigner": qe[128:160],
                 "isvprodid": struct.unpack_from("<H", qe, 256)[0], "isvsvn": struct.unpack_from("<H", qe, 258)[0],
                 "report_data": qe[320:384]}
    return out


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
    ext = next((e for e in leaf.extensions if e.oid.dotted_string == OID_SGX_EXT), None)
    if ext is None:
        return {}
    out: dict = {}
    for _, val in _walk(_walk(ext.value.value)[0][1]):
        items = _walk(val)
        o, v = _oid(items[0][1]), items[1]
        if o == OID_SGX_EXT + ".4":
            out["fmspc"] = v[1].hex()
        elif o == OID_SGX_EXT + ".3":
            out["pceid"] = v[1].hex()
        elif o == OID_SGX_EXT + ".2":
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

def _intel_signed_json(text: str, key: str) -> Tuple[Dict[str, Any], bytes, str]:
    """Intel signs the exact bytes of the `tcbInfo` / `enclaveIdentity` value; cut them out as written.
    Duplicate keys are refused (json.loads keeps the last one, which once let a forged copy pass)."""
    def _no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key in an Intel document")
        return dict(pairs)
    doc = json.loads(text, object_pairs_hook=_no_dupes)
    prefix = '{"' + key + '":'
    if (not text.startswith(prefix) or set(doc) != {key, "signature"} or not isinstance(doc.get(key), dict)
            or not isinstance(doc.get("signature"), str)):
        raise ValueError(f"not an Intel {key} document")
    _, end = json.JSONDecoder().raw_decode(text, len(prefix))
    raw = text[len(prefix):end]
    return json.loads(raw, object_pairs_hook=_no_dupes), raw.encode(), doc["signature"]


def _tcb_level(tcb_info: dict, cpusvn: bytes, pcesvn: int, tee_tcb_svn: bytes) -> Tuple[str, list, str]:
    for lvl in tcb_info.get("tcbLevels", []):
        t = lvl.get("tcb") or {}
        sgx = [int(c.get("svn", 0)) for c in t.get("sgxtcbcomponents", [])]
        tdx = [int(c.get("svn", 0)) for c in t.get("tdxtcbcomponents", [])]
        if len(sgx) != 16 or len(cpusvn) != 16:
            continue
        if (all(cpusvn[i] >= sgx[i] for i in range(16)) and pcesvn >= int(t.get("pcesvn", 1 << 30))
                and all(tee_tcb_svn[i] >= tdx[i] for i in range(min(len(tdx), len(tee_tcb_svn))))):
            return str(lvl.get("tcbStatus")), list(lvl.get("advisoryIDs", [])), str(lvl.get("tcbDate", ""))
    return "Unknown", [], ""


def _qe_status(qe_id: dict, qe: dict) -> Tuple[str, str]:
    try:
        if bytes.fromhex(qe_id["mrsigner"]) != qe["mrsigner"]:
            return "Mismatch", "QE MRSIGNER differs from Intel's QE Identity"
        if int(qe_id["isvprodid"]) != qe["isvprodid"]:
            return "Mismatch", "QE ISVPRODID differs from Intel's QE Identity"
        am, av = bytes.fromhex(qe_id.get("attributesMask", "00" * 16)), bytes.fromhex(qe_id.get("attributes", "00" * 16))
        if bytes(a & m for a, m in zip(qe["attributes"], am)) != bytes(v & m for v, m in zip(av, am)):
            return "Mismatch", "QE attributes differ from Intel's QE Identity"
        mask = int.from_bytes(bytes.fromhex(qe_id.get("miscselectMask", "00000000")), "little")
        if (qe["miscselect"] & mask) != int.from_bytes(bytes.fromhex(qe_id.get("miscselect", "00000000")), "little"):
            return "Mismatch", "QE miscselect differs from Intel's QE Identity"
    except (KeyError, ValueError):
        return "Mismatch", "Intel's QE Identity is malformed"
    for lvl in qe_id.get("tcbLevels", []):
        if qe["isvsvn"] >= int((lvl.get("tcb") or {}).get("isvsvn", 1 << 30)):
            return str(lvl.get("tcbStatus")), f"QE ISVSVN {qe['isvsvn']} at level dated {str(lvl.get('tcbDate', '?'))[:10]}"
    return "Unknown", f"QE ISVSVN {qe['isvsvn']} below every published level"


def check_intel_collateral(c: Checks, q: Dict[str, Any], certs: list, intel: Optional[dict], at: dt.datetime) -> None:
    x509 = _x509()
    if not isinstance(intel, dict) or not intel.get("tcb_info"):
        c.add(None, "Intel collateral (TCB info, QE identity, CRLs)",
              "not kept in this receipt (written by a client before 0.9.126, or Intel was unreachable): the device checked "
              "TCB currency, QE identity and revocation online at the time; none of it can be re-checked here")
        return
    leaf, inter, root = certs[0], certs[1], certs[2]
    try:
        tcb_info, tcb_raw, tcb_sig = _intel_signed_json(str(intel["tcb_info"]), "tcbInfo")
        qe_id, qe_raw, qe_sig = _intel_signed_json(str(intel["qe_identity"]), "enclaveIdentity")
        signers = [_pem_chain(str(intel.get("tcb_info_issuer_chain", "")).encode()),
                   _pem_chain(str(intel.get("qe_identity_issuer_chain", "")).encode())]
        root_crl = x509.load_der_x509_crl(_b64(intel["root_ca_crl"]))
        pck_crl = x509.load_der_x509_crl(_b64(intel["pck_crl"]))
        ext = pck_extension(leaf)
    except Exception as exc:                                # noqa: BLE001
        c.add(False, "Intel collateral (TCB info, QE identity, CRLs)", f"present but unreadable ({type(exc).__name__}: {str(exc)[:80]})")
        return

    def _signer_ok(chain: list):
        sgn = next((x for x in chain if _cn(x) == "Intel SGX TCB Signing"), None)
        if sgn is None or not _issued_by(sgn, root) or not _cert_ok_at(sgn, at):
            return None
        if root_crl.get_revoked_certificate_by_serial_number(sgn.serial_number) is not None:
            return None
        return sgn

    def _window(doc: dict) -> bool:
        a, b = _parse_time(doc.get("issueDate")), _parse_time(doc.get("nextUpdate"))
        return a is not None and b is not None and a <= at <= b

    s1 = _signer_ok(signers[0])
    ok1 = (s1 is not None and _p256_raw_ok(s1.public_key(), bytes.fromhex(tcb_sig), tcb_raw)
           and tcb_info.get("id") == "TDX" and int(tcb_info.get("version", 0)) == 3 and _window(tcb_info))
    c.add(ok1, "Intel TCB info", f"signed by Intel SGX TCB Signing under the pinned root, TDX v3, issued {tcb_info.get('issueDate')}, "
          f"next update {tcb_info.get('nextUpdate')}" + ("" if ok1 else " — signature, signer, kind or validity window does NOT hold at the session's time"))
    s2 = _signer_ok(signers[1])
    ok2 = (s2 is not None and _p256_raw_ok(s2.public_key(), bytes.fromhex(qe_sig), qe_raw)
           and qe_id.get("id") == "TD_QE" and int(qe_id.get("version", 0)) == 2 and _window(qe_id))
    c.add(ok2, "Intel QE identity", f"signed by Intel SGX TCB Signing under the pinned root, TD_QE v2, next update {qe_id.get('nextUpdate')}"
          + ("" if ok2 else " — signature, signer, kind or validity window does NOT hold at the session's time"))
    crl_ok = (root_crl.issuer == root.subject and root_crl.is_signature_valid(root.public_key())
              and pck_crl.issuer == inter.subject and pck_crl.is_signature_valid(inter.public_key())
              and all(x.last_update_utc <= at <= (x.next_update_utc or at) for x in (root_crl, pck_crl)))
    revoked = [n for n, crl, cert in (("intermediate", root_crl, inter), ("PCK", pck_crl, leaf))
               if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None]
    c.add(crl_ok and not revoked, "Intel revocation lists",
          "Intel's root and PCK CRLs verify, were current at the session's time, and list neither the intermediate nor the PCK certificate"
          if crl_ok and not revoked else ("REVOKED: " + ", ".join(revoked) if revoked else
                                          "a CRL does not verify, is not Intel's, or was not current at the session's time"))
    plat = (str(ext.get("fmspc", "")).lower() == str(tcb_info.get("fmspc", "")).lower()
            and str(ext.get("pceid", "")).lower() == str(tcb_info.get("pceId", "")).lower() and "cpusvn" in ext)
    tm = tcb_info.get("tdxModule") or {}
    try:
        seam_ok = (bytes.fromhex(tm.get("mrsigner", "")) == q["mrsignerseam"]
                   and bytes(a & b for a, b in zip(bytes.fromhex(tm.get("attributesMask", "")), q["seam_attributes"]))
                   == bytes.fromhex(tm.get("attributes", "")))
    except ValueError:
        seam_ok = False
    status, advisories, date = (_tcb_level(tcb_info, ext["cpusvn"], int(ext.get("pcesvn", 0)), q["tee_tcb_svn"]) if plat
                                else ("Unknown", [], ""))
    up = ok1 and plat and seam_ok and status in ACCEPTED_TCB
    adv = f", advisories {', '.join(advisories)}" if advisories else ""
    c.add(up, "Intel TCB status (platform)",
          f"FMSPC {ext.get('fmspc', '?')}, status {status} (level {date[:10]}{adv}); accepted statuses: {', '.join(ACCEPTED_TCB)}"
          + ("" if plat else "; the TCB info is for a DIFFERENT platform") + ("" if seam_ok else "; the TDX module's signer or attributes are NOT Intel's"))
    qstatus, qwhy = _qe_status(qe_id, q["qe"])
    c.add(ok2 and qstatus in ACCEPTED_TCB, "Intel Quoting Enclave identity and status", f"{qstatus}: {qwhy}")


# ───────────────────────── NVIDIA ─────────────────────────

def _jwt_parts(tok: str) -> Tuple[dict, dict, bytes, bytes]:
    h, p, s = tok.split(".")
    return json.loads(_b64u(h)), json.loads(_b64u(p)), _b64u(s), f"{h}.{p}".encode()


def _jwk_chain_ok(jwk: dict, at: dt.datetime) -> Tuple[Optional[Any], str]:
    """The x5c chain of a JWKS entry: links verify, the last certificate's public key is a pinned NVIDIA
    Attestation Service intermediate, the leaf is valid at `at` and carries the JWK's own x/y."""
    from cryptography.hazmat.primitives.asymmetric import ec
    x509 = _x509()
    try:
        chain = [x509.load_der_x509_certificate(_b64(c)) for c in (jwk.get("x5c") or [])]
    except Exception as exc:                                # noqa: BLE001
        return None, f"x5c unreadable ({type(exc).__name__})"
    if not chain:
        return None, "JWKS entry carries no x5c chain"
    for a, b in zip(chain, chain[1:]):
        if not _issued_by(a, b):
            return None, f"x5c link {_cn(a)} → {_cn(b)} does not verify"
    pin = _spki_sha256(chain[-1])
    if pin not in NVIDIA_NRAS_SIGNING_SPKI_SHA256:
        return None, f"x5c ends in {_cn(chain[-1])} (SPKI {pin[:16]}…), which is not a pinned NVIDIA Attestation Service intermediate"
    if not _cert_ok_at(chain[0], at):
        return None, f"signing certificate {_cn(chain[0])} not valid at {at.isoformat()}"
    pub = chain[0].public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or jwk.get("kty") != "EC":
        return None, "signing key is not an EC key"
    try:
        n = pub.public_numbers()
        if (n.x, n.y) != (int.from_bytes(_b64u(jwk["x"]), "big"), int.from_bytes(_b64u(jwk["y"]), "big")):
            return None, "the JWK's x/y are not the x5c leaf's public key"
    except Exception:                                       # noqa: BLE001
        return None, "the JWK's x/y are unreadable"
    return pub, f"{_cn(chain[0])} ← {NVIDIA_NRAS_SIGNING_SPKI_SHA256[pin].split(' (')[0]} (pinned)"


def _verify_eat(tok: str, jwks_used: dict, at: dt.datetime) -> Tuple[Optional[dict], str]:
    from cryptography.hazmat.primitives import hashes
    try:
        hdr, claims, sig, signed = _jwt_parts(tok)
    except Exception:                                       # noqa: BLE001
        return None, "token is not a JWT"
    if hdr.get("alg") != "ES384":
        return None, f"token alg {hdr.get('alg')!r} is not ES384"
    jwk = (jwks_used or {}).get(hdr.get("kid"))
    if not isinstance(jwk, dict):
        return None, f"no JWKS entry kept for kid {str(hdr.get('kid'))[:40]}"
    pub, how = _jwk_chain_ok(jwk, at)
    if pub is None:
        return None, how
    if not _p256_raw_ok(pub, sig, signed, hashes.SHA384()):
        return None, "ES384 signature does NOT verify under the JWKS key"
    return claims, how


def check_nvidia(c: Checks, body: dict, loose_gpu: Any, nvidia: Optional[dict], challenge: str, at: dt.datetime) -> None:
    nv = (body.get("evidence") or {}).get("nvtrust_evidence")
    try:
        if isinstance(nv, str):
            nv = json.loads(nv)
    except ValueError:
        nv = None
    signed_gpu = list(nv) if isinstance(nv, list) else []
    if not signed_gpu:
        c.add(False, "GPU reports inside the signed evidence", "the enclave-signed body carries no GPU evidence")
    elif loose_gpu and loose_gpu != signed_gpu:
        c.add(False, "GPU reports inside the signed evidence", "the GPU evidence outside the signed body DIFFERS from the signed copy")
    else:
        c.add(True, "GPU reports inside the signed evidence", f"{len(signed_gpu)} GPU report(s) read from the enclave-signed body")
    # Each GPU's identity chain → the pinned NVIDIA Device Identity CA.
    bad: List[str] = []
    models: set = set()
    for i, g in enumerate(signed_gpu):
        try:
            chain = _pem_chain(_b64(g.get("certificate")))
            if not chain:
                raise ValueError("no certificates")
            if any(not _issued_by(a, b) for a, b in zip(chain, chain[1:])):
                raise ValueError("a link does not verify")
            if _spki_sha256(chain[-1]) != NVIDIA_DEVICE_ROOT_SPKI_SHA256 or not _issued_by(chain[-1], chain[-1]):
                raise ValueError(f"root {_cn(chain[-1])} is not the pinned NVIDIA Device Identity CA")
            if not _cert_ok_at(chain[0], at):
                raise ValueError("leaf not valid at the session's time")
            models.add(_cn(chain[0]).split(" ")[0])
        except Exception as exc:                            # noqa: BLE001
            bad.append(f"GPU-{i}: {exc}")
    if signed_gpu:
        c.add(not bad, "GPU certificate chains", f"{len(signed_gpu)} chain(s) ({'/'.join(sorted(models)) or '?'}) verify link by link to the pinned "
              "NVIDIA Device Identity CA" if not bad else "; ".join(bad)[:300])
    if not isinstance(nvidia, dict) or nvidia.get("response") is None:
        c.add(None, "NVIDIA verdict tokens",
              "not kept in this receipt (written by a client before 0.9.126, or NVIDIA was unreachable): the device had NVIDIA judge "
              "each GPU's report online at the time; that verdict cannot be re-checked here")
        c.add(None, "GPU confidential-computing mode", "NVIDIA's verdict carries no claim for it; not checkable from this record")
        return
    resp, jwks_used = nvidia.get("response"), nvidia.get("jwks_used") or {}
    want = str(nvidia.get("challenge") or "")
    expected = _sha256_hex((challenge + str(body.get("_e2e_pubkey") or "")).encode()) if challenge else ""
    try:
        overall_tok, per = resp[0][1], resp[1] or {}
    except Exception:                                       # noqa: BLE001
        c.add(False, "NVIDIA verdict tokens", "response is not NRAS's [[\"JWT\", overall], {gpu: token}] shape")
        c.add(None, "GPU confidential-computing mode", "NVIDIA's verdict carries no claim for it; not checkable from this record")
        return
    oc, how = _verify_eat(overall_tok, jwks_used, at)
    sig_fail = [] if oc is not None else [f"overall: {how}"]
    gpu_claims: Dict[str, dict] = {}
    for name, tok in per.items():
        cl, h2 = _verify_eat(tok, jwks_used, at)
        if cl is None:
            sig_fail.append(f"{name}: {h2}")
        else:
            gpu_claims[name] = cl
    c.add(not sig_fail, "NVIDIA verdict token signatures",
          f"overall + {len(per)} per-GPU EAT tokens, ES384 under {how}" if not sig_fail else "; ".join(sig_fail)[:300])
    if oc is None:
        c.add(False, "NVIDIA verdict (challenge, overall result)", "overall token not verified")
    else:
        nonce_ok = bool(expected) and oc.get("eat_nonce") == expected and want == expected
        win_ok = all(isinstance(oc.get(k), (int, float)) for k in ("nbf", "exp")) and oc["nbf"] <= at.timestamp() + 3600 * 24 and oc["exp"] >= at.timestamp()
        ok = nonce_ok and oc.get("x-nvidia-overall-att-result") is True and win_ok
        c.add(ok, "NVIDIA verdict (challenge, overall result)",
              (f"eat_nonce == SHA-256(nonce ‖ sealing key) for THIS session; overall result true; issued "
               f"{dt.datetime.fromtimestamp(oc.get('iat', 0), dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}") if ok else
              ("the verdict is for a DIFFERENT challenge" if not nonce_ok else
               "overall result is not true" if oc.get("x-nvidia-overall-att-result") is not True else
               "the token's validity window does not cover the session"))
    probs: List[str] = []
    for name in per:
        cl = gpu_claims.get(name)
        if cl is None:
            probs.append(f"{name}: unverified")
            continue
        missing = [k for k in REQUIRED_GPU_CLAIMS if cl.get(k) is not True]
        if cl.get("measres") != "success":
            missing.append("measres")
        if cl.get("dbgstat") != "disabled":
            missing.append("debug-enabled")
        if cl.get("secboot") is not True:
            missing.append("secure-boot-off")
        if expected and cl.get("eat_nonce") != expected:
            missing.append("eat_nonce")
        if missing:
            probs.append(f"{name}: {', '.join(missing)}")
    count_ok = len(per) == len(signed_gpu) and len(per) > 0
    c.add(count_ok and not probs and not sig_fail, "NVIDIA verdict per GPU",
          (f"{len(per)} GPU(s): report parsed, signed, chain validated, challenge matched; driver and VBIOS reference manifests "
           f"fetched, signed and matching; secure boot on; debug off") if (count_ok and not probs and not sig_fail) else
          (f"{len(per)} verdict(s) for {len(signed_gpu)} GPU report(s)" if not count_ok else "; ".join(probs)[:300]))
    c.add(None, "GPU confidential-computing mode", "NVIDIA's verdict carries no claim for it; not checkable from this record")


# ───────────────────────── builds ─────────────────────────

def _signed_bytes(row: dict) -> bytes:
    fields = ("id", "mrtd", "rtmr1", "rtmr2", "rtmr3", "status")
    body = {k: str(row.get(k, "")).lower() for k in fields}
    body["purpose"] = SIGNED_PURPOSE
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _row_signed(row: dict) -> bool:
    sig = row.get("sig")
    if not sig:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw, msg = bytes.fromhex(str(sig)), _signed_bytes(row)
    except (ImportError, ValueError):
        return False
    for pub in SIGNING_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(raw, msg)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def check_build(c: Checks, q: Dict[str, Any], receipt_row: Any) -> None:
    key = (q["mrtd"].hex(), q["rtmr1"].hex(), q["rtmr2"].hex(), q["rtmr3"].hex())
    rows = [b for b in RECORDED_BUILDS if (b["mrtd"], b["rtmr1"], b["rtmr2"], b["rtmr3"]) == key]
    # A refused row in THIS file outranks anything the receipt carries: a refusal is a decision InferRoute shipped.
    if any(b.get("status") == "refused" for b in rows):
        b = next(b for b in rows if b.get("status") == "refused")
        c.add(False, "recorded build", f"build {b['id']} — REFUSED by InferRoute since {b.get('refused_on', '?')}: {b.get('refused_because', '')}")
        return
    if rows:
        b = rows[0]
        repro = "+".join(r.upper() for r in b.get("reproduced") or [])
        c.add(True, "recorded build", f"build {b['id']} ({b.get('status')}), recorded by InferRoute since {b.get('first_seen', '?')}"
              + (f"; {repro} recomputed by InferRoute from the operator's published artifacts" if repro else "")
              + f"; MRTD {key[0][:12]}…, RTMR3 {key[3][:12]}…")
        return
    if isinstance(receipt_row, dict) and receipt_row.get("mrtd"):
        rk = tuple(str(receipt_row.get(k, "")).lower() for k in ("mrtd", "rtmr1", "rtmr2", "rtmr3"))
        if rk != key:
            c.add(False, "recorded build", "the build row the receipt carries is for DIFFERENT measurements than the quote")
        elif _row_signed(receipt_row) and str(receipt_row.get("status", "")).lower() != "refused":
            c.add(True, "recorded build", f"build {receipt_row.get('id', '?')} — a run-time row signed by InferRoute's offline publication "
                  f"key (pinned here); not bundled in this verifier")
        elif _row_signed(receipt_row):
            c.add(False, "recorded build", f"build {receipt_row.get('id', '?')} — REFUSED by a row signed by InferRoute's offline key")
        else:
            c.add(False, "recorded build", f"build {receipt_row.get('id', '?')} — the receipt carries an UNSIGNED run-time row "
                  f"({receipt_row.get('status', '?')}): not InferRoute's record; the device opened it anyway")
        return
    c.add(False, "recorded build", f"MRTD {key[0][:12]}… / RTMR3 {key[3][:12]}… is not a build this verifier knows, and the receipt "
          "carries no signed row for it")


# ───────────────────────── one machine ─────────────────────────

def check_machine(c: Checks, att: dict, at: dt.datetime, *, label: str) -> Dict[str, Any]:
    """Every per-machine row. Returns {instance_id, mrtd, rtmrs, operator} for the summary."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    info: Dict[str, Any] = {"instance_id": str(att.get("instance_id") or ""), "operator": ""}
    raw_body = att.get("attested_body")
    try:
        dec = _b64(raw_body)
        body = json.loads(dec)
        if not isinstance(body, dict):
            raise ValueError("not an object")
    except Exception as exc:                                # noqa: BLE001
        c.add(False, f"{label} signed evidence body", f"attested_body is not base64 JSON ({type(exc).__name__})")
        return info
    tq = (body.get("evidence") or {}).get("tdx_quote")
    loose = att.get("quote")
    if not isinstance(tq, str) or not tq:
        c.add(False, f"{label} quote inside the signed evidence", "the signed body carries no TDX quote")
        return info
    c.add(not loose or loose == tq, f"{label} quote inside the signed evidence",
          "the quote checked is the copy the enclave signed" + ("" if not loose else "; the loose copy is byte-identical")
          if (not loose or loose == tq) else "the quote outside the signed body DIFFERS from the signed copy")
    cw = att.get("checked_with") if isinstance(att.get("checked_with"), dict) else {}
    challenge, pubkey = str(cw.get("challenge") or ""), str(cw.get("e2e_pubkey") or "")
    body["_e2e_pubkey"] = pubkey
    if challenge:
        c.add(challenge.encode() in dec, f"{label} fresh challenge answered",
              "the device's nonce appears verbatim in the enclave-signed body" if challenge.encode() in dec
              else "the device's recorded nonce is ABSENT from the signed body — evidence may be replayed")
    else:
        c.add(None, f"{label} fresh challenge answered", "the receipt does not record the device's nonce (client before 0.9.117); not re-checkable")
    cert = _load_cert(str(att.get("certificate") or ""))
    if cert is None:
        c.add(False, f"{label} signature over the evidence", "certificate did not parse")
        sig_ok = False
    else:
        info["operator"] = _issuer_org(cert) or _cn(cert)
        pub = cert.public_key()
        sig_ok = False
        try:
            sig = _b64(att.get("signature"))
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(sig, dec, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(sig, dec, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError(f"unsupported key type {type(pub).__name__}")
            sig_ok = True
        except Exception:                                   # noqa: BLE001
            sig_ok = False
        c.add(sig_ok, f"{label} signature over the evidence",
              f"verifies under the certificate's key (CN={_cn(cert)}, issued by O={_issuer_org(cert) or '?'}, {type(pub).__name__.replace('PublicKey', '')})"
              if sig_ok else "does NOT verify over the signed body under the certificate's key")
    try:
        q = parse_quote(_b64(tq))
    except Exception as exc:                                # noqa: BLE001
        c.add(False, f"{label} TDX quote", f"unparsable ({type(exc).__name__}: {str(exc)[:80]})")
        return info
    info.update({"mrtd": q["mrtd"].hex(), "rtmrs": [q[k].hex() for k in ("rtmr0", "rtmr1", "rtmr2", "rtmr3")]})
    shape = q["version"] == 4 and q["tee_type"] == 0x81 and q["vendor_ok"] and not (q["td_attributes"][0] & 0x01)
    c.add(shape, f"{label} genuine TDX, debug off",
          "quote v4, tee_type 0x81, Intel's QE vendor id, TD DEBUG attribute clear" if shape else
          ("TD DEBUG bit is SET — a debuggable TD's measurements prove nothing" if (q["td_attributes"][0] & 0x01) else
           f"version {q['version']}, tee_type {q['tee_type']:#x}, vendor ok={q['vendor_ok']}"))
    if cert is not None:
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        bound = q["report_data"][32:64] == hashlib.sha256(spki).digest()
        c.add(bound, f"{label} signing key bound to the enclave", "report_data[32:64] == SHA-256(certificate SPKI)" if bound
              else "the quote does NOT commit to the certificate's key")
    if challenge and pubkey:
        want = hashlib.sha256((challenge + pubkey).encode()).digest()
        kb = q["report_data"][:32] == want
        pk_sha = hashlib.sha256(_b64(pubkey)).hexdigest() if pubkey else ""
        rec_sha = str((att.get("_instance") or {}).get("e2ee_pubkey_sha256") or cw.get("e2e_pubkey_sha256") or "")
        c.add(kb and (not rec_sha or rec_sha == pk_sha), f"{label} sealing key bound to the enclave",
              "report_data[0:32] == SHA-256(nonce ‖ the ML-KEM key the device sealed to)" + ("" if not rec_sha else "; its hash matches the receipt's instance row")
              if kb and (not rec_sha or rec_sha == pk_sha) else
              ("the quote does NOT commit to the key the device sealed to" if not kb else "the receipt names a different key hash than the one recorded with the challenge"))
    else:
        c.add(None, f"{label} sealing key bound to the enclave", "the receipt does not record the sealing key with the challenge; not re-checkable")
    # PCK chain + quote signature.
    certs = _pem_chain(q["pck_chain_pem"].rstrip(b"\x00"))
    if len(certs) != 3:
        c.add(False, f"{label} Intel PCK certificate chain", f"{len(certs)} certificate(s) embedded; expected leaf, intermediate, root")
        return info
    leaf, inter, root = certs
    root_spki = _spki_sha256(root)
    names_ok = (_cn(root) == "Intel SGX Root CA" and _cn(inter) in ("Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA")
                and _cn(leaf) == "Intel SGX PCK Certificate")
    chain_ok = (names_ok and root_spki == INTEL_SGX_ROOT_SPKI_SHA256 and _issued_by(root, root) and _issued_by(inter, root)
                and _issued_by(leaf, inter) and all(_cert_ok_at(x, at) for x in certs))
    c.add(chain_ok, f"{label} Intel PCK certificate chain",
          f"PCK ← {_cn(inter)} ← {_cn(root)}; root public key SHA-256 {root_spki[:16]}… "
          + ("is the pinned Intel SGX Root CA; all three valid at the session's time" if chain_ok else
             ("is NOT the pinned Intel root" if root_spki != INTEL_SGX_ROOT_SPKI_SHA256 else
              "a certificate does not carry the name Intel gives that role" if not names_ok else
              "a link does not verify or a certificate is outside its validity")))
    qe_sig_ok = _p256_raw_ok(leaf.public_key(), q["qe_signature"], q["qe_report_raw"])
    bound = q["qe"]["report_data"] == hashlib.sha256(q["attestation_key"] + q["qe_auth_data"]).digest() + bytes(32)
    try:
        ak = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + q["attestation_key"])
        qs = _p256_raw_ok(ak, q["signature"], q["signed"])
    except Exception:                                       # noqa: BLE001
        qs = False
    c.add(qe_sig_ok and bound and qs, f"{label} quote signed by Intel's Quoting Enclave",
          "QE report signed by the PCK key; QE REPORTDATA binds the attestation key; the quote's ECDSA-P256 signature verifies under it"
          if (qe_sig_ok and bound and qs) else
          ("the QE report signature does NOT verify under the PCK certificate" if not qe_sig_ok else
           "the QE report does NOT bind this attestation key" if not bound else "the quote's signature does NOT verify under its attestation key"))
    check_build(c, q, att.get("build"))
    col = att.get("collateral") if isinstance(att.get("collateral"), dict) else {}
    t_col = _collateral_time(c, col, at, label)
    check_intel_collateral(c, q, certs, col.get("intel"), t_col)
    check_nvidia(c, body, att.get("gpu_evidence"), col.get("nvidia"), challenge, t_col)
    return info


COLLATERAL_SLACK_S = 15 * 60


def _collateral_time(c: Checks, col: dict, at: dt.datetime, label: str) -> dt.datetime:
    """When the device fetched Intel's and NVIDIA's answers. Their validity windows are judged at THAT moment
    (Intel stamps a TCB info's issueDate at generation, NVIDIA's signing certificates live a day), and the
    moment itself must sit at the pin: collateral fetched hours later describes the platform then, not when
    the text was sealed. No collateral → no row here; the collateral rows say SKIP themselves."""
    times = [_parse_time((col.get(k) or {}).get("fetched_at")) for k in ("intel", "nvidia") if isinstance(col.get(k), dict)]
    times = [t for t in times if t is not None]
    if not times:
        return at
    gap = max(abs((t - at).total_seconds()) for t in times)
    ok = gap <= COLLATERAL_SLACK_S
    c.add(ok, f"{label} collateral fetched at the pin",
          f"Intel/NVIDIA answers fetched within {int(gap)} s of the pin ({at.strftime('%Y-%m-%dT%H:%M:%SZ')})" if ok
          else f"fetched {int(gap)} s away from the pin: they describe the platform then, not when the text was sealed")
    return max(times)


# ───────────────────────── one receipt ─────────────────────────

def _machines(receipt: dict, bundle_dir: Optional[str], c: Checks) -> List[Tuple[str, dict, dt.datetime]]:
    """(label, attestation row, time) for every machine that served. From `served_by` when present (each row's
    evidence file content-addressed), else the receipt's single `attestation`."""
    out: List[Tuple[str, dict, dt.datetime]] = []
    at0 = _parse_time(receipt.get("verified_at")) or _parse_time(receipt.get("started_at")) or dt.datetime.now(dt.timezone.utc)
    served = receipt.get("served_by") if isinstance(receipt.get("served_by"), list) else []
    if not served:
        att = receipt.get("attestation") if isinstance(receipt.get("attestation"), dict) else {}
        if not att:
            c.add(False, "evidence row", "the receipt carries no attestation evidence")
            return out
        att = dict(att)
        att["_instance"] = receipt.get("instance") or {}
        out.append(("machine 1", att, at0))
        return out
    seen: Dict[str, int] = {}
    last_sha = ""
    for i, entry in enumerate(served, 1):
        if not isinstance(entry, dict):
            c.add(False, f"evidence row {i}", "malformed served_by entry")
            continue
        if entry.get("from_previous_session"):
            continue                # an earlier leg's machine: checked on that leg's own receipt, not here
        sha, fname = str(entry.get("attestation_sha256") or ""), str(entry.get("attestation_file") or "")
        iid = str((entry.get("instance") or {}).get("id") or "")[:12]
        at = _parse_time(entry.get("at")) or at0
        last_sha = sha or last_sha
        if sha in seen:
            c.add(True, f"evidence row {i} ({iid})", f"same machine and evidence as row {seen[sha]} (re-pinned)")
            continue
        if not sha:
            c.add(False, f"evidence row {i} ({iid})", entry.get("attestation_absent") or "no evidence named for this machine")
            continue
        fname = fname or f"{sha[:16]}.attestation.json"
        path = os.path.join(bundle_dir or "", fname) if bundle_dir else fname
        try:
            raw = open(path, "rb").read()
        except OSError:
            # The receipt's own `attestation` IS the last machine's row; a session that pinned once wrote no separate
            # file for it (client before 0.9.126). The same bytes under the same sha256 are the same evidence.
            top = receipt.get("attestation") if isinstance(receipt.get("attestation"), dict) else None
            raw = json.dumps(top, sort_keys=True).encode() if top else b""
            if not top or _sha256_hex(raw) != sha:
                c.add(False, f"evidence row {i} ({iid})", f"{fname} is not in the record")
                continue
            fname = "the receipt's own attestation row"
        if _sha256_hex(raw) != sha:
            c.add(False, f"evidence row {i} ({iid})", f"{fname} does not hash to the sha256 the receipt names")
            continue
        try:
            att = json.loads(raw)
            if not isinstance(att, dict):
                raise ValueError("not an object")
        except Exception as exc:                            # noqa: BLE001
            c.add(False, f"evidence row {i} ({iid})", f"{fname} unreadable ({type(exc).__name__})")
            continue
        c.add(True, f"evidence row {i} ({iid})", f"{fname} hashes to the sha256 the receipt names; pinned {entry.get('at')}")
        seen[sha] = i
        att = dict(att)
        att["_instance"] = entry.get("instance") or {}
        out.append((f"machine {len(out) + 1} ({iid})", att, at))
    if not any(isinstance(e, dict) and not e.get("from_previous_session") for e in served):
        c.add(False, "evidence row", "every served_by row was carried from an earlier leg: this leg has no evidence of its own")
    top = receipt.get("attestation") if isinstance(receipt.get("attestation"), dict) else None
    if top and last_sha:
        top_sha = _sha256_hex(json.dumps(top, sort_keys=True).encode())
        c.add(top_sha == last_sha, "receipt's own attestation row",
              "is the last machine's evidence row" if top_sha == last_sha else "is NOT the evidence row of the last machine served")
    return out


REVERIFY_LIMIT = 3            # session.py REVERIFY_FAILURES_ALLOWED: the run of failed re-checks that stops a session
NO_ELIGIBLE_WHY = ("the verified instance is gone and no verified alternative is available — refusing to continue "
                   "unverified")


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def leg_stops(receipt: dict) -> List[Tuple[dt.datetime, str]]:
    """Every stop in this receipt's own leg as (time, reason); see _stops."""
    return [(t, w) for t, w, _k in _stops(receipt)]


def _stops(receipt: dict) -> List[Tuple[dt.datetime, str, str]]:
    """Every stop in this receipt's own leg, each with its own reason: a `refused` event (its detail is the reason), a
    `no-eligible-instance` event, and each run of `reverify-failed` events that reaches the limit — the event whose
    detail says "(3 in a row)". A receipt with a stopping verdict and no such event falls back to its last failed
    re-check. The receipt's single `refusal` text is the reason of its LAST stop only, so it is never paired with an
    earlier stop's time (review of 24f5c42)."""
    import re as _re
    own = [e for e in _as_list(receipt.get("events")) if isinstance(e, dict) and not e.get("from_previous_session")]
    out: List[Tuple[dt.datetime, str, str]] = []
    for e in own:
        t = _parse_time(e.get("ts"))
        if t is None:
            continue
        k, det = e.get("kind"), str(e.get("detail") or "")
        if k == "refused":
            out.append((t, det or str(receipt.get("refusal") or ""), "refused"))
        elif k == "no-eligible-instance":
            out.append((t, NO_ELIGIBLE_WHY, "no-eligible-instance"))
        elif k == "reverify-failed":
            m = _re.search(r"\((\d+) in a row\)", det)
            if m and int(m.group(1)) >= REVERIFY_LIMIT:
                out.append((t, f"the enclave could not be re-verified {m.group(1)} times in a row — refusing to "
                               "continue on stale evidence", "reverify-failed"))
    if not out and str(receipt.get("verdict") or "") not in ("", "confidential"):
        rever = [t for t in (_parse_time(e.get("ts")) for e in own if e.get("kind") == "reverify-failed") if t]
        if rever:
            out.append((rever[-1], str(receipt.get("refusal") or ""), "reverify-failed"))
    out.sort(key=lambda x: x[0])
    if out and receipt.get("refusal"):
        out[-1] = (out[-1][0], str(receipt["refusal"]), out[-1][2])     # the receipt's own reason: its last stop
    return out


def check_receipt_consistency(c: Checks, receipt: dict, machines: List[Dict[str, Any]], searches: List[dict], *,
                              leg: Optional[Dict[str, Any]] = None) -> None:
    events = [e for e in (receipt.get("events") or []) if isinstance(e, dict)]
    pins = [e for e in events if e.get("kind") == "pinned"]
    # A conversation that moved machines continues in the NEW leg's receipt, which carries the earlier legs' served_by
    # rows and continuity events tagged `from_previous_session`. Those are INFORMATION about the earlier legs, never
    # evidence for this one: every check below judges this receipt on its own leg, and each earlier leg is judged on
    # its own receipt, which the record carries beside this one.
    own_events = [e for e in events if not e.get("from_previous_session")]
    carried_events = [e for e in events if e.get("from_previous_session")]
    own_pins = [e for e in pins if not e.get("from_previous_session")]
    served = receipt.get("served_by") if isinstance(receipt.get("served_by"), list) else []
    counters = receipt.get("counters") if isinstance(receipt.get("counters"), dict) else {}
    started, last = _parse_time(receipt.get("started_at")), _parse_time(receipt.get("last_activity_at") or receipt.get("ended_at"))
    verified = _parse_time(receipt.get("verified_at"))
    # Every pin the events record has an evidence row.
    if served:
        pinned_ids = [str(e.get("detail", "")).split(" ")[0] for e in pins]
        served_ids = [str((s.get("instance") or {}).get("id") or "") for s in served if isinstance(s, dict)]
        missing = [i for i in pinned_ids if i and i not in served_ids]
        c.add(not missing, "every pinned machine has an evidence row",
              f"{len(pins)} pin event(s), {len(served)} served_by row(s), {len(set(served_ids))} distinct machine(s)" if not missing
              else f"pinned but no evidence row: {', '.join(m[:12] for m in missing)}")
        switches = counters.get("instance_switches")
        # instance_switches counts THIS leg's re-pins; rows carried from an earlier leg are that leg's.
        own_rows = [x for x in served if isinstance(x, dict) and not x.get("from_previous_session")]
        if isinstance(switches, int):
            if switches == len(own_rows) - 1:
                c.add(True, "instance switches vs pins", f"{switches} switch(es) = {len(own_rows)} pin(s) − 1")
            elif switches > len(own_rows) - 1:
                c.add(False, "instance switches vs pins", f"{switches} switch(es) counted but only {len(own_rows)} pin(s) recorded")
            else:
                c.add(None, "instance switches vs pins", f"{switches} switch(es) for {len(own_rows)} pin(s): a re-pin after a re-check is not counted as a switch; not contradictory, not confirmed")
        else:
            c.add(None, "instance switches vs pins", "the receipt carries no instance_switches counter (older client)")
        reqs = counters.get("requests")
        # This leg's count against this leg's rows: a carried row's requests were counted by its own leg's receipt.
        credited = sum(int(s.get("requests") or 0) for s in own_rows)
        if isinstance(reqs, int):
            # Zero counted with requests credited is a contradiction, not a retry (code-reading review, 2 Nov): the plain
            # words for an empty session say no request was sent, which must not print over rows crediting some.
            ok = credited >= reqs and (reqs > 0 or credited == 0)
            c.add(ok, "requests credited per machine",
                  f"{credited} credited across machines ≥ {reqs} counted (a retried request is credited to each machine that carried it)"
                  if ok else (f"{credited} credited across machines although {reqs} counted" if reqs == 0
                              else f"only {credited} credited across machines for {reqs} counted"))
    else:
        c.add(None, "every pinned machine has an evidence row", "the receipt has no served_by rows (older client); only the last machine's evidence is kept")
    # Timeline: this leg's own events inside its window and in order.
    ts = [_parse_time(e.get("ts")) for e in own_events]
    tl_ok = (started is not None and last is not None and started <= last and all(t is not None for t in ts)
             and all(started <= t <= last for t in ts if t) and ts == sorted(t for t in ts if t)
             and (verified is None or started <= verified <= last))
    c.add(tl_ok, "receipt timeline", f"{receipt.get('started_at')} → {receipt.get('last_activity_at') or receipt.get('ended_at')}, "
          f"{len(own_events)} event(s) in order inside that window" if tl_ok else "events out of order, undated, or outside the session window")
    # Earlier legs carried in: information, checked only for being dated, the events in order among themselves, and
    # nothing after this leg's last activity. They open no window and back nothing below.
    carried_rows = [x for x in served if isinstance(x, dict) and x.get("from_previous_session")]
    if carried_events or carried_rows:
        cts = [_parse_time(e.get("ts")) for e in carried_events]
        row_ts = [_parse_time(x.get("at")) for x in carried_rows]
        carried_ok = (last is not None and all(t is not None for t in cts + row_ts) and cts == sorted(t for t in cts if t)
                      and all(t <= last for t in cts + row_ts if t))
        legs = {str(e.get("from_previous_session")) for e in carried_events} | {str(x.get("from_previous_session")) for x in carried_rows}
        c.add(carried_ok, "earlier legs carried in",
              f"{len(carried_events)} event(s) and {len(row_ts)} evidence row(s) carried from {len(legs)} earlier leg(s): each "
              "dated, the events in order among themselves, none after this leg's last activity. Information only: "
              "nothing here is checked as this leg's, and each earlier leg is checked on its own receipt"
              if carried_ok else "carried events or rows undated, out of order, or after this leg's last activity")
    # The conversation's switch counter against the `switched` events this receipt holds: the one that moved the
    # conversation here is this leg's own, and each earlier one is carried. Every released client that keeps the
    # counter also carries the events (0.9.118 shipped both); a receipt with the counter and no carried events can only
    # come from a development build between those two changes, so a shortfall there is SKIPped, not judged.
    cs = counters.get("continuity_switches")
    if isinstance(cs, int):
        sw = sum(1 for e in events if e.get("kind") == "switched")
        if sw == cs:
            c.add(True, "continuity switches vs switched events", f"{cs} switch(es) counted, {sw} switched event(s) recorded")
        elif not carried_events and cs > sw:
            c.add(None, "continuity switches vs switched events",
                  f"{cs} counted, {sw} recorded, and no earlier leg's events carried: written by a client that did not carry them")
        else:
            c.add(False, "continuity switches vs switched events", f"{cs} switch(es) counted but {sw} switched event(s) recorded")
    # Searches attributed to this receipt fall inside the window in which a verified machine of THIS leg served.
    verdict = str(receipt.get("verdict") or "")
    stop_list = _stops(receipt)
    stops = [t for t, _why, _k in stop_list]
    stop_kind = {t: k for t, _why, k in stop_list}
    pin_times = [t for t in (_parse_time(p.get("ts")) for p in own_pins) if t is not None]
    # Resuming after a stop: a machine selected again, or a re-check that passed and was not followed by the pinned
    # machine failing it (session.py _reverify writes `reverified`, then `pinned-failed-reverify` if the pin lost).
    rechecked = [t for t in (_parse_time(e.get("ts")) for e in own_events if e.get("kind") == "reverified") if t]
    lost = [t for t in (_parse_time(e.get("ts")) for e in own_events if e.get("kind") == "pinned-failed-reverify") if t]
    # The window opens at THIS leg's first pin, never an earlier leg's (review of 00a6650) — and for a leg the
    # conversation was switched INTO, not before that switch: a standby pins when it is warmed, long before it serves
    # (review of a14e349).
    first_pin = pin_times[0] if pin_times else verified
    moved_in = next((t for t in (_parse_time(e.get("ts")) for e in own_events if e.get("kind") == "switched") if t), None)
    opens = max(first_pin, moved_in) if (first_pin is not None and moved_in is not None) else first_pin
    legmeta = leg or {}
    until = legmeta.get("ends")              # a leg the conversation moved off served until that switch
    left = _moved_off(receipt)               # …and says so itself since review of 5051307
    if left is not None and (until is None or left < until):
        until = left
    if not searches:
        c.add(None, "searches inside the session's verified window",
              "no search in this record is attributed to this " + ("leg" if legmeta.get("leg") else "session"))
    elif verdict == "refused" or opens is None:
        c.add(False, "searches inside the session's verified window",
              f"{len(searches)} search(es) attributed to a session whose AI machine was never verified ({verdict or 'no verdict'})")
    else:
        outside = []
        for s_ in searches:
            t = _parse_time(s_.get("at"))
            # After a stop, a search counts as inside only if the app selected a machine again after the LATEST stop
            # before it and before the search (a session can stop and resume more than once; honouring only the first
            # stop passed a search made after the second — review of a14e349).
            stop = max((x for x in stops if t is not None and x < t), default=None)
            # A passing re-check resumes only a stop that failed re-checks caused: after `refused` or
            # `no-eligible-instance` there is no machine to keep, so only a new pin resumes (review of c5156d2).
            resumed = stop is None or any(stop < pt <= t for pt in pin_times) or (
                stop_kind.get(stop) == "reverify-failed"
                and any(stop < r <= t and not any(r <= x <= t for x in lost) for r in rechecked))
            late = (t > until or t == until) if (t is not None and until is not None) else (
                last is not None and t is not None and t > last + dt.timedelta(minutes=5))
            if t is None or t < opens or late or not resumed:
                outside.append(str(s_.get("at")))
        began = "the switch that moved the conversation here" if moved_in is not None and opens == moved_in else "the first pin"
        ends = (f"the switch that moved the conversation off it ({until.strftime('%H:%M:%SZ')})" if until is not None
                else "five minutes after the session's last activity")
        c.add(not outside, "searches inside the session's verified window",
              f"{len(searches)} search(es) between {began} ({opens.strftime('%H:%M:%SZ')}) and {ends}" if not outside
              else f"outside the window (before a verified machine of this receipt served, after the session, or after a stop with no machine selected again): {', '.join(outside)[:200]}")


def _malformed(receipt: dict) -> str:
    """What is the wrong shape in a receipt, or "" — checked before anything reads it."""
    for key, kind in (("events", list), ("served_by", list), ("counters", dict), ("instance", dict),
                      ("attestation", dict), ("checks", dict)):
        v = receipt.get(key)
        if v is not None and not isinstance(v, kind):
            return f"'{key}' is a {type(v).__name__}, not a {kind.__name__}"
    for key in ("events", "served_by"):
        for i, x in enumerate(receipt.get(key) or []):
            if not isinstance(x, dict):
                return f"'{key}[{i}]' is a {type(x).__name__}, not an object"
            for sub in ("instance",):
                if x.get(sub) is not None and not isinstance(x.get(sub), dict):
                    return f"'{key}[{i}].{sub}' is a {type(x.get(sub)).__name__}, not an object"
    return ""


def verify_receipt(receipt: dict, *, bundle_dir: Optional[str] = None, searches: Optional[List[dict]] = None,
                   leg: Optional[Dict[str, Any]] = None) -> Tuple[Checks, bool]:
    """All rows for one receipt. Returns (checks, ok) where ok means NO FAIL and NO SKIP: a receipt an older
    client wrote is not 'ok' here even when nothing in it contradicts, because part of it was not re-checked."""
    c = Checks()
    if not isinstance(receipt, dict):
        c.add(False, "receipt", "not a JSON object")
        return c, False
    schema_ok = receipt.get("schema") == SCHEMA and bool(receipt.get("session_id"))
    c.add(schema_ok, "receipt shape", f"schema {receipt.get('schema')!r}, verdict {receipt.get('verdict')!r}, written by {receipt.get('written_by') or '?'}, "
          f"lane {receipt.get('upstream_model') or receipt.get('model_short') or '?'}, carrier {receipt.get('transport') or '?'}"
          if schema_ok else f"not an {SCHEMA} receipt")
    if not schema_ok:
        return c, False
    bad = _malformed(receipt)
    if bad:
        # A receipt whose fields have the wrong shapes is reported, never a traceback (review of c5156d2).
        c.add(False, "malformed receipt", bad)
        return c, False
    try:
        machines = _machines(receipt, bundle_dir, c)
        infos = []
        for label, att, at in machines:
            try:
                infos.append(check_machine(c, att, at, label=label))
            except Exception as exc:                            # noqa: BLE001 — a crash must read as a refusal
                c.add(False, f"{label}", f"verifier error: {type(exc).__name__}: {str(exc)[:100]}")
        check_receipt_consistency(c, receipt, infos, list(searches or []), leg=leg)
    except (TypeError, AttributeError, ValueError, KeyError, IndexError) as exc:
        c.add(False, "malformed receipt", f"{type(exc).__name__}: {str(exc)[:120]}")
        return c, False
    for n in NOT_RECOMPUTED:
        c.add(None, "not recomputed", n)
    if receipt.get("preamble_path") != "home-relative":
        for n in OLDER_CLIENT_NOT_RECORDED:
            c.add(None, "not recomputed", n)
    return c, (not c.failed and not blocking_skips(c))


# SKIP rows that are the lane's permanent limits or a record's legitimate shape, not evidence this receipt failed
# to keep. Every other SKIP means part of the receipt could not be re-checked, which keeps `ok` false.
ALWAYS_SKIPPED = ("not recomputed", "GPU confidential-computing mode", "searches inside the session's verified window")


def blocking_skips(c: Checks) -> List[str]:
    return [n for n in c.skipped if n not in ALWAYS_SKIPPED]


# ───────────────────────── a bundle ─────────────────────────

def receipt_files(bundle_dir: str) -> List[str]:
    try:
        return sorted(n for n in os.listdir(bundle_dir) if n.startswith("session-") and n.endswith(".receipt.json"))
    except OSError:
        return []


LEG_MARK = ".leg-"


def session_of(receipt_file: str) -> str:
    """The session a receipt file belongs to. A conversation that moved machines has one receipt per leg: the last as
    `session-<sid>.receipt.json`, each earlier one as `session-<sid>.leg-<k>.receipt.json` (k from 1, in order)."""
    sid = receipt_file[len("session-"):-len(".receipt.json")]
    i = sid.rfind(LEG_MARK)
    return sid[:i] if i > 0 and sid[i + len(LEG_MARK):].isdigit() else sid


def _own_switch(receipt: dict) -> Optional[dt.datetime]:
    """When the conversation was switched INTO this leg: its own (untagged) `switched` event, or None for a first leg."""
    for e in _as_list(receipt.get("events")):
        if isinstance(e, dict) and not e.get("from_previous_session") and e.get("kind") == "switched":
            t = _parse_time(e.get("ts"))
            if t is not None:
                return t
    return None


def _serving_from(receipt: dict) -> Optional[dt.datetime]:
    """When a leg began serving: the switch into it, or for a first leg its first pin. Own events only."""
    sw = _own_switch(receipt)
    if sw is not None:
        return sw
    for e in _as_list(receipt.get("events")):
        if isinstance(e, dict) and not e.get("from_previous_session") and e.get("kind") == "pinned":
            t = _parse_time(e.get("ts"))
            if t is not None:
                return t
    return _parse_time(receipt.get("verified_at")) or _parse_time(receipt.get("started_at"))


def _leg_number(name: str) -> int:
    sid = name[len("session-"):-len(".receipt.json")]
    i = sid.rfind(LEG_MARK)
    return int(sid[i + len(LEG_MARK):]) if i > 0 and sid[i + len(LEG_MARK):].isdigit() else 0


def _switches(receipt: dict) -> List[Tuple[dt.datetime, str]]:
    """The conversation's switches as a last leg's receipt holds them, in the order they happened: carried ones first
    (in the order each leg carried them), then its own. Each is (time, detail); the detail names the move ("m1 -> m2
    (why)"), so two switches in the same second remain two (review of 24f5c42)."""
    out = []
    for e in _as_list(receipt.get("events")):
        if isinstance(e, dict) and e.get("kind") == "switched":
            t = _parse_time(e.get("ts"))
            if t is not None:
                out.append((t, str(e.get("detail") or "")))
    return out


def _own_switch_event(receipt: dict) -> Optional[Tuple[dt.datetime, str]]:
    for e in _as_list(receipt.get("events")):
        if isinstance(e, dict) and not e.get("from_previous_session") and e.get("kind") == "switched":
            t = _parse_time(e.get("ts"))
            if t is not None:
                return (t, str(e.get("detail") or ""))
    return None


EVERY_LEG = "a receipt for every leg"
UNSIGNED = ("receipts are not signed, so this record cannot tell a receipt that was never exported from one that was "
            "removed")


def _gone(g: Dict[str, Any]) -> str:
    """One missing leg, in the words every summary uses."""
    s = f"leg {g['leg']}'s receipt is not in this record" + (
        " (a receipt here records that the conversation moved from its own leg to this later one)" if g.get("after_move")
        else "")
    if g.get("searches"):
        s += f", and {g['searches']} search(es) made during that leg were not re-checked"
    return s


def _moved_off(receipt: dict) -> Optional[dt.datetime]:
    """When this receipt's own leg was left for another: its own `moved-off` event (written since review of 5051307)."""
    for e in _as_list(receipt.get("events")):
        if isinstance(e, dict) and not e.get("from_previous_session") and e.get("kind") == "moved-off":
            t = _parse_time(e.get("ts"))
            if t is not None:
                return t
    return None
SEARCHES_IN_MISSING_LEG = "searches in a leg whose receipt is not here"
# Rows that only say a leg's receipt is absent from the record. Absence is a gap, never a contradiction: they are SKIP
# (the receipt is not fully re-checked: exit 4), and a reader of the plain words is told the gap, not a failure.
MISSING_LEG_ROWS = (EVERY_LEG, SEARCHES_IN_MISSING_LEG)


def _plan(bundle_dir: str, searches: Optional[List[dict]]):
    """(searches per receipt file, extra rows per receipt file, leg facts per receipt file) for every session.

    A conversation that moved machines has one receipt per leg. Its LAST leg's receipt (`session-<sid>.receipt.json`)
    holds every `switched` event of the conversation — its own and, carried, the earlier legs' — so it says where each
    leg's serving began and ended: leg 1 before the first switch, leg j from switch j-1 until switch j. Each search goes
    to the leg serving at its time and is judged on that leg's receipt, so a leg's searches never run past the switch
    that moved the conversation off it, whatever that leg's own last activity says. A leg's receipt is recognised by its
    own `switched` event (time and detail), or for leg 1 by having none, not by its file name.

    A leg with no readable receipt here is not re-checked — a SKIP, never a FAIL and never a PASS. A search that falls
    in it is given to no receipt (the next leg's receipt cannot vouch for it) and is named as not re-checked. Receipts
    are not signed, so a record cannot tell a receipt that was never exported (a record made before receipts travelled
    per leg carries one per session) from one that was removed; the rows say so (reviews of 24f5c42 and 5051307).

    A receipt whose own `moved-off` event says the conversation left it is not the conversation's last leg, even when
    it is the only receipt of its session: the legs after it are reported missing instead of extending it.
    """
    names = receipt_files(bundle_dir)
    docs: Dict[str, Optional[dict]] = {}
    for n in names:
        try:
            d = json.load(open(os.path.join(bundle_dir, n)))
            docs[n] = d if isinstance(d, dict) else None
        except Exception:                                   # noqa: BLE001 — unreadable: it already FAILs on its own
            docs[n] = None
    groups: Dict[str, List[str]] = {}
    for n in names:
        groups.setdefault(session_of(n), []).append(n)
    given: Dict[str, List[dict]] = {n: [] for n in names}
    extra: Dict[str, List[Tuple[Optional[bool], str, str]]] = {n: [] for n in names}
    facts: Dict[str, Dict[str, Any]] = {n: {"leg": False} for n in names}
    for sid, files in groups.items():
        files = sorted(files, key=lambda n: (_leg_number(n) == 0, _leg_number(n)))    # leg-1, leg-2, … then the last
        for n in files:
            facts[n]["leg"] = len(files) > 1 or bool(_leg_number(n))
        mine = [x for x in (searches or []) if isinstance(x, dict) and str(x.get("session_id") or "") == sid]
        main = f"session-{sid}.receipt.json"
        top = docs.get(main)
        sw = _switches(top) if isinstance(top, dict) else []
        left = _moved_off(top) if isinstance(top, dict) else None
        if isinstance(top, dict) and (sw or len(files) > 1 or left is not None):
            if left is not None:
                # This "last" receipt says the conversation moved off it: there is at least one leg after it.
                sw = sw + [(left, "moved-off")]
            legs: Dict[int, str] = {}
            for n in files:
                d = docs.get(n)
                if not isinstance(d, dict):
                    continue
                own = _own_switch_event(d)
                if own is None:
                    j = 1
                elif own in sw:
                    j = 2 + sw.index(own)
                else:
                    continue
                legs.setdefault(j, n)
            k = len(sw) + 1
            for j, n in legs.items():
                facts[n].update(leg=True, index=j, of=k, ends=(sw[j - 1][0] if j <= len(sw) else None))
            missing = [j for j in range(1, k + 1) if j not in legs]
            lost: Dict[int, List[str]] = {}
            for x in mine:
                t = _parse_time(x.get("at"))
                j = 1 + sum(1 for w, _d in sw if t is not None and w <= t)
                if j in legs:
                    given[legs[j]].append(x)
                else:
                    lost.setdefault(j, []).append(str(x.get("at")))
            cs = _as_dict(top.get("counters")).get("continuity_switches")
            want = max((cs if isinstance(cs, int) else 0), len(sw)) + 1
            readable = [n for n in files if isinstance(docs.get(n), dict)]
            unplaced = [n for n in readable if n not in legs.values()]
            gaps = [{"leg": j, "searches": len(lost.get(j, [])), "session": sid,
                     "after_move": left is not None and j == k,
                     # which receipt's own `moved-off` names this leg: only that receipt may say "this receipt records…"
                     "moved_from": main if (left is not None and j == k) else ""} for j in missing]
            for n in files:
                facts[n]["missing"] = [dict(g, own_move=(g["moved_from"] == n)) for g in gaps]
            gone = "; ".join(_gone(g) for g in gaps)
            if not missing and len(readable) == want:
                extra[main].append((True, EVERY_LEG, f"{want} leg(s) by the conversation's switch count, a readable "
                                                     "receipt here for each"))
            elif missing and not unplaced:
                extra[main].append((None, EVERY_LEG, "not re-checked: " + gone + "; " + UNSIGNED + (
                    " (one possible reason: a record exported before receipts were carried for each leg holds one "
                    "receipt per session)" if len(files) == 1 and left is None else "")))
            else:
                # Something present contradicts something present: a receipt here that is no leg of this conversation.
                extra[main].append((False, EVERY_LEG,
                                    f"{want} leg(s) by the conversation's switch count, {len(files)} receipt file(s) here, "
                                    "and the receipts here do not match its legs one to one"
                                    + "".join(f"; no receipt here is recognisable as leg {j}'s " + (
                                        "(a first leg's receipt is the one with no switch into it)" if j == 1
                                        else "(by its own switch event)") for j in missing)))
            for j, ats in sorted(lost.items()):
                # Never a PASS: these searches are given to no receipt. Not a FAIL either: nothing here contradicts them.
                extra[main].append((None, SEARCHES_IN_MISSING_LEG,
                                    f"not re-checked: {len(ats)} search(es) fall in leg {j} of this conversation, whose "
                                    f"receipt is not in this record, so nothing here shows which machine served them: "
                                    f"{', '.join(ats)[:160]}"))
            continue
        if main not in files or not isinstance(top, dict):
            if any(_leg_number(n) for n in files):
                # Without the last leg's receipt the legs' serving times are unknown, so no search can be placed on one:
                # every search of this session is not re-checked, and none can pass.
                extra[files[0]].append((None, EVERY_LEG, "not re-checked: the last leg's receipt is not in this record, "
                                                         "so this conversation's legs cannot be told apart"))
                if mine:
                    extra[files[0]].append((None, SEARCHES_IN_MISSING_LEG,
                                            f"not re-checked: {len(mine)} search(es) of a conversation whose last leg's "
                                            "receipt is not in this record, so nothing here shows which machine served them"))
                continue
        if len(files) == 1:
            given[files[0]] = mine
            continue
        # Several receipts and no last leg to read the switches from: by each leg's own serving start.
        known = sorted((t, n) for n in files if isinstance(docs.get(n), dict)
                       for t in [_serving_from(docs[n])] if t is not None)
        if not known:
            if mine:
                extra[files[0]].append((False, "searches inside the session's verified window",
                                        f"{len(mine)} search(es) of a session whose receipts give no time to judge them by"))
            continue
        for x in mine:
            t = _parse_time(x.get("at"))
            pick = known[0][1]
            for st, n in known:
                if t is not None and st <= t:
                    pick = n
            given[pick].append(x)
    return given, extra, facts


def leg_facts(bundle_dir: str, searches: Optional[List[dict]] = None) -> Dict[str, Dict[str, Any]]:
    """Per receipt file: whether it is one leg of a conversation that moved between machines (`leg`); for a leg that is
    not the last, when the conversation moved off it (`ends`); and the legs of its conversation whose receipts are not
    in this record, each with how many of `searches` fell in it (`missing`)."""
    return _plan(bundle_dir, searches or [])[2]


def searches_by_receipt(bundle_dir: str, searches: Optional[List[dict]] = None) -> Dict[str, List[dict]]:
    """Which searches each receipt file is judged on (see _plan). A search that falls in a leg with no receipt here is
    given to no file; verify_bundle reports it as not re-checked (SKIP) on the session's last receipt — never a PASS."""
    return _plan(bundle_dir, searches)[0]


def verify_bundle(bundle_dir: str, searches: Optional[List[dict]] = None) -> List[Tuple[str, Checks, bool]]:
    """One (file, checks, ok) per receipt in the record, each judged on its own leg with the searches _plan gives it
    (an unsigned index written by the exporter; the rows then check those searches' TIMES against that receipt), plus
    the session-level rows _plan adds to a conversation's last receipt."""
    out = []
    given, extra, _legs = _plan(bundle_dir, searches)
    for name in receipt_files(bundle_dir):
        try:
            receipt = json.load(open(os.path.join(bundle_dir, name)))
        except Exception as exc:                            # noqa: BLE001
            c = Checks()
            c.add(False, "receipt", f"unreadable ({type(exc).__name__})")
            out.append((name, c, False))
            continue
        c, ok = verify_receipt(receipt, bundle_dir=bundle_dir, searches=given.get(name, []), leg=_legs.get(name))
        for row in extra.get(name, []):
            c.add(*row)
        if extra.get(name):
            ok = not c.failed and not blocking_skips(c)
        out.append((name, c, ok))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Re-check AI-session receipts offline, from an exported record or a receipt file.")
    ap.add_argument("target", help="an exported record directory (session-*.receipt.json + *.attestation.json) or one receipt file")
    a = ap.parse_args(argv)
    try:
        import cryptography
        if int(str(cryptography.__version__).split(".")[0]) < MIN_CRYPTOGRAPHY:
            print(f"REFUSED: cryptography {cryptography.__version__} is too old; this program needs >= {MIN_CRYPTOGRAPHY}")
            return 2
    except Exception:                                       # noqa: BLE001
        print("REFUSED: the `cryptography` package is required (pip install cryptography>=42)")
        return 2
    print("AI session receipts — offline re-check (Intel SGX Root CA, NVIDIA Device Identity CA and NVIDIA Attestation Service "
          "intermediates pinned; InferRoute's recorded builds and offline publication key bundled)")
    if os.path.isdir(a.target):
        searches: List[dict] = []
        try:
            loaded = json.load(open(os.path.join(a.target, "searches.json")))
            searches = loaded if isinstance(loaded, list) else []
        except Exception:                                   # noqa: BLE001
            pass
        results = verify_bundle(a.target, searches)
        if not results:
            print("  no session-*.receipt.json in this directory")
            return 1
    else:
        try:
            receipt = json.load(open(a.target))
        except Exception as exc:                            # noqa: BLE001
            print(f"REFUSED: {a.target} unreadable ({type(exc).__name__})")
            return 2
        c, ok = verify_receipt(receipt, bundle_dir=os.path.dirname(os.path.abspath(a.target)) or ".")
        results = [(os.path.basename(a.target), c, ok)]
    for name, c, ok in results:
        print(f"\n{name}")
        c.dump()
        print(f"  → {'re-checked offline, nothing contradicts the receipt' if ok else ('FAILED: ' + str(len(c.failed)) + ' row(s)' if c.failed else 'INCOMPLETE: ' + str(len(blocking_skips(c))) + ' row(s) could not be re-checked')}")
    return exit_code(results)


def exit_code(results: List[Tuple[str, Checks, bool]]) -> int:
    """1 if ANY receipt has a failed row, else 4 if any could not be fully re-checked, else 0. A FAIL outranks
    an incomplete re-check whatever the numbers: taking the numeric maximum let one incomplete receipt turn
    another receipt's FAIL into exit 4, which reads as "incomplete" (review of 9eecef6, 3 Nov)."""
    if any(c.failed for _, c, _ in results):
        return 1
    return 4 if any(not ok for _, _, ok in results) else 0


if __name__ == "__main__":
    sys.exit(main())
