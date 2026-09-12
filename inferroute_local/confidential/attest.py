"""Verify an enclave instance's attestation ON THIS DEVICE, with no vendor SDK.

Evidence is fetched from the enclave operator directly — never through InferRoute, because the
point of the check is that the user does not have to trust InferRoute (or the operator) about it:

    GET <operator evidence endpoint>?nonce={64 hex}   (unauthenticated)
    GET <operator measurement registry>                (unauthenticated)

Both addresses come from the operator profile the carrier hands us (see ``transport.py``); none
is compiled into this client, and none needs to be trusted — every byte they return is checked
below against Intel's pinned root, Intel's and NVIDIA's own services, and our recorded builds.

Per running instance the evidence carries an Intel TDX ``quote``, NVIDIA ``gpu_evidence``, a
``certificate``, a ``signature`` and a base64-JSON ``attested_body`` that embeds our nonce.

Each check states what it proves. The display prints these words; keep them honest.

  nonce_in_body   our 32-byte nonce appears verbatim in the decoded attested body
                  → the evidence was produced FOR THIS CHALLENGE, not replayed.
  sig_ok          ``signature`` verifies (RSA-PKCS1v15/SHA-256 or ECDSA) over the body under
                  the public key in ``certificate`` → whoever answered holds that private key.
  spki_bound      TDX report_data[32:64] == SHA-256(SubjectPublicKeyInfo of ``certificate``)
                  → the hardware quote COMMITS to that key. With sig_ok this is the
                  load-bearing link: the party that signed for our nonce is the party the
                  quote is about.
  tdx_shape       tee_type 0x81, quote version 4, TD DEBUG attribute clear → a real
                  confidential VM, not a debuggable one whose measurements mean nothing.
  measurement_ok  MRTD and RTMR0–3 all appear in ONE config of the published registry
                  → the VM runs a build the provider publishes, not an arbitrary image.
  chain_ok        every certificate in the quote's embedded PCK chain verifies under the
                  next, ending in a self-signed root → the chain is internally sound.
  e2e_key_bound   TDX report_data[0:32] == SHA-256(our nonce ‖ the instance's ML-KEM public key
                  as served by /e2e/instances) → the hardware quote COMMITS to the encryption
                  key we seal to. The operator's evidence service derives the quote's challenge exactly
                  this way (`sha256((nonce + e2e_pubkey).encode())` in its open-source runtime,
                  measured live 2026-09-12 on 8/8 instances, negative on every other key). This
                  closes the join between "attested" and "encrypted to": a substituted key
                  fails here before a byte is sent.

What this does NOT prove (rendered by the display as stated limitations, never as checks):
  * that the attested GPUs are physically the ones serving this VM — their reports answered this
    session's challenge and travel inside the enclave-signed evidence, so the attested software
    vouches for the pairing; there is no separate hardware proof of it.
  Online (attest_intel.py / attest_nvidia.py, added by `verify_online`): quote signature and QE
  binding, Intel root pin, CRLs, TCB and QE currency from Intel PCS; every GPU's report verified
  by NVIDIA's attestation service for this session's challenge.

Fail-closed: a check that cannot be performed is False with a reason, never absent, and an
instance is ``verified`` only when every REQUIRED check passed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field

UA = "inferroute-confidential/1 (+native verifier, no SDK)"

# TDX quote v4 (Intel DCAP): 48-byte header, then a 584-byte TD report body.
_HDR, _BODY = 48, 584
_OFF = {
    "td_attributes": (120, 128), "mrtd": (136, 184), "rtmr0": (328, 376),
    "rtmr1": (376, 424), "rtmr2": (424, 472), "rtmr3": (472, 520), "report_data": (520, 584),
}
REQUIRED = ("nonce_in_body", "sig_ok", "spki_bound", "e2e_key_bound", "tdx_shape", "measurement_ok", "build_recorded", "chain_ok")
# Online checks (Intel PCS + NVIDIA NRAS), added by `verify_online`; an instance is verified only
# when BOTH sets pass. Kept separate so the offline pass can run over a whole fleet cheaply and the
# online pass only over the instances a session could actually use.
REQUIRED_ONLINE = ("quote_sig", "root_pinned", "not_revoked", "tcb_current", "qe_current", "gpu_in_signed_evidence", "gpu_verified")

# Plain-language labels + the one line of "why it matters" the display prints beside each.
LABELS: dict[str, tuple[str, str]] = {
    "nonce_in_body": ("Fresh challenge answered", "the evidence was made for this session, not replayed"),
    "sig_ok": ("Signature valid", "signed by the key the enclave holds"),
    "spki_bound": ("Signing key bound to enclave", "the hardware quote commits to that signing key"),
    "e2e_key_bound": ("Encryption key bound to enclave", "the quote commits to SHA-256(challenge ‖ the key you seal to)"),
    "tdx_shape": ("Genuine TDX, debug off", "a real confidential VM, not a debuggable one"),
    "measurement_ok": ("Published build", "measurements match the operator's published registry"),
    "build_recorded": ("Recorded build", "a build InferRoute has recorded and watches — not only the operator's word"),
    "chain_ok": ("Certificate chain sound", "every link verifies up to a self-signed root"),
    "quote_sig": ("Quote signed by the hardware", "Intel's Quoting Enclave signed it; the signature verifies"),
    "root_pinned": ("Intel root of trust", "the chain ends in Intel's published SGX Root CA"),
    "not_revoked": ("Nothing revoked", "no certificate in the chain is on Intel's revocation lists"),
    "tcb_current": ("Platform firmware current", "Intel's signed TCB status for this platform is up to date"),
    "qe_current": ("Quoting Enclave current", "matches Intel's signed identity, at an up-to-date version"),
    "gpu_in_signed_evidence": ("GPU reports inside the signed evidence", "the reports NVIDIA checked are the bytes the enclave signed for this challenge"),
    "gpu_verified": ("GPUs verified by NVIDIA", "each GPU's report checked by NVIDIA for this session's challenge"),
}

LIMITATIONS = (
    ("build-review", "InferRoute records the enclave builds it has seen and refuses unrecorded ones; independent "
                     "reproduction of the recorded image is in progress, so today the image's contents rest on the "
                     "operator's published sources."),
    ("metadata-visible", "Message sizes, timing, model and instance id are visible to relays; "
                         "the words are not."),
)


@dataclass
class Check:
    ok: bool
    why: str


@dataclass
class InstanceReport:
    instance_id: str
    checks: dict[str, Check]
    gpu_count: int
    mrtd: str
    rtmrs: list[str]
    verified: bool
    chain: str = ""
    e2e_pubkey: str = ""     # the ML-KEM key (base64) the quote was found to commit to; "" if unchecked
    gpus: dict = field(default_factory=dict)   # per-GPU {hwmodel, ueid, driver, vbios} once NVIDIA verified them

    @property
    def failing(self) -> list[str]:
        return [k for k in REQUIRED + REQUIRED_ONLINE if k in self.checks and not self.checks[k].ok]

    @property
    def online_done(self) -> bool:
        return all(k in self.checks for k in REQUIRED_ONLINE)

    def as_dict(self) -> dict:
        return {
            "instance_id": self.instance_id, "verified": self.verified, "gpu_count": self.gpu_count,
            "mrtd": self.mrtd, "rtmrs": self.rtmrs, "chain": self.chain, "e2e_pubkey": self.e2e_pubkey, "gpus": self.gpus,
            "checks": {k: {"ok": c.ok, "why": c.why} for k, c in self.checks.items()},
        }


@dataclass
class FleetReport:
    fleet_id: str
    nonce: str
    instances: list[InstanceReport]
    failed_instance_ids: list = field(default_factory=list)
    raw: list = field(default_factory=list)      # the evidence rows, for the online pass

    @property
    def verified_ids(self) -> list[str]:
        return [i.instance_id for i in self.instances if i.verified]

    def as_dict(self) -> dict:
        return {"fleet_id": self.fleet_id, "nonce": self.nonce,
                "verified": len(self.verified_ids), "instances": [i.as_dict() for i in self.instances],
                "failed_instance_ids": self.failed_instance_ids}


# ───────────────────────────── parsing ─────────────────────────────

def _b64(s: str) -> bytes:
    s = (s or "").strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def quote_fields(quote_b: bytes) -> dict:
    """Structural parse; {} when the buffer is too short to BE a v4 TDX quote."""
    if len(quote_b) < _HDR + _BODY:
        return {}
    body = quote_b[_HDR:_HDR + _BODY]
    out = {"version": int.from_bytes(quote_b[0:2], "little"),
           "tee_type": int.from_bytes(quote_b[4:8], "little")}
    for k, (a, b) in _OFF.items():
        out[k] = body[a:b]
    return out


def body_bytes(attested_body) -> tuple[bytes, str]:
    """``attested_body`` is base64 of a JSON document; the nonce lives in the DECODED bytes and the
    signature covers them (measured 2026-09-02). Both forms are tried and the one that verified is
    named, because a verifier that silently accepts either has not established what was signed."""
    raw = attested_body.encode() if isinstance(attested_body, str) else (attested_body or b"")
    try:
        dec = base64.b64decode(raw + b"=" * (-len(raw) % 4), validate=True)
        if dec[:1] in (b"{", b"["):
            return dec, "base64-decoded JSON"
    except Exception:
        pass
    return raw, "raw bytes"


def _load_cert(s: str):
    from cryptography import x509
    if not s:
        return None
    try:
        t = s if "BEGIN CERT" in s else ("-----BEGIN CERTIFICATE-----\n" + s.strip() + "\n-----END CERTIFICATE-----\n")
        return x509.load_pem_x509_certificate(t.encode())
    except Exception:
        try:
            return x509.load_der_x509_certificate(_b64(s))
        except Exception:
            return None


def _cn(cert) -> str:
    from cryptography.x509.oid import NameOID
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return cert.subject.rfc4514_string()[:40]


# ───────────────────────────── checks ─────────────────────────────

def check_nonce(attested_body, nonce: str) -> Check:
    dec, form = body_bytes(attested_body)
    ok = bool(nonce) and nonce.encode() in dec
    return Check(ok, f"nonce present verbatim in the {form}" if ok else "OUR NONCE IS ABSENT — evidence may be replayed")


def check_signature(attested_body, signature_b64: str, cert_s: str) -> Check:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    cert = _load_cert(cert_s)
    if cert is None:
        return Check(False, "certificate did not parse")
    pub = cert.public_key()
    try:
        sig = _b64(signature_b64)
    except Exception:
        return Check(False, "signature is not base64")
    raw = attested_body.encode() if isinstance(attested_body, str) else (attested_body or b"")
    dec, form = body_bytes(attested_body)
    for data, label in ((dec, form), (raw, "raw base64 string")):
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            else:
                return Check(False, f"unsupported key type {type(pub).__name__}")
            return Check(True, f"verifies over the {label} ({len(data)} B)")
        except Exception:
            continue
    return Check(False, "signature does NOT verify over the decoded body or the raw string")


def check_spki_bound(q: dict, cert_s: str) -> Check:
    from cryptography.hazmat.primitives import serialization
    if not q:
        return Check(False, "no quote to bind")
    cert = _load_cert(cert_s)
    if cert is None:
        return Check(False, "certificate did not parse")
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    want, got = hashlib.sha256(spki).digest(), q["report_data"][32:64]
    return Check(got == want, "report_data[32:64] == SHA-256(SPKI)" if got == want
                 else f"MISMATCH: quote {got.hex()[:16]}… vs SPKI hash {want.hex()[:16]}…")


def check_e2e_key_bound(q: dict, nonce: str, e2e_pubkey_b64: str | None) -> Check:
    """report_data[0:32] must equal SHA-256 of the nonce string concatenated with the base64
    ML-KEM public key string — the exact derivation the operator's evidence service uses."""
    if not q:
        return Check(False, "no quote to bind")
    if not e2e_pubkey_b64:
        return Check(False, "no encryption key supplied to bind (instance not listed by /e2e/instances)")
    want = hashlib.sha256((nonce + e2e_pubkey_b64).encode()).digest()
    got = q["report_data"][:32]
    return Check(got == want, "report_data[0:32] == SHA-256(nonce ‖ e2e_pubkey)" if got == want
                 else f"MISMATCH: the quote does not commit to this encryption key ({got.hex()[:16]}… vs {want.hex()[:16]}…)")


def check_tdx_shape(q: dict) -> Check:
    if not q:
        return Check(False, "buffer too short to be a v4 TDX quote")
    if q["tee_type"] != 0x81:
        return Check(False, f"tee_type 0x{q['tee_type']:02x} is not TDX (0x81)")
    if q["version"] != 4:
        return Check(False, f"quote version {q['version']} is not 4")
    if q["td_attributes"][0] & 0x01:
        return Check(False, "TD DEBUG bit is SET — a debuggable TD's measurements prove nothing")
    return Check(True, "TDX v4, debug bit clear")


def check_build_recorded(q: dict) -> Check:
    """MRTD + RTMR1..3 must be a build InferRoute has recorded (builds.py). Unknown → refused,
    unless IR_CONFIDENTIAL_ALLOW_NEW_BUILD=1 (then passes with a warning the panel shows)."""
    from . import builds
    if not q:
        return Check(False, "no quote to match")
    rtmrs = [q[k].hex() for k in ("rtmr0", "rtmr1", "rtmr2", "rtmr3")]
    b = builds.lookup(q["mrtd"].hex(), rtmrs)
    if b is not None:
        st = b.get("status", "observed")
        return Check(True, f"build {b.get('id', '?')} — {'reviewed by InferRoute' if st == 'reviewed' else 'recorded by InferRoute since ' + str(b.get('first_seen', '?'))}")
    if builds.allow_new_builds():
        return Check(True, "NEW BUILD — not yet recorded by InferRoute (allowed by IR_CONFIDENTIAL_ALLOW_NEW_BUILD)")
    return Check(False, "the operator is running an enclave build InferRoute has not recorded yet (usually recorded within hours; "
                        "IR_CONFIDENTIAL_ALLOW_NEW_BUILD=1 opens anyway with a warning)")


def check_measurements(q: dict, reference) -> Check:
    """MRTD and all four RTMRs must appear TOGETHER in one published reference config."""
    if not q:
        return Check(False, "no quote to match")
    mine = {k: q[k].hex() for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    configs = reference.get("configs") if isinstance(reference, dict) else None
    if isinstance(configs, list) and configs:
        for cfg in configs:
            blob = json.dumps(cfg).lower()
            if all(v in blob for v in mine.values()):
                return Check(True, f"MRTD + RTMR0–3 all present in registry config '{cfg.get('name', '?')}'")
        return Check(False, f"no single registry config holds all five measurements ({len(configs)} configs)")
    blob = json.dumps(reference).lower()
    missing = [k for k, v in mine.items() if v not in blob]
    return Check(not missing, "MRTD + RTMR0–3 all present in the registry" if not missing
                 else f"not in the published registry: {', '.join(missing)}")


def embedded_chain(quote_b: bytes) -> list:
    from cryptography import x509
    out, beg, end = [], b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    i = quote_b.find(beg)
    while i != -1:
        j = quote_b.find(end, i)
        if j == -1:
            break
        j += len(end)
        try:
            out.append(x509.load_pem_x509_certificate(quote_b[i:j]))
        except Exception:
            pass
        i = quote_b.find(beg, j)
    return out


def check_chain(certs: list) -> Check:
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    if not certs:
        return Check(False, "no certificates embedded in the quote")

    def signed_by(child, parent) -> bool:
        pub = parent.public_key()
        try:
            if isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
            else:
                pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
            return True
        except Exception:
            return False

    for a, b in zip(certs, certs[1:]):
        if not signed_by(a, b):
            return Check(False, f"link broken: {_cn(a)} is not signed by {_cn(b)}")
    if not signed_by(certs[-1], certs[-1]):
        return Check(False, f"root {_cn(certs[-1])} is not self-signed")
    return Check(True, "chain internally sound: " + " → ".join(_cn(c) for c in certs))


# ───────────────────────────── verdicts ─────────────────────────────

def verify_instance(inst: dict, nonce: str, reference, e2e_pubkey_b64: str | None = None) -> InstanceReport:
    body = inst.get("attested_body") or ""
    quote_b = _b64(inst.get("quote") or "")
    q = quote_fields(quote_b)
    certs = embedded_chain(quote_b)
    checks = {
        "nonce_in_body": check_nonce(body, nonce),
        "sig_ok": check_signature(body, inst.get("signature") or "", inst.get("certificate") or ""),
        "spki_bound": check_spki_bound(q, inst.get("certificate") or ""),
        "e2e_key_bound": check_e2e_key_bound(q, nonce, e2e_pubkey_b64),
        "tdx_shape": check_tdx_shape(q),
        "measurement_ok": check_measurements(q, reference),
        "build_recorded": check_build_recorded(q),
        "chain_ok": check_chain(certs),
    }
    return InstanceReport(
        instance_id=str(inst.get("instance_id") or ""),
        checks=checks,
        gpu_count=len(inst.get("gpu_evidence") or []),
        mrtd=q["mrtd"].hex() if q else "",
        rtmrs=[q[k].hex() for k in ("rtmr0", "rtmr1", "rtmr2", "rtmr3")] if q else [],
        verified=all(checks[k].ok for k in REQUIRED),
        chain=" → ".join(_cn(c) for c in certs),
        e2e_pubkey=(e2e_pubkey_b64 or "") if checks["e2e_key_bound"].ok else "",
    )


def verify_fleet(fleet_id: str, evidence_doc, reference, nonce: str,
                 e2e_pubkeys: dict[str, str] | None = None) -> FleetReport:
    """``e2e_pubkeys``: instance_id → base64 ML-KEM key as served by /e2e/instances. Without it
    the e2e_key_bound check cannot run and NO instance verifies (fail-closed)."""
    inst = evidence_doc.get("evidence") if isinstance(evidence_doc, dict) else evidence_doc
    keys = e2e_pubkeys or {}
    rows = [verify_instance(i, nonce, reference, keys.get(str(i.get("instance_id") or ""))) for i in (inst or [])]
    failed = evidence_doc.get("failed_instance_ids") if isinstance(evidence_doc, dict) else None
    return FleetReport(fleet_id=fleet_id, nonce=nonce, instances=rows, failed_instance_ids=list(failed or []), raw=list(inst or []))


def new_nonce() -> str:
    return secrets.token_hex(32)





async def fetch_and_verify(fleet_id: str, http, profile, nonce: str | None = None, timeout: float = 240.0,
                           e2e_pubkeys: dict[str, str] | None = None) -> FleetReport:
    """Fetch evidence + registry FROM THE OPERATOR DIRECTLY with a fresh nonce, then verify offline.
    ``http`` is an ``httpx.AsyncClient``; ``profile`` is the carrier's operator profile (where the
    evidence lives); the 1–2 MB evidence document takes ~10 s to arrive.
    ``e2e_pubkeys`` (instance_id → key) lets the quote be checked against the key we will seal
    to; the session passes the keys it just fetched, so the SAME key is verified and used."""
    nonce = nonce or new_nonce()
    h = {"User-Agent": UA}
    ref = (await _get_retry(http, profile.measurements_url(), h, timeout)).json()
    r = await _get_retry(http, profile.evidence_url(fleet_id, nonce), h, timeout)
    return verify_fleet(fleet_id, r.json(), ref, nonce, e2e_pubkeys)


async def _get_retry(http, url: str, headers: dict, timeout: float, attempts: int = 4):
    """GET with backoff on 429 / 5xx (Retry-After honoured, capped): the evidence document is
    ~1.7 MB per fleet and the provider rate-limits it; one busy minute must not refuse a session."""
    import asyncio
    delay = 2.0
    for i in range(attempts):
        r = await http.get(url, headers=headers, timeout=timeout)
        if r.status_code == 429 or 500 <= r.status_code < 600:
            if i == attempts - 1:
                r.raise_for_status()
            try:
                wait = min(float(r.headers.get("Retry-After") or delay), 20.0)
            except ValueError:
                wait = delay
            await asyncio.sleep(wait)
            delay = min(delay * 2, 20.0)
            continue
        r.raise_for_status()
        return r
    r.raise_for_status()
    return r


def signed_gpu_evidence(inst: dict) -> list:
    """The GPU evidence list as it sits INSIDE the signed attested body (`evidence.nvtrust_evidence`,
    a JSON string), or [] when absent/unparseable."""
    try:
        body = json.loads(body_bytes(inst.get("attested_body") or "")[0])
        nv = (body.get("evidence") or {}).get("nvtrust_evidence")
        if isinstance(nv, str):
            nv = json.loads(nv)
        return list(nv) if isinstance(nv, list) else []
    except Exception:
        return []


async def verify_online(report: InstanceReport, inst: dict, nonce: str, http, timeout: float = 120.0) -> InstanceReport:
    """Add the Intel PCS + NVIDIA NRAS checks to an offline-verified report (in place) and recompute
    `verified`. Never raises: an unreachable service is a failed check with the reason named."""
    from . import attest_intel, attest_nvidia
    quote_b = _b64(inst.get("quote") or "")
    certs = embedded_chain(quote_b)
    ck = report.checks
    try:
        ck["quote_sig"] = attest_intel.check_quote_signature(quote_b, certs)
        ext = attest_intel.pck_extension(certs[0]) if certs else {}
        if not ext.get("fmspc"):
            for k in ("root_pinned", "not_revoked", "tcb_current", "qe_current"):
                ck[k] = Check(False, "PCK certificate has no SGX extension (no FMSPC)")
        else:
            col = await attest_intel.fetch_collateral(http, ext["fmspc"], attest_intel.ca_kind(certs), timeout=timeout)
            ck.update(attest_intel.platform_checks(quote_b, certs, col))
    except Exception as e:
        for k in ("quote_sig", "root_pinned", "not_revoked", "tcb_current", "qe_current"):
            ck.setdefault(k, Check(False, f"Intel collateral unavailable: {type(e).__name__}: {str(e)[:80]}"))
    # The GPU reports are taken from INSIDE the quote-signed attested body (nonce_in_body + sig_ok
    # + spki_bound cover those bytes), never from the loose `gpu_evidence` field — so what NVIDIA
    # verifies is exactly what the enclave signed for this challenge. The loose copy must agree.
    signed_gpu = signed_gpu_evidence(inst)
    loose = inst.get("gpu_evidence") or []
    if not signed_gpu:
        ck["gpu_in_signed_evidence"] = Check(False, "the signed attested body carries no GPU evidence")
    elif loose and loose != signed_gpu:
        ck["gpu_in_signed_evidence"] = Check(False, "the GPU evidence outside the signed body DIFFERS from the signed copy")
    else:
        ck["gpu_in_signed_evidence"] = Check(True, f"{len(signed_gpu)} GPU report(s) read from the enclave-signed body (the copy the quote-bound key signed)")
    try:
        v = await attest_nvidia.attest_gpus(http, signed_gpu, nonce, report.e2e_pubkey, timeout=timeout)
        ck["gpu_verified"] = attest_nvidia.check_from(v)
        report.gpus = v.per_gpu if v.ok else {}
    except Exception as e:
        ck["gpu_verified"] = Check(False, f"NVIDIA attestation service unavailable: {type(e).__name__}: {str(e)[:80]}")
    report.verified = all(ck[k].ok for k in REQUIRED + REQUIRED_ONLINE if k in ck) and report.online_done
    return report
