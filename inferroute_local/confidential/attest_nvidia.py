"""NVIDIA side of the attestation: the GPUs' own attestation reports, verified by NVIDIA's
Remote Attestation Service (NRAS) and checked for this session's challenge.

The enclave's evidence carries one SPDM attestation report per GPU plus its certificate chain.
The report was generated for a challenge the enclave derives as SHA-256(our nonce ‖ its ML-KEM
public key) — the same derivation the TDX quote commits to — so a report that matches that
challenge was produced for THIS session, by the enclave that holds the key we seal to.

NRAS (https://nras.attestation.nvidia.com/v3/attest/gpu) parses each report, verifies its
signature and certificate chain against NVIDIA's roots, fetches the driver and VBIOS Reference
Integrity Manifests and compares the measured values, checks secure boot and debug state, and
returns its verdict as EAT JWTs signed with ES384. We verify those signatures against NVIDIA's
published JWKS and require, per GPU: report parsed, signature verified, cert chain validated,
nonce matched, driver RIM and VBIOS RIM validated with measurements matching, no debug, secure
boot on — and the overall verdict true with `eat_nonce` equal to our challenge.

What is sent to NVIDIA: the GPU attestation reports and certificates (hardware measurements) and
the challenge. Nothing about the user or the conversation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field

from .attest import Check

NRAS = "https://nras.attestation.nvidia.com"
UA = "inferroute-confidential/1 (+native verifier, no SDK)"
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


def challenge(nonce: str, e2e_pubkey_b64: str) -> str:
    """The GPU (and TDX) challenge the enclave derives from our nonce and its own key."""
    return hashlib.sha256((nonce + e2e_pubkey_b64).encode()).hexdigest()


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_parts(tok: str) -> tuple[dict, dict, bytes, bytes]:
    h, p, s = tok.split(".")
    return json.loads(_b64u(h)), json.loads(_b64u(p)), _b64u(s), f"{h}.{p}".encode()


def verify_jwt(tok: str, jwks: dict) -> tuple[dict, str]:
    """(claims, error). ES384 over header.payload under the JWKS key named by `kid`."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    try:
        hdr, claims, sig, signed = jwt_parts(tok)
    except Exception:
        return {}, "token is not a JWT"
    if hdr.get("alg") != "ES384":
        return {}, f"unexpected JWT alg {hdr.get('alg')}"
    k = next((k for k in jwks.get("keys", []) if k.get("kid") == hdr.get("kid")), None)
    if k is None or k.get("kty") != "EC" or k.get("crv") != "P-384":
        return {}, "JWT key id not in NVIDIA's JWKS"
    try:
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64u(k["x"]), "big"), int.from_bytes(_b64u(k["y"]), "big"), ec.SECP384R1()).public_key()
        pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")), signed, ec.ECDSA(hashes.SHA384()))
    except Exception:
        return {}, "JWT signature does not verify under NVIDIA's key"
    now = time.time()
    if claims.get("exp") and claims["exp"] < now:
        return {}, "NVIDIA verdict token expired"
    if claims.get("iss") != NRAS:
        return {}, f"unexpected issuer {claims.get('iss')}"
    return claims, ""


@dataclass
class GpuVerdict:
    ok: bool
    why: str
    n_gpus: int = 0
    hwmodel: str = ""
    driver: str = ""
    vbios: str = ""
    warnings: list = field(default_factory=list)
    per_gpu: dict = field(default_factory=dict)


def evaluate(resp, jwks: dict, expected_nonce: str) -> GpuVerdict:
    """Pure: the NRAS response body (a JSON list: [["JWT", overall], {gpu: token…}]) → verdict."""
    try:
        overall_tok = resp[0][1]
        per = resp[1]
    except Exception:
        return GpuVerdict(False, "unexpected NRAS response shape")
    oc, err = verify_jwt(overall_tok, jwks)
    if err:
        return GpuVerdict(False, f"overall verdict: {err}")
    if oc.get("eat_nonce") != expected_nonce:
        return GpuVerdict(False, "NVIDIA's verdict is for a different challenge")
    if oc.get("x-nvidia-overall-att-result") is not True:
        details = []
        for name, tok in (per or {}).items():
            try:
                c = jwt_parts(tok)[1]
                details.append(f"{name}: {c.get('x-nvidia-error-details') or {k: v for k, v in c.items() if k.startswith('x-nvidia') and v is False}}")
            except Exception:
                details.append(f"{name}: unreadable")
        return GpuVerdict(False, "NVIDIA overall result false — " + "; ".join(details)[:300])
    gpus: dict = {}
    models, drivers, vbioses, warns = set(), set(), set(), []
    for name, tok in (per or {}).items():
        c, err = verify_jwt(tok, jwks)
        if err:
            return GpuVerdict(False, f"{name}: {err}")
        if c.get("eat_nonce") != expected_nonce:
            return GpuVerdict(False, f"{name}: verdict is for a different challenge")
        bad = [k for k in REQUIRED_GPU_CLAIMS if c.get(k) is not True]
        if c.get("measres") != "success":
            bad.append("measres")
        if c.get("dbgstat") != "disabled":
            bad.append("debug-enabled")
        if c.get("secboot") is not True:
            bad.append("secure-boot-off")
        if bad:
            return GpuVerdict(False, f"{name}: failed {', '.join(bad)}")
        w = c.get("x-nvidia-attestation-warning")
        if w and str(w).lower() != "none":
            warns.append(f"{name}: {w}")
        models.add(str(c.get("hwmodel", "")))
        drivers.add(str(c.get("x-nvidia-gpu-driver-version", "")))
        vbioses.add(str(c.get("x-nvidia-gpu-vbios-version", "")))
        gpus[name] = {"hwmodel": c.get("hwmodel"), "ueid": str(c.get("ueid", ""))[-12:], "driver": c.get("x-nvidia-gpu-driver-version"), "vbios": c.get("x-nvidia-gpu-vbios-version")}
    if not gpus:
        return GpuVerdict(False, "NVIDIA returned no per-GPU verdicts")
    why = (f"{len(gpus)}× {'/'.join(sorted(models))} · driver {'/'.join(sorted(drivers))} · VBIOS {'/'.join(sorted(vbioses))} · "
           f"measurements match NVIDIA's reference manifests · challenge matched · secure boot on, debug off")
    return GpuVerdict(True, why, len(gpus), "/".join(sorted(models)), "/".join(sorted(drivers)), "/".join(sorted(vbioses)), warns, gpus)


_JWKS: dict = {}
_JWKS_AT = 0.0


async def fetch_jwks(http, timeout: float = 30.0) -> dict:
    global _JWKS, _JWKS_AT
    if _JWKS and time.time() - _JWKS_AT < 3600:
        return _JWKS
    r = await http.get(f"{NRAS}/.well-known/jwks.json", headers={"User-Agent": UA}, timeout=timeout)
    r.raise_for_status()
    _JWKS, _JWKS_AT = r.json(), time.time()
    return _JWKS


async def attest_gpus(http, gpu_evidence: list, nonce: str, e2e_pubkey_b64: str, timeout: float = 120.0) -> GpuVerdict:
    """Submit the enclave's GPU evidence to NRAS for this session's challenge and evaluate."""
    if not gpu_evidence:
        return GpuVerdict(False, "no GPU evidence in the attestation")
    arch = str(gpu_evidence[0].get("arch") or "")
    if not arch:
        return GpuVerdict(False, "GPU evidence carries no architecture")
    expected = challenge(nonce, e2e_pubkey_b64)
    payload = {"nonce": expected, "arch": arch, "claims_version": "3.0",
               "evidence_list": [{"evidence": g.get("evidence"), "certificate": g.get("certificate")} for g in gpu_evidence]}
    jwks = await fetch_jwks(http)
    r = await http.post(f"{NRAS}/v3/attest/gpu", json=payload, headers={"User-Agent": UA}, timeout=timeout)
    if r.status_code != 200:
        return GpuVerdict(False, f"NVIDIA attestation service answered {r.status_code}: {r.text[:120]}")
    return evaluate(r.json(), jwks, expected)


def check_from(v: GpuVerdict) -> Check:
    return Check(v.ok, v.why)
