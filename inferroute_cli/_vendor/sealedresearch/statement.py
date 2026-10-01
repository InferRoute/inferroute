"""Signed statements: the enclave's own account of a run, verifiable under a key born inside it.

Split out of enclave_job so the open-source client (which must verify statements) never imports the
enclave code. Canonical JSON — sorted keys, no whitespace — so signer and verifier agree byte for byte.
The Ed25519 public key is bound into the attestation's REPORT_DATA, which is what lets a firm trust it:
they read it out of a hardware-signed report, never out of a file we hand them. HOW it is bound depends on
the lane: the self-hosted lane folds it through snp.binding (length-prefixed SHA-512 over six fields); the
Azure ACI lane commits it as `statement_signer_pub` inside runtime_data, with REPORT_DATA = SHA-256(
runtime_data) ‖ 32 zero bytes (aci_evidence.report_data_for). sign_statement / verify_statement are the
same for both.
"""
from __future__ import annotations

import json
from typing import Any, Dict


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_statement(sign_path: str, statement: Dict[str, Any]) -> Dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    with open(sign_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    return {**statement, "sig": key.sign(canonical(statement)).hex()}


def verify_statement(pub_raw: bytes, signed: Dict[str, Any]) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    s = dict(signed)
    try:
        sig = bytes.fromhex(s.pop("sig"))
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, canonical(s))
        return True
    except Exception:            # noqa: BLE001 — any failure is a refusal, never a partial pass
        return False
