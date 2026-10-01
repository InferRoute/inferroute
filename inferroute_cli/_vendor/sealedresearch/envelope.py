"""The envelope: how a disclosure reaches the enclave and how a report reaches the firm.

Deliberately boring cryptography, chosen so the client can be ported to browser WebCrypto in a few
hundred lines with no library: X25519 key agreement, HKDF-SHA256, ChaCha20-Poly1305. No HPKE
dependency, no negotiation, one version byte.

Two directions, one primitive:

    firm  --seal(enclave_pub, disclosure)-->  enclave      plaintext exists only inside the TEE
    enclave --seal(firm_pub, report)------->  firm         the operator cannot read the findings

The enclave's keypair is generated INSIDE the TEE and its public key is bound into the attestation's
REPORT_DATA (see snp.binding), so the firm's client can prove the key it encrypts to was born in a
measured enclave before releasing a single byte of plaintext. That order — verify, then encrypt — is
the whole design, and it is why the client holds the plaintext locally until an attested enclave
exists rather than uploading to anything that promises to forward it.

Wire format (all lengths fixed, no parsing ambiguity):

    version(1) ‖ ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext+tag(N+16)

`aad` binds the blob to a context (job id, direction) so a ciphertext for one job cannot be replayed
as another's. Both sides must pass the same aad or open() fails.
"""
from __future__ import annotations

import os
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = b"\x01"
_INFO = b"sealed-research/envelope/v1"


class EnvelopeError(ValueError):
    """Refused to open: wrong key, tampered bytes, or wrong context. Never partially decrypts."""


def gen_keypair() -> Tuple[bytes, bytes]:
    """(private_raw32, public_raw32). Call this INSIDE the enclave; the private half never leaves it."""
    priv = X25519PrivateKey.generate()
    return (priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption()),
            priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _derive(shared: bytes, eph_pub: bytes, recipient_pub: bytes, aad: bytes) -> bytes:
    # Salt over both public keys so the derived key is bound to this exact pairing, not just the
    # shared secret; info carries the context so a key for one job cannot open another's.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=_INFO + b"|" + aad).derive(shared)


def seal(recipient_pub: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(recipient_pub) != 32:
        raise EnvelopeError("recipient public key must be 32 raw X25519 bytes")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    key = _derive(shared, eph_pub, recipient_pub, aad)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return VERSION + eph_pub + nonce + ct


def open_(recipient_priv: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 1 + 32 + 12 + 16:
        raise EnvelopeError("blob too short to be an envelope")
    if blob[:1] != VERSION:
        raise EnvelopeError(f"unsupported envelope version {blob[0]}")
    eph_pub, nonce, ct = blob[1:33], blob[33:45], blob[45:]
    priv = X25519PrivateKey.from_private_bytes(recipient_priv)
    my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _derive(shared, eph_pub, my_pub, aad)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        # One error for every failure mode on purpose: distinguishing "wrong key" from "tampered"
        # from "wrong aad" to a caller is an oracle, and none of them should ever be retried.
        raise EnvelopeError("refused: authentication failed") from exc
