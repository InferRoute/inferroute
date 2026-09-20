"""Handing a corpus of claims to another Probant user — a lawyer, a co-counsel, a colleague.

The recipient opens it as a REAL matter: their own sessions, their own sealed searches on their own account,
their own marks and their own exported records. What travels is the claims and their evidence, sealed so
that only they can open it and signed so they know it is yours and unaltered.

The shape, and why each part is there:

* **An identity per installation.** An ML-KEM-768 key to receive shares and an Ed25519 key to sign them,
  with a short fingerprint you read to each other once, out of band. Nothing secret ever travels: you
  encrypt TO their public key, so a share can be sent through any channel that would carry an email.
* **Signed, then sealed.** The signature covers the claims, the date bound and the sender's fingerprint, so
  a share cannot be altered in flight or attributed to someone else. Sealing is the same ML-KEM-768 +
  ChaCha20-Poly1305 the confidential lane uses — one crypto vocabulary in this product, not two.
* **The date bound travels inside the signature.** It decides what a search may return, so it must arrive
  as the sender set it. The recipient sees it on opening; changing it afterwards is a recorded change of
  their own matter, as it already is for a matter they created.
* **The source documents do NOT travel.** Each claim carries its verbatim quote and the sha256 of the
  document it came from. The recipient's Probant therefore cannot re-check a quote against its source the
  way the sender's could, and says so plainly rather than implying a verification it did not do.

What this is not: a shared live matter. Two people working one matter needs merge rules and per-participant
provenance on every mark; sharing back is the same act in the other direction, which is enough until the
round trip is actually wanted.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import probant as S

SCHEMA = "inferroute.probant-share/1"
SUFFIX = ".probant-share"


def identity_dir() -> Path:
    return S._irhome() / "confidential" / "identity"


def _b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode()


def _unb64(text: str) -> bytes:
    import base64
    return base64.b64decode(text.encode(), validate=True)


def fingerprint(mlkem_pub: bytes, ed_pub: bytes) -> str:
    """What two people read to each other on the phone. Short enough to say, long enough to mean it."""
    digest = hashlib.sha256(b"probant-identity-v1" + mlkem_pub + ed_pub).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def identity(create: bool = True) -> Dict[str, Any]:
    """This installation's identity, created on first use. Secret keys never leave this directory."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from inferroute_local.confidential import e2ee
    d = identity_dir()
    path = d / "identity.json"
    if path.is_file():
        held = json.loads(path.read_text())
        return {**held, "mlkem_pub_raw": _unb64(held["mlkem_pub"]), "ed_pub_raw": _unb64(held["ed_pub"])}
    if not create:
        raise S.ProbantError("this installation has no Probant identity yet: run `ir probant identity`")
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    # How the secret is STORED depends on the backend, because only one of them can reload what it made:
    # OpenSSL's ML-KEM key offers no from_private_bytes, only from_seed_bytes, so there we generate from a
    # seed we keep; kyber-py round-trips its raw decapsulation key. The PUBLIC key is standard either way,
    # so two installations on different backends can still share with each other.
    seed = ""
    if e2ee.backend().name.startswith("cryptography"):
        from cryptography.hazmat.primitives.asymmetric import mlkem
        raw_seed = os.urandom(64)
        sk_obj = mlkem.MLKEM768PrivateKey.from_seed_bytes(raw_seed)
        mlkem_pub, mlkem_sk_raw, seed = sk_obj.public_key().public_bytes_raw(), b"", _b64(raw_seed)
    else:
        mlkem_pub, mlkem_sk = e2ee.backend().keygen()
        mlkem_sk_raw = bytes(mlkem_sk)
    ed = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    ed_pub = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed_sk = ed.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    held = {"schema": "inferroute.probant-identity/1",
            "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mlkem_pub": _b64(bytes(mlkem_pub)), "mlkem_sk": _b64(bytes(mlkem_sk_raw)), "mlkem_seed": seed,
            "ed_pub": _b64(ed_pub), "ed_sk": _b64(ed_sk),
            "fingerprint": fingerprint(bytes(mlkem_pub), ed_pub)}
    path.write_text(json.dumps(held, indent=1))
    os.chmod(path, 0o600)
    return {**held, "mlkem_pub_raw": bytes(mlkem_pub), "ed_pub_raw": ed_pub}


def public_card(me: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """What you send someone so they can share with you: public keys and the fingerprint, nothing else."""
    me = me or identity()
    return {"schema": "inferroute.probant-contact/1", "mlkem_pub": me["mlkem_pub"], "ed_pub": me["ed_pub"],
            "fingerprint": me["fingerprint"]}


def contacts_path() -> Path:
    return identity_dir() / "contacts.json"


def contacts() -> Dict[str, Dict[str, str]]:
    try:
        return json.loads(contacts_path().read_text())
    except (OSError, ValueError):
        return {}


def add_contact(name: str, card: Dict[str, str]) -> Dict[str, str]:
    """Record someone you can share with. Their fingerprint is computed HERE from the keys they sent, never
    taken from the card: the number you confirm by phone must be one this machine derived."""
    name = S.sanitize(name, "contact name")
    try:
        mlkem_pub, ed_pub = _unb64(card["mlkem_pub"]), _unb64(card["ed_pub"])
    except (KeyError, ValueError, TypeError):
        raise S.ProbantError("that is not a Probant contact card: it needs mlkem_pub and ed_pub")
    got = fingerprint(mlkem_pub, ed_pub)
    if card.get("fingerprint") and card["fingerprint"] != got:
        raise S.ProbantError(f"the card's fingerprint {card['fingerprint']} is not the one its keys give "
                              f"({got}) — do not use it")
    known = contacts()
    known[name] = {"mlkem_pub": card["mlkem_pub"], "ed_pub": card["ed_pub"], "fingerprint": got,
                   "added_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    contacts_path().parent.mkdir(parents=True, exist_ok=True)
    contacts_path().write_text(json.dumps(known, indent=1))
    os.chmod(contacts_path(), 0o600)
    return known[name]


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def seal_to(card: Dict[str, str], payload: Dict[str, Any], me: Dict[str, Any]) -> bytes:
    """Sign the payload with our Ed25519 key, then seal it to their ML-KEM key.

    Signed THEN sealed, so the signature covers what they read: a signature over the ciphertext would prove
    only who sent an opaque blob.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from inferroute_local.confidential import e2ee
    signed = {**payload, "from_fingerprint": me["fingerprint"], "from_ed_pub": me["ed_pub"]}
    sk = Ed25519PrivateKey.from_private_bytes(_unb64(me["ed_sk"]))
    signed["sig"] = sk.sign(_canonical(signed)).hex()
    shared, ct = e2ee.backend().encaps(_unb64(card["mlkem_pub"]))
    key = e2ee.derive_key(shared, ct, b"probant-share-v1")
    nonce = os.urandom(12)
    body = e2ee._seal(key, nonce, json.dumps(signed, ensure_ascii=False).encode())
    return json.dumps({"schema": SCHEMA, "mlkem_ct": _b64(ct), "nonce": _b64(nonce), "body": _b64(body),
                       "to_fingerprint": card["fingerprint"]}, indent=1).encode()


def open_sealed(blob: bytes, me: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Open a share addressed to us, and say who signed it and whether we know them.

    A signature that verifies proves the payload is as its sender wrote it. Whether that sender is who you
    think requires the fingerprint you confirmed out of band — so an unknown sender is reported, never
    silently accepted.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from inferroute_local.confidential import e2ee
    me = me or identity(create=False)
    try:
        outer = json.loads(blob)
        ct, nonce, body = _unb64(outer["mlkem_ct"]), _unb64(outer["nonce"]), _unb64(outer["body"])
    except (ValueError, KeyError, TypeError):
        raise S.ProbantError("that file is not a Probant share")
    if outer.get("to_fingerprint") and outer["to_fingerprint"] != me["fingerprint"]:
        raise S.ProbantError(f"this share is addressed to {outer['to_fingerprint']}, not to this "
                              f"installation ({me['fingerprint']})")
    backend = e2ee.backend()
    try:
        secret = backend.decaps(_secret_key(me), ct)
        payload = json.loads(e2ee._open(e2ee.derive_key(secret, ct, b"probant-share-v1"), nonce, body))
    except Exception as exc:                                   # noqa: BLE001
        raise S.ProbantError(f"this share could not be opened with this installation's key ({type(exc).__name__})")
    signed = {k: v for k, v in payload.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(payload["from_ed_pub"])).verify(
            bytes.fromhex(payload["sig"]), _canonical(signed))
    except (InvalidSignature, KeyError, ValueError):
        raise S.ProbantError("this share's signature does not check out; it was altered or is not what it claims")
    known = {c["fingerprint"]: name for name, c in contacts().items()}
    payload["from_name"] = known.get(payload.get("from_fingerprint", ""), "")
    payload["from_known"] = bool(payload["from_name"])
    return payload


def _secret_key(me: Dict[str, Any]):
    """The decapsulation key in whatever form this backend can use: rebuilt from the stored seed under
    OpenSSL, the stored raw key under kyber-py."""
    if me.get("mlkem_seed"):
        from cryptography.hazmat.primitives.asymmetric import mlkem
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(_unb64(me["mlkem_seed"]))
    return _unb64(me["mlkem_sk"])


def claims_from_portfolio(ident: str, limit: int = 2000) -> List[Dict[str, Any]]:
    """The claims corpus a portfolio run produced: each with its quote and the document it came from.

    The documents themselves do not travel, so what goes is the hash of each — enough to tell two sources
    apart and to match one later, not enough to re-check the quote. Said plainly in the share.
    """
    from . import probant_portfolio as PF
    meta = PF.meta_of(ident)
    by_name = {d["name"]: d for d in meta["documents"]}
    out = []
    for c in PF.candidates(ident)[:limit]:
        doc = by_name.get(c["source"], {})
        out.append({"title": c["title"], "summary": c["summary"], "quote": c["quote"],
                    "source": c["source"], "source_sha256": doc.get("sha256", "")})
    return out


def build_share(claims: List[Dict[str, Any]], *, matter: str, date_bound: str, note: str = "",
                origin: str = "") -> Dict[str, Any]:
    return {"schema": SCHEMA, "matter": matter, "date_bound": date_bound, "note": note[:2000],
            "origin": origin, "claims": claims,
            "made_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence": ("Each claim carries a verbatim quote and the sha256 of the document it came from. "
                         "Those documents are NOT in this share, so the Probant that opens it cannot "
                         "re-check a quote against its source; the sender's signature covers the claims as "
                         "written, and nothing here proves the quote is in the document it names.")}


def create_matter_from_share(payload: Dict[str, Any], client: str, matter: str) -> str:
    """Open a share as a real matter: the recipient's own, with the sender's date bound and a note saying
    where it came from. From here it is an ordinary matter — their sessions, their searches, their records."""
    date = payload.get("date_bound") or None
    rc = S.cmd_new(client, matter, date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(date or "")) else None)
    if rc != 0:
        raise S.ProbantError("the matter could not be created")
    client, matter = S.sanitize(client, "client"), S.sanitize(matter, "matter")
    who = payload.get("from_name") or payload.get("from_fingerprint", "an unknown sender")
    lines = [f"# {payload.get('matter') or matter}", "",
             f"Shared by {who} on {payload.get('made_at', '')}, opened as this matter.", ""]
    if payload.get("note"):
        lines += [payload["note"], ""]
    lines += ["## Claims", ""]
    for i, c in enumerate(payload.get("claims") or [], 1):
        lines += [f"### {i}. {c.get('title', '')}", "", str(c.get("summary", "")), "",
                  f"> {c.get('quote', '')}", "",
                  f"From {c.get('source', 'an unnamed document')}"
                  + (f" (sha256 {c.get('source_sha256', '')[:16]}…)" if c.get("source_sha256") else ""), ""]
    lines += ["## About this evidence", "", payload.get("evidence", ""), ""]
    doc = S.workspace_path(client, matter) / "disclosure.md"
    doc.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(doc, 0o600)
    provenance = {"schema": "inferroute.probant-share-origin/1", "from": payload.get("from_fingerprint"),
                  "from_name": payload.get("from_name"), "known_contact": payload.get("from_known"),
                  "made_at": payload.get("made_at"), "date_bound": payload.get("date_bound"),
                  "claims": len(payload.get("claims") or []), "opened_at": dt.datetime.now(dt.timezone.utc)
                  .strftime("%Y-%m-%dT%H:%M:%SZ")}
    p = S.records_dir(client, matter)
    p.mkdir(parents=True, exist_ok=True)
    (p / "shared-origin.json").write_text(json.dumps(provenance, indent=1))
    os.chmod(p / "shared-origin.json", 0o600)
    return f"{client}/{matter}"
