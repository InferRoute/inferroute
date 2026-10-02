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
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import probant as S

SCHEMA = "inferroute.probant-share/3"        # /2 shares still open: the corpus block is optional
MAX_CORPUS_FILE = 4_000_000                  # one side document; the reading guide of a 9-filing cluster is 47 KB
MAX_CORPUS_TOTAL = 16_000_000
MAX_CORPUS_FILES = 64                        # 4 context files a folder, plus a cluster's matter list and guide
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


def read_card(card: Dict[str, str]) -> str:
    """Derive a card's fingerprint from the keys IN it, refusing anything that is not a card.

    The number is computed here and never taken from the card, because the number a person confirms by
    voice must be one this machine derived. Adding a contact and merely previewing one both come through
    here: a preview that computed the fingerprint its own way could show a number the add step would not
    agree with, and the one being confirmed aloud would be the weaker of the two."""
    if not isinstance(card, dict) or card.get("schema", "inferroute.probant-contact/1") != "inferroute.probant-contact/1":
        raise S.ProbantError("that is not a supported Probant public key card")
    try:
        mlkem_pub, ed_pub = _unb64(card["mlkem_pub"]), _unb64(card["ed_pub"])
    except (KeyError, ValueError, TypeError, AttributeError):
        raise S.ProbantError("that is not a Probant public key: it needs mlkem_pub and ed_pub")
    if len(mlkem_pub) != 1184 or len(ed_pub) != 32:
        raise S.ProbantError("the public keys have the wrong size: expected ML-KEM-768 and Ed25519 keys")
    got = fingerprint(mlkem_pub, ed_pub)
    if card.get("fingerprint") and card["fingerprint"] != got:
        raise S.ProbantError(f"the card's fingerprint {card['fingerprint']} is not the one its keys give "
                              f"({got}) — do not use it")
    return got


def add_contact(name: str, card: Dict[str, str]) -> Dict[str, str]:
    """Record someone you can share with."""
    name = S.sanitize(name, "contact name")
    got = read_card(card)
    known = contacts()
    known[name] = {"mlkem_pub": card["mlkem_pub"], "ed_pub": card["ed_pub"], "fingerprint": got,
                   "added_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    contacts_path().parent.mkdir(parents=True, exist_ok=True)
    contacts_path().write_text(json.dumps(known, indent=1))
    os.chmod(contacts_path(), 0o600)
    return known[name]


def remove_contact(name: str, expected_fingerprint: str) -> None:
    """Forget an address-book entry, leaving identity keys and deliveries intact."""
    name = S.sanitize(name, "contact name")
    known = contacts()
    if name not in known:
        return
    if known[name].get("fingerprint") != expected_fingerprint:
        raise S.ProbantError("this person's key changed: refresh the list before removing them")
    del known[name]
    contacts_path().write_text(json.dumps(known, indent=1))
    os.chmod(contacts_path(), 0o600)


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def seal_to(cards: Any, payload: Dict[str, Any], me: Dict[str, Any]) -> bytes:
    """Sign the payload with our Ed25519 key, then seal it to one or more recipients.

    Signed THEN sealed, so the signature covers what they read: a signature over the ciphertext would prove
    only who sent an opaque blob.

    The claims are encrypted ONCE under a content key, and that key is wrapped separately for each
    recipient. So a share can be addressed to the lawyer AND to yourself without the file growing by the
    size of the claims — and keeping a copy you can reopen is what makes "what exactly did I send him?"
    answerable months later, which for a patent file is not a small thing.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from inferroute_local.confidential import e2ee
    if isinstance(cards, dict):
        cards = [cards]
    signed = {**payload, "from_fingerprint": me["fingerprint"], "from_ed_pub": me["ed_pub"]}
    sk = Ed25519PrivateKey.from_private_bytes(_unb64(me["ed_sk"]))
    signed["sig"] = sk.sign(_canonical(signed)).hex()
    content_key, nonce = os.urandom(32), os.urandom(12)
    body = e2ee._seal(content_key, nonce, json.dumps(signed, ensure_ascii=False).encode())
    recipients = []
    for card in cards:
        shared, ct = e2ee.backend().encaps(_unb64(card["mlkem_pub"]))
        wrap_nonce = os.urandom(12)
        wrapped = e2ee._seal(e2ee.derive_key(shared, ct, b"probant-share-wrap-v1"), wrap_nonce, content_key)
        recipients.append({"fingerprint": card["fingerprint"], "mlkem_ct": _b64(ct),
                           "nonce": _b64(wrap_nonce), "wrapped": _b64(wrapped)})
    return json.dumps({"schema": SCHEMA, "nonce": _b64(nonce), "body": _b64(body),
                       "recipients": recipients}, indent=1).encode()


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
        nonce, body = _unb64(outer["nonce"]), _unb64(outer["body"])
        recipients = outer.get("recipients") or []
    except (ValueError, KeyError, TypeError):
        raise S.ProbantError("that file is not a Probant share")
    mine = next((r for r in recipients if r.get("fingerprint") == me["fingerprint"]), None)
    if mine is None:
        addressed = ", ".join(str(r.get("fingerprint")) for r in recipients) or "nobody"
        raise S.ProbantError(f"this share is addressed to {addressed}, not to this installation "
                              f"({me['fingerprint']})")
    from inferroute_local.confidential import e2ee
    try:
        secret = e2ee.backend().decaps(_secret_key(me), _unb64(mine["mlkem_ct"]))
        content_key = e2ee._open(e2ee.derive_key(secret, _unb64(mine["mlkem_ct"]), b"probant-share-wrap-v1"),
                                 _unb64(mine["nonce"]), _unb64(mine["wrapped"]))
        payload = json.loads(e2ee._open(content_key, nonce, body))
    except Exception as exc:                                   # noqa: BLE001
        raise S.ProbantError(f"this share could not be opened with this installation's key ({type(exc).__name__})")
    signed = {k: v for k, v in payload.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(payload["from_ed_pub"])).verify(
            bytes.fromhex(payload["sig"]), _canonical(signed))
    except (InvalidSignature, KeyError, ValueError):
        raise S.ProbantError("this share's signature does not check out; it was altered or is not what it claims")
    # Your own fingerprint is one you always know: reopening the copy sealed to yourself should not read
    # "an UNKNOWN sender", which is what it said the first time it was tried (20 Sep).
    known = {c["fingerprint"]: name for name, c in contacts().items()}
    known[me["fingerprint"]] = "you (this installation)"
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


def claims_from_cluster(ident: str, limit: int = 2000) -> List[Dict[str, Any]]:
    """The claims corpus a cluster run produced: each with its quote and the document it came from.

    The documents themselves do not travel, so what goes is the hash of each — enough to tell two sources
    apart and to match one later, not enough to re-check the quote. Said plainly in the share.
    """
    from . import probant_cluster as PF
    meta = PF.meta_of(ident)
    by_name = {d["name"]: d for d in meta["documents"]}
    out = []
    for c in PF.candidates(ident)[:limit]:
        doc = by_name.get(c["source"], {})
        out.append({"title": c["title"], "summary": c["summary"], "quote": c["quote"],
                    "source": c["source"], "source_sha256": doc.get("sha256", "")})
    return out


def matter_payload(client: str, matter: str, *, include_marks: bool = False) -> Dict[str, Any]:
    """One matter as it travels: its disclosure, date bound, and optionally the sender's marks.

    The sender's marks travel as the SENDER'S view, recorded as theirs. They do not become the recipient's
    marks — "your marks are yours alone" has to survive a matter changing hands, or the words stop meaning
    anything the moment two people work the same claims.
    """
    rec = S.load_record(client, matter)
    doc = S.workspace_path(client, matter) / "disclosure.md"
    marks: Dict[str, str] = {}
    if include_marks:
        try:
            state = json.loads(S.state_path(client, matter).read_text())
            marks = {k: str((v.get("latest") or {}).get("value", "")) for k, v in (state.get("marks") or {}).items()}
        except (OSError, ValueError, AttributeError):
            marks = {}
    return {"matter": f"{client}/{matter}", "date_bound": rec.get("date_bound", ""),
            "disclosure": doc.read_text(encoding="utf-8")[:200_000] if doc.is_file() else "",
            "marks": marks, "claims": [], "origin": f"matter:{client}/{matter}"}


def cluster_payload(ident: str, limit: int = 2000) -> Dict[str, Any]:
    from . import probant_cluster as PF
    return {"matter": f"cluster {ident}", "date_bound": "", "disclosure": "",
            "marks": {}, "claims": claims_from_cluster(ident, limit), "origin": f"cluster:{ident}"}


def corpus_files(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    """Side documents that belong to the DELIVERY rather than to any one matter.

    A matter list and a reading guide describe a cluster as a whole; there was nowhere for them to travel,
    so they would have gone as plain email attachments — carrying verbatim quotes from every filing and from
    the UNFILED surplus. That is the disclosure this product exists to prevent, and the fix is not to warn
    about it but to give the corpus somewhere to put them, inside the same seal as the matters.

    Text only, and said so: these are read by a person, not re-verified by a machine.
    """
    out: List[Dict[str, Any]] = []
    total = 0
    for path in paths:
        p = Path(path)
        if not p.is_file():
            raise S.ProbantError(f"no such file to include: {p}")
        raw = p.read_bytes()
        if len(raw) > MAX_CORPUS_FILE:
            raise S.ProbantError(f"{p.name} is {len(raw) / 1e6:.1f} MB; a corpus document may be up to "
                                  f"{MAX_CORPUS_FILE / 1e6:.0f} MB")
        total += len(raw)
        if total > MAX_CORPUS_TOTAL:
            raise S.ProbantError("those documents come to more than this share carries; send fewer")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise S.ProbantError(f"{p.name} is not text; a corpus document travels as text a person reads") from e
        out.append({"name": re.sub(r"[^A-Za-z0-9._ -]+", "-", p.name)[:80] or "document.txt",
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "text": text})
    return out


def build_share(matters: List[Dict[str, Any]], note: str = "", files: Optional[List[Dict[str, Any]]] = None,
                corpus_name: str = "") -> Dict[str, Any]:
    """A corpus of matters in one share: several matters, one file, one signature, one key exchange.

    One matter at a time was the first shape, and it is the wrong unit for the job — handing a cluster to
    counsel means handing over everything at once, not fifteen files and fifteen confirmations.

    The corpus also carries an IDENTITY and its own side documents. The identity is what lets the recipient
    tell three things apart that otherwise blur into one folder: the matters that arrived in this delivery,
    the documents that describe the delivery as a whole, and the matters they go on to create themselves.
    Without it, work done on top of someone else's corpus is indistinguishable from the corpus.
    """
    if not matters:
        raise S.ProbantError("there is nothing to share")
    corpus = {"id": f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}",
              "name": (corpus_name or "shared corpus")[:80], "files": list(files or [])}
    return {"schema": SCHEMA, "matters": matters, "corpus": corpus, "note": note[:2000],
            "made_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence": ("Each claim carries a verbatim quote and the sha256 of the document it came from. "
                         "Those documents are NOT in this share, so the Probant that opens it cannot "
                         "re-check a quote against its source; the sender's signature covers the claims as "
                         "written, and nothing here proves a quote is in the document it names.")}


def _matter_document(entry: Dict[str, Any], payload: Dict[str, Any], who: str) -> str:
    lines = [f"# {entry.get('matter') or 'Shared matter'}", "",
             f"Shared by {who} on {payload.get('made_at', '')}, opened as this matter.", ""]
    if payload.get("note"):
        lines += [payload["note"], ""]
    if entry.get("disclosure"):
        lines += ["## Disclosure, as shared", "", entry["disclosure"], ""]
    if entry.get("claims"):
        lines += ["## Claims", ""]
        for i, c in enumerate(entry["claims"], 1):
            lines += [f"### {i}. {c.get('title', '')}", "", str(c.get("summary", "")), "",
                      f"> {c.get('quote', '')}", "",
                      f"From {c.get('source', 'an unnamed document')}"
                      + (f" (sha256 {c.get('source_sha256', '')[:16]}…)" if c.get("source_sha256") else ""), ""]
    if entry.get("marks"):
        lines += ["## What the sender marked", "",
                  f"These are {who}'s judgements, travelling as theirs. Your own marks are separate.", ""]
        for key, value in sorted(entry["marks"].items()):
            lines += [f"- {key}: {str(value).replace('-', ' ')}"]
        lines += [""]
    lines += ["## About this evidence", "", payload.get("evidence", ""), ""]
    return "\n".join(lines)


def corpus_dir(client: str) -> Path:
    """Where a delivery's own documents live: beside the matters, named so nobody mistakes them for one.

    Not inside a matter, because they describe the whole corpus, and not under confidential/, because the
    recipient is meant to READ them.
    """
    return S.probant_root() / S.sanitize(client, "client") / "shared-corpus"


def corpora_record(corpus_id: str) -> Path:
    return S._irhome() / "confidential" / "corpora" / f"{re.sub(r'[^A-Za-z0-9-]+', '-', corpus_id)[:60]}.json"


def write_corpus(payload: Dict[str, Any], client: str) -> Dict[str, Any]:
    """Write the delivery's side documents and record the delivery itself. Returns what was written.

    Each file is checked against the sha256 the sender put beside it — not proof of anything about the
    document's CONTENT, which only the sender's signature covers, but it catches a file that did not
    survive the trip, which otherwise shows up as a silently short reading guide.
    """
    corpus = payload.get("corpus") or {}
    files = corpus.get("files") or []
    if not corpus:
        return {"id": "", "written": [], "corpus": {}}

    # THE SAME LIMITS ON THE WAY IN AS ON THE WAY OUT. corpus_files() bounds a delivery when WE build one,
    # which bounds nothing about one we are handed: the count and the sizes in an incoming payload are the
    # sender's, and a sender who assembles a payload by hand never calls that function. Unbounded, opening a
    # delivery writes whatever it names into the recipient's own directory. Checked before anything is
    # written, so a refusal leaves nothing half-opened.
    if len(files) > MAX_CORPUS_FILES:
        raise S.ProbantError(f"this delivery carries {len(files)} documents; a corpus carries up to "
                             f"{MAX_CORPUS_FILES}. Nothing was written \u2014 ask the sender what it is.")
    total = 0
    for f in files:
        size = len(str(f.get("text") or "").encode("utf-8"))
        name = str(f.get("name") or "document.txt")
        if size > MAX_CORPUS_FILE:
            raise S.ProbantError(f"{name} is {size / 1e6:.1f} MB; a corpus document may be up to "
                                 f"{MAX_CORPUS_FILE / 1e6:.0f} MB. Nothing was written.")
        total += size
        if total > MAX_CORPUS_TOTAL:
            raise S.ProbantError(f"this delivery's documents come to more than {MAX_CORPUS_TOTAL / 1e6:.0f} MB. "
                                 "Nothing was written \u2014 ask the sender to send fewer.")
    d = corpus_dir(client)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)

    # RE-OPENING THE SAME DELIVERY REPLACES ITS OWN FILES, it does not accumulate them. The record for a
    # corpus id is overwritten by this open, so the files the previous open of THIS delivery wrote would
    # otherwise be left behind belonging to no record — and with the collision suffixing below they would be
    # kept rather than overwritten, which turns a tidy overwrite into an unattributable copy of the quotes.
    # Only this sender's own previous open is cleared: the id comes from the sender, so a different signer
    # reusing someone's corpus id must not be able to delete their files.
    prior = corpora_record(str(corpus.get("id") or "unnamed"))
    try:
        was = json.loads(prior.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        was = {}
    if was.get("from") and was.get("from") == payload.get("from_fingerprint"):
        for name in was.get("files") or []:
            old_file = d / str(name)
            if old_file.is_file() and old_file.parent.resolve() == d.resolve():
                old_file.unlink()

    written = []
    for f in files:
        name = re.sub(r"[^A-Za-z0-9._ -]+", "-", str(f.get("name") or "document.txt"))[:80] or "document.txt"
        raw = str(f.get("text") or "").encode("utf-8")
        said = str(f.get("sha256") or "")
        if said and hashlib.sha256(raw).hexdigest() != said:
            raise S.ProbantError(f"{name} did not arrive as it was sent (its hash does not match); "
                                  "ask for the share again rather than reading a truncated document")
        # TWO DOCUMENTS MAY ARRIVE UNDER ONE NAME. Two folders each hold a reading-guide.md, two cluster runs
        # each hold a MATTERS.txt — and the name travels from the SENDER, so it is also the easy way to make
        # this record lie: send two files called the same thing and the second overwrites the first while the
        # record still claims two arrived. Keep both, and let the record name what is actually on disk.
        out = d / name
        if name in written or out.exists():
            stem, dot, ext = name.rpartition(".")
            n = 2
            while True:
                alt = f"{stem or name}-{n}{dot}{ext}" if dot else f"{name}-{n}"
                if alt not in written and not (d / alt).exists():
                    name, out = alt, d / alt
                    break
                n += 1
        out.write_bytes(raw)
        os.chmod(out, 0o600)
        written.append(name)
    record = {"schema": "inferroute.probant-corpus/1", "id": corpus.get("id", ""),
              "name": corpus.get("name", ""), "client": client,
              "from": payload.get("from_fingerprint"), "from_name": payload.get("from_name"),
              "known_contact": payload.get("from_known"), "made_at": payload.get("made_at"),
              "note": payload.get("note", ""), "files": written,
              "matters": [e.get("matter") for e in (payload.get("matters") or [])],
              "opened_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    rec = corpora_record(record["id"] or "unnamed")
    rec.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(rec.parent, 0o700)
    rec.write_text(json.dumps(record, indent=1))
    os.chmod(rec, 0o600)
    return {"id": record["id"], "written": written, "corpus": record, "dir": str(d)}


def record_sent(payload: dict, to: str, fingerprint: str, dest: Path) -> Path:
    """Record a delivery on the SENDER's side.

    Only the receiving path wrote a corpus record, so the person who MADE a delivery kept no trace of it:
    what went, to whom, when, with which documents. For the user that is the audit trail of their own
    outbound disclosure, and it is the first thing they would be asked to produce. Henry, on his own
    machine after sealing a real corpus: "can I see it in the client" — and he could not, because nothing
    had been written.
    """
    c = (payload.get("corpus") or {})
    cid = str(c.get("id") or "")
    if not cid:
        return Path()
    rec = {"schema": "inferroute.probant-corpus/1", "id": cid, "name": c.get("name") or "",
           "direction": "sent", "to": to, "to_fingerprint": fingerprint,
           "made_at": c.get("made_at") or "", "note": payload.get("note") or "",
           "files": [f.get("name") for f in (c.get("files") or []) if f.get("name")],
           # `matter` in a payload entry already reads "client/matter"; prefixing client again produced
           # "None/InferRoute/attest-dynamics" the first time this printed.
           "matters": [str(e.get("matter")) for e in (payload.get("matters") or []) if e.get("matter")],
           "sealed_to": str(dest)}
    out = corpora_record(cid)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec, indent=1) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)
    return out


def corpora() -> list:
    """Every corpus this installation holds, newest first.

    The records were written from the day corpora existed and nothing ever read them back: a corpus could
    be made, sent, received and opened, and there was no way to SEE one. Henry, twice: "I didn't see the
    corpus integration in the client." The object was real; it had no surface.
    """
    d = corpora_record("x").parent
    out = []
    for f in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(r, dict) and r.get("id"):
            out.append(r)
    out.sort(key=lambda r: str(r.get("made_at") or ""), reverse=True)
    return out


def origin_of(client: str, matter: str) -> dict:
    """The corpus a matter arrived in or was tied to, or {}."""
    f = S.records_dir(S.sanitize(client, "client"), S.sanitize(matter, "matter")) / "corpus-origin.json"
    try:
        r = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return r if isinstance(r, dict) else {}


def note_corpus_origin(client: str, matter: str, corpus_id: str, how: str = "created here") -> Path:
    """Mark a matter as belonging to, or derived from, a delivery.

    Two different facts, kept apart on purpose: a matter that ARRIVED in the corpus, and one the recipient
    created afterwards while reading it. Both trace to the same delivery; only the first is the sender's
    work, and conflating them would let someone else's claims acquire your authorship, or yours theirs.
    """
    c, m = S.sanitize(client, "client"), S.sanitize(matter, "matter")
    rd = S.records_dir(c, m)
    rd.mkdir(parents=True, exist_ok=True)
    out = rd / "corpus-origin.json"
    out.write_text(json.dumps({"schema": "inferroute.probant-corpus-origin/1", "corpus": corpus_id,
                               "how": how,
                               "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, indent=1))
    os.chmod(out, 0o600)
    return out


def create_matters_from_share(payload: Dict[str, Any], client: str,
                              rename: Optional[Dict[str, str]] = None) -> List[str]:
    """Open every matter in a share, under one client of the recipient's choosing.

    Each keeps the name it was shared under (as a safe path component) and its own date bound, because the
    bound decides what any search of it may return. A name already taken is reported, not overwritten.
    """
    who = payload.get("from_name") or payload.get("from_fingerprint", "an unknown sender")
    made: List[str] = []
    taken: List[str] = []
    for entry in payload.get("matters") or []:
        raw = (rename or {}).get(entry.get("matter", ""), "") or str(entry.get("matter") or "shared")
        name = re.sub(r"[^A-Za-z0-9 ._-]+", "-", raw.split("/")[-1]).strip(" -.")[:60] or "shared-matter"
        if S.record_path(S.sanitize(client, "client"), name).exists():
            taken.append(name)
            continue
        date = entry.get("date_bound") or ""
        if S.cmd_new(client, name, date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else None) != 0:
            taken.append(name)
            continue
        c, m = S.sanitize(client, "client"), S.sanitize(name, "matter")
        doc = S.workspace_path(c, m) / "disclosure.md"
        doc.write_text(_matter_document(entry, payload, who), encoding="utf-8")
        os.chmod(doc, 0o600)
        provenance = {"schema": "inferroute.probant-share-origin/1", "from": payload.get("from_fingerprint"),
                      "from_name": payload.get("from_name"), "known_contact": payload.get("from_known"),
                      "made_at": payload.get("made_at"), "shared_as": entry.get("matter"),
                      "date_bound": entry.get("date_bound"), "claims": len(entry.get("claims") or []),
                      "marks_shared": len(entry.get("marks") or {}),
                      "opened_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        rd = S.records_dir(c, m)
        rd.mkdir(parents=True, exist_ok=True)
        (rd / "shared-origin.json").write_text(json.dumps(provenance, indent=1))
        os.chmod(rd / "shared-origin.json", 0o600)
        if (payload.get("corpus") or {}).get("id"):
            note_corpus_origin(c, m, payload["corpus"]["id"], how="arrived in this corpus")
        made.append(f"{c}/{m}")
    if taken:
        raise S.ProbantError(f"opened {len(made)}; these names are already taken in {client}: "
                              f"{', '.join(taken)} — rename or delete them and open the share again")
    return made
