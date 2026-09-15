"""`ir surveyor reference` — issue the out-of-band reference that lets a record say "InferRoute's enclave".

THIS IS THE OPERATOR'S SIDE OF THE PROOF, not the attorney's. A record bundle proves, on its own, that a
genuine AMD SEV-SNP container ran inside Microsoft's utility VM. It proves the container was OURS only when
the reader compares the container-policy hash and the index / encoder manifest hashes against values they
obtained from InferRoute through a channel they already trust. These commands produce and sign those values.

    ir surveyor reference new-key   --out KEY        once, on an OFFLINE machine; prints the public key
    ir surveyor reference build     --from-offer F   derive the values from a deployment YOU control
    ir surveyor reference retire    --value HEX      withdraw an entry (an explicit act, never a silent swap)
    ir surveyor reference sign      --key KEY        on the OFFLINE machine that holds the key
    ir surveyor reference verify    --key-hex HEX    what a firm sees; also a check before you publish

Three rules the tooling enforces or states, because getting them wrong silently is the failure mode:

 1. `policy_sha256` is HOST_DATA as the hardware reports it (bytes 0xC0..0xE0 of the SNP report), read from
    a real offer — never transcribed by hand. When the offer also carries the policy, SHA-256 of the decoded
    policy must equal HOST_DATA or the build is REFUSED.
 2. Derive from a deployment YOU control. Deriving a reference from a bundle a client sent you is circular:
    it would make the record validate against itself.
 3. A new release does not make the old one acceptable forever. `--supersede` closes every still-open
    validity window at the new entry's start, so a retired or superseded release cannot pass as current.

The signature is Ed25519 over the canonical JSON of the reference with `sig` removed — byte-for-byte the
same canonicalisation the bundled verifier uses (a test asserts the two agree, including on non-ASCII).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FIELDS = ("policy_sha256", "index_manifest_sha256", "model_manifest_sha256")
HOST_DATA_OFF, HOST_DATA_END = 0xC0, 0xE0
REPORT_LEN = 1184


class ReferenceError(ValueError):
    pass


def canonical(obj: Any) -> bytes:
    """Identical to the bundled verifier's canonical(): sorted keys, no spaces, non-ASCII kept as-is."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s: Any) -> Optional[dt.datetime]:
    """ISO-8601 → aware UTC. Matches the verifier: trailing Z normalised, offsets honoured, naive = UTC."""
    if not isinstance(s, str) or not s.strip():
        return None
    t = s.strip()
    if t[-1] in "Zz":
        t = t[:-1] + "+00:00"
    try:
        d = dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)


def _require_time(s: Optional[str], what: str) -> Optional[str]:
    if s is None:
        return None
    if parse_time(s) is None:
        raise ReferenceError(f"{what} {s!r} is not an ISO-8601 time (e.g. 2026-09-15T00:00:00Z)")
    return s


# ───────────────────────────── deriving the values from a real deployment ─────────────────────────────


def values_from_offer(path: str) -> Dict[str, str]:
    """HOST_DATA and the manifest hashes, read from a deployment's own attestation offer.

    Accepts a raw `/offer` document or an evidence bundle `{"offer": {...}, "policy_b64": ...}`. When the
    policy is present it MUST hash to HOST_DATA — a mismatch means the policy on file is not the policy the
    hardware attested, which is exactly the confusion this reference exists to prevent.
    """
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise ReferenceError(f"cannot read an offer from {path}: {e}") from e
    offer = doc.get("offer") if isinstance(doc.get("offer"), dict) else doc
    if not isinstance(offer, dict):
        raise ReferenceError(f"{path} does not contain an offer object")
    try:
        report = base64.b64decode(offer["evidence"], validate=True)
        if len(report) != REPORT_LEN:
            raise ValueError(f"the report is {len(report)} bytes, expected {REPORT_LEN}")
        host_data = report[HOST_DATA_OFF:HOST_DATA_END].hex()
        rd = json.loads(base64.b64decode(offer["runtime_data"], validate=True))
        if not isinstance(rd, dict):
            raise ValueError("runtime_data is not a JSON object")
    except (KeyError, ValueError, TypeError) as e:
        raise ReferenceError(f"{path} is not a usable offer ({type(e).__name__}: {e})") from e

    policy_b64 = doc.get("policy_b64") or offer.get("policy_b64")
    if policy_b64:
        try:
            got = hashlib.sha256(base64.b64decode(policy_b64)).hexdigest()
        except Exception as e:                                   # noqa: BLE001
            raise ReferenceError(f"the policy in {path} is not valid base64") from e
        if got != host_data:
            raise ReferenceError(
                "REFUSING: the policy in this file does not hash to the HOST_DATA the hardware reported "
                f"(policy sha256 {got}, HOST_DATA {host_data}). The policy on file is not the policy that "
                "was attested; publishing it as the reference would anchor identity to the wrong value.")

    out = {"policy_sha256": host_data}
    for ref_field, rd_field in (("index_manifest_sha256", "index_manifest_sha256"),
                                ("model_manifest_sha256", "model_manifest_sha256")):
        v = rd.get(rd_field)
        if not (isinstance(v, str) and len(v) == 64 and v.lower() != "0" * 64):
            raise ReferenceError(f"the offer's runtime data has no usable {rd_field} (got {v!r})")
        out[ref_field] = v.lower()
    return out


# ───────────────────────────── building, superseding, retiring ─────────────────────────────


def _entries(ref: Dict[str, Any], field: str) -> List[Dict[str, Any]]:
    """Normalise a field's entries to objects, preserving order."""
    out: List[Dict[str, Any]] = []
    for e in ref.get(field, []) or []:
        if isinstance(e, str):
            out.append({"value": e.lower()})
        elif isinstance(e, dict) and isinstance(e.get("value"), str):
            out.append({k: v for k, v in e.items() if v not in (None, "")} | {"value": e["value"].lower()})
    return out


def build(values: Dict[str, str], *, merge: Optional[Dict[str, Any]] = None, valid_from: Optional[str] = None,
          valid_to: Optional[str] = None, source: Optional[str] = None, supersede: bool = False,
          note: Optional[str] = None) -> Dict[str, Any]:
    """Create or extend a reference. `supersede` closes every still-open window at `valid_from`, so the
    previous release stops being acceptable the moment this one starts."""
    _require_time(valid_from, "--valid-from")
    _require_time(valid_to, "--valid-to")
    if supersede and not valid_from:
        raise ReferenceError("--supersede needs --valid-from: it closes the previous entries' windows at the "
                             "moment this release starts, so there must be a moment to close them at")
    missing = [f for f in FIELDS if not values.get(f)]
    if missing:
        raise ReferenceError(f"refusing to write a reference missing {missing}: it would fail identity for "
                             "every record a client verifies")

    ref: Dict[str, Any] = dict(merge or {})
    ref.pop("sig", None)                                          # any edit invalidates a previous signature
    for field in FIELDS:
        existing = _entries(ref, field)
        if supersede:
            for e in existing:
                if not e.get("retired") and not e.get("valid_to"):
                    e["valid_to"] = valid_from
        fresh: Dict[str, Any] = {"value": values[field].lower()}
        if valid_from:
            fresh["valid_from"] = valid_from
        if valid_to:
            fresh["valid_to"] = valid_to
        if not any(e == fresh for e in existing):
            existing.append(fresh)
        ref[field] = existing
    ref["schema"] = "inferroute.enclave-reference/1"
    if source:
        ref["source"] = source
    if note:
        ref["note"] = note
    ref.setdefault("source", "InferRoute")
    ref["published_at"] = _utcnow()
    return ref


def retire(ref: Dict[str, Any], value: str, *, field: Optional[str] = None, at: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
    """Mark matching entries retired (and close an open window at `at`). Returns (reference, n_retired)."""
    _require_time(at, "--at")
    ref = dict(ref)
    ref.pop("sig", None)
    v = value.lower()
    n = 0
    for f in ([field] if field else list(FIELDS)):
        if f not in FIELDS:
            raise ReferenceError(f"unknown field {f!r}; expected one of {', '.join(FIELDS)}")
        entries = _entries(ref, f)
        for e in entries:
            if e["value"] == v and not e.get("retired"):
                e["retired"] = True
                if at and not e.get("valid_to"):
                    e["valid_to"] = at
                n += 1
        ref[f] = entries
    if not n:
        raise ReferenceError(f"no entry with value {value} was found to retire")
    ref["published_at"] = _utcnow()
    return ref, n


# ───────────────────────────── the publication key ─────────────────────────────


def new_key(out_path: str, *, passphrase: Optional[bytes] = None) -> str:
    """Generate the long-lived publication key. Returns the public key hex — the value that goes in the
    engagement letter and that every firm records at first use."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    p = Path(out_path)
    if p.exists():
        raise ReferenceError(f"{p} already exists; refusing to overwrite a publication key")
    key = Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _load_key(path: str, passphrase: Optional[bytes]):
    from cryptography.hazmat.primitives import serialization
    try:
        return serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    except TypeError as e:
        raise ReferenceError(f"{path} is encrypted; give the passphrase with --passphrase-env VAR") from e
    except ValueError as e:
        raise ReferenceError(f"cannot load the publication key from {path}: {e}") from e


def sign(ref: Dict[str, Any], key_path: str, *, passphrase: Optional[bytes] = None) -> Dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = _load_key(key_path, passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise ReferenceError(f"{key_path} is not an Ed25519 key")
    # The public key is recorded INSIDE the signed body, so a reader can see which key they should already
    # hold — but it proves nothing on its own: the check is against the key they recorded at first use.
    body = {k: v for k, v in ref.items() if k != "sig"}
    body["publication_key"] = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return {**body, "sig": key.sign(canonical(body)).hex()}


def verify(ref: Dict[str, Any], key_hex: Optional[str]) -> Tuple[bool, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    sig = ref.get("sig")
    if not sig:
        return False, "this reference is unsigned"
    if not key_hex:
        return False, ("this reference is signed but no publication key was given; record InferRoute's key at "
                       "first use and pass --key-hex")
    body = {k: v for k, v in ref.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(str(sig)), canonical(body))
    except Exception:                                            # noqa: BLE001
        return False, f"the signature does NOT verify under {key_hex[:16]}…"
    return True, f"verifies under the publication key {key_hex[:16]}…"


def describe(ref: Dict[str, Any], at_iso: Optional[str] = None) -> List[str]:
    """One line per entry, saying whether it is current at `at` (default: now)."""
    at = parse_time(at_iso) or dt.datetime.now(dt.timezone.utc)
    lines = [f"reference from {ref.get('source') or '(unnamed)'}, published {ref.get('published_at') or '?'}"
             f" — status at {at.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
    for field in FIELDS:
        entries = _entries(ref, field)
        lines.append(f"  {field}:" + ("" if entries else "  (none — identity will FAIL for every record)"))
        for e in entries:
            vf, vt = parse_time(e.get("valid_from")), parse_time(e.get("valid_to"))
            if e.get("retired"):
                status = "RETIRED"
            elif not (e.get("valid_from") or e.get("valid_to")):
                status = "current (no window)"
            elif (e.get("valid_from") and vf is None) or (e.get("valid_to") and vt is None):
                status = "UNPARSABLE WINDOW — will fail"
            elif vf is not None and at < vf:
                status = f"not yet current (from {e['valid_from']})"
            elif vt is not None and at > vt:
                status = f"expired (to {e['valid_to']})"
            else:
                status = "current"
            window = f"  [{e.get('valid_from') or '…'} → {e.get('valid_to') or '…'}]" if (e.get("valid_from") or e.get("valid_to")) else ""
            lines.append(f"    {e['value']}  {status}{window}")
    return lines


# ───────────────────────────── command line ─────────────────────────────


def _read(path: str) -> Dict[str, Any]:
    try:
        d = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise ReferenceError(f"cannot read a reference from {path}: {e}") from e
    if not isinstance(d, dict):
        raise ReferenceError(f"{path} is not a reference object")
    return d


def _write(ref: Dict[str, Any], out: Optional[str]) -> None:
    text = json.dumps(ref, indent=1, ensure_ascii=False) + "\n"
    if not out:
        print(text, end="")
        return
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    print(f"wrote {p}")


def _passphrase(var: Optional[str]) -> Optional[bytes]:
    if not var:
        return None
    v = os.environ.get(var)
    if not v:
        raise ReferenceError(f"--passphrase-env {var} is set but ${var} is empty")
    return v.encode()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="ir surveyor reference", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("new-key", help="OFFLINE MACHINE: generate the long-lived publication key")
    k.add_argument("--out", required=True)
    k.add_argument("--passphrase-env", default=None, metavar="VAR", help="encrypt the key with $VAR (never pass a passphrase in argv)")

    b = sub.add_parser("build", help="derive the reference from a deployment YOU control")
    b.add_argument("--from-offer", default=None, metavar="FILE", help="a /offer document or evidence bundle from YOUR deployment")
    for f in FIELDS:
        b.add_argument("--" + f.replace("_", "-"), default=None)
    b.add_argument("--merge", default=None, metavar="FILE", help="extend an existing reference")
    b.add_argument("--valid-from", default=None)
    b.add_argument("--valid-to", default=None)
    b.add_argument("--supersede", action="store_true", help="close every still-open window at --valid-from")
    b.add_argument("--source", default=None, help="where a reader is told to get this (engagement letter, release note)")
    b.add_argument("--note", default=None)
    b.add_argument("--out", default=None)

    r = sub.add_parser("retire", help="withdraw an entry — an explicit act, never a silent swap")
    r.add_argument("--in", dest="inp", required=True)
    r.add_argument("--value", required=True)
    r.add_argument("--field", default=None, choices=list(FIELDS))
    r.add_argument("--at", default=None, help="also close an open window at this time")
    r.add_argument("--out", default=None)

    s = sub.add_parser("sign", help="OFFLINE MACHINE: sign with the publication key")
    s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--passphrase-env", default=None, metavar="VAR")
    s.add_argument("--out", default=None)

    v = sub.add_parser("verify", help="what a firm sees; run it before publishing too")
    v.add_argument("--in", dest="inp", required=True)
    v.add_argument("--key-hex", default=None)
    v.add_argument("--at", default=None, help="report status as of this time (default: now)")

    a = p.parse_args(argv)
    try:
        if a.cmd == "new-key":
            pub = new_key(a.out, passphrase=_passphrase(a.passphrase_env))
            print(f"publication key written to {a.out}")
            print(f"  public key (this goes in the engagement letter and every firm records it): {pub}")
            print("  KEEP THE PRIVATE KEY OFFLINE. It is the root of every firm's trust in every later")
            print("  reference; anyone holding it can re-anchor identity for all of them.")
            if not a.passphrase_env:
                print("  (written unencrypted — the air gap is the control; use --passphrase-env to add one)")
            return 0

        if a.cmd == "build":
            vals = values_from_offer(a.from_offer) if a.from_offer else {}
            for f in FIELDS:
                given = getattr(a, f)
                if given:
                    vals[f] = given.lower()
            ref = build(vals, merge=_read(a.merge) if a.merge else None, valid_from=a.valid_from,
                        valid_to=a.valid_to, source=a.source, supersede=a.supersede, note=a.note)
            _write(ref, a.out)
            if a.from_offer:
                print(f"  derived from {a.from_offer}: policy_sha256 is HOST_DATA as the hardware reported it")
            print("  this reference is UNSIGNED — sign it on the offline machine before publishing")
            return 0

        if a.cmd == "retire":
            ref, n = retire(_read(a.inp), a.value, field=a.field, at=a.at)
            _write(ref, a.out or a.inp)
            print(f"  retired {n} entr{'y' if n == 1 else 'ies'}; the signature was removed — re-sign before publishing")
            return 0

        if a.cmd == "sign":
            ref = sign(_read(a.inp), a.key, passphrase=_passphrase(a.passphrase_env))
            _write(ref, a.out or a.inp)
            print(f"  signed under {ref['publication_key'][:16]}…")
            return 0

        if a.cmd == "verify":
            ref = _read(a.inp)
            ok, why = verify(ref, a.key_hex)
            print(("OK   " if ok else "NOT VERIFIED  ") + why)
            for line in describe(ref, a.at):
                print(line)
            return 0 if (ok or not a.key_hex) else 1
    except ReferenceError as e:
        import sys
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0
