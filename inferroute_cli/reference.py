"""`ir probant reference` — issue the out-of-band reference that lets a record say "InferRoute's enclave".

THIS IS THE OPERATOR'S SIDE OF THE PROOF, not the user's. A record bundle proves, on its own, that a
genuine AMD SEV-SNP container ran inside Microsoft's utility VM. It proves the container was OURS only when
the reader compares the container-policy hash and the index / encoder manifest hashes against values they
obtained from InferRoute through a channel they already trust. These commands produce and sign those values.

    ir probant reference new-key   --out KEY        once, on an OFFLINE machine; prints the public key
    ir probant reference build     --from-offer F   derive the values from a deployment YOU control
    ir probant reference retire    --value HEX      withdraw an entry (an explicit act, never a silent swap)
    ir probant reference sign      --key KEY        on the OFFLINE machine that holds the key
    ir probant reference verify    --key-hex HEX    what a firm sees; also a check before you publish

`verify` exit codes, because a reference has two independent verdicts and the code must carry both:
    0  signed by the key you gave, and something is current for every field — usable
    1  the signature was not verified (unsigned, or no key given); --allow-unverified to inspect a draft
    2  refused: unreadable file, bad argument
    3  signed, but not usable as a production anchor — nothing is current, or it is marked DEVELOPMENT

Three rules the tooling enforces or states, because getting them wrong silently is the failure mode:

 1. `policy_sha256` is HOST_DATA as the hardware reports it (bytes 0xC0..0xE0 of the SNP report), read from
    a real offer — never transcribed by hand. When the offer also carries the policy, SHA-256 of the decoded
    policy must equal HOST_DATA or the build is REFUSED.
 2. Derive from a deployment YOU control. Deriving a reference from a bundle a client sent you is circular:
    it would make the record validate against itself.
 3. A new release does not make the old one acceptable forever. `--supersede` closes EVERY non-retired
    entry at the new entry's start — setting its end to the earlier of its own end and this moment, not only
    the entries that had no end. An entry given an explicit end date would otherwise survive a supersede and
    keep passing, because the verifier accepts ANY matching entry that is current.
 4. A reference is refused at SIGNING if it would fail or confuse the moment it is published: nothing
    current (identity fails for every client), two entries current for one field (two different enclaves
    both pass), or a window that ends before it begins. The first two have explicit overrides for the
    deliberate cases — a historical or pre-announced reference, and a planned rollout overlap.

The signature is Ed25519 over the canonical JSON of the reference with `sig` removed — byte-for-byte the
same canonicalisation the bundled verifier uses (a test asserts the two agree, including on non-ASCII).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FIELDS = ("policy_sha256", "index_manifest_sha256", "model_manifest_sha256")
HOST_DATA_OFF, HOST_DATA_END = 0xC0, 0xE0
REPORT_LEN = 1184


# A reference anchors identity to these values, so a value that names nothing must never be accepted.
#   all zeros            — a placeholder, never a measurement
#   SHA-256 of b""       — what a manifest builder returns when it found NO FILES. It looks like a real
#                          digest, it is the same for every index, and it is exactly what build_manifest_hash
#                          produces over a root whose directories are symlinks (Python 3.12's rglob does not
#                          follow them: measured 0 files over the assembled root). A reference pinning it
#                          would "prove" a match against any empty enclave while naming no searched bytes.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
UNUSABLE_DIGESTS = {"0" * 64: "all zeros — a placeholder, not a measurement",
                    EMPTY_SHA256: "SHA-256 of nothing — a manifest built over no files; it names no bytes "
                                  "and is identical for every index"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def digest_problem(value: Any) -> Optional[str]:
    """Why `value` cannot be anchored to, or None if it can. The single definition, shared by --from-offer
    and by explicit flags — two validators would let the weaker path publish what the stronger refuses."""
    if not isinstance(value, str) or not _HEX64.match(value.lower()):
        return f"not a 64-character hex SHA-256 (got {value!r})"
    return UNUSABLE_DIGESTS.get(value.lower())


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


# Signs that an attested policy carries a per-deploy secret. Found on the first working deploy (2026-09-17):
# confcom wrote the container's INDEX_URL environment value — a blob SAS URL, expiry and signature included —
# verbatim into the policy, so HOST_DATA differed on every deploy of the same code and the token was published
# with every bundle. Narrow on purpose: the parameters of an Azure SAS, which never belong in an identity anchor.
_SAS_MARKERS = (b"sig=", b"&se=", b"?se=", b"&sp=", b"sv=20")


def policy_credential(policy: bytes) -> Optional[str]:
    """What credential-shaped text an attested policy contains, or None."""
    low = policy.lower()
    hits = [m.decode() for m in _SAS_MARKERS if m in low]
    return f"Azure SAS parameters {', '.join(hits)}" if "sig=" in " ".join(hits) else None


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
            raw = base64.b64decode(policy_b64)
            got = hashlib.sha256(raw).hexdigest()
        except Exception as e:                                   # noqa: BLE001
            raise ReferenceError(f"the policy in {path} is not valid base64") from e
        cred = policy_credential(raw)
        if cred:
            raise ReferenceError(
                f"REFUSING: the attested policy embeds a credential ({cred}). A value that changes on every "
                "deploy makes HOST_DATA change on every deploy, so a reference pinning it would never match the "
                "next container — and the policy ships in every exported bundle, so the credential would too. "
                "Fix the deployment so the policy is identical across deploys, then build the reference.")
        if got != host_data:
            raise ReferenceError(
                "REFUSING: the policy in this file does not hash to the HOST_DATA the hardware reported "
                f"(policy sha256 {got}, HOST_DATA {host_data}). The policy on file is not the policy that "
                "was attested; publishing it as the reference would anchor identity to the wrong value.")

    out = {"policy_sha256": host_data}
    for ref_field, rd_field in (("index_manifest_sha256", "index_manifest_sha256"),
                                ("model_manifest_sha256", "model_manifest_sha256")):
        v = rd.get(rd_field)
        why = digest_problem(v)
        if why:
            raise ReferenceError(f"the offer's runtime data has no usable {rd_field}: {why}")
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



def entry_status(e: Dict[str, Any], at: dt.datetime) -> Tuple[bool, str]:
    """(is_current_at, human status) for one entry. The single place that decides "current", so describe()
    and the pre-publication check can never disagree with each other."""
    vf, vt = parse_time(e.get("valid_from")), parse_time(e.get("valid_to"))
    if e.get("retired"):
        return False, "RETIRED"
    if (e.get("valid_from") and vf is None) or (e.get("valid_to") and vt is None):
        return False, "UNPARSABLE WINDOW — will fail for every reader"
    if vf is not None and vt is not None and vt < vf:
        return False, f"DEAD INTERVAL ({e['valid_from']} → {e['valid_to']}) — can never be current"
    if not (vf or vt):
        return True, "current (no window)"
    if vf is not None and at < vf:
        return False, f"not yet current (from {e['valid_from']})"
    if vt is not None and at > vt:
        return False, f"expired (to {e['valid_to']})"
    return True, "current"


def current_entries(ref: Dict[str, Any], field: str, at: dt.datetime) -> List[Dict[str, Any]]:
    return [e for e in _entries(ref, field) if entry_status(e, at)[0]]


def currency(ref: Dict[str, Any], at: dt.datetime) -> Dict[str, List[Dict[str, Any]]]:
    """Per field, the entries current at `at`. One definition, shared by the pre-publication refusal and by
    `verify`, so the operator's check and the firm's check can never disagree about what "usable" means."""
    return {f: current_entries(ref, f, at) for f in FIELDS}


def check_publishable(ref: Dict[str, Any], *, at: Optional[dt.datetime] = None, allow_not_current: bool = False,
                      allow_overlap: bool = False) -> None:
    """Refuse to sign a reference that would fail, or be ambiguous, the moment it is published.

    The verifier accepts a value if ANY matching entry is current, so: nothing current means identity fails
    for every client of every record, and two current entries for one field means two different enclaves both
    pass — right during a planned rollout overlap, wrong the rest of the time, and today nothing else would
    tell the operator which situation they are in. (A one-instant overlap at a supersede boundary is possible
    and harmless; it is only visible if you sign at exactly that second.)
    """
    at = at or dt.datetime.now(dt.timezone.utc)
    dead, empty, overlap = [], [], []
    for field in FIELDS:
        entries = _entries(ref, field)
        for e in entries:
            ok, why = entry_status(e, at)
            if not ok and ("DEAD INTERVAL" in why or "UNPARSABLE" in why):
                dead.append(f"{field} {e['value'][:16]}…: {why}")
        cur = current_entries(ref, field, at)
        if not cur:
            empty.append(f"{field} (" + "; ".join(f"{e['value'][:16]}… {entry_status(e, at)[1]}" for e in entries) + ")"
                         if entries else f"{field} (no entries)")
        elif len(cur) > 1:
            overlap.append(f"{field}: {len(cur)} current — " + ", ".join(e["value"][:16] + "…" for e in cur))
    problems = list(dead)
    if empty and not allow_not_current:
        problems.append("nothing is current for: " + "; ".join(empty) +
                        " — published as-is, identity FAILS for every client of every record. Use "
                        "--allow-not-current only to publish a deliberately historical or pre-announced reference.")
    if overlap and not allow_overlap:
        problems.append("more than one entry is current for: " + "; ".join(overlap) +
                        " — two different enclaves would both pass identity. This is correct only during a "
                        "planned rollout overlap; if you superseded a release and still see two, the previous "
                        "window did not close. Use --allow-overlap if the overlap is intended.")
    if problems:
        raise ReferenceError("refusing to sign:\n    - " + "\n    - ".join(problems))


# A firmware floor and a source pointer are fields the VERIFIER already reads, and until now there was no
# way to put either into a reference. The verifier's own blocker text tells the operator to "put min_tcb in
# the published reference"; `reference build` offered no option to do it. An instrument that names a remedy
# has to provide it, or the remedy is advice.
def parse_min_tcb(specs: List[str]) -> Dict[str, Dict[str, int]]:
    """`Genoa=snpSPL:23,ucodeSPL:84` -> {"Genoa": {"snpSPL": 23, "ucodeSPL": 84}}.

    A floor of all zeros is refused. Every firmware in existence is at or above zero, so such a floor
    passes whatever it is shown and reads, in the record, exactly like a floor that was checked.
    """
    out: Dict[str, Dict[str, int]] = {}
    for spec in specs:
        product, _, rest = spec.partition("=")
        product, rest = product.strip(), rest.strip()
        if not product or not rest:
            raise ReferenceError(f"--min-tcb {spec!r}: expected PRODUCT=level:N[,level:N], e.g. "
                                 "Genoa=snpSPL:23,ucodeSPL:84")
        levels: Dict[str, int] = {}
        for part in rest.split(","):
            name, sep, num = part.partition(":")
            name, num = name.strip(), num.strip()
            if not sep or not name:
                raise ReferenceError(f"--min-tcb {spec!r}: {part!r} is not level:N")
            try:
                levels[name] = int(num)
            except ValueError:
                raise ReferenceError(f"--min-tcb {spec!r}: {num!r} is not a whole number") from None
            if levels[name] < 0:
                raise ReferenceError(f"--min-tcb {spec!r}: {name} cannot be negative")
        if not any(levels.values()):
            raise ReferenceError(
                f"refusing an all-zero firmware floor for {product}: every firmware ever shipped is at or "
                "above zero, so this would pass whatever it is shown while reading like a check that held. "
                "Pin the level actually deployed, or omit --min-tcb and let the row stay a visible SKIP.")
        out[product] = levels
    return out


def build(values: Dict[str, str], *, merge: Optional[Dict[str, Any]] = None, valid_from: Optional[str] = None,
          valid_to: Optional[str] = None, source: Optional[str] = None, supersede: bool = False,
          note: Optional[str] = None, min_tcb: Optional[Dict[str, Dict[str, int]]] = None,
          image_source: Optional[str] = None) -> Dict[str, Any]:
    """Create or extend a reference.

    `supersede` closes EVERY non-retired entry at `valid_from` — setting valid_to to the earlier of its
    existing end and this moment, not only the entries that had no end. An entry given an explicit end date
    at build time would otherwise survive a supersede and keep passing as current, because the verifier
    accepts any matching entry that is current.
    """
    _require_time(valid_from, "--valid-from")
    _require_time(valid_to, "--valid-to")
    new_vf, new_vt = parse_time(valid_from), parse_time(valid_to)
    if new_vf is not None and new_vt is not None and new_vt < new_vf:
        raise ReferenceError(f"--valid-to {valid_to} is before --valid-from {valid_from}: that entry could "
                             "never be current, so no record would ever verify against it")
    if supersede and not valid_from:
        raise ReferenceError("--supersede needs --valid-from: it closes the previous entries' windows at the "
                             "moment this release starts, so there must be a moment to close them at")
    missing = [f for f in FIELDS if not values.get(f)]
    if missing:
        raise ReferenceError(f"refusing to write a reference missing {missing}: it would fail identity for "
                             "every record a client verifies")
    bad = {f: digest_problem(values.get(f)) for f in FIELDS}
    bad = {f: why for f, why in bad.items() if why}
    if bad:
        raise ReferenceError("refusing to anchor identity to a value that names nothing: "
                             + "; ".join(f"{f} is {why}" for f, why in bad.items()))
    values = {f: values[f].lower() for f in FIELDS}

    ref: Dict[str, Any] = dict(merge or {})
    ref.pop("sig", None)                                          # any edit invalidates a previous signature
    ref.pop("publication_key", None)
    if supersede:
        # Check every field BEFORE mutating any, so a refusal never leaves a half-superseded reference.
        for field in FIELDS:
            for e in _entries(ref, field):
                evf = parse_time(e.get("valid_from"))
                if not e.get("retired") and evf is not None and new_vf is not None and new_vf < evf:
                    raise ReferenceError(
                        f"--supersede at {valid_from} is BEFORE an existing {field} entry starts "
                        f"({e['value'][:16]}… from {e['valid_from']}). Closing it then would write a window "
                        "that ends before it begins, and that entry could never be current again.")
    for field in FIELDS:
        existing = _entries(ref, field)
        if supersede:
            for e in existing:
                if e.get("retired"):
                    continue
                evt = parse_time(e.get("valid_to"))
                # close at the EARLIER of its own end and this moment
                if evt is None or (new_vf is not None and new_vf < evt):
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
    # Both are merged, not replaced wholesale, so extending a reference for one product does not silently
    # drop the floor pinned for another.
    if min_tcb:
        floors = dict(ref.get("min_tcb") or {})
        floors.update(min_tcb)
        ref["min_tcb"] = floors
    if image_source:
        ref["image_source"] = image_source
    ref["published_at"] = _utcnow()
    return ref


def retire(ref: Dict[str, Any], value: str, *, field: Optional[str] = None, at: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
    """Mark matching entries retired (and close an open window at `at`). Returns (reference, n_retired)."""
    _require_time(at, "--at")
    ref = dict(ref)
    ref.pop("sig", None)
    ref.pop("publication_key", None)
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
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    except OSError as e:
        raise ReferenceError(f"cannot write the publication key to {p}: {e.strerror or e}") from e
    # VERIFY the permissions actually took. On a filesystem with no POSIX permissions — exFAT, FAT, NTFS,
    # most removable media as shipped — chmod SUCCEEDS and changes nothing, so the key would sit
    # world-readable while this command reported it protected. Refuse rather than report a protection we
    # did not achieve; delete the key we just wrote, since it was exposed the moment it landed.
    try:
        os.chmod(p, 0o600)
        mode = p.stat().st_mode & 0o777
    except OSError as e:
        mode = None
        exposed = f"cannot read back the permissions ({e.strerror or e})"
    else:
        exposed = f"the file is mode {oct(mode)} — group/other can read it" if mode & 0o077 else ""
    if exposed:
        try:
            p.unlink()
        except OSError:
            pass
        raise ReferenceError(
            f"REFUSING to leave a publication key at {p}: {exposed}. That filesystem cannot enforce owner-only "
            "permissions (exFAT, FAT and NTFS cannot), so the key would be readable by anything that can read "
            "the mount. The key just written has been deleted. Write it to a filesystem with POSIX "
            "permissions — ext4 on a dedicated USB stick you unplug afterwards is the intended home.")
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _load_key(path: str, passphrase: Optional[bytes]):
    from cryptography.hazmat.primitives import serialization
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise ReferenceError(f"cannot read the publication key at {path}: {e.strerror or e}. "
                             "Check the path — this is about the file, not the key.") from e
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except TypeError as e:
        raise ReferenceError(f"{path} is encrypted; give the passphrase with --passphrase-env VAR") from e
    except ValueError as e:
        raise ReferenceError(f"cannot load the publication key from {path}: {e}") from e


def sign(ref: Dict[str, Any], key_path: str, *, passphrase: Optional[bytes] = None,
         allow_not_current: bool = False, allow_overlap: bool = False,
         at: Optional[dt.datetime] = None, development: bool = False) -> Dict[str, Any]:
    """Sign a reference — after refusing the states that fail or confuse at the moment of publication. The
    principle the verifier already follows, applied one step earlier: fail when the bad value is CREATED,
    not when a firm tries to use it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    check_publishable(ref, at=at, allow_not_current=allow_not_current, allow_overlap=allow_overlap)
    key = _load_key(key_path, passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise ReferenceError(f"{key_path} is not an Ed25519 key")
    # The public key is recorded INSIDE the signed body, so a reader can see which key they should already
    # hold — but it proves nothing on its own: the check is against the key they recorded at first use.
    body = {k: v for k, v in ref.items() if k != "sig"}
    # A development reference carries the mark INSIDE the signature, so it cannot be stripped without
    # invalidating it. The record verifier refuses identity against a marked reference outright.
    if development:
        body["development"] = True
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
    """One line per entry, saying whether it is current at `at` (default: now). An unparsable `at` is
    REFUSED: an operator asking what was current on a past date must never get a confident answer about a
    different moment — the failure closed inside the verifier's window check, not reopened at the door."""
    if at_iso is not None and parse_time(at_iso) is None:
        raise ReferenceError(f"--at {at_iso!r} is not an ISO-8601 time; refusing to report status as of some "
                             "other moment than the one you asked about")
    at = parse_time(at_iso) or dt.datetime.now(dt.timezone.utc)
    lines = [f"reference from {ref.get('source') or '(unnamed)'}, published {ref.get('published_at') or '?'}"
             f" — status at {at.strftime('%Y-%m-%dT%H:%M:%SZ')}"]
    for field in FIELDS:
        entries = _entries(ref, field)
        lines.append(f"  {field}:" + ("" if entries else "  (none — identity will FAIL for every record)"))
        for e in entries:
            _, status = entry_status(e, at)
            window = (f"  [{e.get('valid_from') or '…'} → {e.get('valid_to') or '…'}]"
                      if (e.get("valid_from") or e.get("valid_to")) else "")
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


def _passphrase(var: Optional[str], prompt: bool = False, confirm: bool = False) -> Optional[bytes]:
    """From $VAR, or typed at a prompt. Never from argv — a passphrase on a command line lands in the shell
    history and in every `ps` listing on the machine."""
    if prompt:
        import getpass
        first = getpass.getpass("passphrase for the publication key: ")
        if not first:
            raise ReferenceError("empty passphrase; run without --passphrase-prompt to write an unencrypted key")
        if confirm and getpass.getpass("confirm passphrase: ") != first:
            raise ReferenceError("the two passphrases do not match; nothing was written")
        return first.encode()
    if not var:
        return None
    v = os.environ.get(var)
    if not v:
        raise ReferenceError(f"--passphrase-env {var} is set but ${var} is empty")
    return v.encode()


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="ir probant reference", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("new-key", help="OFFLINE MACHINE: generate the long-lived publication key")
    k.add_argument("--out", required=True)
    k.add_argument("--passphrase-env", default=None, metavar="VAR", help="encrypt the key with $VAR (never pass a passphrase in argv)")
    k.add_argument("--passphrase-prompt", action="store_true", help="type the passphrase at a prompt instead (not in argv, env or history)")

    b = sub.add_parser("build", help="derive the reference from a deployment YOU control")
    b.add_argument("--from-offer", default=None, metavar="FILE", help="a /offer document or evidence bundle from YOUR deployment")
    for f in FIELDS:
        b.add_argument("--" + f.replace("_", "-"), default=None)
    b.add_argument("--merge", default=None, metavar="FILE", help="extend an existing reference")
    b.add_argument("--valid-from", default=None)
    b.add_argument("--valid-to", default=None)
    b.add_argument("--supersede", action="store_true", help="close every still-open window at --valid-from")
    b.add_argument("--source", default=None, help="where a reader is told to get this (engagement letter, release note)")
    b.add_argument("--min-tcb", action="append", default=[], metavar="PRODUCT=level:N,...",
                   help="firmware floor, e.g. Genoa=snpSPL:23,ucodeSPL:84 (repeatable per product)")
    b.add_argument("--image-source", default=None, metavar="URL",
                   help="where the program that ran can be read; naming it does NOT verify a build")
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
    s.add_argument("--passphrase-prompt", action="store_true", help="type the passphrase at a prompt instead")
    s.add_argument("--allow-not-current", action="store_true",
                   help="sign even though no entry is current now (a deliberately historical or pre-announced reference)")
    s.add_argument("--allow-overlap", action="store_true",
                   help="sign even though two entries are current for one field (a planned rollout overlap)")
    s.add_argument("--development", action="store_true",
                   help="mark this reference DEVELOPMENT: it announces itself, and the record verifier refuses "
                        "identity against it. Use for every key that is not the offline production key.")
    s.add_argument("--out", default=None)

    v = sub.add_parser("verify", help="what a firm sees; run it before publishing too")
    v.add_argument("--in", dest="inp", required=True)
    v.add_argument("--key-hex", default=None)
    v.add_argument("--at", default=None, help="report status as of this time (default: now)")
    v.add_argument("--allow-unverified", action="store_true",
                   help="exit 0 even though the signature was not verified — for inspecting an unsigned draft")

    a = p.parse_args(argv)
    try:
        if a.cmd == "new-key":
            pub = new_key(a.out, passphrase=_passphrase(a.passphrase_env, a.passphrase_prompt, confirm=True))
            print(f"publication key written to {a.out}")
            print(f"  public key (this goes in the engagement letter and every firm records it): {pub}")
            print("  KEEP THE PRIVATE KEY OFFLINE. It is the root of every firm's trust in every later")
            print("  reference; anyone holding it can re-anchor identity for all of them.")
            if not (a.passphrase_env or a.passphrase_prompt):
                print("  (written unencrypted — the air gap is the control; use --passphrase-env to add one)")
            return 0

        if a.cmd == "build":
            vals = values_from_offer(a.from_offer) if a.from_offer else {}
            for f in FIELDS:
                given = getattr(a, f)
                if given:
                    vals[f] = given.lower()
            ref = build(vals, merge=_read(a.merge) if a.merge else None, valid_from=a.valid_from,
                        valid_to=a.valid_to, source=a.source, supersede=a.supersede, note=a.note,
                        min_tcb=parse_min_tcb(a.min_tcb) if a.min_tcb else None,
                        image_source=a.image_source)
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
            ref = sign(_read(a.inp), a.key, passphrase=_passphrase(a.passphrase_env, a.passphrase_prompt),
                       allow_not_current=a.allow_not_current, allow_overlap=a.allow_overlap,
                       development=a.development)
            _write(ref, a.out or a.inp)
            print(f"  signed under {ref['publication_key'][:16]}…")
            return 0

        if a.cmd == "verify":
            ref = _read(a.inp)
            _require_time(a.at, "--at")
            at = parse_time(a.at) or dt.datetime.now(dt.timezone.utc)
            ok, why = verify(ref, a.key_hex)
            cur = currency(ref, at)
            empty = [f for f, entries in cur.items() if not entries]
            overlapping = [f for f, entries in cur.items() if len(entries) > 1]
            # A reference has TWO independent verdicts — is it signed by the key you hold, and is it usable —
            # and the exit code has to carry both. Leading with OK while something below says "expired" is
            # the failure mode this whole series kept finding.
            if ref.get("development"):
                print("!!! DEVELOPMENT REFERENCE — signed by a key that is NOT the offline production key. "
                      "The record verifier REFUSES identity against this. Never put its key in an engagement "
                      "letter. !!!")
            if not ok:
                print("NOT VERIFIED  " + why)
            elif empty:
                print(f"SIGNED BUT NOT USABLE  {why} — but nothing is current for: {', '.join(empty)}")
            else:
                print("OK   " + why)
            for line in describe(ref, a.at):
                print(line)
            if overlapping:
                print(f"note: more than one entry is current for {', '.join(overlapping)} — two different "
                      "enclaves would both pass identity; correct only during a planned rollout overlap.")
            if not ok and not a.allow_unverified:
                print("exit 1: the signature was NOT verified. Pass --key-hex with the key you recorded at "
                      "first use, or --allow-unverified if you are deliberately inspecting an unsigned draft.")
            elif empty:
                print("exit 3: the signature is good, but every record checked against this reference will "
                      "FAIL identity" + (f" as of {a.at}" if a.at else " right now") + ". If this is a "
                      "deliberately historical reference that is expected; otherwise build and sign a current one.")
            if ref.get("development"):
                print("exit 3: a development reference is signed and may be usable for testing, but it can "
                      "never establish production identity.")
            if not ok and not a.allow_unverified:
                return 1
            return 3 if (empty or ref.get("development")) else 0
    except (ReferenceError, OSError) as e:
        import sys
        sys.stderr.write(f"\n  {e}\n\n")
        return 2
    return 0
