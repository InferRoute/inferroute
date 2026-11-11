"""Offline verification of Sigsum proofs — the same decision `sigsum-verify -k KEY -p POLICY FILE.proof < FILE` makes.

Pure Python plus `cryptography` (Ed25519). No network. The Go reference (sigsum.org/sigsum-go v1.0.0:
pkg/proof, pkg/types, pkg/merkle, pkg/policy, pkg/crypto, pkg/ascii) is the ground truth this mirrors;
the module's tests check it differentially against the `sigsum-verify` binary.

What a proof binds (Sigsum log.md, c2sp tlog-checkpoint / tlog-cosignature):

* message      = SHA-256(file bytes)                  (what `sigsum-verify` reads on stdin, hashed)
* checksum     = SHA-256(message)                     (so the leaf commits to H(H(file)))
* leaf sig     = Ed25519(submitter, "sigsum.org/v1/tree-leaf" || 0x00 || checksum)
* key_hash     = SHA-256(submitter public key)
* leaf hash    = SHA-256(0x00 || checksum || signature || key_hash)        (RFC 6962 leaf)
* interior     = SHA-256(0x01 || left || right)                            (RFC 6962 node)
* checkpoint   = "sigsum.org/v1/tree/<hex(log key hash)>\\n<size>\\n<base64(root)>\\n", signed by the log
* cosignature  = Ed25519(witness, "cosignature/v1\\ntime <ts>\\n" || checkpoint)

`verify_proof` takes the FILE bytes (like the CLI); `verify_proof_hash` takes the 32-byte message.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["SigsumError", "Policy", "Result", "parse_policy", "parse_ssh_ed25519_pubkeys",
           "verify_proof", "verify_proof_hash", "parse_proof", "Proof"]

TREE_LEAF_NAMESPACE = b"sigsum.org/v1/tree-leaf"
COSIGNATURE_NAMESPACE = "cosignature/v1"
CHECKPOINT_NAME_PREFIX = "sigsum.org/v1/tree/"
PROOF_SIZE_LIMIT = 63          # max node_hash lines (types/proof.go proofSizeLimit)
_MAX_INT = (1 << 63) - 1       # ascii.IntFromDecimal: strconv.ParseUint(s, 10, 63)


class SigsumError(ValueError):
    """The proof, policy or key material is malformed, or the proof does not verify."""


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- Ed25519, with sigsum-go's extra checks
# crypto.PublicKey.Verify additionally rejects a public key or signature-R that is a non-canonical
# encoding, not on the curve, or of low order (crypto/ed25519.go validateEd25519Point). OpenSSL does not
# make all of those checks, so they are done here in pure Python before handing off to `cryptography`.

_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(b: bytes):
    """Decode as filippo.io/edwards25519 SetBytes (lenient: y may be >= p). None if not on the curve."""
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    y %= _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = (_P - x) % _P
    return x, y


def _encode_point(x: int, y: int) -> bytes:
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return x3, y3


def _valid_point(b: bytes) -> bool:
    pt = _decode_point(b)
    if pt is None or _encode_point(*pt) != b:          # off-curve, or non-canonical encoding
        return False
    q = pt
    for _ in range(3):                                   # [8]P
        q = _add(q, q)
    return q != (0, 1)                                   # low-order point


def _ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    if not _valid_point(pub) or not _valid_point(sig[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- ascii helpers (pkg/ascii)

_HEX = re.compile(r"[0-9a-fA-F]*")
_DEC = re.compile(r"0|[1-9][0-9]*")


def _hex(s: str, n: int, what: str) -> bytes:
    if not _HEX.fullmatch(s) or len(s) != 2 * n:
        raise SigsumError(f"invalid {what}: want {n} hex-encoded bytes")
    return bytes.fromhex(s)


def _int(s: str, what: str) -> int:
    if not _DEC.fullmatch(s) or int(s) > _MAX_INT:
        raise SigsumError(f"invalid {what}: {s!r}")
    return int(s)


class _Lines:
    """pkg/ascii LineReader + Parser: '\\n'-terminated lines; a final unterminated line is an error."""

    def __init__(self, text: str):
        if text and not text.endswith("\n"):
            raise SigsumError("proof does not end with a newline")
        self._lines = text.split("\n")[:-1] if text else []
        self._i = 0

    def get_line(self):
        if self._i >= len(self._lines):
            return None                                   # EOF
        line = self._lines[self._i]
        self._i += 1
        return line

    def empty_line(self):
        line = self.get_line()
        if line is None:
            raise SigsumError("unexpected end of proof, expected an empty line")
        if line != "":
            raise SigsumError(f"garbage where line should be empty: {line!r}")

    _EMPTY = object()

    def next(self, name: str):
        """Value of `name=value`; None at EOF; _EMPTY at an empty line."""
        line = self.get_line()
        if line is None:
            return None
        if line == "":
            return self._EMPTY
        key, sep, value = line.partition("=")
        if not sep:
            raise SigsumError(f"invalid input line: {line!r}")
        if key != name:
            raise SigsumError(f"expected {name!r}, got key {key!r}")
        return value

    def require(self, name: str) -> str:
        v = self.next(name)
        if v is None or v is self._EMPTY:
            raise SigsumError(f"missing {name!r} line")
        return v

    def values(self, name: str, count: int):
        v = self.next(name)
        if v is None or v is self._EMPTY:
            return v
        parts = v.split(" ")
        if len(parts) != count:
            raise SigsumError(f"{name}: got {len(parts)} values, expected {count}")
        return parts


# ---------------------------------------------------------------- policy (pkg/policy)

@dataclass(frozen=True)
class _Witness:
    key_hash: bytes


@dataclass(frozen=True)
class _Group:
    k: int
    members: tuple


@dataclass
class Policy:
    logs: dict = field(default_factory=dict)          # key_hash -> (pubkey, url)
    witnesses: dict = field(default_factory=dict)     # key_hash -> (name, pubkey, url)
    quorum: object = None

    def _satisfied(self, node, verified: set) -> bool:
        if isinstance(node, _Witness):
            return node.key_hash in verified
        return sum(self._satisfied(m, verified) for m in node.members) >= node.k


_ATOI = re.compile(r"[+-]?[0-9]+")


def parse_policy(text) -> Policy:
    """Parse a Sigsum trust policy (as `sigsum-policy show NAME` prints it). Mirrors policy.ParseConfig."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    pol = Policy()
    names: dict = {"none": _Group(0, ())}
    used: dict = {"none": ""}
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for lineno, line in enumerate(lines, 1):
        if line.endswith("\r"):                       # bufio.ScanLines drops one trailing CR
            line = line[:-1]
        for c in line:
            if not (ord(c) >= 0x80 or c == "\t" or 0x20 <= ord(c) < 0x7F):
                raise SigsumError(f"{lineno}: invalid control character 0x{ord(c):02x}")
        fields = [f for f in re.split(r"[ \t]+", line) if f]
        if not fields or fields[0].startswith("#"):
            continue
        kw, args = fields[0], fields[1:]
        try:
            if kw == "log":
                if not 1 <= len(args) <= 2:
                    raise SigsumError("invalid log line, public key required, url optional")
                key = _hex(args[0], 32, "log public key")
                h = _sha256(key)
                if h in pol.logs:
                    raise SigsumError("duplicate log")
                pol.logs[h] = (key, args[1] if len(args) > 1 else "")
            elif kw == "witness":
                if not 2 <= len(args) <= 3:
                    raise SigsumError("invalid witness line, public key and name required, url optional")
                name, key = args[0], _hex(args[1], 32, "witness public key")
                if name in names:
                    raise SigsumError(f"duplicate name: {name!r}")
                h = _sha256(key)
                if h in pol.witnesses:
                    raise SigsumError("duplicate witness")
                pol.witnesses[h] = (name, key, args[2] if len(args) > 2 else "")
                names[name] = _Witness(h)
            elif kw == "group":
                if len(args) < 3:
                    raise SigsumError("too few arguments, name, threshold and at least one member is required")
                name, t, members = args[0], args[1], args[2:]
                n = len(members)
                if t == "any":
                    k = 1
                elif t == "all":
                    k = n
                elif _ATOI.fullmatch(t):
                    k = int(t)
                else:
                    raise SigsumError(f"invalid threshold {t!r}")
                if k < 1 or k > n:
                    raise SigsumError("threshold out of range")
                if name in names:
                    raise SigsumError(f"duplicate name {name!r}")
                nodes = []
                for m in members:
                    if m in used:
                        raise SigsumError(f"group/witness {m!r} cannot be (re)used as a member")
                    if m not in names:
                        raise SigsumError(f"undefined name: {m!r}")
                    used[m] = name
                    nodes.append(names[m])
                names[name] = _Group(k, tuple(nodes))
            elif kw == "quorum":
                if len(args) != 1:
                    raise SigsumError("incorrect number of arguments: group or witness required")
                if pol.quorum is not None:
                    raise SigsumError("quorum can only be set once")
                if args[0] not in names:
                    raise SigsumError(f"undefined name {args[0]!r}")
                pol.quorum = names[args[0]]
            else:
                raise SigsumError(f"unknown keyword: {kw!r}")
        except SigsumError as e:
            raise SigsumError(f"{lineno}: {e}") from None
    if pol.quorum is None:
        raise SigsumError("no quorum defined")
    return pol


def parse_ssh_ed25519_pubkeys(text) -> list:
    """Raw 32-byte keys from OpenSSH `ssh-ed25519 AAAA... comment` lines (blank lines and # comments skipped)."""
    if isinstance(text, bytes):
        text = text.decode()
    out = []
    for line in text.splitlines():
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if f[0] != "ssh-ed25519" or len(f) < 2:
            raise SigsumError("not an ssh-ed25519 public key line")
        blob = base64.b64decode(f[1], validate=True)
        want = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
        if len(blob) != len(want) + 32 or not blob.startswith(want):
            raise SigsumError("malformed ssh-ed25519 key blob")
        out.append(blob[len(want):])
    if not out:
        raise SigsumError("no public keys")
    return out


# ---------------------------------------------------------------- proof (pkg/proof, version 1 and 2)

@dataclass
class Proof:
    version: int
    log_key_hash: bytes
    key_hash: bytes
    leaf_signature: bytes
    size: int
    root_hash: bytes
    log_signature: bytes
    cosignatures: dict           # witness key_hash -> (timestamp, signature)
    leaf_index: int
    path: list


def parse_proof(text) -> Proof:
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise SigsumError("proof is not text") from None
    p = _Lines(text)
    version = _int(p.require("version"), "version")
    if version not in (1, 2):
        raise SigsumError(f"unknown version {version}")
    log_kh = _hex(p.require("log"), 32, "log key hash")
    leaf = p.values("leaf", 3 if version == 1 else 2)
    if leaf is None or leaf is _Lines._EMPTY:
        raise SigsumError("missing leaf line")
    if version == 1:
        _hex(leaf[0], 2, "(version 1) short checksum")
        leaf = leaf[1:]
    key_hash = _hex(leaf[0], 32, "submitter key hash")
    leaf_sig = _hex(leaf[1], 64, "leaf signature")
    p.empty_line()

    size = _int(p.require("size"), "size")
    root = _hex(p.require("root_hash"), 32, "root hash")
    log_sig = _hex(p.require("signature"), 64, "log signature")
    cosigs: dict = {}
    empty = False
    while True:
        v = p.values("cosignature", 3)
        if v is None:
            break
        if v is _Lines._EMPTY:
            empty = True
            break
        kh = _hex(v[0], 32, "cosignature key hash")
        ts = _int(v[1], "cosignature timestamp")
        sig = _hex(v[2], 64, "cosignature")
        if kh in cosigs:
            raise SigsumError("duplicate cosignature keyhash")
        cosigs[kh] = (ts, sig)

    if size == 0:
        raise SigsumError("invalid tree: empty")
    leaf_index, path = 0, []
    if size == 1:
        if empty:
            raise SigsumError("unexpected empty line after a size-1 tree head")
    else:
        if not empty:
            raise SigsumError("missing inclusion proof part")
        leaf_index = _int(p.require("leaf_index"), "leaf_index")
        while True:
            v = p.next("node_hash")
            if v is None:
                break
            if v is _Lines._EMPTY:
                raise SigsumError("unexpected empty line in inclusion path")
            if len(path) >= PROOF_SIZE_LIMIT:
                raise SigsumError("too many node hashes")
            path.append(_hex(v, 32, "node_hash"))
        if not path:
            raise SigsumError("invalid path, empty")
    return Proof(version, log_kh, key_hash, leaf_sig, size, root, log_sig, cosigs, leaf_index, path)


# ---------------------------------------------------------------- Merkle (pkg/merkle, RFC 6962 / 9162)

def _node(l: bytes, r: bytes) -> bytes:
    return _sha256(b"\x01" + l + r)


def _path_length(index: int, size: int) -> int:
    k = (index ^ (size - 1)).bit_length()
    return k + bin(index >> k).count("1")


def _verify_inclusion(leaf: bytes, index: int, size: int, root: bytes, path: list) -> None:
    if index >= size:
        raise SigsumError("inclusion proof: index out of range")
    if len(path) != _path_length(index, size):
        raise SigsumError(f"inclusion proof: path length {len(path)}, should be {_path_length(index, size)}")
    r, fn, sn, i = leaf, index, size - 1, 0
    while sn > 0:
        if fn & 1:
            r = _node(path[i], r)
            i += 1
        elif fn < sn:
            r = _node(r, path[i])
            i += 1
        fn >>= 1
        sn >>= 1
    if r != root:
        raise SigsumError("inclusion proof: root mismatch")


# ---------------------------------------------------------------- verification

@dataclass(frozen=True)
class Result:
    size: int
    root_hash: bytes
    leaf_index: int
    log_key_hash: bytes
    submitter_key_hash: bytes
    cosignatures: dict           # witness name -> timestamp (unix seconds), verified policy witnesses only


def _checkpoint(origin: str, size: int, root: bytes) -> str:
    return f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"


def verify_proof_hash(message: bytes, proof_text, submitter_pubkeys: list, policy: Policy) -> Result:
    """Verify with `message` the 32-byte value the leaf checksum is computed over (the CLI's --raw-hash)."""
    if len(message) != 32:
        raise SigsumError("message must be 32 bytes (a SHA-256 digest)")
    pr = parse_proof(proof_text)

    # 1. leaf: checksum, submitter key by key hash, leaf signature
    keys = {}
    for k in submitter_pubkeys:
        if len(k) != 32:
            raise SigsumError("submitter key must be 32 raw Ed25519 bytes")
        keys[_sha256(bytes(k))] = bytes(k)
    checksum = _sha256(message)
    key = keys.get(pr.key_hash)
    if key is None:
        raise SigsumError("leaf key hash not known")
    if not _ed25519_verify(key, TREE_LEAF_NAMESPACE + b"\x00" + checksum, pr.leaf_signature):
        raise SigsumError("invalid leaf signature")

    # 2. tree head: log signature on the checkpoint, then the witness quorum
    log = policy.logs.get(pr.log_key_hash)
    if log is None:
        raise SigsumError("unknown log")
    log_key = log[0]
    origin = CHECKPOINT_NAME_PREFIX + pr.log_key_hash.hex()
    cp = _checkpoint(origin, pr.size, pr.root_hash)
    if not _ed25519_verify(log_key, cp.encode(), pr.log_signature):
        raise SigsumError("invalid log signature")
    verified, stamps, failed = set(), {}, 0
    for kh, (ts, sig) in pr.cosignatures.items():
        w = policy.witnesses.get(kh)
        if w is None:
            continue                                 # not in this policy: ignored, as in sigsum-go
        if _ed25519_verify(w[1], f"{COSIGNATURE_NAMESPACE}\ntime {ts}\n{cp}".encode(), sig):
            verified.add(kh)
            stamps[w[0]] = ts
        else:
            failed += 1
    if not policy._satisfied(policy.quorum, verified):
        raise SigsumError(f"not enough cosignatures, total: {len(pr.cosignatures)}, "
                          f"verified: {len(verified)}, failed to verify: {failed}")

    # 3. inclusion of the leaf under the signed root
    leaf_hash = _sha256(b"\x00" + checksum + pr.leaf_signature + pr.key_hash)
    _verify_inclusion(leaf_hash, pr.leaf_index, pr.size, pr.root_hash, pr.path)
    return Result(pr.size, pr.root_hash, pr.leaf_index, pr.log_key_hash, pr.key_hash, stamps)


def verify_proof(message: bytes, proof_text, submitter_pubkeys: list, policy: Policy) -> Result:
    """Verify `proof_text` for the file contents `message`, as `sigsum-verify -k KEY -p POLICY PROOF < FILE`.

    Raises SigsumError on any failure; returns the verified tree head and witness timestamps otherwise.
    Freshness is NOT judged here: the caller compares `Result.cosignatures` timestamps to its own clock.
    """
    return verify_proof_hash(_sha256(bytes(message)), proof_text, submitter_pubkeys, policy)
