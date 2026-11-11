"""The Sigsum verifier accepts exactly what the Go reference `sigsum-verify` accepts.

Real fixtures (tests/fixtures/sigsum/) were submitted to the TEST log only (policy sigsum-test1-2025) with a
throwaway key. Every mutant is checked to change the input, and — when `sigsum-verify` is installed — is
run through the Go binary too, so a disagreement fails the test rather than being assumed away.
"""
import base64
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from inferroute_cli import transparency as T

F = Path(__file__).parent / "fixtures" / "sigsum"
TEST_POLICY = (F / "sigsum-test1-2025.policy").read_text()
REAL = [("msg1.bin", "submitter.pub"), ("msg2.bin", "submitter.pub"), ("msg3.bin", "submitter.pub"),
        ("example.json", "example.pub")]
POLICY_WITNESS_HASHES = {   # sha256 of the three witness keys in sigsum-test1-2025
    "1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c",
    "70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc",
    "42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8",
}


def _go_binary():
    found = shutil.which("sigsum-verify")
    if found:
        return found
    p = Path.home() / "go" / "bin" / "sigsum-verify"
    return str(p) if p.exists() else None


GO = _go_binary()


def sha(b):
    return hashlib.sha256(b).digest()


def go_accepts(tmp_path, message: bytes, proof: str, pub_text: str, policy_text: str):
    """None when the Go reference is not installed."""
    if GO is None:
        return None
    d = tmp_path / f"go{len(list(tmp_path.iterdir()))}"
    d.mkdir()
    (d / "m").write_bytes(message)
    (d / "m.proof").write_text(proof)
    (d / "k.pub").write_text(pub_text)
    (d / "p.policy").write_text(policy_text)
    r = subprocess.run([GO, "-k", str(d / "k.pub"), "-p", str(d / "p.policy"), str(d / "m.proof")],
                       stdin=open(d / "m", "rb"), capture_output=True, timeout=60)
    return r.returncode == 0


def py_accepts(message, proof, pub_text, policy_text):
    try:
        T.verify_proof(message, proof, T.parse_ssh_ed25519_pubkeys(pub_text), T.parse_policy(policy_text))
        return True
    except T.SigsumError:
        return False


def both(tmp_path, message, proof, pub_text, policy_text):
    py = py_accepts(message, proof, pub_text, policy_text)
    go = go_accepts(tmp_path, message, proof, pub_text, policy_text)
    if go is not None:
        assert py == go, f"DISAGREEMENT: python={py} go={go}"
    return py


# ------------------------------------------------------------------ mutation helpers

def flip_hex_at(line: str, start: int) -> str:
    c = line[start]
    return line[:start] + ("0" if c != "0" else "1") + line[start + 1:]


def mutate_line(proof: str, idx: int, fn) -> str:
    lines = proof.split("\n")
    lines[idx] = fn(lines[idx])
    out = "\n".join(lines)
    assert out != proof, "mutant did not change the proof"
    return out


def line_indexes(proof: str, prefix: str):
    return [i for i, l in enumerate(proof.split("\n")) if l.startswith(prefix)]


def bump_int(s: str, d: int) -> str:
    return str(int(s) + d)


def proof_mutants(proof: str):
    """(name, mutant) for every field of the proof; each mutant is asserted to differ from the input."""
    out = []
    lines = proof.split("\n")

    def add(name, idx, fn):
        out.append((name, mutate_line(proof, idx, fn)))

    li = line_indexes(proof, "leaf=")[0]
    add("leaf.keyhash", li, lambda l: flip_hex_at(l, len("leaf=") + 10))
    add("leaf.signature", li, lambda l: flip_hex_at(l, len("leaf=") + 65 + 20))
    add("leaf.signature.S", li, lambda l: flip_hex_at(l, len(l) - 3))
    add("log keyhash", line_indexes(proof, "log=")[0], lambda l: flip_hex_at(l, 8))
    si = line_indexes(proof, "size=")[0]
    add("size+1", si, lambda l: "size=" + bump_int(l[5:], 1))
    if int(lines[si][5:]) > 1:
        add("size-1", si, lambda l: "size=" + bump_int(l[5:], -1))
    add("root_hash", line_indexes(proof, "root_hash=")[0], lambda l: flip_hex_at(l, 20))
    add("log signature", line_indexes(proof, "signature=")[0], lambda l: flip_hex_at(l, 30))
    for n, i in enumerate(line_indexes(proof, "node_hash=")):
        add(f"node_hash[{n}]", i, lambda l: flip_hex_at(l, 15))
    for i in line_indexes(proof, "leaf_index="):
        add("leaf_index+1", i, lambda l: "leaf_index=" + bump_int(l[11:], 1))
        if int(lines[i][11:]) > 0:
            add("leaf_index-1", i, lambda l: "leaf_index=" + bump_int(l[11:], -1))
    return out


def cosig_mutants(proof: str):
    out = []
    for n, i in enumerate(line_indexes(proof, "cosignature=")):
        kh = proof.split("\n")[i].split("=", 1)[1].split(" ")[0]
        out.append((f"cosig[{n}].signature", kh, mutate_line(proof, i, lambda l: flip_hex_at(l, len(l) - 40))))
        out.append((f"cosig[{n}].timestamp", kh, mutate_line(
            proof, i, lambda l: (lambda k, t, s: f"cosignature={k} {int(t) + 1} {s}")(*l[12:].split(" ")))))
    return out


def keep_cosigs(proof: str, keep) -> str:
    lines = [l for l in proof.split("\n")
             if not l.startswith("cosignature=") or l[12:76] in keep]
    return "\n".join(lines)


def load(name, key):
    return (F / name).read_bytes(), (F / f"{name}.proof").read_text(), (F / key).read_text()


# ------------------------------------------------------------------ real proofs from the test log

@pytest.mark.parametrize("name,key", REAL)
def test_real_proof_accepted_by_both(tmp_path, name, key):
    msg, proof, pub = load(name, key)
    assert both(tmp_path, msg, proof, pub, TEST_POLICY)
    r = T.verify_proof(msg, proof, T.parse_ssh_ed25519_pubkeys(pub), T.parse_policy(TEST_POLICY))
    assert r.size == int(re.search(r"^size=(\d+)$", proof, re.M).group(1))
    assert r.root_hash.hex() == re.search(r"^root_hash=(\w+)$", proof, re.M).group(1)
    assert set(r.cosignatures) == {"poc.sigsum.org/nisse", "rgdd.se/poc-witness", "witness1.smartit.nu/witness1"}
    assert all(ts > 1_700_000_000 for ts in r.cosignatures.values())


def test_raw_hash_entry_point_matches():
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    keys, pol = T.parse_ssh_ed25519_pubkeys(pub), T.parse_policy(TEST_POLICY)
    assert T.verify_proof_hash(sha(msg), proof, keys, pol) == T.verify_proof(msg, proof, keys, pol)
    with pytest.raises(T.SigsumError):          # the leaf commits to H(H(file)), not H(file)
        T.verify_proof_hash(sha(sha(msg)), proof, keys, pol)


@pytest.mark.parametrize("name,key", REAL[:2] + REAL[3:])
def test_real_proof_field_mutants_rejected_by_both(tmp_path, name, key):
    msg, proof, pub = load(name, key)
    muts = proof_mutants(proof)
    assert len(muts) >= 10
    for label, m in muts:
        assert not both(tmp_path, msg, m, pub, TEST_POLICY), label


@pytest.mark.parametrize("name,key", REAL[:1] + REAL[3:])
def test_message_byte_mutants_rejected_by_both(tmp_path, name, key):
    msg, proof, pub = load(name, key)
    for pos in (0, len(msg) // 2, len(msg) - 1):
        m = bytearray(msg)
        m[pos] ^= 0x01
        assert bytes(m) != msg
        assert not both(tmp_path, bytes(m), proof, pub, TEST_POLICY), pos
    assert not both(tmp_path, msg + b"\n", proof, pub, TEST_POLICY)


def test_cosignature_mutants_at_exact_quorum_rejected(tmp_path):
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    two = sorted(POLICY_WITNESS_HASHES)[:2]
    exact = keep_cosigs(proof, set(two))
    assert exact != proof and exact.count("cosignature=") == 2
    assert both(tmp_path, msg, exact, pub, TEST_POLICY)            # 2-of-3 met exactly
    muts = cosig_mutants(exact)
    assert len(muts) == 4
    for label, kh, m in muts:
        assert not both(tmp_path, msg, m, pub, TEST_POLICY), label


def test_cosignature_mutants_on_full_proof_agree_with_go(tmp_path):
    """A bad cosignature does not by itself fail a proof: sigsum-go ignores non-policy witnesses and counts a
    bad policy cosignature as 'failed' — the proof fails only if the quorum is then missed. With all three
    policy witnesses present, one broken cosignature leaves 2-of-3, so both verifiers accept."""
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    muts = cosig_mutants(proof)
    assert len(muts) == 30
    for label, kh, m in muts:
        assert both(tmp_path, msg, m, pub, TEST_POLICY), label     # quorum still met either way


def test_quorum_not_met(tmp_path):
    msg, proof, pub = load("msg2.bin", "submitter.pub")
    one = keep_cosigs(proof, {sorted(POLICY_WITNESS_HASHES)[0]})
    assert one.count("cosignature=") == 1
    assert not both(tmp_path, msg, one, pub, TEST_POLICY)
    none_left = keep_cosigs(proof, set())
    assert "cosignature=" not in none_left
    assert not both(tmp_path, msg, none_left, pub, TEST_POLICY)
    # thirteen non-policy cosignatures are worth nothing under this policy
    others = {l[12:76] for l in proof.split("\n") if l.startswith("cosignature=")} - POLICY_WITNESS_HASHES
    assert len(others) == 12
    assert not both(tmp_path, msg, keep_cosigs(proof, others), pub, TEST_POLICY)


def test_wrong_submitter_key(tmp_path):
    msg, proof, _ = load("msg1.bin", "submitter.pub")
    other = (F / "example.pub").read_text()
    assert other != (F / "submitter.pub").read_text()
    assert not both(tmp_path, msg, proof, other, TEST_POLICY)
    fresh = Ed25519PrivateKey.generate().public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH)
    assert not both(tmp_path, msg, proof, fresh.decode() + "\n", TEST_POLICY)


def test_policy_with_different_log_key(tmp_path):
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    bad = re.sub(r"^log [0-9a-f]{64}", "log " + os.urandom(32).hex(), TEST_POLICY, flags=re.M)
    assert bad != TEST_POLICY
    assert not both(tmp_path, msg, proof, pub, bad)


def test_policy_quorum_none_needs_only_the_log(tmp_path):
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    pol = TEST_POLICY.replace("quorum quorum-rule", "quorum none")
    assert pol != TEST_POLICY
    assert both(tmp_path, msg, keep_cosigs(proof, set()), pub, pol)


def test_policy_all_three_required(tmp_path):
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    pol = TEST_POLICY.replace("group quorum-rule 2 ", "group quorum-rule all ")
    assert pol != TEST_POLICY
    assert both(tmp_path, msg, proof, pub, pol)
    for label, kh, m in cosig_mutants(proof):
        if kh in POLICY_WITNESS_HASHES:
            assert not both(tmp_path, msg, m, pub, pol), label


@pytest.mark.parametrize("label,edit", [
    ("uppercase hex", lambda p: re.sub(r"^root_hash=(\w+)$", lambda m: "root_hash=" + m.group(1).upper(), p, flags=re.M)),
    ("missing final newline", lambda p: p.rstrip("\n")),
    ("trailing garbage", lambda p: p + "x=1\n"),
    ("trailing empty line", lambda p: p + "\n"),
    ("leading zero size", lambda p: re.sub(r"^size=", "size=0", p, flags=re.M)),
    ("CRLF", lambda p: p.replace("\n", "\r\n")),
    ("version 3", lambda p: p.replace("version=2", "version=3")),
    ("two spaces in leaf", lambda p: re.sub(r"^(leaf=[0-9a-f]{64}) ", r"\1  ", p, flags=re.M)),
    ("duplicate cosignature", lambda p: re.sub(r"^(cosignature=.*)$", r"\1\n\1", p, count=1, flags=re.M)),
    ("no blank before leaf_index", lambda p: p.replace("\n\nleaf_index", "\nleaf_index")),
    ("hex with space", lambda p: re.sub(r"^root_hash=(..)", r"root_hash= \1", p, flags=re.M)),
])
def test_text_format_edge_cases_agree(tmp_path, label, edit):
    msg, proof, pub = load("msg1.bin", "submitter.pub")
    m = edit(proof)
    assert m != proof, label
    verdict = both(tmp_path, msg, m, pub, TEST_POLICY)
    assert verdict == (label == "uppercase hex"), label


# ------------------------------------------------------------------ synthetic logs: sizes 1..9, built per spec

def raw(k):
    return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def mth(leaves):                         # RFC 6962 §2.1, independent of the module under test
    if len(leaves) == 1:
        return sha(b"\x00" + leaves[0])
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return sha(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def rfc_path(m, leaves):                 # RFC 6962 §2.1.1 PATH(m, D[n])
    if len(leaves) == 1:
        return []
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if m < k:
        return rfc_path(m, leaves[:k]) + [mth(leaves[k:])]
    return rfc_path(m - k, leaves[k:]) + [mth(leaves[:k])]


class SynthLog:
    def __init__(self, n_witnesses=3):
        self.log = Ed25519PrivateKey.generate()
        self.sub = Ed25519PrivateKey.generate()
        self.wit = [Ed25519PrivateKey.generate() for _ in range(n_witnesses)]
        self.pub_text = self.sub.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH).decode() + "\n"
        names = [f"w{i}.example" for i in range(n_witnesses)]
        self.policy = (f"log {raw(self.log).hex()} https://log.example\n"
                       + "".join(f"witness {nm} {raw(w).hex()}\n" for nm, w in zip(names, self.wit))
                       + f"group g 2 {' '.join(names)}\nquorum g\n")

    def leaf(self, msg):
        checksum = sha(sha(msg))
        sig = self.sub.sign(b"sigsum.org/v1/tree-leaf\x00" + checksum)
        return checksum + sig + sha(raw(self.sub)), sig

    def proof(self, msgs, index, ts=1_790_000_000):
        leaves = [self.leaf(m)[0] for m in msgs]
        root, size = mth(leaves), len(leaves)
        lkh = sha(raw(self.log))
        cp = f"sigsum.org/v1/tree/{lkh.hex()}\n{size}\n{base64.b64encode(root).decode()}\n"
        lines = ["version=2", f"log={lkh.hex()}",
                 f"leaf={sha(raw(self.sub)).hex()} {leaves[index][32:96].hex()}", "",
                 f"size={size}", f"root_hash={root.hex()}", f"signature={self.log.sign(cp.encode()).hex()}"]
        for w in self.wit:
            sig = w.sign(f"cosignature/v1\ntime {ts}\n{cp}".encode())
            lines.append(f"cosignature={sha(raw(w)).hex()} {ts} {sig.hex()}")
        if size > 1:
            lines += ["", f"leaf_index={index}"] + [f"node_hash={h.hex()}" for h in rfc_path(index, leaves)]
        return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def synth():
    return SynthLog()


def test_size_one_tree(tmp_path, synth):
    msg = b"only leaf"
    p = synth.proof([msg], 0)
    assert "node_hash" not in p and "leaf_index" not in p
    assert both(tmp_path, msg, p, synth.pub_text, synth.policy)
    r = T.verify_proof(msg, p, T.parse_ssh_ed25519_pubkeys(synth.pub_text), T.parse_policy(synth.policy))
    assert (r.size, r.leaf_index) == (1, 0)
    assert r.root_hash == sha(b"\x00" + synth.leaf(msg)[0])
    assert set(r.cosignatures.values()) == {1_790_000_000}
    for label, m in proof_mutants(p):
        assert not both(tmp_path, msg, m, synth.pub_text, synth.policy), label
    # a size-1 proof followed by an (empty) inclusion part is malformed
    assert not both(tmp_path, msg, p + "\nleaf_index=0\n", synth.pub_text, synth.policy)


@pytest.mark.parametrize("size", [2, 3, 4, 5, 6, 7, 8, 9])
def test_every_index_of_small_trees(tmp_path, synth, size):
    msgs = [f"m{i}".encode() for i in range(size)]
    for idx in range(size):
        p = synth.proof(msgs, idx)
        assert both(tmp_path, msgs[idx], p, synth.pub_text, synth.policy), (size, idx)
        if idx != (idx + 1) % size:     # the proof for one leaf does not prove another
            assert not both(tmp_path, msgs[(idx + 1) % size], p, synth.pub_text, synth.policy)
    for label, m in proof_mutants(synth.proof(msgs, size // 2)):
        assert not both(tmp_path, msgs[size // 2], m, synth.pub_text, synth.policy), (size, label)


def test_synthetic_cosignature_timestamps_and_quorum(tmp_path, synth):
    msgs = [b"a", b"b", b"c"]
    p = synth.proof(msgs, 1)
    for label, kh, m in cosig_mutants(p):                      # 3 present, 2 needed: one break tolerated
        assert both(tmp_path, b"b", m, synth.pub_text, synth.policy), label
    exact = keep_cosigs(p, {sha(raw(w)).hex() for w in synth.wit[:2]})
    assert exact.count("cosignature=") == 2
    for label, kh, m in cosig_mutants(exact):
        assert not both(tmp_path, b"b", m, synth.pub_text, synth.policy), label


# ------------------------------------------------------------------ Ed25519 strictness and policy parsing

LOW_ORDER = ["0100000000000000000000000000000000000000000000000000000000000000",
             "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
             "0000000000000000000000000000000000000000000000000000000000000000",
             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"]


def test_point_validation_matches_sigsum_go_rules():
    for h in LOW_ORDER:
        assert not T._valid_point(bytes.fromhex(h)), h
    assert not T._valid_point(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"))
    noncanon = (2 ** 255 - 19 + 1).to_bytes(32, "little")      # y = p + 1 encodes y = 1 non-canonically
    assert not T._valid_point(noncanon)
    for _ in range(20):
        assert T._valid_point(raw(Ed25519PrivateKey.generate()))


def test_low_order_submitter_key_rejected(tmp_path):
    msg, proof, _ = load("msg1.bin", "submitter.pub")
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes.fromhex(LOW_ORDER[0])
    pub = f"ssh-ed25519 {base64.b64encode(blob).decode()} x\n"
    assert not both(tmp_path, msg, proof, pub, TEST_POLICY)


GENERIC = """# vetted
log 0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25 https://seasalp.glasklar.is
log f00c159663d09bbda6131ee1816863b6adcacfe80b0b288000b11aba8fe38314 https://ginkgo.tlog.mullvad.net
witness witness.glasklar.is            b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536
witness witness.mullvad.net            15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad
witness tillitis.se/tillitis-witness-1 076be8c9ee7ea60916f0df3608c945d7730082ecb37749dad2c9ed339fea770c
group quorum-rule 2 witness.glasklar.is witness.mullvad.net tillitis.se/tillitis-witness-1
quorum quorum-rule
"""


def test_parse_generic_policy():
    p = T.parse_policy(GENERIC)
    assert len(p.logs) == 2 and len(p.witnesses) == 3
    assert {v[0] for v in p.witnesses.values()} == {"witness.glasklar.is", "witness.mullvad.net",
                                                     "tillitis.se/tillitis-witness-1"}
    assert p.quorum.k == 2 and len(p.quorum.members) == 3


@pytest.mark.parametrize("label,text", [
    ("no quorum", GENERIC.replace("quorum quorum-rule\n", "")),
    ("twice quorum", GENERIC + "quorum quorum-rule\n"),
    ("threshold 4", GENERIC.replace("quorum-rule 2", "quorum-rule 4")),
    ("threshold 0", GENERIC.replace("quorum-rule 2", "quorum-rule 0")),
    ("undefined member", GENERIC.replace("witness.mullvad.net tillitis", "nobody tillitis")),
    ("member reused", GENERIC.replace("quorum quorum-rule", "group g2 1 witness.glasklar.is\nquorum g2")),
    ("dup witness name", GENERIC.replace("witness witness.mullvad.net", "witness witness.glasklar.is")),
    ("dup log", GENERIC + GENERIC.split("\n")[1] + "\n"),
    ("short key", GENERIC.replace("b2106db9", "b2106d")),
    ("unknown keyword", GENERIC + "logs abc\n"),
    ("control char", GENERIC.replace("# vetted", "# vet\x01ted")),
    ("none as member", GENERIC.replace("quorum quorum-rule", "group g2 1 none\nquorum g2")),
])
def test_policy_errors(label, text):
    assert text != GENERIC
    with pytest.raises(T.SigsumError):
        T.parse_policy(text)


def test_policy_nested_groups_and_keywords():
    p = T.parse_policy(GENERIC.replace(
        "group quorum-rule 2 witness.glasklar.is witness.mullvad.net tillitis.se/tillitis-witness-1\nquorum quorum-rule",
        "group a any witness.glasklar.is witness.mullvad.net\ngroup b all a tillitis.se/tillitis-witness-1\nquorum b"))
    kh = {v[0]: k for k, v in p.witnesses.items()}
    sat = lambda names: p._satisfied(p.quorum, {kh[n] for n in names})
    assert sat(["witness.mullvad.net", "tillitis.se/tillitis-witness-1"])
    assert not sat(["witness.mullvad.net", "witness.glasklar.is"])
    assert not sat(["tillitis.se/tillitis-witness-1"])
    assert T.parse_policy("quorum none\n").quorum.k == 0


def test_go_reference_was_exercised():
    """Make it visible when the differential half silently did not run."""
    if GO is None:
        pytest.skip("sigsum-verify not installed: only the Python half of the differential tests ran")
    assert subprocess.run([GO, "--version"], capture_output=True).returncode == 0
