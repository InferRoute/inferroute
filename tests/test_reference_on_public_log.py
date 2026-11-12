"""0.9.138: the signed reference is used only when it is proven to be on InferRoute's public Sigsum log.

The fixture is the PRODUCTION reference of 10 Nov 2026 and its real proof (log index 6089, cosigned 3/3), checked
against the submitter key and policy this program ships pinned in docs/trust."""
from pathlib import Path

import pytest

from inferroute_cli import probant_search_setup as S

FIX = Path(__file__).parent / "fixtures" / "sigsum" / "prod"
REF = (FIX / "current.json").read_bytes()
PROOF = (FIX / "current.json.proof").read_bytes()


def test_the_published_reference_is_on_the_log():
    got = S.check_on_public_log(REF, PROOF)
    assert got["leaf_index"] == 6089 and got["tree_size"] >= 6090


def test_a_reference_with_no_proof_is_refused():
    with pytest.raises(S.SetupError, match="no proof that it is on InferRoute's public log"):
        S.check_on_public_log(REF, None)


@pytest.mark.parametrize("change", [lambda b: b.replace(b"published_at", b"published_aT", 1),
                                    lambda b: b + b"\n", lambda b: b[:-1]])
def test_any_other_bytes_are_refused(change):
    with pytest.raises(S.SetupError, match="not proven to be on InferRoute's public log"):
        S.check_on_public_log(change(REF), PROOF)


def _damage(lines, i):
    last = lines[i][-1]
    lines[i] = lines[i][:-1] + ("0" if last != "0" else "1")


@pytest.mark.parametrize("prefix", ["node_hash=", "leaf="])
def test_a_damaged_proof_is_refused(prefix):
    lines = PROOF.decode().splitlines()
    _damage(lines, next(n for n, l in enumerate(lines) if l.startswith(prefix)))
    with pytest.raises(S.SetupError, match="not proven to be on InferRoute's public log"):
        S.check_on_public_log(REF, ("\n".join(lines) + "\n").encode())


def test_one_bad_witness_of_three_still_meets_the_quorum_and_two_do_not():
    cos = [n for n, l in enumerate(PROOF.decode().splitlines()) if l.startswith("cosignature=")]
    assert len(cos) == 3
    one = PROOF.decode().splitlines()
    _damage(one, cos[0])
    S.check_on_public_log(REF, ("\n".join(one) + "\n").encode())
    two = PROOF.decode().splitlines()
    _damage(two, cos[0]); _damage(two, cos[1])
    with pytest.raises(S.SetupError, match="not proven to be on InferRoute's public log"):
        S.check_on_public_log(REF, ("\n".join(two) + "\n").encode())


def test_the_pins_ship_in_the_wheel():
    t = Path(__file__).resolve().parents[1] / "pyproject.toml"
    s = t.read_text()
    assert '"docs/trust/transparency-submitter.pub" = "inferroute_cli/trust/transparency-submitter.pub"' in s
    assert '"docs/trust/sigsum-policy.txt" = "inferroute_cli/trust/sigsum-policy.txt"' in s
