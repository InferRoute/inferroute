"""`ir surveyor reference` — the operator side of the identity anchor.

The load-bearing tests are the cross-implementation ones: the issuer and the bundled verifier must agree on
canonicalisation byte-for-byte (or every signed reference fails for every firm), and a reference this tool
builds and signs must be accepted by the verifier a stranger actually runs. The rest guard the ways a
reference gets built wrong in silence: a policy that is not the attested one, a release that never expires,
an incomplete reference that would fail identity for everyone.
"""
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from inferroute_cli import reference as R

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures" / "aci"
SCRIPT = HERE.parent / "inferroute_cli" / "pi_attested" / "verify_record.py"


def _verifier():
    spec = importlib.util.spec_from_file_location("verify_record", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def V():
    return _verifier()


@pytest.fixture(scope="module")
def kms():
    return json.load(open(FIX / "kms-snp.json"))


RD = {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8,
      "enclave_x25519_pub": "cd" * 32, "index_manifest_sha256": "ef" * 32, "model_manifest_sha256": "12" * 32}


def _offer_file(tmp_path, kms, *, rd=None, policy_b64=None, name="offer.json"):
    """A real SNP report (so HOST_DATA is real) with our runtime data — what the operator's own deployment
    serves at /offer."""
    doc = {"offer": {"evidence": kms["evidence"], "endorsements": kms["endorsements"],
                     "uvm_endorsements": kms["uvm_endorsements"],
                     "runtime_data": base64.b64encode(json.dumps(rd if rd is not None else RD).encode()).decode()}}
    if policy_b64 is not None:
        doc["policy_b64"] = policy_b64
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def _host_data(kms):
    return base64.b64decode(kms["evidence"])[0xC0:0xE0].hex()


# ───────────────────────────── the cross-implementation checks ─────────────────────────────


def test_canonicalisation_matches_the_bundled_verifier(V):
    """If these two ever disagree, every signed reference fails for every firm — silently and everywhere."""
    for obj in ({}, {"a": 1}, {"b": [1, 2, {"c": "d"}]},
                {"source": "Kanzlei Müller & Partner — Zürich"},          # non-ASCII: ensure_ascii must match
                {"z": "ü", "a": "日本語", "n": None, "t": True, "f": 1.5},
                {"policy_sha256": [{"value": "ab" * 32, "valid_from": "2026-01-01T00:00:00Z"}]}):
        assert R.canonical(obj) == V.canonical(obj), obj


def test_a_built_and_signed_reference_is_accepted_by_the_bundled_verifier(tmp_path, V, kms):
    key_path = tmp_path / "pub.key"
    pub = R.new_key(str(key_path))
    ref = R.build(R.values_from_offer(str(_offer_file(tmp_path, kms))), source="engagement letter")
    signed = R.sign(ref, str(key_path))
    # the verifier a stranger runs accepts it under the key they recorded at first use
    c = V.Checks()
    V.check_reference_signature(c, signed, pub)
    assert c.failed == [] and "verifies under the publication key" in c.rows[0][2]
    # and refuses it under any other key
    other = R.new_key(str(tmp_path / "other.key"))
    c2 = V.Checks()
    V.check_reference_signature(c2, signed, other)
    assert "reference signature" in c2.failed
    # the entries it wrote are the ones the verifier matches
    assert V._ref_match(V._ref_entries(signed, "policy_sha256"), _host_data(kms), None)[0] is True
    assert V._ref_match(V._ref_entries(signed, "index_manifest_sha256"), RD["index_manifest_sha256"], None)[0] is True


def test_windows_written_here_are_read_the_same_way_there(tmp_path, V, kms):
    ref = R.build(R.values_from_offer(str(_offer_file(tmp_path, kms))),
                  valid_from="2026-01-01T00:00:00Z", valid_to="2026-12-31T00:00:00Z")
    entries = V._ref_entries(ref, "policy_sha256")
    host = _host_data(kms)
    assert V._ref_match(entries, host, "2026-06-01T12:00:00Z")[0] is True
    assert V._ref_match(entries, host, "2025-06-01T12:00:00Z") == (False, "matches, but the search (2025-06-01T12:00:00Z) predates its valid_from 2026-01-01T00:00:00Z")
    assert V._ref_match(entries, host, None)[0] is False          # windowed + no statement time → refused


def test_a_full_bundle_verifies_against_a_signed_reference(tmp_path, V, kms):
    """End to end through the real CLI: build, sign, then run verify_record.py over a bundle."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    signer = Ed25519PrivateKey.generate()
    signer_pub = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    rd = {**RD, "statement_signer_pub": signer_pub}
    offer_path = _offer_file(tmp_path, kms, rd=rd)

    key_path = tmp_path / "pub.key"
    pub = R.new_key(str(key_path))
    ref_path = tmp_path / "reference.json"
    assert R.main(["build", "--from-offer", str(offer_path), "--source", "engagement letter",
                   "--valid-from", "2026-01-01T00:00:00Z", "--out", str(ref_path)]) == 0
    assert R.main(["sign", "--in", str(ref_path), "--key", str(key_path)]) == 0
    assert json.loads(ref_path.read_text())["publication_key"] == pub

    # a bundle whose statement is signed by the key that offer's runtime data commits to
    rd_bytes = base64.b64decode(json.loads(offer_path.read_text())["offer"]["runtime_data"])
    rid = "0" * 32
    q, res = "a coolant channel between cells", {"hits": [{"key": "US-7000-B2"}]}
    st = {"v": 1, "kind": "search", "lifetime_id": rd["lifetime_id"], "request_id": rid, "seq": 1,
          "started_utc": "2026-06-01T12:00:00Z", "runtime_data_sha256": hashlib.sha256(rd_bytes).hexdigest(),
          "index_manifest_sha256": rd["index_manifest_sha256"], "model_manifest_sha256": rd["model_manifest_sha256"],
          "cutoff_date": 20200115, "hits_n": 1, "outcome": "answered",
          "query_sha256": V.salted(rid, q), "result_sha256": V.salted(rid, res)}
    st["sig"] = signer.sign(V.canonical(st)).hex()
    d = tmp_path / "bundle"
    d.mkdir()
    ev_bytes = json.loads(offer_path.read_text())
    ev_raw = json.dumps(ev_bytes, indent=1).encode()
    ev_sha = hashlib.sha256(ev_raw).hexdigest()
    (d / f"{ev_sha[:16]}.evidence.json").write_bytes(ev_raw)
    (d / "searches.json").write_text(json.dumps([{"n": 1, "session_id": "s", "at": "t", "statement": st, "result": res,
                                                  "query_text": q, "signer_pub": signer_pub,
                                                  "evidence_file": f"{ev_sha[:16]}.evidence.json", "evidence_sha256": ev_sha}]))
    for n in ("record.html", "VERIFY.md"):
        (d / n).write_text("x")
    (d / "verify_record.py").write_bytes(SCRIPT.read_bytes())
    files = {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in os.listdir(d)}
    (d / "MANIFEST.json").write_text(json.dumps({"files": files, "matter_cutoff": 20200115}))

    r = subprocess.run([sys.executable, str(SCRIPT), str(d), "--reference", str(ref_path), "--reference-key", pub],
                       capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert "PASS reference signature" in out, out
    assert "PASS enclave identity" in out and "policy: current" in out, out
    assert "PASS statement signature" in out and "PASS signer key committed in runtime data" in out


# ───────────────────────────── the ways a reference gets built wrong ─────────────────────────────


def test_a_policy_that_is_not_the_attested_one_is_refused(tmp_path, kms):
    bad = _offer_file(tmp_path, kms, policy_b64=base64.b64encode(b"some other policy").decode())
    with pytest.raises(R.ReferenceError) as e:
        R.values_from_offer(str(bad))
    assert "does not hash to the HOST_DATA" in str(e.value)
    # the matching policy is accepted and is exactly HOST_DATA
    host = _host_data(kms)
    real_policy = (FIX / "sidecar-uvm_security_policy.base64").read_text().strip()
    ok = _offer_file(tmp_path, kms, policy_b64=real_policy, name="ok.json")
    # the sidecar policy belongs to a different report, so this must refuse too — proving the check is live
    with pytest.raises(R.ReferenceError):
        R.values_from_offer(str(ok))
    assert R.values_from_offer(str(_offer_file(tmp_path, kms, name="nopolicy.json")))["policy_sha256"] == host


def test_an_incomplete_reference_is_refused(tmp_path):
    with pytest.raises(R.ReferenceError) as e:
        R.build({"policy_sha256": "ab" * 32})
    assert "index_manifest_sha256" in str(e.value) and "fail identity for every record" in str(e.value)


def test_supersede_closes_the_previous_release(tmp_path, kms):
    first = R.build({"policy_sha256": "a" * 64, "index_manifest_sha256": "b" * 64, "model_manifest_sha256": "c" * 64},
                    valid_from="2026-01-01T00:00:00Z")
    assert "valid_to" not in first["policy_sha256"][0]
    second = R.build({"policy_sha256": "d" * 64, "index_manifest_sha256": "b" * 64, "model_manifest_sha256": "c" * 64},
                     merge=first, valid_from="2026-06-01T00:00:00Z", supersede=True)
    old = [e for e in second["policy_sha256"] if e["value"] == "a" * 64][0]
    assert old["valid_to"] == "2026-06-01T00:00:00Z"              # the old release stops being current
    new = [e for e in second["policy_sha256"] if e["value"] == "d" * 64][0]
    assert new["valid_from"] == "2026-06-01T00:00:00Z" and "valid_to" not in new
    # an unchanged manifest is not duplicated, and its window is still closed then reopened by the new entry
    assert len([e for e in second["index_manifest_sha256"] if e["value"] == "b" * 64]) == 2
    with pytest.raises(R.ReferenceError):
        R.build({f: "0" * 64 for f in R.FIELDS}, merge=first, supersede=True)   # supersede needs a start time


def test_retire_marks_the_entry_and_drops_the_signature(tmp_path):
    ref = R.build({f: c * 64 for f, c in zip(R.FIELDS, "abc")}, valid_from="2026-01-01T00:00:00Z")
    key = tmp_path / "k.key"
    pub = R.new_key(str(key))
    signed = R.sign(ref, str(key))
    assert "sig" in signed
    retired, n = R.retire(signed, "a" * 64, at="2026-07-01T00:00:00Z")
    assert n == 1 and "sig" not in retired                        # an edit invalidates the signature
    e = retired["policy_sha256"][0]
    assert e["retired"] is True and e["valid_to"] == "2026-07-01T00:00:00Z"
    with pytest.raises(R.ReferenceError):
        R.retire(retired, "ff" * 32)                              # nothing to retire is an error, not a no-op


def test_new_key_refuses_to_overwrite_and_can_be_encrypted(tmp_path, monkeypatch):
    p = tmp_path / "k.key"
    R.new_key(str(p))
    assert (p.stat().st_mode & 0o777) == 0o600
    with pytest.raises(R.ReferenceError):
        R.new_key(str(p))
    monkeypatch.setenv("PP", "correct horse")
    enc = tmp_path / "enc.key"
    pub = R.new_key(str(enc), passphrase=b"correct horse")
    ref = R.build({f: c * 64 for f, c in zip(R.FIELDS, "abc")})
    with pytest.raises(R.ReferenceError):
        R.sign(ref, str(enc))                                     # encrypted key without the passphrase
    assert R.sign(ref, str(enc), passphrase=b"correct horse")["publication_key"] == pub


def test_verify_cli_reports_status_and_exits_nonzero_on_a_bad_key(tmp_path, capsys):
    ref = R.build({f: c * 64 for f, c in zip(R.FIELDS, "abc")},
                  valid_from="2020-01-01T00:00:00Z", valid_to="2020-12-31T00:00:00Z")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(ref))
    key = tmp_path / "k.key"
    pub = R.new_key(str(key))
    assert R.main(["sign", "--in", str(p), "--key", str(key)]) == 0
    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 0
    out = capsys.readouterr().out
    assert "OK   verifies under the publication key" in out and "expired (to 2020-12-31T00:00:00Z)" in out
    other = R.new_key(str(tmp_path / "o.key"))
    assert R.main(["verify", "--in", str(p), "--key-hex", other]) == 1
    assert "does NOT verify" in capsys.readouterr().out
