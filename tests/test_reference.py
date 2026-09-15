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
    assert R.main(["sign", "--in", str(p), "--key", str(key)]) == 2          # nothing current → refused
    assert R.main(["sign", "--in", str(p), "--key", str(key), "--allow-not-current"]) == 0
    # signed under the right key, but nothing current: the signature verdict and the usability verdict differ
    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 3
    out = capsys.readouterr().out
    assert "SIGNED BUT NOT USABLE" in out and "verifies under the publication key" in out
    assert "expired (to 2020-12-31T00:00:00Z)" in out
    other = R.new_key(str(tmp_path / "o.key"))
    assert R.main(["verify", "--in", str(p), "--key-hex", other]) == 1
    assert "does NOT verify" in capsys.readouterr().out


# ───────── reviewer's knife on the issuer: supersede that does not supersede, dead windows, dead references ─────────

def _three(vals, **kw):
    return R.build({f: v * 64 for f, v in zip(R.FIELDS, vals)}, **kw)


def test_supersede_closes_an_entry_that_already_had_an_end_date(V):
    """Finding 1: --supersede skipped any entry that already carried a valid_to, so a release given an
    explicit end date at build time survived it — and since the verifier accepts ANY matching entry that is
    current, the superseded release kept passing until its original end."""
    v1 = _three("abc", valid_from="2026-01-01T00:00:00Z", valid_to="2030-01-01T00:00:00Z")
    v2 = _three("dbc", merge=v1, valid_from="2026-06-01T00:00:00Z", supersede=True)
    old = [e for e in v2["policy_sha256"] if e["value"] == "a" * 64][0]
    assert old["valid_to"] == "2026-06-01T00:00:00Z", old      # closed at the supersede, not left at 2030
    # and the verifier a stranger runs now refuses it twelve hours after the supersede
    entries = V._ref_entries(v2, "policy_sha256")
    ok, why = V._ref_match(entries, "a" * 64, "2026-06-01T12:00:00Z")
    assert ok is False and "after its valid_to 2026-06-01T00:00:00Z" in why
    assert V._ref_match(entries, "d" * 64, "2026-06-01T12:00:00Z")[0] is True
    # an entry that already ended EARLIER than the supersede keeps its own earlier end
    early = _three("abc", valid_from="2026-01-01T00:00:00Z", valid_to="2026-02-01T00:00:00Z")
    later = _three("dbc", merge=early, valid_from="2026-06-01T00:00:00Z", supersede=True)
    assert [e for e in later["policy_sha256"] if e["value"] == "a" * 64][0]["valid_to"] == "2026-02-01T00:00:00Z"


def test_a_backwards_supersede_is_refused(V):
    """Finding 2: superseding before an existing entry starts wrote a window ending before it began — an
    entry dead for every input, whose only symptom is an unexplainable refusal in the field."""
    v1 = _three("abc", valid_from="2026-06-01T00:00:00Z")
    with pytest.raises(R.ReferenceError) as e:
        _three("dbc", merge=v1, valid_from="2026-01-01T00:00:00Z", supersede=True)
    assert "is BEFORE an existing" in str(e.value) and "could never be current" in str(e.value)
    # the reference was not half-superseded by the refusal
    assert "valid_to" not in v1["policy_sha256"][0]
    # and a new entry whose own end precedes its own start is refused too
    with pytest.raises(R.ReferenceError) as e2:
        _three("abc", valid_from="2026-06-01T00:00:00Z", valid_to="2026-01-01T00:00:00Z")
    assert "before --valid-from" in str(e2.value)


def test_sign_refuses_a_reference_in_which_nothing_is_current(tmp_path):
    """Finding 3: a signed reference whose entries had all expired was published-ready and would have failed
    identity for every client of every record. Fail when the bad value is created, not when a firm uses it."""
    key = tmp_path / "k.key"
    R.new_key(str(key))
    dead = _three("abc", valid_from="2020-01-01T00:00:00Z", valid_to="2021-01-01T00:00:00Z")
    with pytest.raises(R.ReferenceError) as e:
        R.sign(dead, str(key))
    assert "nothing is current" in str(e.value) and "expired (to 2021-01-01T00:00:00Z)" in str(e.value)
    assert "--allow-not-current" in str(e.value)
    assert "sig" in R.sign(dead, str(key), allow_not_current=True)      # the deliberate historical case
    # a pre-announced (not yet current) reference is the same refusal with the same escape hatch
    future = _three("abc", valid_from="2099-01-01T00:00:00Z")
    with pytest.raises(R.ReferenceError):
        R.sign(future, str(key))
    assert "sig" in R.sign(future, str(key), allow_not_current=True)


def test_sign_refuses_two_simultaneously_current_entries_for_one_field(tmp_path):
    """The structural gap: the verifier accepts any current entry, so two current entries mean two different
    enclaves both pass identity — right during a planned overlap, wrong otherwise, and nothing said which."""
    key = tmp_path / "k.key"
    R.new_key(str(key))
    overlapping = _three("dbc", merge=_three("abc"), valid_from=None)    # two open policy entries
    assert len(overlapping["policy_sha256"]) == 2
    with pytest.raises(R.ReferenceError) as e:
        R.sign(overlapping, str(key))
    assert "more than one entry is current" in str(e.value) and "--allow-overlap" in str(e.value)
    assert "sig" in R.sign(overlapping, str(key), allow_overlap=True)
    # a correct supersede leaves exactly one current, so it signs with no override at all
    clean = _three("dbc", merge=_three("abc", valid_from="2026-01-01T00:00:00Z"),
                   valid_from="2026-06-01T00:00:00Z", supersede=True)
    assert "sig" in R.sign(clean, str(key))


def test_dead_and_unparsable_windows_are_refused_at_signing(tmp_path):
    key = tmp_path / "k.key"
    R.new_key(str(key))
    hand_edited = {**_three("abc"), "policy_sha256": [{"value": "a" * 64, "valid_from": "2026-01-01T00:00:00Z",
                                                       "valid_to": "2025-01-01T00:00:00Z"}]}
    with pytest.raises(R.ReferenceError) as e:
        R.sign(hand_edited, str(key), allow_not_current=True, allow_overlap=True)
    assert "DEAD INTERVAL" in str(e.value)                      # not silenced by the overrides
    bad_time = {**_three("abc"), "policy_sha256": [{"value": "a" * 64, "valid_to": "whenever"}]}
    with pytest.raises(R.ReferenceError) as e2:
        R.sign(bad_time, str(key), allow_not_current=True, allow_overlap=True)
    assert "UNPARSABLE WINDOW" in str(e2.value)


# ───────────────────────── the argv layer: no tracebacks, no exit code that lies ─────────────────────────

def test_sign_with_a_missing_key_file_is_a_message_not_a_traceback(tmp_path, capsys):
    ref = _three("abc")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(ref))
    assert R.main(["sign", "--in", str(p), "--key", str(tmp_path / "nope.key")]) == 2
    err = capsys.readouterr().err
    assert "cannot read the publication key" in err and "about the file, not the key" in err
    assert "Traceback" not in err


def test_verify_exit_code_does_not_contradict_its_own_output(tmp_path, capsys):
    """An unsigned reference, or a signed one checked without a key, must not exit 0 — anyone scripting the
    check the runbook tells a firm to run would get a green light on a reference nobody signed."""
    ref = _three("abc")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(ref))
    assert R.main(["verify", "--in", str(p)]) == 1                       # unsigned
    out = capsys.readouterr().out
    assert "NOT VERIFIED" in out and "unsigned" in out and "exit 1" in out
    assert R.main(["verify", "--in", str(p), "--allow-unverified"]) == 0  # deliberate draft inspection
    assert "NOT VERIFIED" in capsys.readouterr().out                      # still says so

    key = tmp_path / "k.key"
    pub = R.new_key(str(key))
    assert R.main(["sign", "--in", str(p), "--key", str(key)]) == 0
    capsys.readouterr()
    assert R.main(["verify", "--in", str(p)]) == 1                       # signed, but nobody checked it
    assert "no publication key was given" in capsys.readouterr().out
    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 0


def test_verify_refuses_an_unparsable_at_rather_than_answering_about_now(tmp_path, capsys):
    ref = _three("abc")
    p = tmp_path / "r.json"
    p.write_text(json.dumps(ref))
    assert R.main(["verify", "--in", str(p), "--at", "last tuesday"]) == 2
    assert "not an ISO-8601 time" in capsys.readouterr().err
    with pytest.raises(R.ReferenceError):
        R.describe(ref, "last tuesday")                                  # closed in the API too
    assert R.describe(ref, "2026-06-01T12:00:00Z")                       # a real time still works


def test_verify_separates_the_signature_verdict_from_the_usability_verdict(tmp_path, capsys):
    """A signed reference under which nothing is current led with OK and exited 0 — while being one under
    which every record fails identity for every client. The exit code has to carry both verdicts."""
    key = tmp_path / "k.key"
    pub = R.new_key(str(key))

    dead = _three("abc", valid_from="2020-01-01T00:00:00Z", valid_to="2021-01-01T00:00:00Z")
    p = tmp_path / "dead.json"
    p.write_text(json.dumps(R.sign(dead, str(key), allow_not_current=True)))
    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 3
    out = capsys.readouterr().out
    assert out.startswith("SIGNED BUT NOT USABLE"), out           # not "OK"
    assert "nothing is current for: policy_sha256" in out and "expired (to 2021-01-01T00:00:00Z)" in out
    assert "exit 3" in out and "FAIL identity" in out
    # waiving the SIGNATURE concern does not waive the usability one
    assert R.main(["verify", "--in", str(p), "--allow-unverified"]) == 3
    capsys.readouterr()

    # the same reference, asked about a date when it WAS current, is usable then
    assert R.main(["verify", "--in", str(p), "--key-hex", pub, "--at", "2020-06-01T00:00:00Z"]) == 0
    assert capsys.readouterr().out.startswith("OK   ")

    # a current, signed reference is plain 0
    live = _three("abc", valid_from="2020-01-01T00:00:00Z")
    q = tmp_path / "live.json"
    q.write_text(json.dumps(R.sign(live, str(key))))
    assert R.main(["verify", "--in", str(q), "--key-hex", pub]) == 0
    assert capsys.readouterr().out.startswith("OK   ")

    # an unsigned reference that is also unusable reports the signature problem first (exit 1)
    u = tmp_path / "unsigned.json"
    u.write_text(json.dumps(dead))
    assert R.main(["verify", "--in", str(u), "--key-hex", pub]) == 1
    assert capsys.readouterr().out.startswith("NOT VERIFIED")


def test_verify_notes_an_overlap_without_failing_on_it(tmp_path, capsys):
    key = tmp_path / "k.key"
    pub = R.new_key(str(key))
    overlapping = _three("dbc", merge=_three("abc"))
    p = tmp_path / "o.json"
    p.write_text(json.dumps(R.sign(overlapping, str(key), allow_overlap=True)))
    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 0     # usable; the reader is not blocked
    out = capsys.readouterr().out
    assert "more than one entry is current for policy_sha256" in out and "planned rollout overlap" in out


def test_new_key_refuses_a_filesystem_that_cannot_enforce_owner_only(tmp_path, monkeypatch):
    """chmod on exFAT/FAT/NTFS SUCCEEDS and changes nothing, so the key would sit world-readable while the
    command reported it protected — the same report-one-thing-do-another shape. Refuse, and delete the key
    that was briefly written. (Simulated by making the read-back report a permissive mode.)"""
    real_stat = Path.stat
    target = tmp_path / "k.key"

    def fake_stat(self, *a, **kw):
        st = real_stat(self, *a, **kw)
        if Path(self) == target:
            class S:
                st_mode = 0o100755                        # what exFAT reports back
            return S()
        return st

    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(R.ReferenceError) as e:
        R.new_key(str(target))
    assert "group/other can read it" in str(e.value) and "exFAT" in str(e.value)
    monkeypatch.undo()
    assert not target.exists(), "the exposed key must be deleted, not left behind"
    # a filesystem that does enforce it still works
    assert R.new_key(str(tmp_path / "ok.key"))
    assert (tmp_path / "ok.key").stat().st_mode & 0o077 == 0


def test_passphrase_can_be_typed_rather_than_put_in_argv_or_env(tmp_path, monkeypatch):
    typed = iter(["s3cret", "s3cret", "s3cret"])
    monkeypatch.setattr("getpass.getpass", lambda *a, **kw: next(typed))
    key = tmp_path / "k.key"
    pub = R.new_key(str(key), passphrase=R._passphrase(None, prompt=True, confirm=True))
    ref = _three("abc")
    assert R.sign(ref, str(key), passphrase=R._passphrase(None, prompt=True))["publication_key"] == pub
    # a mismatch writes nothing
    two = iter(["a", "b"])
    monkeypatch.setattr("getpass.getpass", lambda *a, **kw: next(two))
    with pytest.raises(R.ReferenceError) as e:
        R._passphrase(None, prompt=True, confirm=True)
    assert "do not match" in str(e.value)


def test_a_development_reference_announces_itself_and_cannot_establish_identity(tmp_path, capsys):
    """A key that is not the offline production key must be impossible to mistake for it — in a few days,
    or by whoever fills in the engagement letter. The mark is inside the signature, so stripping it breaks
    the signature, and the record verifier refuses identity against it outright."""
    key = tmp_path / "dev.key"
    pub = R.new_key(str(key))
    ref = R.sign(_three("abc"), str(key), development=True)
    assert ref["development"] is True
    p = tmp_path / "dev.json"
    p.write_text(json.dumps(ref))

    assert R.main(["verify", "--in", str(p), "--key-hex", pub]) == 3       # signed, but never production
    out = capsys.readouterr().out
    assert "DEVELOPMENT REFERENCE" in out and "engagement letter" in out and "exit 3" in out

    # the mark is signed: removing it invalidates the signature rather than laundering the reference
    stripped = {k: v for k, v in ref.items() if k != "development"}
    ok, _ = R.verify(stripped, pub)
    assert ok is False

    # and the verifier a firm runs refuses identity against it
    V = _verifier()
    c = V.Checks()
    st = {"started_utc": "2026-06-01T12:00:00Z"}
    V.verify_search({"statement": st, "signer_pub": ""}, {}, pins=V.AMD_ARK_SPKI_SHA256,
                    uvm_root=V.MS_UVM_ROOT_SHA256_B64URL, uvm_min_svn=100, matter_cutoff=None, reference=ref)
    rows = V.verify_search({"statement": st, "signer_pub": ""}, {}, pins=V.AMD_ARK_SPKI_SHA256,
                           uvm_root=V.MS_UVM_ROOT_SHA256_B64URL, uvm_min_svn=100, matter_cutoff=None, reference=ref).rows
    identity = [r for r in rows if "enclave identity" in r[1]][0]
    assert identity[0] == "FAIL" and "marked DEVELOPMENT" in identity[2]
