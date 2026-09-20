"""Handing a corpus of claims to another Probant user (Henry, 20 Sep: "share a corpus of claims to another
probant user like the lawyer").

Two installations, two identities, one sealed file between them. What is checked here is what a person
cannot check by eye: that only the addressee can open it, that a signature is about the claims they read,
that an unknown sender is SAID to be unknown rather than quietly accepted, and that the date bound — which
decides what any later search may return — arrives as the sender set it.
"""
import json
import os
import stat

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_share as SH


def _install(tmp_path, name, monkeypatch):
    """A whole separate Probant installation: its own home, its own identity, its own matters."""
    home = tmp_path / name
    monkeypatch.setenv("INFERROUTE_HOME", str(home / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(home / "Probant"))
    return SH.identity()


CLAIMS = [{"title": "Cooling jacket", "summary": "Coolant channels moulded between the cells.",
           "quote": "coolant channels are moulded between the cells themselves", "source": "report.md",
           "source_sha256": "ab" * 32}]


def test_only_the_addressee_can_open_a_share(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    stranger = _install(tmp_path, "stranger", monkeypatch)
    payload = SH.build_share(CLAIMS, matter="Acme/battery", date_bound="2021-03-01", note="for review")
    blob = SH.seal_to(SH.public_card(lawyer), payload, henry)
    assert b"coolant channels" not in blob                 # the claims are not in the file in the clear
    got = SH.open_sealed(blob, lawyer)
    assert [c["title"] for c in got["claims"]] == ["Cooling jacket"]
    assert got["date_bound"] == "2021-03-01"               # the bound travels, inside the signature
    assert got["from_fingerprint"] == henry["fingerprint"]
    with pytest.raises(S.ProbantError, match="addressed to"):
        SH.open_sealed(blob, stranger)


def test_a_signature_is_about_the_claims_that_were_read(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    payload = SH.build_share(CLAIMS, matter="Acme/battery", date_bound="2021-03-01")
    blob = SH.seal_to(SH.public_card(lawyer), payload, henry)
    # Re-seal an altered payload with someone else's signature left on it: the signature must not carry over.
    opened = SH.open_sealed(blob, lawyer)
    forged = {**opened, "date_bound": "2019-01-01"}
    forged.pop("from_name", None)
    forged.pop("from_known", None)
    import inferroute_local.confidential.e2ee as e2ee
    shared, ct = e2ee.backend().encaps(SH._unb64(SH.public_card(lawyer)["mlkem_pub"]))
    key = e2ee.derive_key(shared, ct, b"probant-share-v1")
    nonce = os.urandom(12)
    body = e2ee._seal(key, nonce, json.dumps(forged).encode())
    blob2 = json.dumps({"schema": SH.SCHEMA, "mlkem_ct": SH._b64(ct), "nonce": SH._b64(nonce),
                        "body": SH._b64(body), "to_fingerprint": lawyer["fingerprint"]}).encode()
    with pytest.raises(S.ProbantError, match="signature does not check out"):
        SH.open_sealed(blob2, lawyer)


def test_an_unknown_sender_is_named_as_unknown(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    blob = SH.seal_to(SH.public_card(lawyer), SH.build_share(CLAIMS, matter="m", date_bound=""), henry)
    unknown = SH.open_sealed(blob, lawyer)
    assert unknown["from_known"] is False and unknown["from_name"] == ""
    SH.add_contact("henry", SH.public_card(henry))
    known = SH.open_sealed(blob, lawyer)
    assert known["from_known"] is True and known["from_name"] == "henry"
    # A card whose fingerprint does not match its own keys is refused outright.
    bad = {**SH.public_card(henry), "fingerprint": "0000-0000-0000-0000"}
    with pytest.raises(S.ProbantError, match="not the one its keys give"):
        SH.add_contact("impostor", bad)


def test_the_recipient_opens_it_as_a_matter_of_their_own(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    SH.add_contact("henry", SH.public_card(henry))
    blob = SH.seal_to(SH.public_card(lawyer), SH.build_share(
        CLAIMS, matter="Acme/battery", date_bound="2021-03-01", note="please review claim 1"), henry)
    payload = SH.open_sealed(blob, lawyer)
    made = SH.create_matter_from_share(payload, "Acme", "battery-review")
    assert made == "Acme/battery-review"
    rec = S.load_record("Acme", "battery-review")
    assert rec["date_bound"] == "2021-03-01"               # the sender's bound, not today's
    text = (S.workspace_path("Acme", "battery-review") / "disclosure.md").read_text()
    assert "Shared by henry" in text and "please review claim 1" in text
    assert "coolant channels are moulded between the cells themselves" in text
    # The claim that this Probant did NOT verify the quote is made in the matter itself, not left implied.
    assert "cannot re-check a quote against its source" in text
    origin = json.loads((S.records_dir("Acme", "battery-review") / "shared-origin.json").read_text())
    assert origin["from"] == henry["fingerprint"] and origin["known_contact"] is True


def test_the_secret_keys_stay_owner_only_and_the_card_carries_no_secret(tmp_path, monkeypatch):
    me = _install(tmp_path, "henry", monkeypatch)
    path = SH.identity_dir() / "identity.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(SH.identity_dir().stat().st_mode) == 0o700
    card = SH.public_card(me)
    assert set(card) == {"schema", "mlkem_pub", "ed_pub", "fingerprint"}
    blob = json.dumps(card)
    for secret in ("mlkem_sk", "ed_sk", "mlkem_seed"):
        assert me.get(secret, "") == "" or me[secret] not in blob
    assert SH.identity()["fingerprint"] == me["fingerprint"]          # stable across calls
