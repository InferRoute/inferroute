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


def _corpus(n=1, date="2021-03-01"):
    """A share carrying n matters — the unit Henry asked for: a corpus, not one at a time."""
    return SH.build_share([{"matter": f"Acme/battery-{i}", "date_bound": date, "disclosure": f"disclosure {i}",
                            "marks": {"US-7000-B2": "relevant"} if i == 0 else {}, "claims": CLAIMS,
                            "origin": f"matter:Acme/battery-{i}"} for i in range(n)], note="for review")


def test_only_the_addressee_can_open_a_share(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    stranger = _install(tmp_path, "stranger", monkeypatch)
    blob = SH.seal_to(SH.public_card(lawyer), _corpus(3), henry)
    assert b"coolant channels" not in blob                 # the claims are not in the file in the clear
    got = SH.open_sealed(blob, lawyer)
    assert [m["matter"] for m in got["matters"]] == ["Acme/battery-0", "Acme/battery-1", "Acme/battery-2"]
    assert got["matters"][0]["date_bound"] == "2021-03-01"  # each bound travels, inside the signature
    assert got["from_fingerprint"] == henry["fingerprint"]
    with pytest.raises(S.ProbantError, match="addressed to"):
        SH.open_sealed(blob, stranger)


def test_a_signature_is_about_the_claims_that_were_read(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    blob = SH.seal_to(SH.public_card(lawyer), _corpus(1), henry)
    # Re-seal an ALTERED payload, in the current envelope format, keeping the sender's signature on it:
    # the signature must not carry over to claims it was not made about.
    opened = SH.open_sealed(blob, lawyer)
    forged = {k: v for k, v in opened.items() if k not in ("from_name", "from_known")}
    forged["matters"] = [{**opened["matters"][0], "date_bound": "2019-01-01"}]
    assert _reseal_without_signing(forged, SH.public_card(lawyer)) is not None
    with pytest.raises(S.ProbantError, match="signature does not check out"):
        SH.open_sealed(_reseal_without_signing(forged, SH.public_card(lawyer)), lawyer)


def _reseal_without_signing(payload, card):
    """The same envelope seal_to() writes, with no signing step — what a forger can actually do: they can
    re-encrypt to the recipient, but they cannot re-sign as the sender."""
    import inferroute_local.confidential.e2ee as e2ee
    content_key, nonce = os.urandom(32), os.urandom(12)
    body = e2ee._seal(content_key, nonce, json.dumps(payload).encode())
    shared, ct = e2ee.backend().encaps(SH._unb64(card["mlkem_pub"]))
    wrap_nonce = os.urandom(12)
    wrapped = e2ee._seal(e2ee.derive_key(shared, ct, b"probant-share-wrap-v1"), wrap_nonce, content_key)
    return json.dumps({"schema": SH.SCHEMA, "nonce": SH._b64(nonce), "body": SH._b64(body),
                       "recipients": [{"fingerprint": card["fingerprint"], "mlkem_ct": SH._b64(ct),
                                       "nonce": SH._b64(wrap_nonce), "wrapped": SH._b64(wrapped)}]}).encode()


def test_an_unknown_sender_is_named_as_unknown(tmp_path, monkeypatch):
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    blob = SH.seal_to(SH.public_card(lawyer), _corpus(1, date=""), henry)
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
    blob = SH.seal_to(SH.public_card(lawyer), _corpus(3), henry)
    payload = SH.open_sealed(blob, lawyer)
    made = SH.create_matters_from_share(payload, "FromHenry")
    assert made == ["FromHenry/battery-0", "FromHenry/battery-1", "FromHenry/battery-2"]
    assert S.load_record("FromHenry", "battery-0")["date_bound"] == "2021-03-01"   # the sender's bound
    text = (S.workspace_path("FromHenry", "battery-0") / "disclosure.md").read_text()
    assert "Shared by henry" in text and "for review" in text
    assert "coolant channels are moulded between the cells themselves" in text
    # The sender's marks travel as THEIRS, not as the recipient's own judgements.
    assert "What the sender marked" in text and "US-7000-B2: relevant" in text
    assert S.state_path("FromHenry", "battery-0").exists() is False
    # The claim that this Probant did NOT verify the quote is made in the matter itself, not left implied.
    assert "cannot re-check a quote against its source" in text
    origin = json.loads((S.records_dir("FromHenry", "battery-0") / "shared-origin.json").read_text())
    assert origin["from"] == henry["fingerprint"] and origin["known_contact"] is True
    assert origin["shared_as"] == "Acme/battery-0"
    # Opening the same share twice does not overwrite: it says which names are taken.
    with pytest.raises(S.ProbantError, match="already taken"):
        SH.create_matters_from_share(payload, "FromHenry")


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


def test_a_share_can_be_sealed_to_the_sender_as_well(tmp_path, monkeypatch):
    """Henry, 20 Sep: a readable copy of what was handed over. The claims are encrypted once under a content
    key wrapped per recipient, so a second addressee costs a wrapped key, not a second copy of the corpus."""
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    one = SH.seal_to(SH.public_card(lawyer), _corpus(3), henry)
    both = SH.seal_to([SH.public_card(lawyer), SH.public_card(henry)], _corpus(3), henry)
    assert len(both) - len(one) < 3000                     # one wrapped key, not a second corpus
    assert len(SH.open_sealed(both, henry)["matters"]) == 3
    assert len(SH.open_sealed(both, lawyer)["matters"]) == 3
    with pytest.raises(S.ProbantError, match="addressed to"):
        SH.open_sealed(one, henry)                         # without the copy, the sender cannot reopen it


def test_your_own_fingerprint_is_a_sender_you_know(tmp_path, monkeypatch):
    """Reopening the copy sealed to yourself said "an UNKNOWN sender" — your own key is the one fingerprint
    you never have to confirm by voice."""
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    blob = SH.seal_to([SH.public_card(lawyer), SH.public_card(henry)], _corpus(2), henry)
    mine = SH.open_sealed(blob, henry)
    assert mine["from_known"] is True and mine["from_name"] == "you (this installation)"
    theirs = SH.open_sealed(blob, lawyer)
    assert theirs["from_known"] is False                     # they still have to confirm it is Henry's
