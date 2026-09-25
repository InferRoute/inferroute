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


CORPUS_DOC = ("READING GUIDE\n\nFR2609630-P1.txt (99 KB) 137 passage(s)\n"
              "  read: 5-29%, 38-95%\n  @5584 \"the coolant channels are moulded between the cells\"\n")


def test_a_corpus_carries_the_documents_that_describe_the_whole_delivery(tmp_path, monkeypatch):
    """Henry, 22 Sep: "should we create a corpus object that includes such side files".

    A matter list and a reading guide describe a PORTFOLIO, not any one matter, so there was nowhere for
    them to travel and they would have gone as plain email attachments — carrying verbatim quotes from every
    filing and from the UNFILED surplus, which is the disclosure this product exists to prevent. They now
    travel inside the same seal as the matters."""
    henry = _install(tmp_path, "henry", monkeypatch)
    guide = tmp_path / "READING-GUIDE.txt"
    guide.write_text(CORPUS_DOC)
    matters_txt = tmp_path / "MATTERS.txt"
    matters_txt.write_text("MATTERS\n\n1. CONTINUITY\n")
    files = SH.corpus_files([guide, matters_txt])
    assert [f["name"] for f in files] == ["READING-GUIDE.txt", "MATTERS.txt"]
    payload = SH.build_share([{"matter": "InferRoute/continuity", "date_bound": "2026-07-13",
                               "disclosure": "d", "marks": {}, "claims": CLAIMS, "origin": "x"}],
                             note="the pre-work you asked for", files=files, corpus_name="InferRoute cluster")
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    blob = SH.seal_to(SH.public_card(lawyer), payload, henry)
    # The side documents are sealed with everything else — not in the clear anywhere in the file.
    assert b"coolant channels are moulded" not in blob
    got = SH.open_sealed(blob, lawyer)
    assert got["corpus"]["name"] == "InferRoute cluster" and got["corpus"]["id"]

    SH.create_matters_from_share(got, "FromHenry")
    written = SH.write_corpus(got, "FromHenry")
    assert sorted(written["written"]) == ["MATTERS.txt", "READING-GUIDE.txt"]
    landed = SH.corpus_dir("FromHenry") / "READING-GUIDE.txt"
    assert landed.read_text() == CORPUS_DOC and stat.S_IMODE(landed.stat().st_mode) == 0o600
    # …and they are NOT inside a matter: they describe the delivery, not one invention.
    assert "shared-corpus" in str(landed) and "continuity" not in str(landed)

    # A matter that ARRIVED says which delivery it came in.
    origin = json.loads((S.records_dir("FromHenry", "continuity") / "corpus-origin.json").read_text())
    assert origin["corpus"] == got["corpus"]["id"] and "arrived in this corpus" in origin["how"]

    # A matter the RECIPIENT creates while reading it is tied to the delivery but is NOT part of it —
    # someone else's claims must not acquire your authorship, nor yours theirs.
    S.cmd_new("FromHenry", "my-own-idea", None, from_corpus=got["corpus"]["id"])
    mine = json.loads((S.records_dir("FromHenry", "my-own-idea") / "corpus-origin.json").read_text())
    assert mine["corpus"] == got["corpus"]["id"]
    assert mine["how"] != origin["how"] and "created here" in mine["how"]
    record = json.loads(SH.corpora_record(got["corpus"]["id"]).read_text())
    assert record["matters"] == ["InferRoute/continuity"] and record["from"] == henry["fingerprint"]


def test_a_corpus_document_that_did_not_survive_the_trip_is_refused(tmp_path, monkeypatch):
    """A truncated reading guide reads as a short one. The sha256 beside each file does not prove anything
    about its CONTENT — only the signature does — but it catches a file that did not arrive whole."""
    henry = _install(tmp_path, "henry", monkeypatch)
    f = tmp_path / "GUIDE.txt"
    f.write_text(CORPUS_DOC)
    files = SH.corpus_files([f])
    files[0]["text"] = files[0]["text"][:40]              # truncated in transit
    payload = SH.build_share([{"matter": "A/b", "date_bound": "", "disclosure": "", "marks": {},
                               "claims": CLAIMS, "origin": "x"}], files=files)
    with pytest.raises(S.ProbantError, match="did not arrive as it was sent"):
        SH.write_corpus(payload, "FromHenry")


def test_a_share_without_a_corpus_block_still_opens(tmp_path, monkeypatch):
    """Schema /2 shares predate the corpus and must keep working: the block is optional, not required."""
    henry = _install(tmp_path, "henry", monkeypatch)
    lawyer = _install(tmp_path, "lawyer", monkeypatch)
    payload = SH.build_share([{"matter": "A/b", "date_bound": "", "disclosure": "d", "marks": {},
                               "claims": CLAIMS, "origin": "x"}])
    payload.pop("corpus")
    blob = SH.seal_to(SH.public_card(lawyer), payload, henry)
    got = SH.open_sealed(blob, lawyer)
    assert SH.create_matters_from_share(got, "Old") == ["Old/b"]
    assert SH.write_corpus(got, "Old") == {"id": "", "written": [], "corpus": {}}


def test_a_base_install_says_what_to_install_instead_of_a_traceback(monkeypatch, capsys):
    """Caught by installing the release candidate in a clean venv: `ir probant identity` — the FIRST command
    a new user runs, the one that makes the key card they must send before anyone can share with them —
    died with ModuleNotFoundError. Probant's dependencies live in the `confidential` extra, and a traceback
    is the worst possible first impression of a product whose subject is careful handling. The package
    already keeps `click` core for this exact reason ("the henry-ft failure" in pyproject)."""
    import sys as _sys
    from inferroute_cli import probant as CLI

    def _boom(*a, **k):
        raise ImportError("No module named 'cryptography'", name="cryptography")
    monkeypatch.setattr(CLI, "cmd_identity", _boom)
    rc = CLI.main(["identity"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "Traceback" not in err
    assert "cryptography" in err and "pip install 'inferroute[confidential]'" in err
    assert "Nothing was changed" in err


def test_bare_ir_probant_says_where_to_start(monkeypatch, capsys):
    """22 Sep, walking the install as a newcomer: `ir probant` answered with argparse's "error: the
    following arguments are required: cmd" above nineteen subcommand names. True, useless, and the first
    thing a patent professional sees. A first screen should answer "what do I do", not "what did you do
    wrong"."""
    import sys as _sys
    from inferroute_cli import probant as CLI
    monkeypatch.setattr(_sys, "argv", ["ir", "probant"])
    rc = CLI.main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert "ir probant home" in err and "opens the page" in err
    assert "the following arguments are required" not in err
    assert "identity" in err                       # the command he needs to be sent a sealed corpus
    # A real subcommand is untouched by the guard.
    monkeypatch.setattr(_sys, "argv", ["ir", "probant", "list"])
    assert CLI.main(["list"]) == 0
