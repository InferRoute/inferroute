"""The audit pack: an evidence-only copy of a record for the professional's OWN AI to audit (Henry, 19 Sep).

It must say nothing of the invention, and it must lose nothing else. The first is checked by looking for
every word that was withheld; the second by running the SAME verifier over the record and over its pack:
the only check lines allowed to differ are the ones that need the withheld text, and they may only turn into
SKIP, never PASS.
"""
import json
from types import SimpleNamespace
import re
import stat

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_check
from inferroute_cli import probant_export as E

from tests.test_verify_record import V, _run, _synthetic_bundle, kms  # noqa: F401  (fixtures)

LINE = re.compile(r"^\s*(PASS|FAIL|SKIP)\s+(.+?):")


def _lines(out):
    return [m.groups() for m in map(LINE.match, out.splitlines()) if m]


@pytest.fixture
def no_anchors(monkeypatch):
    monkeypatch.setattr(probant_check, "published_reference", lambda: (None, None))


def test_the_pack_verifies_like_the_record_except_the_texts_it_withholds(tmp_path, V, kms, no_anchors):
    rec = _synthetic_bundle(tmp_path, V, kms)
    ref = str(tmp_path / "reference.json")
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    code_r, out_r = _run(rec, "--reference", ref)
    code_p, out_p = _run(pack, "--reference", ref)
    before, after = _lines(out_r), _lines(out_p)
    # One line disappears: the hit count is counted FROM the result, so with the result withheld there is
    # nothing to count. Every other check is there, in the same order.
    kept = [row for row in before if row[1] != "hit count as signed"]
    assert len(kept) == len(before) - 1
    assert [n for _, n in kept] == [n for _, n in after]
    changed = {n: (a, b) for (a, n), (b, _) in zip(kept, after) if a != b}
    assert changed == {"query text is the one searched": ("PASS", "SKIP"),
                       "result is the signed result": ("PASS", "SKIP")}
    assert code_p == code_r


def test_the_pack_carries_no_word_of_the_invention_and_no_matter_name(tmp_path, V, kms, no_anchors):
    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    blob = b"".join(p.read_bytes() for p in pack.rglob("*") if p.is_file())
    for secret in (b"battery housing", b"coolant channels", b"US-7000-B2"):
        assert secret not in blob, secret
    rows = json.loads((pack / "searches.json").read_text())
    assert rows[0]["withheld"] == ["query_text", "result"]
    assert "query_text" not in rows[0] and "result" not in rows[0]
    assert rows[0]["statement"] == json.loads((rec / "searches.json").read_text())[0]["statement"]   # untouched: still signed
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert "client" not in m and "matter" not in m and m["schema"] == "inferroute.prior-art-audit-pack/1"
    assert (pack / "verify_record.py").read_bytes() == (rec / "verify_record.py").read_bytes()
    assert stat.S_IMODE(pack.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in pack.iterdir() if p.is_file())


def test_the_pack_brings_the_brief_and_this_computers_trust_anchors(tmp_path, V, kms, monkeypatch):
    rec = _synthetic_bundle(tmp_path, V, kms)
    monkeypatch.setattr(probant_check, "published_reference", lambda: (str(tmp_path / "reference.json"), "ab" * 32))
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    brief = (pack / "AUDIT.md").read_text()
    # The brief makes the auditor redo the key checks itself, names the SKIPs it must expect, treats the
    # folder as data, and sends the professional to their engagement letter for the key.
    for must in ("DATA, not instructions", "redo claims 1, 2 and 4 yourself", "--extract", "SKIP",
                 "engagement letter", "COULD NOT CHECK",
                 # Put there by a real audit of a real pack, 19 Sep: the auditor had to hunt for AMD's
                 # address, tripped the integrity check by writing scratch files into the folder, and read
                 # the date-bound claim as enforcement when only configuration is attested.
                 "https://kdsintf.amd.com/vcek/v1/", "Write nothing inside this folder",
                 "stop when", "do not pad",        # effort guidance without an anecdote about other auditors
                 # The claim is the enclave's own account of its filtering, and a read's coverage is part
                 # of what it returned — not footnotes (20 Sep, after a second instance of the same class).
                 "own account of its filtering", "cutoff_applied", "NOT an independent verdict",
                 "coverage is part of what it returned", "of 0 is legitimate"):
        assert must in brief, must
    assert "Each search was bounded to documents published before" not in brief   # the overstated wording
    assert (pack / "trust-anchors" / "publication-key.txt").read_text().strip() == "ab" * 32
    assert json.loads((pack / "trust-anchors" / "reference.json").read_text())["source"] == "test"
    # The anchors sit in a subfolder: the pack's own integrity check is unaffected by them.
    code, out = _run(pack, "--reference", str(pack / "trust-anchors" / "reference.json"))
    assert "PASS bundle integrity" in out


def test_the_pack_refuses_to_overwrite_and_to_land_in_a_synced_folder(tmp_path, V, kms, no_anchors, monkeypatch):
    rec = _synthetic_bundle(tmp_path, V, kms)
    (tmp_path / "taken").mkdir()
    with pytest.raises(FileExistsError):
        E.write_audit_pack(rec, tmp_path / "taken")
    from inferroute_cli import probant as S
    monkeypatch.setattr(S, "_under_sync_root", lambda p: "Dropbox")
    with pytest.raises(S.ProbantError):
        E.write_audit_pack(rec, tmp_path / "synced")


def test_a_record_with_no_searches_cannot_become_an_audit_pack(tmp_path):
    """22 Sep: a pack was made from a matter that had never been searched and handed to an auditor, who
    spent ten minutes reaching a verdict on claims that NOTHING in the folder could evidence. Every claim in
    the brief rests on an enclave-signed statement per search; with none, the pack is a folder of tooling.
    Refusing costs a click. Not refusing costs the professional's credibility with whoever they sent it to."""
    rec = tmp_path / "record"
    rec.mkdir()
    (rec / "searches.json").write_text("[]")
    (rec / "MANIFEST.json").write_text(json.dumps({"files": {}, "matter_cutoff": 20260814}))
    with pytest.raises(S.ProbantError, match="no searches"):
        E.write_audit_pack(rec, tmp_path / "pack")
    assert not (tmp_path / "pack").exists(), "it must refuse BEFORE creating the folder"


def test_the_brief_tells_the_auditor_the_verifier_is_untrusted_and_how_to_check_it(tmp_path):
    """Henry, 22 Sep: make this stronger — point the agent at our public client source.

    That instruction named one source and could not be carried out: verify_record.py was in neither the
    published wheel nor the public repository. Two things have changed since. The wheel we distribute DOES
    carry it now, and on 24 Sep an auditor ran the brief, fetched 42 releases from the index, found it in
    none, and reported the brief's claim as unfounded — correctly.

    So the brief names three sources and separates what each one proves. The index is not us; the wheel is
    us and therefore shows a targeted substitution has not happened rather than corroborating anything; the
    installed copy shares an origin with the folder. Collapsing them would make three checks read as
    agreement between independent parties, which is the failure this whole pack exists to avoid."""
    md = E.AUDIT_MD
    assert "Treat `verify_record.py` as untrusted code" in md
    assert "Get other copies and compare, before you run anything" in md
    assert "pip download inferroute" in md          # executable, not an aspiration
    assert "Report every hash you obtained" in md
    assert "A MISMATCH against (a) or (b) is a" in md
    # The self-reference that makes reading it insufficient is stated, not left for the auditor to notice.
    assert "the manifest that lists it is in the same folder" in md
    # Redoing the checks is named as the part that carries the audit, above running our program.
    assert "not step 2" in md
    # …and the report must separate what the auditor computed from what our program told them.
    assert "which of it you computed yourself" in md
    # An empty folder gets a one-line report — but claim 7 is NOT empty just because no search ran, and
    # the brief used to say "there is nothing here to audit", which dismissed the one thing that was.
    # An auditor planted a file under trust-anchors/ and integrity still said "no unlisted files".
    # The warning was true only at the top level, and the same blind spot leaves the anchors unhashed.
    assert "AT THE TOP LEVEL" in md
    assert "does not descend into subdirectories" in md
    assert "every claim EXCEPT 7 is COULD NOT CHECK" in md
    assert "Claim 7 rests on the session receipt and not on any search" in md


def test_the_empty_pack_refusal_names_what_is_actually_in_the_way(tmp_path, monkeypatch):
    """23 Sep, Henry trying the audit: he got "Run a search on this matter first" — advice he cannot take,
    because the enclave this computer points at no longer resolves. A refusal that tells someone to do
    something the product knows they cannot do reads as the product being broken, not the search machine.
    With no search machine configured it now says so."""
    from inferroute_cli import pi_attested
    rec = tmp_path / "record"
    rec.mkdir()
    (rec / "searches.json").write_text("[]")
    (rec / "MANIFEST.json").write_text(json.dumps({"files": {}, "matter_cutoff": 20260814}))

    monkeypatch.setattr(pi_attested, "search_config_path", lambda: tmp_path / "absent.json")
    with pytest.raises(S.ProbantError, match="No search machine is set up"):
        E.write_audit_pack(rec, tmp_path / "pack-a")

    cfg = tmp_path / "search.json"
    cfg.write_text(json.dumps({"enclave": "http://x"}))
    monkeypatch.setattr(pi_attested, "search_config_path", lambda: cfg)
    # Configured is not the same as WORKING — Henry's own machine has a search.json pointing at an enclave
    # that no longer resolves — so the configured branch must not promise that a search is possible either.
    with pytest.raises(S.ProbantError, match="the search machine not answering"):
        E.write_audit_pack(rec, tmp_path / "pack-b")


def test_the_bundle_carries_the_conversation_receipt_and_the_brief_asks_about_it(tmp_path, monkeypatch):
    """Henry, 23 Sep: "can't it check that the part that checks that the chat I had with the confidential AI
    was confidential?"

    It could not. record.html DESCRIBES the model lane verbatim from this device's receipt, and the receipt
    stayed on the device — so the strongest sentence in the document rested on our word, which is the
    receipt-written-by-the-audited-component shape. The receipt travels now, and the brief asks about it
    honestly: the raw attestation behind its fifteen verdicts is not in the folder, so an auditor compares
    the measurements against the published reference and REPORTS what they read rather than verified."""
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    assert S.cmd_new("Acme", "cooling", "2026-01-15") == 0
    receipts = tmp_path / "ir" / "confidential" / "receipts"
    receipts.mkdir(parents=True)
    rp = receipts / "r1.json"
    rp.write_text(json.dumps({"verdict": "confidential", "checks": {"sig_ok": {"ok": True, "why": "w"}},
                              "instance": {"mrtd": "abc", "rtmrs": ["d"]},
                              "counters": {"plaintext_bytes_sealed_here": 10}}))
    rdir = S.records_dir("Acme", "cooling")
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "sess1.json").write_text(json.dumps({
        "session_id": "sess1", "surface": "browser", "confinement": "require",
        "model_lane": {"verified": True, "checks": "15/15", "receipt": str(rp)}}))

    b = E.build_bundle("Acme", "cooling")
    assert len(b["sessions"]) == 1                       # exposed so the writer can carry the receipt
    dest = E.write_bundle("Acme", "cooling", str(tmp_path / "out"))
    carried = dest / "session-sess1.receipt.json"
    assert carried.is_file(), sorted(p.name for p in dest.iterdir())
    assert json.loads(carried.read_text())["instance"]["mrtd"] == "abc"

    md = E.AUDIT_MD
    assert "The CONVERSATION, not only the searches" in md
    assert "session-*.receipt.json" in md
    # Until 24 Sep the raw attestation was absent and claim 7 could only be READ. It is carried now, so the
    # brief asks for it to be recomputed — and states the limit that remains rather than the one that went.
    assert "Recompute the verdicts from it rather than reading them" in md
    assert "the ONLINE checks" in md and "need those services" in md
    assert "which of this you verified and which you read" in md
    # The report is per-claim. Since 24 Sep the heading carries the claim's own title, so a claim that was
    # never reached cannot be papered over by a heading the auditor wrote themselves — one answered a list
    # of the verifier's check names and its report gave no sign that claim 3 had gone unexamined.
    assert "### Claim N —" in md
    assert "paste the claim's bold title from above, exactly" in md


def _bare_record(tmp_path, *, receipt=None):
    """The smallest thing write_audit_pack will read: a record with no searches at all."""
    rec = tmp_path / "record"
    rec.mkdir()
    (rec / "searches.json").write_text("[]")
    (rec / "MANIFEST.json").write_text(json.dumps({"files": {}, "matter_cutoff": 20260814}))
    (rec / "VERIFY.md").write_text("how to verify\n")
    (rec / "verify_record.py").write_text("# verifier\n")
    if receipt is not None:
        (rec / "session-abc123.receipt.json").write_text(json.dumps(receipt))
    return rec


def test_a_sealed_session_with_no_searches_still_makes_a_pack(tmp_path, no_anchors):
    """23 Sep: the audit gained claim 7 — the CONVERSATION — but the guard still refused on searches alone,
    so the one case the feature was built for could not produce a pack at all. Henry's case exactly: no
    search machine resolves from this device, yet the chat with the AI machine WAS sealed and is the thing
    he asked to have checked."""
    receipt = {"session_id": "abc123", "verdict": "confidential",
               "checks": {"quote": {"ok": True, "why": "chains to AMD root"}},
               "instance": {"mrtd": "aa" * 48}, "path": "/home/henry/.inferroute/x.json"}
    pack = E.write_audit_pack(_bare_record(tmp_path, receipt=receipt), tmp_path / "pack")
    carried = json.loads((pack / "session-abc123.receipt.json").read_text())
    assert carried["instance"]["mrtd"] == "aa" * 48
    assert carried["checks"]["quote"]["ok"] is True
    # indexed like every other file, so the pack's own integrity check covers it
    assert "session-abc123.receipt.json" in json.loads((pack / "MANIFEST.json").read_text())["files"]


def test_the_pack_does_not_carry_the_professionals_own_filesystem_path(tmp_path, no_anchors):
    """The receipt evidences the session; `path` evidences nothing and names the professional and their
    folders to whoever receives the pack."""
    receipt = {"session_id": "abc123", "path": "/home/henry/.inferroute/confidential/receipts/x.json"}
    pack = E.write_audit_pack(_bare_record(tmp_path, receipt=receipt), tmp_path / "pack")
    blob = (pack / "session-abc123.receipt.json").read_bytes()
    assert b"/home/henry" not in blob
    assert json.loads(blob)["withheld"] == ["path"]      # absence is stated, never silent


def test_a_pack_with_no_searches_tells_the_auditor_so_before_they_start(tmp_path, no_anchors):
    """Without it an auditor spends the fifteen minutes the brief asks for to reach COULD NOT CHECK on
    everything that rests on a search."""
    receipt = {"session_id": "abc123", "verdict": "confidential"}
    pack = E.write_audit_pack(_bare_record(tmp_path, receipt=receipt), tmp_path / "pack")
    brief = (pack / "AUDIT.md").read_text()
    banner = brief.split("\n\n")[1]
    assert "`searches.json` is empty" in banner
    # An auditor, 23 Sep: "an audit brief that supplies the findings has pre-empted the thing it
    # commissioned." The banner states the FACT and stops; the verdicts are the auditor's to reach.
    assert "COULD NOT CHECK" not in banner and "Claims 1 to 6" not in banner
    # The brief asks the auditor to report the exit code. 1 here means "not a pass", not "a check found
    # something wrong", and nothing else in the folder says so.
    assert "NOTHING VERIFIED" in banner and "exit 1" in banner
    assert brief.startswith("# Audit brief: an independent check")   # banner sits under the title
    assert "1. **Sealed hardware.**" in brief          # and the whole brief still follows


def test_a_record_with_neither_searches_nor_a_session_is_still_refused(tmp_path):
    """The original refusal stands where it was right: nothing in the folder can evidence anything."""
    with pytest.raises(S.ProbantError, match="no searches"):
        E.write_audit_pack(_bare_record(tmp_path), tmp_path / "pack")
    assert not (tmp_path / "pack").exists(), "it must refuse BEFORE creating the folder"


def test_the_pack_carries_the_receipt_alongside_searches_too(tmp_path, V, kms, no_anchors):
    """Claim 7 is not conditional on there being no searches."""
    rec = _synthetic_bundle(tmp_path, V, kms)
    (rec / "session-zz9.receipt.json").write_text(json.dumps({"session_id": "zz9", "verdict": "confidential"}))
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    assert json.loads((pack / "session-zz9.receipt.json").read_text())["verdict"] == "confidential"
    assert "no prior-art searches" not in (pack / "AUDIT.md").read_text()   # no banner


def test_claim_7_sends_the_auditor_somewhere_that_can_hold_the_values_it_asks_for():
    """Two independent auditors hit this. Claim 7 said "compare the measurements against InferRoute's
    published reference in trust-anchors/" — but that file describes the SEV-SNP SEARCH lane and carries
    no mrtd/rtmrs at all, while the receipt is Intel TDX. The instruction had no operands. The second
    auditor found the strongest positive result in the pack (all four registers matching a named published
    build) only by ignoring the instruction and going to PyPI on its own initiative."""
    md = E.AUDIT_MD
    assert "inferroute_local/confidential/builds.py" in md and "BUNDLED" in md
    assert "pip download inferroute" in md
    assert "`trust-anchors/` will not" in md, "it must say where NOT to look, or the next auditor repeats it"
    assert "compare the measurements in the receipt against InferRoute's published reference in" not in md


def test_the_place_claim_7_sends_them_actually_has_builds_in_it():
    """The anchor behind claim 7, asserted here so an empty list fails OUR build and not an auditor's
    afternoon — the same discipline the client-audit brief applies to its own anchors."""
    from inferroute_local.confidential import builds
    assert builds.BUNDLED, "claim 7 sends the auditor to builds.BUNDLED; it is empty"
    first = builds.BUNDLED[0]
    for field in ("id", "mrtd", "rtmr1", "rtmr2", "rtmr3"):
        assert first.get(field), f"claim 7 asks them to match {field}, which this entry lacks"


def test_the_brief_asks_what_the_counters_show_rather_than_presuming_it():
    """"check that the counters show ciphertext leaving" presupposes its own answer, and on this record
    every counter is zero. Phrased as a test with a presumed outcome, it invites a reported pass."""
    md = E.AUDIT_MD
    assert "report what the counters show" in md
    assert "check that the counters show ciphertext leaving" not in md


def test_the_brief_does_not_lean_on_the_auditor_with_an_anecdote():
    """It carried a story about another auditor being stopped at nine minutes and "producing nothing at
    all". That is a nudge to keep going dressed as a fact, and it says nothing about the evidence."""
    md = E.AUDIT_MD
    assert "nine minutes" not in md and "Let it finish" not in md
    assert "stop when" in md and "do not pad" in md


def test_verify_md_does_not_name_a_reference_file_that_is_in_neither_folder():
    """`--reference reference.json` appears in no record and in no pack: in a pack the file sits under
    trust-anchors/, and a record ships no reference at all."""
    text = E.VERIFY_MD          # the product's text, not the fixture's stub
    assert "--reference reference.json" not in text
    assert "trust-anchors/reference.json" in text
    assert "not inside this folder" in text


def test_a_receipt_says_which_client_wrote_it_and_the_brief_uses_that():
    """24 Sep: an auditor read a 22 Sep receipt asserting "this session's requests were encrypted" beside a
    zero request counter, and reported it — correctly. `_restate_claim` had already fixed that months of
    client-versions ago, and the 24 Sep receipt sitting next to it in the same pack was worded correctly.
    Nothing in either said why they differed, so a fossil defect and a live one look identical.

    They will keep being audited: nothing rewrites an old receipt, and nothing should. What the pack can do
    is say which client wrote each, and tell the auditor what that does and does not license."""
    from inferroute_local.confidential.receipt import Receipt
    r = Receipt(session_id="s", model_short="m", upstream_model="u", fleet_id="f", transport="t")
    assert r.written_by, "a receipt cannot say which client wrote it"
    assert "written_by" in E.AUDIT_MD
    assert "do not assume the older one describes today's software" in E.AUDIT_MD
    # And it must not be dressed up as attestation: the device is naming itself.
    assert "self-reported" in E.AUDIT_MD


def test_the_brief_says_the_two_lanes_are_different_hardware():
    """Two auditors read this pack on 24 Sep. One concluded "the AUDIT.md template mentions AMD SEV-SNP,
    but the session receipts show Intel TDX v4 — the template appears generic". It is not generic: claims
    1-6 and 8 are about the SEARCH machine (SEV-SNP) and claim 7 is about the AI machine (TDX). But the
    brief never said so, and a document whose whole job is precision had just been called boilerplate by
    the reader it exists to convince.

    The same run explained rtmr0's variation as a nonce. Our own builds.py says it measures the host's
    boot and is deliberately excluded from identity. That auditor reached the right verdict by a route
    that is not true, which on a different field would have excused a real difference."""
    from inferroute_cli import probant_export as E
    brief = E.AUDIT_MD
    assert "Two different machines, two different technologies" in brief
    assert "Intel TDX" in brief and "AMD SEV-SNP" in brief
    assert "not a generic template" in brief
    assert "Neither machine's evidence can be used to check the other." in brief
    # And rtmr0 explained where the auditor meets it, rather than left to be guessed at.
    assert "It does\n   not carry a nonce" in brief or "does not carry a nonce" in brief.replace("\n   ", " ")
    assert "measures the HOST's" in brief


def test_the_brief_names_a_published_reference_without_calling_it_independent():
    """An Opus 5.5 audit of a nine-search pack verified claims 1, 2, 4 and 5 against AMD's own KDS with
    openssl, and declined claim 3: the reference and the key both came from the professional's machine,
    published nine minutes after the enclave was attested and fifty-seven seconds before the session.

    The site was already serving a reference that would have answered the narrow version of that — but the
    superseded one, so the only value fetchable from anywhere other than that laptop was the wrong value.
    It is published now, and the brief says what agreement with it does and does not prove: both copies are
    InferRoute's, so it is not independence; it defeats the reference having been minted where the records
    were made. Those are different questions and only one is closed."""
    from inferroute_cli import probant_export as E
    # The auditor forms the claim-3 verdict in AUDIT.md and follows the ranking in VERIFY.md; the pack
    # ships both, so each has to carry its half or the pointer goes to a document nobody opened.
    import re as _re
    # Whitespace-normalised: these documents are hard-wrapped, and a phrase that happens to straddle a line
    # break is still the phrase. Pinning the wrapping makes the guard fail on reflow, which teaches people
    # to weaken the guard rather than keep the sentence.
    flat = lambda t: _re.sub(r"\s+", " ", t)
    b, v = flat(E.AUDIT_MD), flat(E.VERIFY_MD)
    assert "https://inferroute.ai/reference/current.json" in b, "claim 3 does not say where to get one"
    assert "https://inferroute.ai/reference/current.json" in v, "the ranking does not include it"
    assert "NOT independent of InferRoute" in b and "NOT independent of InferRoute" in v
    assert "minted on the machine being audited" in v
    assert "minted on the audited machine" in b
    # The ranking survives: the engagement letter still comes first, and this is named the weakest form.
    assert v.index("from your engagement letter") < v.index("https://inferroute.ai/reference/current.json")
    assert "the weakest form" in v


def test_an_empty_field_is_not_a_passed_test_and_the_claims_must_be_quoted():
    """Two auditors read the same nine-search pack on 24 Sep and diverged where it mattered most.

    One marked claim 8 VERIFIED because `text_coverage` and `paper_coverage` were null in every search —
    "the fields exist and are correctly null". Nothing was read, so nothing was checked; that is COULD NOT
    CHECK. Turning an absence into a verified claim is the single worst outcome this pack can produce,
    because it reads as "we looked, and it was fine".

    The same report answered a list of its own invention: its "claim 3" was about query text matching a
    hash, where claim 3 here is whether the software is InferRoute's — the claim the other auditor
    declined, on grounds that never surfaced in this one. Substituting the verifier's check names for the
    brief's claims left the hardest question unreached with no sign of the gap, so the brief now requires
    each claim's own title to be quoted before its verdict."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "does not VERIFY this claim — it leaves it COULD NOT CHECK" in b
    assert "an empty list is not a passed test" in b
    assert "bold title from the list above, copied exactly" in b
    assert "Not the name of a check in `verify_record.py`" in b


def test_the_brief_says_which_claims_the_verifier_does_not_settle():
    """The auditor that answered the wrong list explained why, and it was not carelessness: "verify_record's
    claim taxonomy is more present and granular than AUDIT.md's, and the brief does not explicitly map
    them… I assumed PASS on the verifier's 'reference signature' check meant Claim 3 was covered. It is
    not." The brief read the program first by its own instruction, so the program's frame arrived first and
    the eight claims had to be held against it unaided.

    So the mapping is stated before the claims: which the verifier settles, which it barely touches, and
    the one where a PASS answers a different question than the claim asks."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "What `verify_record.py` settles, and what it leaves to you" in b
    assert "Claim 3 is NOT." in b
    assert 'does not establish claim 3' in b


def test_not_verified_and_could_not_check_are_taught_apart():
    """Same auditor: "my original report never DECLINED anything. Everything was either VERIFIED or COULD
    NOT CHECK… The brief's three-outcome system may be structurally biased toward optimistic verdicts."

    NOT VERIFIED was already in the vocabulary — but only in the output-format section at the end, while
    the guidance where verdicts are actually formed said only that what you could not check is "could not
    check, never fine". So the one negative verdict available was never reached for. A real objection filed
    as an absence reads to a professional as no data rather than as something wrong."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "Three verdicts, and the difference between two of them matters" in b
    assert "the evidence is here and it does not support the claim" in b
    assert "that is NOT VERIFIED on provenance, not a gap" in b
    # And it is taught BEFORE the claims, not only in the report format at the end.
    assert b.index("Three verdicts") < b.index("**Sealed hardware.**")


def test_the_receipt_carries_the_evidence_its_verdicts_were_computed_from():
    """Two independent auditors, on the same day, wrote the same sentence about claim 7: "the receipts are
    data, not proof I can recompute". Both returned COULD NOT CHECK on fifteen checks whose inputs this
    device had in memory when it wrote the receipt, and threw away.

    The row is kept now — quote, attested body, its signature and certificate, every GPU report — so the
    eight offline checks can be redone by whoever reads it. It reaches the pack because a receipt travels
    whole except for `path`; this test exists because "added a field" and "the field reached the artifact"
    are different claims, and the deep survey's cap taught me that the hard way today."""
    from inferroute_local.confidential.receipt import Receipt
    from inferroute_cli import probant_export as E
    import json as _json

    r = Receipt(session_id="s", model_short="m", upstream_model="u", fleet_id="f", transport="t")
    assert hasattr(r, "attestation")

    # A receipt with evidence survives the pack's scrubber intact — only `path` is removed.
    row = {"instance_id": "abc", "quote": "QUOTE", "attested_body": "BODY",
           "signature": "SIG", "certificate": "CERT", "gpu_evidence": ["g1", "g2"]}
    packed = _json.loads(E._receipt_for_pack(_json.dumps({"attestation": row, "path": "/home/someone/x"}).encode()))
    assert packed["attestation"] == row, "the evidence did not survive into the pack"
    assert "path" not in packed and packed["withheld"] == ["path"]

    # And the brief tells the auditor it is there and what to do with it, or the bytes sit unread.
    for must in ("`attestation`", "Recompute the verdicts from it", "attested_body", "GPU report"):
        assert must in E.AUDIT_MD.replace("\n   ", " "), must


def test_an_unreadable_session_record_keeps_its_searches_and_says_so(tmp_path, monkeypatch):
    """24 Sep, the most expensive finding of the day. An Opus audit returned NOT VERIFIED on "nothing
    removed": the enclave-wide signed counter jumped 9 → 15 and the record did not account for operations
    10-14. Nothing had been removed. One session's record file was corrupt — two concurrent writers, one
    shared .tmp — and `_sessions()` caught ValueError and `continue`d, taking that session's five searches
    out of the export with it.

    So a write race became, to a careful reader, evidence of tampering. The searches are a separate file,
    intact and individually signed; they stay, and the record says the session's own description is missing
    rather than letting the gap speak for itself. A silent omission is indistinguishable from removal."""
    from inferroute_cli import probant_export as E
    rdir = tmp_path / "recs"
    rdir.mkdir()
    (rdir / "s1.json").write_text('{"session_id": "s1"}')
    (rdir / "s1.searches.jsonl").write_text('{"statement": {"seq": 1}}\n')
    # A complete record followed by a fragment: exactly the shape the shared-tmp race leaves behind.
    (rdir / "s2.json").write_text('{"session_id": "s2"}\n  "search_enclave": "saw 5 query(ies)"\n}\n')
    (rdir / "s2.searches.jsonl").write_text('{"statement": {"seq": 2}}\n{"statement": {"seq": 3}}\n')
    got = E._load_sessions(SimpleNamespace(records_dir=lambda c, m: rdir), "C", "m")
    ids = [s["session_id"] for s in got]
    assert ids == ["s1", "s2"], f"a session vanished from the export: {ids}"
    bad = [s for s in got if s["session_id"] == "s2"][0]
    assert bad["record"].get("unreadable") is True
    assert "could not be read" in bad["record"]["why"]
    # The evidence survives: its searches are intact and signed independently of the record file.
    assert [r["statement"]["seq"] for r in bad["searches"]] == [2, 3]
    # And the sequence across the export has no hole to misread.
    seqs = [r["statement"]["seq"] for s in got for r in s["searches"]]
    assert seqs == [1, 2, 3]


def test_the_brief_asks_for_one_plain_statement_about_confidentiality():
    """Henry, 24 Sep: "it would be nice to ask the audit agent to produce at the end a simple sentence
    stating what is true in terms of what privacy is achieved/proven."

    Four audits produced tables of eight verdicts and no sentence a professional could read to a client.
    The table is the working; this is the answer. It is also the line most likely to be quoted on its own,
    which is why the brief bounds what it may assert rather than only asking for it: the tempting sentence
    — "the invention was never exposed" — is stronger than anything attestation can establish, because no
    hardware evidence says what software did with a text after decrypting it."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "Last: one plain statement about confidentiality" in b
    assert "Write it LAST, from the verdicts you reached" in b
    # The forbidden claims are named, not left to judgement.
    for phrase in ('"was never exposed"', '"could not have been read"', '"remained confidential"'):
        assert phrase in b, phrase
    assert "what software did with a text after decrypting it" in b
    # And the claim-3 constraint: no calling it InferRoute's machine on hardware evidence alone.
    assert "you may not call the machine InferRoute's" in b


def test_the_brief_names_the_substitution_by_its_symptom():
    """Two auditors answered `verify_record.py`'s check names instead of these claims, on a pack that
    ALREADY carried the instruction to quote each claim's title — I checked the pack rather than assuming.
    One of the two had predicted it: "a mechanical requirement that doesn't create its own enforcement is
    exactly the kind of instruction that gets dropped once the work gets interesting."

    So the brief now names the symptom rather than restating the rule. An auditor cannot check whether it
    obeyed an instruction it has forgotten, but it can notice that its own report has a claim 4 about query
    text — which is a check name, and a claim this list does not contain."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert 'a "claim 4" about query text matching a hash' in b
    assert "you are answering the verifier's list and not this one" in b
    assert "Claim 4 here is whether the statements are untampered" in b


def test_both_briefs_condition_the_published_reference_on_who_publishes():
    """An auditor on 24 Sep found the defence we offered for claim 3 to be unsound as written.

    Both documents said that fetching InferRoute's published reference and finding it equal to the one in
    the pack "answers whether the reference was minted on the audited machine". It does not — not when the
    machine that publishes the page is the machine that made the records. That is our own situation today:
    the reference went up from the same host the sessions ran on, nine minutes before them. A fetch then
    proves only that the value is on the page now, which the operator could have arranged in either order.

    So the condition has to travel with the claim, in both places an auditor reads it, and the brief has to
    say what WOULD settle it — a date fixed by someone who is not InferRoute."""
    from inferroute_cli import probant_export as E
    import re

    verify = re.sub(r"\s+", " ", E.VERIFY_MD)
    brief = re.sub(r"\s+", " ", E.AUDIT_MD)

    # The condition itself, stated where the fetch is recommended.
    assert (
        "only if the machine that publishes the page is not the machine that made the records" in verify
    )
    assert "who can publish to that page, and from where" in verify
    assert "the published copy settles nothing and claim 3 stays open" in verify

    # The ordering argument is withdrawn rather than left standing as evidence.
    assert "equally consistent with an honest release and with a minted one" in verify
    assert "a copy whose date is fixed by someone who is not InferRoute" in verify

    # And the brief carries the condition too, since an auditor may read only that.
    assert "only when the publishing machine is not the audited one" in brief
    assert "Establish that before crediting the fetch" in brief


def test_the_census_classifies_rows_the_way_the_verifier_does():
    """The pack states how many rows are searches and how many are document reads, so that a zero is a
    stated zero rather than an empty field an auditor has to interpret — one did interpret it, on 24 Sep,
    and reported claim 8 VERIFIED because the coverage fields were null in every search.

    The rule for what a row IS lives in two files: here, and in verify_record.py's dispatch. That file is
    standalone by design and cannot be imported, so the copies cannot be shared — they can only be pinned.
    If either moves, the census and the verifier will disagree about the same folder, and the pack's own
    index will contradict the program it ships."""
    from inferroute_cli import probant_export as E
    import pathlib
    import re

    src = (pathlib.Path(E.__file__).parent / "pi_attested" / "verify_record.py").read_text()
    # The verifier's rule, verbatim. Written as a regex only to tolerate whitespace, not wording.
    assert re.search(r'str\(st\.get\("kind"\) or "search"\) == "document"', src), \
        "verify_record.py no longer classifies a document read this way; the census below is now wrong"

    doc = {"statement": {"kind": "document"}}
    search = {"statement": {"kind": "search"}}
    default = {"statement": {}}                 # no kind at all: the verifier reads this as a search
    unsigned_only = {"kind": "document"}        # a kind OUTSIDE the statement is unsigned and must not count

    c = E._census([doc, search, default, unsigned_only, doc])
    assert c == {"searches": 2, "document_reads": 2, "unknown_kind": 1}, c

    # The row's own `kind` is the record's unsigned claim about itself. Counting it would let the index
    # assert document reads that no enclave ever signed for.
    assert E._row_kind(unsigned_only) == "unknown"
    assert E._row_kind({"kind": "search", "statement": {"kind": "document"}}) == "document"


def test_the_brief_states_the_count_rather_than_leaving_it_to_be_inferred():
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "`document_reads: 0` says this matter did no document reads" in b
    assert "It does NOT say document reads go unrecorded" in b
    # And the count must not be allowed to outrank the signatures.
    assert "the statements win and the disagreement is itself a finding" in b


def test_the_census_reaches_the_manifest_of_a_real_pack(tmp_path, V, kms, no_anchors):
    """Adding a field and the field arriving in the artifact are two claims. Three times today I asserted
    only the first and the test passed over code that never wrote it."""
    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    m = json.loads((pack / "MANIFEST.json").read_text())

    assert "contents" in m, "the pack's manifest does not state what it contains"
    c = m["contents"]
    rows = json.loads((pack / "searches.json").read_text())
    assert c["searches"] + c["document_reads"] + c["unknown_kind"] == len(rows), \
        "the census does not account for every row in the folder"
    assert c["session_receipts"] == len([p for p in pack.iterdir() if E._is_session_receipt(p.name)])
    # The zero that started this: stated, not inferred from an empty field.
    assert c["document_reads"] == 0 and isinstance(c["document_reads"], int)

    # And it is indexed like everything else, so altering it breaks the folder's own checksum file.
    sums = (pack / "SHA256SUMS").read_text()
    assert "MANIFEST.json" not in sums, "the manifest indexes the folder; it cannot index itself"


def test_the_reference_timestamp_travels_with_the_pack_and_the_brief_bounds_it(tmp_path, V, kms, monkeypatch):
    """The only date in an audit pack that InferRoute does not write. Everything else — the record, the
    receipts, the reference itself — is dated by the party under audit, which is why an auditor on 24 Sep
    could decline claim 3 on timing alone and be right to.

    The brief has to bound it in the same breath as offering it, because an OpenTimestamps proof is easy to
    over-read: `ots verify` prints Success for a proof over ANY bytes, a pending proof rests on calendar
    servers rather than Bitcoin, and no timestamp says a word about whether the file's contents are true."""
    from inferroute_cli import probant_export as E
    from inferroute_cli import probant_check
    import re

    ref = tmp_path / "ref.json"
    ref.write_text('{"schema": "inferroute.enclave-reference/1"}')
    (tmp_path / "ref.json.ots").write_bytes(b"\x00OTS-PROOF-BYTES")
    monkeypatch.setattr(probant_check, "published_reference", lambda: (str(ref), "ab" * 32))

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    got = pack / "trust-anchors" / "reference.json.ots"
    assert got.is_file(), "the reference's timestamp did not travel with the pack"
    assert got.read_bytes() == b"\x00OTS-PROOF-BYTES"

    v = re.sub(r"\s+", " ", E.VERIFY_MD)
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    # The commands, so the auditor does not have to know the tool.
    # --no-bitcoin is the point: plain `ots verify` reaches for a node and fails with a connection error
    # that looks exactly like a failed proof. Both auditors on 24 Sep stopped there.
    assert "ots --no-bitcoin verify trust-anchors/reference.json.ots" in v
    assert "ots info trust-anchors/reference.json.ots" in v
    assert "Use `--no-bitcoin` unless you run a Bitcoin node" in v
    assert "check that Bitcoin block <height> has merkleroot <hash>" in v
    # The three ways to over-read it, each named.
    assert "A proof over some OTHER bytes is not a proof about this reference" in v
    assert "Pending confirmation in Bitcoin blockchain" in v
    assert "It says nothing whatever about whether the reference's CONTENTS are true" in v
    # The direction that decides it — a timestamp AFTER the searches proves nothing.
    assert "if, and only if, the timestamp PRECEDES the searches" in v
    assert "A timestamp later than the searches settles nothing" in b


def test_a_pack_without_a_reference_timestamp_says_absence_not_failure(tmp_path, V, kms, no_anchors):
    """A missing .ots must not read as a failed check. Most installations will not have one."""
    from inferroute_cli import probant_export as E
    import re

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    assert not (pack / "trust-anchors" / "reference.json.ots").exists()
    assert "an absence, not a failure" in re.sub(r"\s+", " ", E.VERIFY_MD)


def test_the_brief_gives_the_quote_offsets_that_the_client_actually_uses():
    """The brief asks the auditor to parse a TDX quote. Offsets stated wrong, or not stated at all, turn a
    three-line recomputation into research most auditors will skip — and a wrong offset produces a
    confident FAIL against software that is fine.

    So the numbers in the brief are pinned to the ones the client parses with. They were also checked
    against a real quote by hand: body[136:184] reproduced that receipt's `mrtd` exactly."""
    from inferroute_cli import probant_export as E
    from inferroute_local.confidential import attest
    import re

    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    hdr, body = attest._HDR, attest._BODY
    assert f"{hdr}-byte header followed by a {body}-byte TD report body" in b

    for name, (lo, hi) in attest._OFF.items():
        if name == "td_attributes":
            continue
        assert f"[{lo}:{hi}]" in b, f"the brief does not give the offset the client uses for {name}"

    # The snippet must slice the same places, not merely mention them in prose.
    assert f'base64.b64decode(a["quote"])[{hdr}:{hdr} + {body}]' in E.AUDIT_MD
    assert f'body[{attest._OFF["mrtd"][0]}:{attest._OFF["mrtd"][1]}].hex() == r["instance"]["mrtd"]' in E.AUDIT_MD
    rd = attest._OFF["report_data"]
    assert f"body[{rd[0]}:{rd[1]}][:32] == want" in E.AUDIT_MD

    # And the equation itself has to match the check the client runs (attest.check_e2e_key_bound).
    assert 'hashlib.sha256((mine["challenge"] + mine["e2e_pubkey"]).encode()).digest()' in E.AUDIT_MD
    assert "sha256((nonce + e2e_pubkey).encode())" in attest.__doc__, \
        "the client's own documented binding moved; the brief's snippet is now wrong"


def test_the_product_does_not_tell_the_user_what_their_profession_is():
    """Henry, 24 Sep: "we shouldn't talk about this attorney in the product code right? it's just the user".

    Probant is built for patent work, but the person at the keyboard may be in-house counsel, a paralegal,
    an agent or an inventor, and several of these strings were read by the CLIENT rather than the user.
    Where the word named a person it is now the user; where what actually mattered was the machine that
    made the record, it says that, which is both person-neutral and more precise than a job title.

    The two survivors are deliberate and are not about the reader: they tell the MODEL what standard of
    practice defines a matter ("one invention a patent attorney would prosecute as a unit"). That is a
    professional standard, not a claim about who is using the software."""
    import pathlib
    import subprocess

    root = pathlib.Path(__file__).resolve().parent.parent
    r = subprocess.run(["grep", "-rn", "attorney", "--include=*.py", "--include=*.ts", "--include=*.js",
                        "inferroute_cli/", "inferroute_local/"], cwd=root, capture_output=True, text=True)
    hits = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert len(hits) == 2, "unexpected uses of 'attorney':\n" + "\n".join(hits)
    assert all("probant_cluster.py" in h for h in hits), hits
    assert all("a patent attorney could act on" in h or "a patent attorney would prosecute" in h for h in hits), hits

    # And the two documents an outside reader is handed must not presume it either.
    from inferroute_cli import probant_export as E
    from inferroute_cli import probant_client_audit as C
    for name, text in (("AUDIT.md", E.AUDIT_MD), ("VERIFY.md", E.VERIFY_MD), ("audit-client", C.__doc__ or "")):
        assert "attorney" not in text.lower(), name
    assert "the machine which made this record was confined" in E.VERIFY_MD


def test_the_manifest_accounts_for_every_file_in_the_folder(tmp_path, V, kms, monkeypatch):
    """An auditor on 24 Sep counted 50 files listed against 56 on disk and had to decide for itself
    whether the gap was deliberate. It was — the anchors are this computer's configuration, not evidence —
    and it stopped being right the day the OpenTimestamps proof moved into that folder. That file IS
    evidence, and it was the one piece of evidence nothing accounted for.

    SHA256SUMS stays the evidence list, in the shape `sha256sum -c` expects. The anchors are indexed under
    their own heading, with what indexing them does NOT mean written beside them."""
    from inferroute_cli import probant_export as E
    from inferroute_cli import probant_check

    ref = tmp_path / "ref.json"
    ref.write_text('{"schema": "inferroute.enclave-reference/1"}')
    (tmp_path / "ref.json.ots").write_bytes(b"\x00OTS")
    monkeypatch.setattr(probant_check, "published_reference", lambda: (str(ref), "ab" * 32))

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    m = json.loads((pack / "MANIFEST.json").read_text())

    anchors = m["trust_anchors"]["files"]
    assert set(anchors) == {"trust-anchors/reference.json", "trust-anchors/reference.json.ots",
                            "trust-anchors/publication-key.txt"}, anchors
    for name, sha in anchors.items():
        assert E._sha256_hex((pack / name).read_bytes()) == sha, name

    # Nothing on disk is unaccounted for: every file is in one list or the other.
    on_disk = {str(p.relative_to(pack)) for p in pack.rglob("*") if p.is_file()}
    # MANIFEST.json indexes the folder and cannot index itself; SHA256SUMS is DERIVED from the manifest,
    # so listing it inside would be circular too. Both are named here rather than silently tolerated.
    accounted = set(m["files"]) | set(anchors) | {"MANIFEST.json", "SHA256SUMS"}
    assert on_disk == accounted, on_disk ^ accounted

    # Listing them must not be mistaken for vouching for them.
    note = m["trust_anchors"]["note"]
    assert "NOT " in note and "proves nothing on its own" in note
    assert "reference.json.ots is the" in note, "the one anchor that IS evidence is not called out"
    # And SHA256SUMS is unchanged in shape — it is the evidence list a reader checks the record with.
    assert "trust-anchors" not in (pack / "SHA256SUMS").read_text()


def test_the_pack_counts_the_filter_reports_and_what_each_receipt_supports(tmp_path, V, kms, no_anchors):
    """Two auditors read the SAME 39 statements and described them differently — one reported every
    statement carried `cutoff_applied`, the other wrote that statements lacking it were correctly SKIPPED,
    a branch that never fired on this record. Both said VERIFIED, so the disagreement was invisible. One
    was describing the verifier's code rather than the folder's data.

    And one of them hand-built a six-row table of which receipts carry `attestation` and `checked_with`
    before it could score claim 7 at all. The pack knows both; it was making them derive it."""
    from inferroute_cli import probant_export as E

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    c = json.loads((pack / "MANIFEST.json").read_text())["contents"]

    rows = json.loads((pack / "searches.json").read_text())
    assert c["statements"] == len(rows)
    for f in ("cutoff_applied", "from_date_applied", "offices_applied"):
        assert f in c and isinstance(c[f], int), f
        assert c[f] == sum(1 for r in rows if (r.get("statement") or {}).get(f) is not None), f

    for f in ("receipts_with_attestation", "receipts_with_checked_with"):
        assert f in c and isinstance(c[f], int), f
        assert c[f] <= c["session_receipts"]


def test_a_receipt_that_cannot_be_read_is_counted_as_supporting_nothing(tmp_path):
    """The census says what each receipt lets an auditor redo. An unreadable file lets them redo nothing,
    and counting it as support is the one direction that misleads — it would promise a recomputation the
    auditor then cannot perform, and they would report our software as broken, correctly."""
    from inferroute_cli import probant_export as E

    good = tmp_path / "a.json"
    good.write_text(json.dumps({"attestation": {"quote": "q", "checked_with": {"challenge": "n"}}}))
    thin = tmp_path / "b.json"
    thin.write_text(json.dumps({"attestation": {"quote": "q"}}))
    none = tmp_path / "c.json"
    none.write_text(json.dumps({"attestation": {}}))
    broken = tmp_path / "d.json"
    broken.write_text("{not json")

    assert E._receipt_has(good, "attestation") and E._receipt_has(good, "checked_with")
    assert E._receipt_has(thin, "attestation") and not E._receipt_has(thin, "checked_with")
    assert not E._receipt_has(none, "attestation")
    assert not E._receipt_has(broken, "attestation") and not E._receipt_has(broken, "checked_with")
    assert not E._receipt_has(tmp_path / "missing.json", "attestation")


def test_the_pack_ships_a_report_skeleton_whose_headings_are_the_brief_s_claims(tmp_path, V, kms, no_anchors):
    """The brief has asked auditors to quote each claim's title since 24 Sep, in increasingly explicit
    prose — including a paragraph naming the exact symptom of getting it wrong. It has now failed on three
    of five auditors, all of whom answered `verify_record.py`'s fifteen check names instead. One said why
    in its own report: a mechanical requirement that creates no enforcement of its own gets dropped once
    the work gets interesting.

    An auditor completing a file whose headings are already numbered cannot renumber them. The point of
    the test is that the headings come OUT of the brief: a second copy would let the brief be edited while
    the template kept asking for the old claims, which is this same failure one level up."""
    from inferroute_cli import probant_export as E

    claims = E.audit_claims()
    assert [n for n, _ in claims] == list(range(1, 9)), claims
    assert claims[0][1] == "Sealed hardware"
    assert claims[4][1] == "Nothing removed"

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    tmpl = (pack / "REPORT-TEMPLATE.md").read_text()

    for n, title in claims:
        assert f"## Claim {n} — {title}" in tmpl, (n, title)
    # Every claim gets the same three prompts, so "could not reach" is a field rather than an omission.
    assert tmpl.count("**Verdict:** ") == len(claims)
    assert tmpl.count("**What I could not reach, and why:** ") == len(claims)

    # The three verdicts, named here because a fourth one gets invented when the allowed set is elsewhere
    # in a long document ("CONDITIONALLY VERIFIED", 25 Sep).
    for v in ("**VERIFIED**", "**NOT VERIFIED**", "**COULD NOT CHECK**"):
        assert v in tmpl, v
    assert "There is no fourth" in tmpl
    assert "VERIFIED is wrong while any part of the claim is unchecked" in tmpl
    assert "give the sample size" in tmpl

    # It is indexed like everything else in the folder.
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert m["files"]["REPORT-TEMPLATE.md"] == E._sha256_hex(tmpl.encode("utf-8"))

    # And the brief sends the auditor to it.
    assert "REPORT-TEMPLATE.md" in E.AUDIT_MD
    assert "its headings are already the eight claims" in E.AUDIT_MD


def test_the_template_refuses_to_be_built_from_a_brief_whose_claims_do_not_number(monkeypatch):
    """If the claim list is ever edited into a state this cannot read, the template must fail loudly. A
    skeleton silently missing claim 6 would be worse than no skeleton: every auditor who completed it
    would return a report with a hole nobody asked about."""
    from inferroute_cli import probant_export as E

    broken = E.AUDIT_MD.replace("6. **Filters", "9. **Filters", 1)
    monkeypatch.setattr(E, "AUDIT_MD", broken)
    with pytest.raises(ValueError, match="not 1..n"):
        E.audit_claims()


def test_the_pack_reads_the_anchored_block_out_of_the_proof(tmp_path, monkeypatch):
    """Two auditors had this proof in front of them on 25 Sep and neither could use it: one had no Bitcoin
    node, the other could not install the client at all because PEP 668 makes `pip install` refuse on a
    modern Linux, and reported the whole of claim 3 as COULD NOT CHECK for want of a tool.

    So the pack carries the block height and merkle root, read from the proof by `ots` at pack time. It is
    a convenience and the brief says so in the same breath: these are OUR values, and a block number we
    typed binds nothing. It buys the date without a toolchain; the binding still lives in the .ots."""
    from inferroute_cli import probant_export as E

    ots = tmp_path / "reference.json.ots"
    ots.write_bytes(b"\x00proof")

    def fake_run(argv, capture_output=True, text=True, timeout=None):
        assert "--no-bitcoin" in argv and "verify" in argv, argv
        return SimpleNamespace(returncode=0, stdout="Assuming target filename is 'current.json'\n"
                               "To verify manually, check that Bitcoin block 968451 has merkleroot "
                               + "d1" * 32 + "\n", stderr="")
    monkeypatch.setattr(E.shutil, "which", lambda n: "/usr/bin/ots")
    monkeypatch.setattr(E.subprocess, "run", fake_run)

    got = E.anchor_block(ots)
    assert got["bitcoin_block"] == 968451 and got["merkle_root"] == "d1" * 32
    assert "not InferRoute's" in got["how_to_check"]
    assert "OUR reading of the proof" in got["how_to_check"]

    # A pending proof has no block, and inventing one would be the worst line in the folder.
    monkeypatch.setattr(E.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout="", stderr="Failed! Timestamp not complete"))
    pending = E.anchor_block(ots)
    assert "bitcoin_block" not in pending and "ots upgrade" in pending["note"]

    # No client, and no proof, are each an absence rather than a guess.
    monkeypatch.setattr(E.shutil, "which", lambda n: None)
    assert "bitcoin_block" not in E.anchor_block(ots)
    assert E.anchor_block(tmp_path / "missing.ots") == {}


def test_the_brief_says_what_the_recorded_block_is_worth_and_what_it_is_not():
    from inferroute_cli import probant_export as E
    import re

    v = re.sub(r"\s+", " ", E.VERIFY_MD)
    # The blocker two auditors actually hit, and the ways round it.
    assert "that is PEP 668 and not a dead end" in v
    assert "uv tool install opentimestamps-client" in v
    assert "you do not need the tool at all to get the date" in v
    # And the bound, in the same breath.
    assert "Those two values are OURS" in v
    assert "it does not bind that block to this reference" in v
    assert "the file wins and the disagreement is a finding" in v
    # The answer that actually comes back, which is neither a pass nor a failure.
    assert 'Expect the answer to be "some of each"' in v
    assert "later than 33 of the 58 searches and earlier than 25" in v
    assert "Give both counts." in v
