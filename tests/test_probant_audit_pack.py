"""The audit pack: an evidence-only copy of a record for the professional's OWN AI to audit (Henry, 19 Sep).

It must say nothing of the invention, and it must lose nothing else. The first is checked by looking for
every word that was withheld; the second by running the SAME verifier over the record and over its pack:
the only check lines allowed to differ are the ones that need the withheld text, and they may only turn into
SKIP, never PASS.
"""
import json
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
    assert "is NOT in this folder" in md                 # the limit is stated, not implied
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
