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
    # 0600 for the evidence; the report template is 0400 because it is the one file an auditor is invited
    # to fill in, and filling it in WHERE IT LIES broke a pack on 25 Sep.
    modes = {p.name: stat.S_IMODE(p.stat().st_mode) for p in pack.iterdir() if p.is_file()}
    assert modes.pop("REPORT-TEMPLATE.md") == 0o400, "the template is writable where it lies"
    assert all(m == 0o600 for m in modes.values()), modes


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
    assert "## Claim N —" in md
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
    assert "Four verdicts, and the difference between two of them matters" in b
    assert "the evidence is here and it does not support the claim" in b
    assert "that is NOT VERIFIED on provenance, not a gap" in b
    # And it is taught BEFORE the claims, not only in the report format at the end.
    assert b.index("Four verdicts") < b.index("**Sealed hardware.**")


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
    """A session whose own metadata cannot be read used to be SKIPPED, silently, taking its searches with
    it — which reads to an auditor as evidence removed. Two shapes now, and they are not the same:

    RECOVERABLE — two interleaved writes leave a COMPLETE first document with an aborted one after it.
    That is the shared-tmp shape fixed on both sides on 24 Sep, and throwing the file away over the tail
    costs the reader a whole session. On 25 Sep two auditors independently found a session with five
    sealed searches and no receipt anywhere; its record was 7994 good bytes plus 1118 of tail, and the
    intact half named a receipt that had been on disk the whole time.

    UNREADABLE — nothing parses at all. The searches still stay, and the record says what was lost.

    Neither is ever silent: a repaired record that does not say it was repaired is worse than a broken one.
    """
    from inferroute_cli import probant_export as E
    from inferroute_cli import probant as S

    rdir = tmp_path / "recs"
    rdir.mkdir()
    monkeypatch.setattr(S, "records_dir", lambda c, m: rdir)

    (rdir / "s1.json").write_text('{"session_id": "s1"}')
    (rdir / "s1.searches.jsonl").write_text('{"statement": {"seq": 1}}\n')
    # A whole document, then an aborted write: recoverable.
    (rdir / "s2.json").write_text('{"session_id": "s2", "model_lane": {"receipt": "/x"}}\n  "oops"\n}\n')
    (rdir / "s2.searches.jsonl").write_text('{"statement": {"seq": 2}}\n{"statement": {"seq": 3}}\n')
    # Nothing parses at all: unreadable.
    (rdir / "s3.json").write_text('not json at all')
    (rdir / "s3.searches.jsonl").write_text('{"statement": {"seq": 4}}\n')

    out = E._load_sessions(S, "C", "M")
    ids = [x["session_id"] for x in out]
    assert ids == ["s1", "s2", "s3"], f"a session vanished from the export: {ids}"

    ok, recovered, unreadable = out
    assert "recovered" not in ok["record"] and not ok["record"].get("unreadable")

    # The recovered one keeps the intact half — INCLUDING the receipt path, which is the whole point.
    assert recovered["record"]["session_id"] == "s2"
    assert recovered["record"]["model_lane"]["receipt"] == "/x"
    assert "did not parse whole" in recovered["record"]["recovered"]["why"]
    assert "trailing bytes were an aborted write" in recovered["record"]["recovered"]["why"]
    assert not recovered["record"].get("unreadable"), "a recoverable record must not be called unreadable"
    assert [r["statement"]["seq"] for r in recovered["searches"]] == [2, 3]

    # The truly unreadable one still keeps its searches and says what was lost.
    assert unreadable["record"].get("unreadable") is True
    assert "could not be read" in unreadable["record"]["why"]
    assert [r["statement"]["seq"] for r in unreadable["searches"]] == [4]

    seqs = sorted(r["statement"]["seq"] for x in out for r in x["searches"])
    assert seqs == [1, 2, 3, 4], "a signed search was dropped with its session's metadata"

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
    # ...plus the stationery, which is in the folder and deliberately NOT pinned: an auditor is invited to
    # write to the report template, so a hash on it would fail by design the moment they did.
    accounted = set(m["files"]) | set(anchors) | set(m["stationery"]) | {"MANIFEST.json", "SHA256SUMS"}
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
    for v in ("**VERIFIED**", "**VERIFIED IN PART**", "**NOT VERIFIED**", "**COULD NOT CHECK**"):
        assert v in tmpl, v
    # The fourth word exists because two models needed it and wrote it anyway on 25 Sep; the brief used
    # to forbid it while praising a report that used it. A FIFTH is still invented, so the bound stays.
    assert "There is no fifth — do not invent one" in tmpl
    assert "you reached some of it, all of what you reached held" in tmpl
    assert 'reads it as "there was no data"' in tmpl
    assert "give the size" in tmpl          # wording moved with the fourth verdict

    # It is accounted for, but as STATIONERY and without a hash. An auditor on 25 Sep filled it in where
    # it lay and broke the pack's own SHA256SUMS — the check the brief tells them to run. The instrument
    # built to stop one mistake was manufacturing a worse one.
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert "REPORT-TEMPLATE.md" not in m["files"], "the template is pinned; filling it in would fail the pack"
    assert "REPORT-TEMPLATE.md" not in (pack / "SHA256SUMS").read_text()
    assert "not evidence" in m["stationery"]["REPORT-TEMPLATE.md"]

    # Writing to it must leave the evidence check green. Asserted by DOING it, not by reading the manifest.
    tmpl_path = pack / "REPORT-TEMPLATE.md"
    tmpl_path.chmod(0o600)          # an auditor determined to ignore the instruction has to do this first
    tmpl_path.write_text(tmpl + "\n\n**Verdict:** VERIFIED\n")
    import subprocess
    r = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=pack, capture_output=True, text=True)
    assert r.returncode == 0, f"filling in the template broke the pack:\n{r.stdout}{r.stderr}"

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
    assert "Give both counts, from your own comparison" in v


def test_the_template_cannot_be_filled_in_where_it_lies(tmp_path, V, kms, no_anchors):
    """25 Sep, from the two auditors who ran on the same pack at once. One filled REPORT-TEMPLATE.md in
    where it lay; the other ran `sha256sum -c SHA256SUMS` at the end, found the record failing, traced the
    writer by pid, and reported plainly that had it been the later of the two it would have filed a
    finding about evidence tampering that was really a colleague's scratch edit.

    The instrument built to stop one mistake was manufacturing a worse one. Three things now have to hold
    at once, and each covers a different way of getting there:
      * the brief names the OUTPUT PATH, so the correct action and the non-destructive action are one act;
      * the file is read-only, so ignoring that fails at the first keystroke and not at the check;
      * it is out of the checked set, so even then nothing breaks."""
    from inferroute_cli import probant_export as E
    import re
    import stat
    import subprocess

    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    tmpl = pack / "REPORT-TEMPLATE.md"

    assert stat.S_IMODE(tmpl.stat().st_mode) == 0o400, "the template is writable where it lies"

    brief = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "cp REPORT-TEMPLATE.md ../REPORT-<this folder's name>.md" in brief
    assert "WHERE was the part the instruction left out" in brief
    # The same instruction where the auditor is actually looking — inside the template itself.
    assert "cp REPORT-TEMPLATE.md ../REPORT-<pack folder name>.md" in tmpl.read_text()
    assert "Write nothing inside the evidence folder" in tmpl.read_text()

    # Even so: an auditor who forces it past read-only must not break the record.
    tmpl.chmod(0o600)
    tmpl.write_text("# my report\n\n**Verdict:** VERIFIED\n")
    r = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=pack, capture_output=True, text=True)
    assert r.returncode == 0, f"filling in the template broke the pack:\n{r.stdout}{r.stderr}"
    code, out = _run(pack)
    assert "PASS bundle integrity" in out, out[-400:]


def test_claim_five_names_both_ways_a_removal_hides():
    """An auditor on 25 Sep: claim 5's caveat mentioned only "one removed from the very end", but an
    entire session or lifetime dropped wholesale is equally undetectable — per-session numbering stays
    contiguous inside every session that IS shown. A verdict citing only the first overstates what was
    checked, and the caveat had named only it since it was written."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "TWO exceptions no counter can reveal" in b
    assert "a verdict that names only the first is overstating what was checked" in b
    assert "an entire session, or an entire enclave lifetime, dropped from the record wholesale" in b


def test_the_pack_says_where_to_get_the_wheel_it_was_built_by(tmp_path, V, kms, no_anchors, monkeypatch):
    """Every auditor so far reported VERIFY.md's step (b) — compare the shipped verifier against an
    independently published copy — as unrunnable. The package is not on PyPI and nothing in the pack said
    where else to look. One of them named the fix exactly: "a URL in MANIFEST (unsigned, but findable)
    would make step (b) runnable."

    Generic, not the per-recipient path: a link minted for one reader is no use to their auditor, who may
    be a third party months later. And bounded in the same breath — both the link and the version are the
    audited party naming itself, so what the comparison is worth comes from the copy arriving over a
    channel this machine does not serve."""
    from inferroute_cli import probant_export as E
    import re

    rec = _synthetic_bundle(tmp_path, V, kms)
    # This tree is not installed, so it reports 0.0.0+dev and correctly emits no link — which is the other
    # half of the behaviour, asserted below. Pin a release version to see the link a real pack carries.
    monkeypatch.setattr(E, "_client_version", lambda: "0.9.32")
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    m = json.loads((pack / "MANIFEST.json").read_text())

    url = m["client_wheel_url"]
    assert url.startswith("https://inferroute.ai/client/inferroute-")
    assert url.endswith("-py3-none-any.whl")
    assert m["client_version"] in url, "the link does not point at the version that built this pack"
    # NOT the per-recipient token path, which is useless to a third-party auditor.
    assert "qsq7adtvwv3ug9" not in url

    # A pack built from an uninstalled tree must NOT claim a published URL: sending an auditor to fetch
    # "inferroute-0.0.0+dev…whl" wastes their time and reads as a broken link in our record rather than
    # as what it is. Absence is the honest output.
    assert E.wheel_url_for("0.9.32") == "https://inferroute.ai/client/inferroute-0.9.32-py3-none-any.whl"
    assert E.wheel_url_for("0.0.0+dev") == ""
    assert E.wheel_url_for("") == ""

    v = re.sub(r"\s+", " ", E.AUDIT_MD)          # step (b) lives in the brief, not VERIFY.md
    assert "`client_wheel_url`" in v and "<same url>.sha256" in v
    # The bound, stated where the link is offered.
    assert "Both the link and the version are the audited party naming itself" in v
    assert "an unsigned URL we control proves nothing on its own" in v
    # And the 404, which is the case an auditor will actually hit on a version we did not publish.
    assert "A 404 means that exact version was not published, not that the record is wrong" in v


def test_the_pack_ships_the_verifier_of_the_client_that_wrote_it(tmp_path, V, kms, no_anchors, monkeypatch):
    """Round 1 of the audit loop, 25 Sep, found this and it is the worst defect of the night.

    The pack shipped the verifier that came with the RECORD — written by whatever client exported it,
    possibly months earlier — while reporting `client_version` for the client writing the PACK and linking
    to that version's wheel. So the moment an auditor did what the brief asks and compared the two, they
    mismatched by construction. One did: it diffed them, established version lag rather than tampering,
    and cleared it, after real work our own packaging created.

    Worse than a false alarm. The stale copy predated REPORT-TEMPLATE.md being declared stationery, so it
    reported `present-but-unlisted ['REPORT-TEMPLATE.md']` and THE PACK FAILED ITS OWN INTEGRITY CHECK —
    exit 1, on evidence that was entirely sound."""
    from inferroute_cli import probant_export as E

    rec = _synthetic_bundle(tmp_path, V, kms)
    # Make the record's copy differ, exactly as a months-old record's would.
    stale = (rec / "verify_record.py").read_bytes()
    (rec / "verify_record.py").write_bytes(b"# an older client's verifier\n" + stale)

    monkeypatch.setattr(E, "_client_version", lambda: "0.9.34")
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    shipped = (pack / "verify_record.py").read_bytes()

    import pathlib as _pl
    installed = (_pl.Path(E.__file__).parent / "pi_attested" / "verify_record.py").read_bytes()
    assert shipped == installed, "the pack ships the record's verifier, not its own"
    assert shipped != (rec / "verify_record.py").read_bytes()

    m = json.loads((pack / "MANIFEST.json").read_text())
    assert m["verify_record_sha256"] == E._sha256_hex(installed)
    assert m["files"]["verify_record.py"] == m["verify_record_sha256"], \
        "the manifest's two statements about the same file disagree"

    # And the pack passes its own verification — the thing that actually broke.
    code, out = _run(pack)
    assert "PASS bundle integrity" in out, out[-500:]
    assert "present-but-unlisted" not in out


def test_the_brief_asks_for_observations_and_never_predicts_the_answer():
    """Round 2 of the audit loop, 25 Sep: an auditor reported a positive independent match of
    verify_record.py against PyPI — "the strongest of the three sources… PyPI is not InferRoute" — for a
    release that does not contain the file at all. I checked PyPI myself rather than acting on it.

    That is the second confabulation in three audits, and both ran in the direction of making the
    auditor's own work look more complete. The client cannot stop an auditor inventing, but it can stop
    ASKING to be agreed with: the brief used to say what the fetch would return, and an expected answer
    printed in a brief is an anchor. It now asks for the artefacts instead — filename, size, and the full
    hash printed beside the one being compared — because a pasted hash is falsifiable and "an exact match"
    is not."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "do not report a match you did not print" in b
    assert "the wheel's exact filename, its byte size" in b
    assert "the full 64-character hash you computed beside the one you are comparing against" in b
    assert "A hash pasted from your own terminal can be checked by the reader" in b
    # The anchor is gone, and the reason it is gone is stated where someone might put it back.
    assert "no longer tells you what your fetch will say" in b
    assert "An expected answer printed here is an anchor" in b
    assert "As of this writing the released versions on the index do **not** contain this file" not in E.AUDIT_MD


def test_the_record_says_which_receipt_covers_which_session(tmp_path, monkeypatch):
    """Two auditors on 25 Sep independently found a session with five sealed searches and no receipt
    anywhere in the pack, and neither could tell an absent AI lane from an omission — which is the one
    distinction claim 7 turns on. The cause was a record that would not parse whole, so the export took
    the `continue` branch and said nothing.

    Both branches now leave a row. A stated absence is a different artefact from a silent one: the first
    is a COULD NOT CHECK an auditor can report, the second is a gap they must guess about."""
    from inferroute_cli import probant_export as E

    b = {"sessions": [
        {"session_id": "has-one", "searches": [1, 2],
         "record": {"model_lane": {"receipt": str(tmp_path / "r.json")}}},
        {"session_id": "no-lane", "searches": [1, 2, 3, 4, 5], "record": {"model_lane": {}}},
        {"session_id": "named-gone", "searches": [1],
         "record": {"model_lane": {"receipt": str(tmp_path / "missing.json")}}},
    ]}
    (tmp_path / "r.json").write_text('{"session_id": "x"}')

    notes = _receipt_notes_via_bundle(E, b, tmp_path)
    by = {n["session"]: n for n in notes}
    assert set(by) == {"has-one", "no-lane", "named-gone"}, "a session left no row at all"

    assert by["has-one"]["receipt"] == "session-has-one.receipt.json"
    assert by["has-one"]["searches"] == 2

    # The case the auditors hit: searches, no receipt, and now a reason.
    assert by["no-lane"]["receipt"] == "none" and by["no-lane"]["searches"] == 5
    assert "AI lane was never opened" in by["no-lane"]["why"]
    assert "could not be read whole" in by["no-lane"]["why"]

    assert by["named-gone"]["receipt"] == "named but unreadable"
    assert "could not read" in by["named-gone"]["why"]

    import re
    brief = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "says which receipt covers which session, or why none does" in brief
    assert "rather than reporting it as evidence withheld" in brief


def _receipt_notes_via_bundle(E, b, tmp_path):
    """Drive write_bundle far enough to collect its per-session receipt rows, with the bundle it would
    have assembled from disk replaced by the one under test."""
    import json
    from inferroute_cli import probant as S

    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    full = dict(b, html="<p>x</p>", searches=[], evidence={}, matter_cutoff=20260814)
    orig_build, orig_load = E.build_bundle, S.load_record
    E.build_bundle = lambda c, m: full
    S.load_record = lambda c, m: {"workspace": str(ws)}
    try:
        out = E.write_bundle("C", "M", str(tmp_path / "bundle"))
    finally:
        E.build_bundle, S.load_record = orig_build, orig_load
    return json.loads((out / "MANIFEST.json").read_text())["sessions"]


def _manifest_via_bundle(E, S, b, tmp_path):
    """The whole record manifest, with the bundle it would have assembled from disk replaced."""
    import json as _j
    ws = tmp_path / "ws2"
    ws.mkdir(exist_ok=True)
    full = dict(b, html="<p>x</p>", evidence={}, matter_cutoff=20260814)
    full.setdefault("searches", [])
    orig_build, orig_load = E.build_bundle, S.load_record
    E.build_bundle = lambda c, m: full
    S.load_record = lambda c, m: {"workspace": str(ws)}
    try:
        out = E.write_bundle("C", "M", str(tmp_path / "bundle2"))
    finally:
        E.build_bundle, S.load_record = orig_build, orig_load
    return _j.loads((out / "MANIFEST.json").read_text())


def test_the_exporter_accounts_for_operations_missing_from_this_record(tmp_path, monkeypatch):
    """The verifier reports enclave-counter gaps as an observation and ends "ask the exporter to account
    for them". Round 3 of the audit loop, 25 Sep, showed why that matters: 28 absent sequence numbers,
    nothing in the folder able to say whose, and the auditor returned NOT VERIFIED on "nothing removed" —
    the right call on what it had.

    An enclave serves every matter on an installation, so a record of one matter is missing the others by
    construction, and only the exporting machine can say so. Counts, never names: that another matter
    exists is unavoidable in answering at all; which one, and what it searched, is not the auditor's."""
    from inferroute_cli import probant_export as E
    from inferroute_cli import probant as S

    root = tmp_path / "attested-records"
    here = root / "C" / "M"
    here.mkdir(parents=True)
    (root / "C" / "Other").mkdir(parents=True)
    monkeypatch.setattr(S, "records_dir", lambda c, m: root / c / m)

    def rows(lid, seqs):
        return [{"statement": {"lifetime_id": lid, "seq": n}} for n in seqs]

    # This matter holds 1,2,5 of 1..5 — 3 and 4 are absent.
    mine = rows("aa" * 16, [1, 2, 5])
    # The other matter holds 3 but not 4, so one is explained and one is not.
    (root / "C" / "Other" / "s.searches.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows("aa" * 16, [3])) + "\n"
        # A torn line accounts for NOTHING and must not be allowed to claim it does.
        + '{"statement": {"lifetime_id": "aaaa\n')

    # THIS matter's own record file holds the very numbers that are absent from the export's `searches`
    # list. If the scan failed to exclude its own directory it would explain the gap with itself, and
    # every gap anywhere would read as accounted for.
    (here / "s.searches.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows("aa" * 16, [3, 4])) + "\n")

    out = E.enclave_gaps(S, "C", "M", mine)
    assert len(out) == 1, out
    g = out[0]
    assert g["absent_from_this_record"] == 2
    assert g["explained_other_matters_same_installation"] == 1
    assert g["unaccounted"] == 1, "a torn line in another matter was counted as an explanation"
    assert "never which matter or what it searched" in g["note"]

    # No matter name, anywhere in the row.
    assert "Other" not in json.dumps(g)

    # A record with no gaps says nothing rather than an empty reassurance.
    assert E.enclave_gaps(S, "C", "M", rows("bb" * 16, [1, 2, 3])) == []

    # And it has to REACH the record's manifest, not merely be computable.
    b = {"sessions": [], "searches": mine}
    man = _manifest_via_bundle(E, S, b, tmp_path)
    assert man["enclave_gaps"] and man["enclave_gaps"][0]["unaccounted"] == 1

    import re
    brief = re.sub(r"\s+", " ", E.AUDIT_MD)
    assert "the exporter answering the question the verifier tells you to ask it" in brief
    assert "a non-zero `unaccounted` is a finding" in brief


def test_the_brief_asks_the_auditor_about_its_own_independence():
    """Round 4 of the audit loop did this unprompted: it noticed the vendor's own repository on the
    filesystem it was working in, stated that none of its findings drew on it, and told the professional
    the audit was not run from an unrelated third party's machine.

    That is the one part of the report only the auditor can write, and claim 3 makes it unavoidable —
    a report that asks whether a REFERENCE is independent of the party that produced it, and never asks
    the same of itself, is incomplete. Three of four audits did not raise it."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "Say what about YOUR OWN position could affect this audit" in b
    assert "also holds InferRoute's source or internal material, say so" in b
    assert "same question applies to you" in b   # sentence-initial since the example was cut
    assert "It is the one part of the report only you can write" in b
    # And NO worked example: an auditor on 25 Sep said the example made one observation the obvious one
    # to make, so it could no longer tell its own noticing from compliance.
    assert "No example is given here, on purpose" in b
    assert "vendor's own repository on the filesystem it" not in b

    # And the skeleton carries the heading, so it is not a paragraph to be skipped.
    tmpl = E.report_template()
    assert "## About this audit" in tmpl
    assert tmpl.index("## About this audit") < tmpl.index("## Claim 1"), "it must come before the claims"


def test_the_brief_disarms_the_last_modified_trap():
    """Round 5 of the audit loop fetched the published reference and found its HTTP `Last-Modified` within
    thirty seconds of the pack's own `generated_at`. It could not rule out that the reference had been
    republished to fit the record, and reported the observation unresolved.

    It had not been. The bytes were unchanged — same sha256 as the copy anchored in Bitcoin block 968451
    three days earlier — and the header moved only because deploying an unrelated file re-stamps every
    static file on the host. The auditor was right to flag it and right not to resolve it in our favour,
    which is exactly why the brief has to answer it rather than leave each one to discover it alone.

    The answer must not be "trust us": it is an arithmetic check the auditor already has the inputs for."""
    from inferroute_cli import probant_export as E
    import re
    v = re.sub(r"\s+", " ", E.AUDIT_MD)          # claim 3 lives in the brief

    assert "Ignore the HTTP `Last-Modified` on that fetch. It is not the reference's age." in v
    assert "re-stamps every file it serves whenever anything on the site is deployed" in v
    # The auditor's own observation is preserved rather than smoothed over.
    assert "within THIRTY SECONDS of the pack's own `generated_at`" in v
    assert "right to flag what it saw, and right not to resolve it in our favour" in v
    # And the resolution is a computation, not an assurance.
    assert "Hash the bytes you fetched and compare them with what the timestamp proof commits to" in v
    assert "curl -s https://inferroute.ai/reference/current.json | sha256sum" in v
    # Including what a genuine mismatch would mean — the check has to be able to fail.
    assert "If they DISAGREE, that is a real finding and a serious one" in v


def test_the_verdict_line_carries_the_completeness_rule():
    """Haiku, 25 Sep, wrote "**Verdict:** VERIFIED" on claim 3 and then, in the same section, wrote that
    establishing the claim "depends on the publication key being InferRoute's, which I cannot verify from
    this folder alone". Two sentences, four lines apart, contradicting each other.

    The brief already forbids this in two separate places. Saying it a third time in the brief was not
    going to work — the rule has to be at the point where the word is typed, which is the template's
    Verdict line. Same reason the three allowed verdicts are printed under each heading rather than left
    in a paragraph elsewhere."""
    from inferroute_cli import probant_export as E

    tmpl = E.report_template()
    n = len(E.audit_claims())
    assert tmpl.count("not plain VERIFIED if any part of this claim below is one you could not reach") == n, \
        "the rule is missing from at least one claim's verdict line"
    # It sits on the Verdict line itself, not in a preamble the reader has already scrolled past.
    for line in tmpl.splitlines():
        if line.startswith("**Verdict:**"):
            assert "could not reach" in line, line


def test_the_brief_requires_every_stated_fact_to_have_been_read():
    """Haiku's first round reported four field values that do not exist in the pack it was auditing —
    a `"receipt": "none"` no session has, a `written_by` string no receipt contains, a `counters_mean`
    field absent from the receipt it was quoted from, and "26" numbers in a range holding 28. All four
    sat inside otherwise careful prose.

    Its second round, given this rule explicitly, fabricated nothing: every figure I spot-checked was
    correct. That is one round of evidence, not proof, but the rule costs nothing and the failure it
    addresses is the one a reader without the pack cannot catch."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "Every fact you state about this folder must be one you read out of it" in b
    assert "If you name a field, you opened that file. If you give a count, you counted." in b
    # The failure named by its symptom, as the renumbering rule had to be.
    assert "four field values that do not exist in the pack it was auditing" in b
    # And why it matters more than an omission.
    assert "worse than one that omits it, because the omission is visible and the invention is not" in b


def test_the_brief_stops_handing_over_the_answer_before_the_question():
    """Opus, 25 Sep, on the brief itself: "The brief itself is the biggest anchoring risk in the folder,
    and it does not say so." It warns at length that verify_record.py's check names will colonise your
    thinking if you meet them first — and then supplies, in advance, the expected gzip ratio, that RTMR0
    varies benignly, that the anchor lands mid-record, that a zero in removed_by_cutoff is legitimate.

    Its sharpest example: `counters_mean` is described in enough detail that a tired auditor could quote
    it as a field they read. It exists in NO receipt in this pack — and Haiku did exactly that, quoting a
    30% figure from a field that is not there.

    So the ratio is no longer stated as a number to expect. The brief says what the field is FOR, tells
    the auditor to check whether it is present, and says what to do when it is not."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "typically 55-75% on JSON" not in b, "the brief still hands over the number to expect"
    assert "a third to a half" not in b, "the brief still predicts the ratio"
    assert "Check whether `counters_mean` is present before quoting it" in b
    # It used to key on the EXPORTING version here; the field is written by whatever client wrote the
    # receipt, which in a pack exported today may be months older. Corrected 25 Sep.
    assert "no receipt in a pack exported before 0.9.34 has it" not in b
    assert "depends on the client version in each receipt's own `written_by`" in b


def test_the_brief_answers_three_more_things_opus_found(tmp_path):
    """Three of the seven criticisms Opus made of the brief on 25 Sep, each a place the brief asked for
    something it had not thought through:

    * it asks the auditor to put the verifier's exit code in the report header, and never says the exit
      code is silent on the one quantitative anomaly in the record — a clean 0 coexists with a 28-hole;
    * it forbids reporting a hash you did not print, and says nothing about a file you did not fetch;
      `pip download` prints "File was already downloaded" over another auditor's leftovers and exits 0;
    * it made filling in a copied template "a file now rather than a request" — and three auditors ran in
      environments that refuse to write files, so the enforcement produced an empty copy and no report."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "A zero exit code does not mean this gap was judged acceptable" in b
    assert "If you find one, put it in the header too" in b

    assert "The same goes for a file you did not fetch" in b
    assert '"File was already downloaded"' in b
    assert "you fetched those bytes yourself, in this session" in b

    assert "If you cannot write files at all, that is not a blocker" in b
    assert "The headings are the requirement" in b
    assert "Do not leave an empty copy behind" in b


def test_the_brief_does_not_send_the_auditor_after_a_chain_that_is_not_there():
    """Opus, 25 Sep: step five of claim 7 read "check the certificate chain", and the receipt's
    certificate is SELF-SIGNED. "An auditor following the instruction literally would report a
    one-certificate chain as a weakness, or would quietly substitute the Intel PCK chain (which IS there,
    inside the quote) and report it as though it were the thing asked for."

    The chain that exists is Intel's, inside the quote, and its root is checkable against Intel's own
    published certificate — which is a real independent check the brief was not asking for."""
    from inferroute_cli import probant_export as E
    import re
    b = re.sub(r"\s+", " ", E.AUDIT_MD)

    assert "SELF-SIGNED (`CN=attestation-service`)" in b
    assert "finding none is not a weakness you have discovered" in b
    assert "PCK → PCK Platform CA → SGX Root CA" in b
    assert "compare its root with Intel's own published certificate" in b
    # The bare instruction that caused it must not come back.
    assert "- check the certificate chain." not in E.AUDIT_MD


# --- An auditor on 25 Sep was asked what was still wrong with the brief itself and returned seven things.
#     These are the ones a later edit could silently undo.

def _template_text():
    t = E.report_template()
    return t if isinstance(t, str) else "\n".join(t)


def test_the_brief_and_the_template_name_the_same_verdicts():
    """AUDIT.md said "Three verdicts" while REPORT-TEMPLATE.md said "exactly four ... do not invent a
    fifth" and required VERIFIED IN PART. The brief forbade the word its own mandatory form demanded."""
    brief, tpl = E.AUDIT_MD, _template_text()
    assert "Four verdicts" in brief
    for verdict in ("VERIFIED IN PART", "NOT VERIFIED", "COULD NOT CHECK"):
        assert verdict in brief, verdict
        assert verdict in tpl, verdict
    assert "Three verdicts" not in brief
    # and the shape the two ask for must agree, not just the vocabulary
    assert "## Claim N —" in brief and "**Verdict:**" in brief


def test_a_sample_verdict_is_resolved_rather_than_left_to_guess():
    """"VERIFIED is wrong if any part is unchecked" and "two of thirty-nine is the right method" gave an
    auditor no way to grade a sample. The brief now names which verdict a sample earns."""
    brief = E.AUDIT_MD
    i = brief.index("verified on a SAMPLE")
    assert "VERIFIED IN PART" in brief[i:i + 700]


def test_the_brief_does_not_print_the_counts_it_asks_the_auditor_to_compute():
    """Claim 5's whole content is a count, and the brief used to print a real record's — so recall and
    arithmetic became indistinguishable on the one claim where that matters most. Same for the anchor
    split in VERIFY.md, and for the verifier comment the brief sends them to read first."""
    verifier = (E.Path(__file__).resolve().parent.parent
                / "inferroute_cli" / "pi_attested" / "verify_record.py").read_text()
    for text, name in ((E.AUDIT_MD, "AUDIT.md"), (E.VERIFY_MD, "VERIFY.md"), (verifier, "verify_record.py")):
        for anchored in ("28 absent", "37 of seq", "33 of the", "1..65"):
            assert anchored not in text, f"{name} still prints {anchored!r}"


def test_the_brief_tells_the_auditor_not_to_read_the_earlier_audits():
    """It sends them to work in the directory where every prior report sits under an obvious name, and
    said nothing about them. The instruction has to ship with the pack, not ride in a covering message."""
    brief = E.AUDIT_MD
    assert "do not read what is already there" in brief
    i = brief.index("do not read what is already there")
    assert "independent" in brief[i:i + 500]


def test_the_confidentiality_section_gives_no_paragraph_to_copy():
    """Its worked example was reproduced almost clause for clause by the auditor who met it — the same
    reason the self-disclosure section had its example removed."""
    brief = E.AUDIT_MD
    assert "No model paragraph is given" in brief
    assert "The shape, not a form of words to copy" not in brief


# --- Round three, 25 Sep. Two of these are plain factual errors in the brief; the third is a command the
#     brief gives as "do this, exactly" that cannot succeed as written.

def test_the_brief_does_not_call_the_verifiers_check_names_fifteen():
    """Fifteen is the RECEIPT's count of checks. The verifier prints over forty, and the brief used the
    receipt's number for it in three places -- one of them inside the passage arguing for precision about
    that very program."""
    brief = E.AUDIT_MD
    for i, line in enumerate(brief.splitlines()):
        if "verify_record.py" in line and "fifteen" in line:
            raise AssertionError(f"line {i}: the verifier's check names called fifteen: {line!r}")
    assert "it prints more than forty of them" in brief


def test_the_number_the_brief_gives_for_the_check_names_is_the_real_one(tmp_path, V, kms):
    """A bound rather than an exact count, because a new check must not make the brief wrong -- but it has
    to be a bound the program actually satisfies, or this is the same error with a different number."""
    from tests.test_verify_record import _synthetic_bundle, _run
    d = _synthetic_bundle(tmp_path, V, kms)
    _, out = _run(d, "--reference", str(tmp_path / "reference.json"))
    names = {m.group(1) for m in re.finditer(r"^\s*(?:PASS|FAIL|SKIP) ([^:]+):", out, re.M)}
    assert len(names) > 15, f"only {len(names)} distinct check names: {sorted(names)}"


def test_the_template_copy_instruction_accounts_for_the_read_only_mode():
    """The template ships 0400 so it cannot be filled in where it lies -- and `cp` carries that mode to
    the copy, so the instruction as given produced a read-only report file."""
    brief = E.AUDIT_MD
    i = brief.index("cp REPORT-TEMPLATE.md")
    assert "chmod u+w" in brief[i:i + 400], "the copy inherits 0400 and nothing says to make it writable"


def test_counters_mean_is_keyed_on_the_receipts_own_version():
    """It is written by the client that wrote the RECEIPT, not by the one that exported the pack: a pack
    exported today can be full of receipts written by clients that had no such field."""
    brief = E.AUDIT_MD
    i = brief.index("counters_mean")
    window = brief[i:i + 1400]
    assert "`written_by`" in window and "NOT on the" in window
    assert "exported before 0.9.34" not in brief


def test_the_no_verified_while_unchecked_rule_has_a_scope():
    """Read strictly it collapses four verdicts to three -- every claim here has some limit no evidence of
    this kind can close, so nothing would ever be VERIFIED. Two auditors split on claim 1 over it."""
    brief = E.AUDIT_MD
    i = brief.index("VERIFIED is the wrong word for it")
    window = brief[i:i + 1400]
    assert "they do not by themselves downgrade a verdict" in window
    assert "a part you COULD have settled" in window


def test_the_verifier_provenance_step_cannot_pollute_the_evidence_folder():
    """`curl -sO` writes to the CURRENT directory, and the auditor starts in the pack. The brief's own
    step (b) therefore dropped two files into the sealed set and broke the integrity check it tells them
    to trust -- warning against the hazard on one line and causing it on another. Found by an auditor on
    25 Sep, who hit it."""
    brief = E.AUDIT_MD
    i = brief.index("curl -sO")
    window = brief[max(0, i - 200):i + 900]
    assert "mktemp -d" in window, "step (b) still downloads into the current directory"
    assert "present-but-unlisted" in window, "the consequence is not explained"
    # and the hazard must be stated as a rule, not only shown in the command
    assert "writes to the CURRENT directory" in window
