"""The plain-language line is a rendering of confidentiality_reach, not a second opinion.

Simplification is where an overclaim comes back: "your search was private" reads as fine and is
false. These pin that the plain line can only ever say what the computed level licenses, and that
the guard against overclaim vocabulary actually refuses rather than decorating.
"""
import io
import re
from contextlib import redirect_stdout

import pytest

from tests.test_verify_record import _load, _policy, _report_claims


def _mod():
    return _load()


ALL_LEVELS = (-1, 0, 1)


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_every_reachable_level_has_a_sentence(level):
    """A level with no sentence must not silently fall back to a stronger one."""
    assert _mod().plain_statement(level) is not None, f"no plain sentence for reach {level}"


def test_unwritten_level_prints_nothing_rather_than_the_nearest_sentence():
    m = _mod()
    assert m.plain_statement(2) is None
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(2)
    text = out.getvalue()
    assert "No plain statement is written" in text
    # the level-1 headline must not leak into a level the ladder never licensed
    assert "sealed computer" not in text.lower()


def test_refusal_level_makes_no_positive_claim():
    headline, caveat = _mod().plain_statement(-1)
    joined = (headline + " " + caveat).lower()
    for phrase in ("sealed computer", "in a position to read", "signed by that machine"):
        assert phrase not in joined, f"refusal text claims something: {phrase!r}"


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_no_level_uses_overclaim_vocabulary(level):
    headline, caveat = _mod().plain_statement(level)
    joined = (headline + " " + caveat).lower()
    for phrase in _mod().PLAIN_FORBIDDEN:
        assert phrase not in joined


def test_the_overclaim_guard_actually_refuses():
    """INVERSION: a guard never seen failing is decoration. Put an overclaim in and it must raise."""
    m = _mod()
    original = m.PLAIN_BY_REACH
    m.PLAIN_BY_REACH = dict(original)
    m.PLAIN_BY_REACH[1] = ("Your search was private and could not have been read.", "No caveat.")
    try:
        with pytest.raises(AssertionError) as exc:
            m.plain_statement(1)
    finally:
        m.PLAIN_BY_REACH = original
    assert "overclaim" in str(exc.value)


def test_higher_level_says_strictly_more_than_lower():
    """Level 1 earns a clause about the controls; level 0 must not carry it.

    This binds to the PROPERTY, not to a phrase. It used to assert the literal words "listed
    protection checks", which made it a lock on wording rather than on meaning: when an audit on
    2026-09-29 showed that phrase reads as a runtime test of the containers rather than a reading of a
    document, the test failed for the fix. A test that fails when a sentence is corrected is guarding
    the wrong thing.
    """
    m = _mod()
    zero = m.plain_statement(0)[0]
    one = m.plain_statement(1)[0]
    assert one != zero
    controls = "the policy document records the protection settings this verifier checked"
    assert controls in one, "level 1 must name what the controls evidence actually is"
    assert controls not in zero, "level 0 has not earned any controls clause"
    # And it must stay a claim about a DOCUMENT, never about what the containers did at runtime.
    assert "passed" not in one.lower(), (
        "level 1 must not say the containers PASSED anything: the evidence is a policy document, and "
        "a reader hears 'passed' as a test that was run against the running program")


@pytest.mark.parametrize("level", (0, 1))
def test_every_positive_level_keeps_the_caveat(level):
    """The unreachable level 2 is what the caveat exists for; it must survive every simplification."""
    caveat = _mod().plain_statement(level)[1]
    assert "does not show" in caveat.lower()
    assert "own computer" in caveat.lower()


@pytest.mark.parametrize("image_source", [None, {"url": "not-a-verified-publication"}])
def test_plain_level_zero_with_stdio_allowed_makes_no_host_secrecy_claim(capsys, image_source):
    """The real record permits host stdio: valid hardware evidence cannot license host exclusion."""
    m = _mod()
    _report_claims(m, _policy(stdio=True), reference={"image_source": image_source})
    out = capsys.readouterr().out
    plain = out.split("In plain words, for a reader")[1]
    assert m.plain_statement(0)[0] in plain
    assert "in a position to read" not in plain
    assert "every time it answers" not in plain
    assert "The program is published" not in plain
    assert "does not show who could read your text" in plain
    assert "AI conversation" in plain
    assert "publication and behavior were not verified" in plain


def test_all_controls_passing_does_not_restore_plain_disclosure_guarantee(capsys):
    m = _mod()
    _report_claims(m)
    out = capsys.readouterr().out
    plain = out.split("In plain words, for a reader")[1]
    assert m.plain_statement(1)[0] in plain
    # Bound to the PROPERTY, not the phrase -- see test_higher_level_says_strictly_more_than_lower.
    assert "the policy document records the protection settings this verifier checked" in plain
    assert "does not show who could read your text" in plain
    assert "could not attach" not in plain


@pytest.mark.parametrize("phrase", ["No one hosting it was in a position to read your text.",
                                     "The program is published.",
                                     "It proves what it is every time it answers."])
def test_lint_rejects_the_specific_0958_overclaims(phrase):
    m = _mod()
    m.PLAIN_BY_REACH = {0: (phrase, "")}
    with pytest.raises(AssertionError, match="overclaim"):
        m.plain_statement(0)


def test_unestablished_coverage_does_not_call_an_intact_record_corrupt(capsys):
    m = _mod()
    _report_claims(m, committed=None)
    out = capsys.readouterr().out
    assert "REFUSED" in out and m.plain_statement(-1)[0] in out
    assert "record did not check out" not in out


# --- the reasons, in plain words ----------------------------------------------------------------------


def test_each_known_blocker_becomes_plain_words():
    m = _mod()
    known = [
        "policy 80c5424d: the policy does not satisfy: policy denies host access to the enclave's stdio",
        "policy 80c5424d: the policy has unresolved external fragments/imports, so the permission rows may "
        "omit effective rules — resolve and verify every dependency",
    ]
    out = m.plain_blockers(known)
    assert any("operator access" in r for r in out)
    assert any("dependencies remain unresolved" in r for r in out)
    assert not any("policy 80c5424d" in r for r in out), "technical prefix leaked into plain words"


def test_an_unrecognised_blocker_is_kept_not_dropped():
    """INVERSION: silence and nothing-to-say must not look alike, and silence is the stronger claim."""
    m = _mod()
    out = m.plain_blockers(["policy abc: some future blocker nobody has worded yet"])
    assert len(out) == 1
    assert "some future blocker nobody has worded yet" in out[0]
    assert "verification gap" in out[0]


def test_no_blockers_prints_no_reasons_section():
    m = _mod()
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(1, [])
    assert "Gaps identified in this record" not in out.getvalue()


def test_reasons_are_printed_under_a_positive_level():
    m = _mod()
    out = io.StringIO()
    with redirect_stdout(out):
        m.report_plain(0, ["policy x: the policy does not satisfy: policy denies host access to the enclave's stdio"])
    text = out.getvalue()
    assert "Gaps identified in this record" in text
    assert "operator access" in text


def test_duplicate_blockers_across_policies_are_said_once():
    m = _mod()
    dupes = ["policy a: the policy does not satisfy: policy denies host access to the enclave's stdio",
             "policy b: the policy does not satisfy: policy denies host access to the enclave's stdio"]
    assert len(m.plain_blockers(dupes)) == 1


@pytest.mark.parametrize("blockers", [[], ["future check not implemented"]])
def test_non_exhaustive_scope_survives_empty_and_unknown_lists(capsys, blockers):
    m = _mod()
    m.report_plain(1, blockers)
    text = capsys.readouterr().out
    assert "not a complete list of risks" in text
    assert "shorter or empty list does not establish privacy" in text
    assert "future deployment" in text and "saved operations" in text


def test_missing_stdio_does_not_turn_into_permission_or_observed_access(capsys):
    import base64
    import json
    m = _mod()
    policy = base64.b64decode(_policy()).decode()
    containers = m._policy_containers(policy)
    for container in containers:
        del container["allow_stdio_access"]
    policy = policy[:policy.index("containers :=")] + "containers := " + json.dumps(containers) + "\n"
    pol = base64.b64encode(policy.encode()).decode()
    _report_claims(m, pol)
    text = capsys.readouterr().out
    plain = text.split("In plain words, for a reader")[1]
    assert "do not establish that operator access" in plain
    assert "does not show that anyone accessed" in plain
    assert "let whoever operates it attach" not in plain
    assert "0 explicitly set it to true" in text
    assert "set allow_stdio_access=true" not in text


def test_fixing_stdio_removes_only_that_gap_and_keeps_privacy_boundary(capsys):
    m = _mod()
    _report_claims(m, _policy(stdio=True))
    before = capsys.readouterr().out.split("In plain words, for a reader")[1]
    _report_claims(m, _policy(stdio=False))
    after = capsys.readouterr().out.split("In plain words, for a reader")[1]
    assert "operator access" in before and "operator access" not in after
    assert "not a complete list of risks" in before and "not a complete list of risks" in after
    assert "whether the program disclosed or retained" in after
    assert "does not establish privacy" in after


def test_unsuccessful_revocation_and_partial_floor_do_not_mean_no_attempt(capsys):
    m = _mod()
    _report_claims(m, floor_pinned=False, revocation_checked=False)
    plain = capsys.readouterr().out.split("In plain words, for a reader")[1]
    assert "shown to be active at the time of every saved search" in plain
    assert "successful certificate-withdrawal check was not established" in plain
    assert "was not asked" not in plain and "machine's certificate" not in plain


@pytest.mark.parametrize("blocker", [
    "new reason: certificate revocation was checked but the log is missing",
    "policy abc: the policy does not satisfy: policy denies host access to the enclave's stdio; additional scope unknown",
    "future reason: first part: second part",
])
def test_familiar_substrings_and_colons_do_not_swallow_unknown_qualifiers(blocker):
    m = _mod()
    reasons = m.plain_blockers([blocker])
    assert len(reasons) == 1 and blocker in reasons[0]
    assert "original words" in reasons[0]


# --- the question-first block, shaped by five rounds of naive-reader testing -------------------------

STDIO_BLOCKER = "policy x: the policy does not satisfy: policy denies host access to the enclave's stdio"


# The platform paragraph is no longer unconditional: since 2026-09-29 it is printed only when the run
# KNOWS what the external dependency is, because every specific in it (a cloud platform, containers
# permitted to attach to stdio, most running elevated) comes from the census of Microsoft's fragment.
# A fixture that wants that prose must now say so; one that stays silent gets the honest
# "rules this check could not read" branch instead. That is the point of the gate, not a nuisance.
_KNOWN_PLATFORM = {"self_contained": False, "dependencies_identified": True}


def _plain(reach, blockers, closed=None):
    out = io.StringIO()
    with redirect_stdout(out):
        _mod().report_plain(reach, blockers, closed)
    return out.getvalue()


def test_the_block_answers_the_readers_question_first():
    """Readers arrive with one question and left to phone their attorney to ask it. Answer it first."""
    text = _plain(0, [STDIO_BLOCKER])
    first = [l.strip() for l in text.splitlines() if l.strip()][1]
    # An auditor read the bare "No —" as answering "was your text private?" (a question this
    # evidence cannot answer either way) rather than "can this record prove it?". The PROPERTY
    # pinned here, not the phrasing: the first line carries the refusal AND the other bound, so
    # it can be read neither as a clean bill of health nor as evidence of a breach.
    # FOURTH re-pinning. Each earlier version pinned a PHRASE ("No —", "cannot rule out",
    # "silent both ways") and went red the moment the phrase changed, having no opinion about the
    # claim. These are the invariants instead:
    #   (i)   the sentence's subject is THE RECORD, so the refusal is scoped to the document rather
    #         than read as a verdict on the reader's situation;
    #   (ii)  it refuses the privacy claim;
    #   (iii) it refuses the OPPOSITE claim too, so neither reader direction is licensed;
    #   (iv)  it does not use evidence-shaped null-finding language (see the test below).
    assert re.search(r"[Tt]his record|\bNo\b", first), f"the refusal must be scoped to the record: {first}"
    assert re.search(r"cannot tell you whether|cannot rule out|cannot prove|stayed private\? No", first), (
        f"the first line must refuse the privacy claim: {first}")
    assert re.search(r"says nothing|silent both ways|either direction|does not show that anyone read", first), (
        f"the first line must also refuse the opposite claim: {first}")
    assert len(first) < 220, f"the answer must be short enough to survive a skim, got {len(first)} chars"




def test_the_block_separates_a_fact_about_the_record_from_a_fact_about_privacy():
    """A reader said of an earlier draft: 'it sounds like a bank vault... but it is about whether the
    report is honest, not whether my invention stayed private.'"""
    text = _plain(0, [STDIO_BLOCKER])
    # The PROPERTY pinned here is the SEPARATION, not the phrasing — this assertion has been rewritten
    # twice already because it was pinned to a sentence rather than to what the sentence must do.
    import re as _re
    assert _re.search(r"(not a fact about whether|does not mean) your text stayed private", text), (
        "the integrity claim must be separated from the privacy claim in so many words")


@pytest.mark.parametrize("word", ["honest", "sealed", "we would rather say so plainly"])
def test_no_word_borrows_warmth_it_has_not_earned(word):
    """Every reader round caught a DIFFERENT warm word: sealed, then honest, then the self-praise,
    then honest again. Removing one grew another, so they are pinned."""
    assert word not in _plain(0, [STDIO_BLOCKER]).lower()


def test_an_unwritten_level_answers_nothing():
    text = _plain(7, [STDIO_BLOCKER])
    assert "No plain statement is written" in text
    assert "cannot rule out" not in text


# --- what survived two adversarial passes -----------------------------------------------------------


def test_the_block_always_leaves_a_next_step():
    """A reader given only gaps has nothing to say to anyone: 'like being told after surgery which
    instruments weren't sterilised'. There is always a next step, even when it is only 'take it to
    someone qualified'."""
    for blockers in ([STDIO_BLOCKER], [], ["policy x: something unrecognised"]):
        assert "What you can do" in _plain(0, blockers)


def test_the_answer_states_BOTH_bounds():
    """'Cannot rule out' alone let a reader supply the lower bound themselves and lean to 'probably no'.
    Telling them to assume disclosure is the same defect with the sign reversed."""
    text = _plain(0, [STDIO_BLOCKER])
    # Both bounds must be present SOMEWHERE in the block, however they are phrased. The upper bound
    # ("cannot prove it stayed private") and the lower ("no sign anyone read it") each guard against
    # the opposite misreading; a round found each of those misreadings in turn.
    import re as _re
    assert _re.search(r"cannot tell you whether|cannot rule out|cannot prove|stayed private\? No", text), (
        "the block must refuse the privacy claim explicitly")
    assert _re.search(r"says nothing|silent both ways|either direction|does not show that anyone (did|read)", text), (
        "the block must also refuse the opposite claim, that disclosure occurred")


def test_it_never_instructs_the_reader_to_assume_disclosure():
    """Steering a client's legal posture on evidence that does not support it is a defect in either
    direction; the downside here is a panic filing or an abandoned application."""
    text = _plain(0, [STDIO_BLOCKER]).lower()
    for phrase in ("treat this text as having been shown", "assume it was read", "assume disclosure"):
        assert phrase not in text


def test_platform_containers_are_described_as_PERMITTED_not_unchecked():
    """We measured them: all permit operator access to their streams, most run elevated, inside the same
    boundary. Reporting that as 'not checked' turns a known adverse fact into an unexamined unknown,
    which is an overclaim by omission."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_stdio_access": True, "allow_elevated": True})
    assert "raised powers" in text
    assert "does not check" not in text


def test_no_reassurance_about_encryption_of_working_storage():
    """SEV-SNP encrypts against the HOST; the platform's containers share the key domain. 'Encrypted'
    reassures about precisely the vector that is open."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_unencrypted_scratch": True}).lower()
    assert "encrypted" not in text


def test_the_gap_list_names_what_it_cannot_contain():
    """An auditor called the 'not a complete list' preamble honest but fragile: a reader who skims it
    and dives into the bullets treats them as a census. Name the categories the instrument cannot see."""
    text = _plain(0, [STDIO_BLOCKER])
    assert _mod().PLAIN_CANNOT_SEE in text
    for category in ("how long your search took", "left in the machine's memory",
                     "layer underneath", "once it had it"):
        assert category in text, category


def test_the_computed_ask_is_actually_RENDERED():
    """It was computed and never printed for two releases: I dropped the branch when reworking the
    action and left PLAIN_ASKS as dead code. Found by the other session reading the served wheel."""
    m = _mod()
    text = _plain(0, [STDIO_BLOCKER])
    assert any(a[:40] in text for _, a in m.PLAIN_ASKS), "the ask is computed but never rendered"


def test_the_uncaptured_categories_survive_an_EMPTY_blocker_list():
    """They lived inside `if reasons:`, so they vanished exactly when the list was empty — the most
    reassuring state, and the one where reading the list as a census is most wrong."""
    assert _mod().PLAIN_CANNOT_SEE in _plain(0, [])


def test_the_record_is_not_described_as_never_expiring():
    """'It does not expire' conflates an unchanged receipt with an unchanging verdict: the check asks
    the chip maker about certificates as they stand on the day it is run."""
    text = _plain(0, [STDIO_BLOCKER])
    assert "does not expire" not in text
    assert "different answer" in text


def test_the_platform_prose_names_the_actor_and_stops_there():
    """allow_stdio_access permits the OPERATOR to attach to container streams. It establishes nothing
    about what passed through them."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_elevated": True, **_KNOWN_PLATFORM})
    assert "whoever operates the machine to attach" in text
    assert "what passed through those streams" in text


def test_the_one_reassuring_line_carries_its_own_limit():
    """A non-technical tester called this "the one positive-sounding sentence", landing exactly where a
    skimmer's eye lands after the technical paragraph: they read "valid", "signatures", "hardware
    evidence", "protected" and took it as "certified protected, therefore my text was protected". The
    qualifier existed, but in the NEXT sentence — "the reader has already been reassured by the time
    they reach it". So the limit must live in the SAME sentence, before the first full stop."""
    m = _mod()
    for reach, (headline, _caveat) in m.PLAIN_BY_REACH.items():
        if reach < 0:
            continue
        first = headline.split(". ")[0]
        assert "not that your text was protected" in first, (
            f"reach {reach}: the reassuring clause must carry its limit before the first full stop, "
            f"or a skimmer stops at the reassurance: {first!r}")


def test_the_closed_controls_read_as_separate_clauses():
    """The same tester's eyes "slid off" the closed-controls sentence when each item was a long noun
    phrase with nested relative clauses. Each item must be a short clause with its own subject."""
    m = _mod()
    for key, phrase in m.PLAIN_CLOSED_WORDS:
        assert len(phrase.split()) <= 15, f"{key}: too long to read in passing ({len(phrase.split())} words)"
        assert " as off" not in phrase, f"{key}: 'X as off' is the config's grammar, not a reader's"


def test_a_permission_is_not_an_event():
    """An auditor found the platform-container disclosure "arrives after the scary description. A reader
    who reads to the end gets the correction; a reader who stops midway does not." The clause that says
    a PERMISSION is not an EVENT must sit inside the same sentence run as the permissions themselves,
    not trail the paragraph."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_elevated": True, **_KNOWN_PLATFORM})
    para = next(l for l in text.splitlines() if "run further" in l)
    scary = para.index("permits most of them to run with raised powers")
    cure = para.index("not a record of what happened")
    assert cure - scary < 120, (
        f"the neutraliser sits {cure - scary} chars after the alarming clause; it must be adjacent")


def test_the_record_is_not_called_a_receipt():
    """"Receipt" primes a reassuring frame: in everyday English it is proof of a COMPLETED, satisfactory
    transaction. An auditor asked for "record" or "document" because the evidence has not earned the
    connotation of completion."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_elevated": True, **_KNOWN_PLATFORM}).lower()
    assert "receipt" not in text, "'receipt' connotes a settled, satisfactory transaction"


def test_the_platform_streams_are_not_the_readers_own_text():
    """An anxious reader called this the sentence they "read three times", and mapped it onto
    themselves: "Whoever operates the machine can attach to input and output. My invention description
    was the input." The pronoun's referent is the PLATFORM's containers, not the reader's search, and
    ambiguity here converts a permission on other containers into an implied live tap on their text."""
    text = _plain(0, [STDIO_BLOCKER], {"allow_elevated": True, **_KNOWN_PLATFORM})
    para = next(l for l in text.splitlines() if "run further" in l)
    assert "attach to their input and output" not in para, (
        "'their' is read as the READER's input; name the containers the permission is about")
    assert "those containers' own input and output" in para


def test_the_answer_does_not_report_a_null_FINDING_about_reads():
    """The deepest defect found in this block, and it survived four audit rounds. "It does not show
    that anyone read it" reads as a FINDING: it implies a sign WOULD exist if someone had read the
    text, so the absence becomes evidence. It is not. Verified against this verifier: every row
    concerns what was PERMITTED (allow_stdio_access, "in a position to read"), none observes an
    access event, and runtime logging is denied by policy — the record has no read-visibility at all.
    So the block must state the MECHANISM (what it records) rather than report a null result."""
    m = _mod()
    for reach, answer in m.PLAIN_ANSWER.items():
        if reach < 0:
            continue
        for banned in ("no sign that anyone", "shows no sign", "does not show that anyone read"):
            assert banned not in answer, (
                f"reach {reach}: {banned!r} dresses absence of evidence as a finding; say what the "
                f"record DOES record instead")
        assert "records what was permitted" in answer, (
            f"reach {reach}: the answer needs the positive anchor — what the record actually is — or "
            f"the reader fills the vacuum with their prior")
