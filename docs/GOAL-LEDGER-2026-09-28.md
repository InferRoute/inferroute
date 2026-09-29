# Goal loop — a client statement that is true, useful, and audit-blessed

**Mission.** Reach a client-facing confidentiality statement that is simultaneously true, useful to a
non-technical reader, and blessed by an independent audit. Each alone is easy; the combination is the
work.

**Stop condition** (all four, measured): (1) a record verifies exit 0 under production roots with
`confidentiality_reach >= 1`; (2) its plain statement leaves a naive reader NOT less confident and
able to repeat something accurate; (3) an independent mac-papa round finds no defect in it *and names
what it attacked*; (4) no printed blocker is one we could have closed and did not.

**Budget.** $15. Spent so far: $0.00 (iteration 1 used no paid services).

---

## Iteration 1 — the firmware floor was enforced in the tree and not in the product

**Symptom.** The Codex session landed `reference_firmware_floors` (1043834) and stopped before
answering its own last question: does it reach the shipped client?

**Root cause.** It did not. Published 0.9.59 carries verifier `c55396bd…`; the tree carried
`26e6aafd…`. The enforcement existed only in the tree, so no client downloading from inferroute.ai
had it. The three source copies (pi_attested, sealedresearch, client-dist/build) were all in sync at
`26e6aafd…` — which is exactly why a source-level check would have said "shipped" and been wrong.
**Sync between source copies is not shipment.**

**Verification before shipping** — by execution, not by reading the commit:

    valid Genoa floor      -> {'Genoa': {'snpSPL': 23, 'ucodeSPL': 84}}
    absent min_tcb         -> None            (no floor, correctly not an error)
    all-zero floor         -> REFUSED
    empty mapping          -> REFUSED
    levels not a dict      -> REFUSED
    unknown SPL name       -> REFUSED
    level out of range     -> REFUSED
    unnamed product        -> REFUSED

The all-zero refusal is the mirror of the guard in `reference build --min-tcb`: the builder will not
write such a floor and the verifier will not accept one. Two independent sessions arrived at the same
guard from opposite ends.

**Fix.** 0.9.60 built and published. Wheel checked behaviourally rather than by label: its
`verify_record.py` hashes to the tree's `26e6aafd06c69817`, the all-zero refusal fires *inside the
wheel*, the R5 decoy still reads the enforced array, and the plain-language layer is present.

**Evidence.** 236 tests. Commits `036a4da` (attested-pi), `0b1d255` (site).

**Carried forward.** "Is it shipped?" must be asked against the published artifact, never the tree or
a sibling copy. Added to the loop's standing checks.

---

## Iteration 2 — "unresolved" was telling the reader nobody looked

**Symptom.** Every record printed "unresolved external fragments/imports — resolve and verify every
dependency". An ACI policy must reference Microsoft's infrastructure fragment (excluding it was tested:
the group cannot start), so that line appears forever and reads as ignorance.

**Root cause.** Wrong in both directions. It understated what we know — the fragment had been fetched
from MCR and read — and it let the permission rows read as though they covered the whole policy, when
they are computed over the literal container array, which holds only our three.

**Fix.** A DISCLOSED row naming the feed, its signing identity, its version floor and the measured
census; and client-facing words for it. Disclosure ADDS a blocker rather than removing one, with a test
pinning that the list cannot shorten.

**Bug found in my own fix.** The first wiring passed the BASE64 policy where the text was wanted. It
found no fragments, returned None, and read exactly like a policy with no platform dependency at all —
silence that looked like a clean result. Regression test added.

**Evidence.** 9 tests; 245 across suites. Commit `5746506`.

---

## Iteration 3 — I built an overclaim, attacked it, and reverted it

**Hypothesis.** `self_contained` can never be true on ACI, so level 1 was permanently unreachable.
Reading the code seemed to justify replacing it with `dependencies_identified`: the rows only ever
covered our containers, so the gate was flagging silence rather than keeping the platform out.

**Built it.** Verified it moved only where intended — future record reaches 1, the 70 historical
records stay 0, an unidentified dependency still blocks. While scoping it I caught a companion defect:
the plain level-1 sentence said "the recorded settings passed the listed protection checks" with no
scope, which would have created at the client layer the overclaim I was fixing at the technical layer.

**Attacked it, and it failed.** An adversarial review: *the old gate encoded a security property — no
foreign code inside the trust boundary — and the new one encodes a bookkeeping property, that we wrote
the foreign code down. The rung moved; the trust boundary did not.* Three specifics:
- SEV-SNP's boundary is the VM, not the container. The platform's 9 elevated containers share the UVM
  with the workload. I had twice filed this as "open". It is decisive.
- The pin is a FLOOR, so the fragment in force may be a version no measurement covers.
- The gate could not fail: on ACI the one dependency is always pinnable, so it was satisfied by
  construction. A pin that cannot fail the gate grades nothing.

**Reverted.** `self_contained` restored, reasoning left at the call site. Kept the disclosure, the
scoped sentences, and a corrected plain wording — the review also caught that "permitted to use their
own input and output streams" understated privilege and hid the proportion.

**Evidence.** 12 disclosure tests including one pinning that identification must NOT raise the level.
Commit `6708839`. Nothing published; the bad version never left the tree.

**Stop condition corrected.** Condition 1 was "reach >= 1", a proxy for "useful". On ACI that is
unreachable without an overclaim, so meeting it would mean bending the system to satisfy my own success
criterion. Dropped. The reader tests agree: the naive reader never complained about the level, they
complained the text was unreadable and nobody answered their question. "Useful" must be earned at
level 0 through clarity, or by leaving ACI — a platform decision, not a wording one.

---

## Iterations 4–5 — the statement now answers the question the reader actually has

**Symptom.** Every tested version left a non-technical reader unable to repeat anything, with no action,
and phoning the professional who ran the tool to ask the one question the document never addressed:
could anyone have read my text.

**Method.** Five candidate wordings, each on a fresh naive reader, measured rather than reviewed:

| | belief | would repeat | read in full | action |
|---|---|---|---|---|
| baseline 09-27 | accurate | **nothing** | no, stopped at "certificate-withdrawal" | none |
| D | accurate | nothing | no | yes |
| E | accurate | **quotes it verbatim** | yes | yes |
| F | accurate, said so | yes | **yes, skimmed nothing** | yes |
| G | accurate | yes | yes | yes, sharper |
| H | accurate | yes | yes | four concrete actions |

**Root cause of the original failure.** The block was organised around what the verifier checked — the
auditor's frame. The reader's frame is a question. It now answers it in the first line.

**Every round caught a different word borrowing warmth it had not earned**: "sealed", then "honest",
then "we would rather say so plainly", then "honest" again. Removing one grew another elsewhere. Those
words are now pinned by test, because the pull reasserts itself wherever it is not actively watched.

**Kept generated, not written in.** The ask ("switch off the setting that lets whoever runs the machine
watch what goes in and out") appears while that gap is open and disappears when it closes. It also says
what it does NOT buy — without that a reader believes one setting bought privacy, when it removes one
reason for doubt out of several.

**Two defects of my own, both familiar shapes.** The ask silently never printed because I matched the
trigger against the RENDERED text rather than the raw blocker. And level -1 said "this record did not
check out", which calls an intact record corrupt when the real state is evidence that could not be
established — caught by a Codex test I had not read. I restored the level headline rather than edit
their failing tests to fit my change.

**Stop conditions 2 corrected, twice.** "Reader is NOT less confident" would force an overclaim: these
readers were wrongly confident beforehand, and becoming less confident is accurate updating. "Would not
need to phone" is also wrong: a client with an unfiled invention SHOULD phone, and the win is the call
getting sharper. The surviving criteria are: reads it fully, believes something true, can repeat it
accurately, has something to do.

**Evidence.** 13 new tests, 255 in the affected suites, 964 across the repo. Commit `a940a98`.
`tests/test_probant_first_key.py::test_the_cli_exposes_show` fails in full-suite runs and passes in
isolation — a working-directory pollution from another test, confirmed pre-existing by re-running with
all three of my test files excluded.

---

## Iteration 6 — shipped the statement; the gate caught a failed round; a self-inflicted blocker closed

**0.9.61 published.** Question-first plain block, verified behaviourally from inside the wheel rather
than by label: answers the reader's question in its first line; the ask appears with the stdio gap and
vanishes without it; states what the fix does not buy; none of the warmth words caught across five
reader rounds survive; level -1 no longer calls an intact record corrupt; R5 decoy still reads the
enforced array; all-zero firmware floor refused. Served bytes confirmed
`d0071989d232032373b6e5f247601c51d53e6431b58a8556b574924fe06f5d7f`.

**The transcript gate earned itself.** Rounds 0961-r1 and -r2 both died on
`502 All providers exhausted` after 37 events, 0 tool turns, $0.00 — and the harness exited 0 both
times with a 1-line report file. Before the gate, each would have been banked as a clean round with no
findings, which reads as *the auditor found nothing wrong*. Both were refused with rc=5.

**The ir lane is down, measured rather than assumed.** 502 from two machines and two clients, using the
short ids the API itself advertises; `/v1/models` healthy, so the control plane is up; `/v1/usage`
shows a $43.81 balance, so it is not a credit state. Henry reported it back up; from this key it was
still 502 on re-probe. Not resolved — the loop probes cheaply and launches the staged round on the
first success.

**Stop condition 4 was violated by our own instructions.** Every record printed "certificate revocation
was not checked successfully". Not because the check is unavailable — it works, and round 3 used it —
but because `--check-revocation` appeared NOWHERE in AUDIT.md or VERIFY.md. The product printed a
blocker its own brief caused. Fixed: the brief now asks for a second run and explains why there are
two, and states that a failed fetch reports not-checked and never revoked. Measured on the real pack:
the row becomes PASS and printed gaps drop from 7 to 6. Shipped as 0.9.62.

**Condition 4 status after this.** The only remaining gaps that could be closed and have not been are
the firmware floor and the image source, both needing the offline publication key. Everything closable
from this seat is closed.

---

## Iteration 7 — the reference is signed and live; the fresh record is close but not landed

**Signed and installed.** Henry signed with the offline key. The live reference at
`/home/henry/inferroute-publication/reference/current.json` now carries a WINDOWED changeover —
historical `80c5424d…` valid until 2026-09-28T00:00:28Z, new `011b8b1a…` valid from then — plus the
firmware floor `Genoa snpSPL:23, ucodeSPL:84, blSPL:10`.

**The tool refused the first attempt and was right to.** Two entries current at once means two
different enclaves both pass identity forever, including the old stdio-open policy. `--allow-overlap`
would have silenced that rather than fixed it. Following the refusal produced a strictly better
reference. Verified against real search times: the historical hash is current at a 09-24 search and
REFUSED after the cutover; the new hash is refused before it and current after; an unparsable
statement time fails closed.

**Measured effect on the delivered pack:** firmware floor SKIP -> PASS, revocation PASS, identity
still PASS on all 70 but now "at the search's time", client-facing gaps **7 -> 5**.

**Cost paid for it:** the `current.json.ots` anchor commits to the OLD bytes, so it was archived. The
live reference currently has NO timestamp anchor until Henry runs `ots stamp`. Stamping publishes a
hash, so it is his call and not something to do on his behalf.

**Fresh record: the policy runs, the service did not become ready.** Generated the stdio-closed policy
against the EXISTING image pinned by digest — no rebuild, no push, so the program stays the one whose
source the supplement matched. All 3 containers stdio false, deploy gate ACCEPTS, HOST_DATA
`011b8b1a…`. It deployed and reached Running in 187s with 0 restarts. `/offer` never answered within
1000s and it tore down cleanly.

- westeurope refuses deployments outright ("region not accepting new customers"); eastus2 works.
- My first explanation — a cross-region 34 GB pull — was WRONG: storage and registry are both eastus2.
- An adversarial review named a better hypothesis I had missed (a key-release policy pinned to the old
  HOST_DATA, which would fit every fact) — checked for $0, does not apply here.
- It also corrected my pipe-blocking theory (~70% that unconnected stdio resolves to /dev/null) and
  caught a blind spot: `containers[].instanceView` survives `--disable-stdio`, so per-container state
  was readable all along. Group "Running, restartCount 0" does not exclude a Terminated container.
- Reading the startup code made the likely answer mundane: it downloads 34 GB, then HASHES the whole
  index for the manifest commitment, then pretouches. Known-good was 428s; the 1000s ceiling is only
  2.3x that. Rerunning at 2400s with instanceView polling.

**Note for the next release, not actionable now:** the right diagnostic is a `/status` endpoint
reporting phase and bytes. It cannot be added tonight — changing the image changes its layer hashes,
hence the policy, hence the HOST_DATA just signed into the reference.

**Audit machine moved to `ade`** (mac-papa sleeps). node + pi installed, provider config proven
(`PI_OK` from Kimi-K2.6-TEE), pack and 2071-word prompt staged. `ir` cannot be installed there
(published wheel needs Python >=3.10, macOS ships 3.9.6) so the runner drives `pi` directly. **I
overstated that as an auditor-facing defect and retract it:** VERIFY.md says 3.9+ and never asks an
auditor to install the CLI.

**Near-miss worth keeping:** a prompt rebuilt from a sleeping machine came out at 155 words — only the
appendix — because the fetch returned empty and `sed` on empty input exits 0. A round on that brief
would have returned "found nothing", which reads as a clean audit. The new runner refuses any brief
under 500 words.

---

## Iteration 8 — the audit landed, and the enclave failure was never about privacy

**The audit round ran and found real defects. Stop condition 3 is NOT met, which is the right
outcome.** 0.9.62, on mac-papa: 91,577 events, 76 tool turns, $5.73. It named what it attacked — it
built a synthetic pack with all five listed gaps closed and confirmed the blocker-to-text mapping is
mechanically sound.

- **Finding 1, residual overclaim:** naming stdio as THE actionable setting gives the reader "a plan
  of action that addresses a relatively small part of the risk surface" while the dozen
  Microsoft-controlled containers sit in a technical bullet. Already fixed before the verdict arrived
  (7381a9d, 8e59f72); the audited pack predates it.
- **Finding 2, fixed in 2fae525:** the five-item list reads as a census. The preamble is "honest but
  fragile". Fixed by naming the CATEGORIES the instrument cannot see — timing and size observable from
  outside, memory remanence, the layer beneath the protected machine, and what the program did with
  the text.
- **Finding 3, recorded not fixed:** "min_tcb exactly matches every record's reported TCB, and the
  reference was published after the records. It is a descriptive capture, not an independently
  meaningful security threshold." A fair hit on a choice I defended. It does block downgrade; it is
  not an external standard. Closing it needs a floor justified by AMD guidance.
- **No defect in the verifier's check logic**, and explicitly no lexical overclaim in PLAIN_ANSWER or
  PLAIN_NARROWER.
- It could not verify the historical-image supplement: I never staged it into r0962.

**The enclave failure had nothing to do with --disable-stdio.** Three runs died identically. The
control — same image by digest, same region, historical stdio-ENABLED policy — failed the same way,
which killed the hypothesis in one run. Root cause: `INDEX_ROOT` defaults to
`/mnt/movies/sealed-patent-root-us`, so `BLOB_NAME` became `sealed-patent-root-us.tar`, while the
staged blob is `sealed-patent-root-usall-epwo.tar` — matching the records' pipeline version
`azure-m2-patent-usall-epwo-1`. Every attempt fetched a nonexistent blob:
`HTTP Error 404: The specified blob does not exist`. Setting IR_M2_INDEX_ROOT cleared the 404.

**Two process failures of mine, both worth keeping:**
1. I ran the treatment three times before the control once. The control refuted the hypothesis
   immediately. Run the control first when a variable is suspected.
2. My diagnostic produced nothing for two runs because I started it on the line AFTER `deploy_m2` —
   and `poll_offer_m2` raises from inside it, so it never returned. A diagnostic that cannot execute
   during the failure it targets is decoration. Moved before the deploy, it immediately showed
   `search Terminated Error` while the GROUP still read Running, and then the 404 itself.

**Two runner defects found by using it:** the report path passed to the runner did not match the path
named inside the prompt, so a round that produced a 20KB report was recorded as producing none; and
the failure message said "the model stopped on an error" for every non-OK status, contradicting a
transcript line that read OK. Both fixed: the path is now derived FROM the prompt, and each status
prints its own message.

**0.9.63 published** with findings 1 and 2 addressed, verified behaviourally from inside the wheel.

**Spend:** $7.43 of $15 on audits; roughly $2 of Azure across five enclave attempts.

---

## Iteration 9 — the other session read the SERVED wheel and found two pieces of dead code

Codex returned and reviewed 0.9.63. I confirmed every finding by downloading and EXECUTING the
published wheel rather than reading the tree. All four held.

1. **The blocker-specific ask was computed and never printed.** `PLAIN_ASKS` had three entries, none
   rendered; `"keep this record"` printed unconditionally. I dropped the `if ask:` branch when
   reworking the action after a reader test. Two releases shipped a forward-looking step no reader
   saw. **I would not have found this by re-reading my own diff** — it needed someone executing the
   artifact.
2. **The uncaptured-channel categories vanished with an EMPTY blocker list**, because they sat inside
   `if reasons:`. The sentence that stops a reader treating the list as a census disappeared exactly
   when the list looked cleanest. The better of the two catches.
3. **"It does not expire"** conflated an unchanged receipt with an unchanging verdict: the verifier
   checks certificate validity against today and fetches a current CRL, so a later re-check can
   answer differently.
4. **The platform prose did not name the actor.** `allow_stdio_access` permits WHOEVER OPERATES THE
   MACHINE to attach to those streams, and establishes nothing about what passed through them.

All four fixed in e624313, verified behaviourally, 251 tests.

**CONFIRMED AND NOT FIXED — the firmware floor is not windowed.** Measured on the live reference and
the served verifier: `min_tcb` is a flat product-to-levels map while `policy_sha256` entries carry
`valid_from`/`valid_to`, and `reference_firmware_floors` takes no time argument. A floor signed at
2026-09-28T00:00:28Z is therefore applied to searches from 22-25 Sep and prints a bare PASS. The
comparison is arithmetically true and the row implies the floor was IN FORCE. Same shape as the OTS
post-dating finding. Left for the session that owns the claim ladder, with the recommendation that a
floor post-dating a search should read SKIP with the reason rather than PASS.

**Codex fixed the INDEX_ROOT default** in sealed-research: implicit US-only default removed, fail-fast
config check, and an Azure blob-existence check before build or deploy.

**Enclave, still unresolved.** Past the 404, but the search container still terminates with Error —
and with the stdio-closed policy the container logs are empty BY DESIGN, so the failure is invisible.
Checked the cheap hypothesis first rather than spending a run: the tar's top-level directory is
`sealed-patent-root-usall-epwo/`, matching INDEX_SUBDIR, so that is not the cause. A control with
stdio enabled is running to make the logs readable.

**Audit machines remain the bottleneck.** ade dropped at launch (89 bytes of output: just the ssh
error), mac-papa has timed out repeatedly mid-transfer. mgld could run a round — it has node, pi and
ir 0.9.63 — but the auditor would then have our repositories in reach, which weakens exactly the
independence the round exists to provide. Using it only as a last resort, and it would be stated.

---

## Iteration 10 — the audit round landed, and the enclave's real blocker surfaced

### The 0.9.63 audit round (round `0963-local`, 55,560 events, 42 tool turns, $2.80, rc=0)

Run on mgld, with the independence caveat stated: this round was driven from the
same machine as the work, so it is an independent *model* and an independent
*reading*, not an independent *operator*.

Its verdict on the mapping was the part worth having: "mechanically sound… I
could not construct a configuration where the sentence shown was the wrong one."
That is a named attack that failed, which is what stop condition 3 asks for.

Three findings, all in the direction that matters — literally true wording that
leaves a non-technical reader more confident than the evidence warrants:

1. The bare **"No —"** answered *"was your text private?"*, which this evidence
   cannot settle either way, rather than *"can this record prove it?"*. Fixed by
   naming the question inside the line. A reader test had already shown the pull
   ("my gut says probably no… the lean toward no is my worry, not the paper").
2. **"None of that shows anyone used those powers"** defanged the disclosure it
   followed: "a skimming reader may retain 'they have powers, but didn't use
   them' → 'I'm safe'." Replaced with what is known: *does not show whether*.
3. Naming four uncapturable categories risked an **implied census** — "the cure
   is milder than the disease it replaced, but not perfect". The set now declares
   itself open before the examples.

Commit `d6e8831`.

**The three tests that broke were pinned to literal wording**, which is why they
go red on every wording round without ever having an opinion about the claim.
Rewritten as properties, and `PLAIN_CANNOT_SEE` hoisted to a constant so a test
binds to the sentence's identity rather than its text — still catching deletion
on an empty blocker list, no longer catching rephrasing.

### The naive-reader round on the result

Persona: non-technical inventor about to file. They ended **less confident** —
which is correct, not a defect, and is why that stop condition was dropped
earlier as mis-specified: a reader who arrives believing the sales page *should*
leave knowing "the promise was bigger than the proof". Their sentence for their
attorney was accurate and specific, which is the half of the condition that
measures something.

Their out-of-character accuracy check found two things three audit rounds had
not, both about *placement* rather than content (commit `67ff282`):

- **The one reassuring sentence outran its limit.** "…valid signatures linked to
  hardware evidence for a protected computer" sits exactly where a skimmer's eye
  lands after the technical paragraph; the qualifier was in the *next* sentence,
  and "the reader has already been reassured by the time they reach it". The
  limit now lives before the first full stop.
- **The closed-controls sentence was unreadable** — one run-on with three nested
  relative clauses. "My eyes slid off it… I jumped ahead looking for a plain
  verdict", skipping the paragraph that does the real work. Each control is now
  a short clause. Pinned: ≤15 words, and no "X as off", which is the config's
  grammar rather than a reader's.

**0.9.64 published**, `832dc009…`, verified behaviourally from inside the wheel.

### The enclave: three invisible failures, one 8-day-old cause

Three m2 deployments reached Running and exited **1** after ~7 minutes with **no
container logs at all**.

The missing logs are not a fault — they are the setting working. `az container
logs` reads stdio through the host, and the policy we now deploy denies exactly
that. **The confidentiality control we ship is also our diagnosis channel.**
Three runs were spent blind on a message we could not read. Runbook consequence:
diagnose on a stdio-OPEN policy, close it only for the known-good run.

Root cause: the index blob was staged **2026-09-17**; the `missing_artifacts`
gate landed **2026-09-25** (146e896). The staged index predates the requirement
by 8 days and can never satisfy the current image. Nothing regressed — the blob
was simply never re-staged.

**A search for the four missing artifacts across mgld, ft, nm and the NAS
returned zero hits, and I reported that they did not exist. That was wrong.**
The builders write differently-named top-level directories; the required names
are what they get linked *as*. Which graphs belong to the combined root was then
settled by measurement rather than by the `epwo-` prefix: `Npos = 29,595,902`,
exactly the combined ann's row count (the `us-` pair matches the US-only
17,556,761). All four are now wired in and the checker passes. The root *name*
was deliberately left alone — `INDEX_SUBDIR` is measured into the policy, so
renaming it would invalidate the reference Henry signed as `011b8b1a…`.

**What now blocks a fresh record is size, and it is Henry's call.** The completed
combined tree measures **57.23 GB** against the container's **50 GB**. The whole
overage is one artifact: the claim store is **15.49 GB** where the code's own
DISK MATH comment budgeted "2-3 GB" — a comment that implied 23 GB of headroom
while the truth was a 7 GB overrun. Corrected in place with `du -sbL` figures
(sealed-research `6833e3d`). US-only measures **41.33 GB** and fits, but is a
different `INDEX_SUBDIR`, hence a different HOST_DATA, hence a re-sign on the
offline key. Reported to Henry by voice with a recommendation: deliver
Bétrancourt with the existing record — whose wording already names this exact
gap and tells the client what to ask for — and build the US-only record when he
can sign.

**Spend:** $10.23 of $15 on audits; ~$3 of Azure across seven enclave attempts.

---

## Iteration 11 — the pendulum, and a number I asserted without checking

### Round 0964-local: the findings inverted direction

37,907 events, 48 tool turns, **$3.09**, rc=0, on the published 0.9.64 pack.

Six named attacks on the verifier, **all failing closed**: tampered `reply_to`
(only that search's recipient row FAILs, statement signature stays VALID, exit
1); unparseable `started_utc`; statement time outside the window; a misleading
policy *comment* claiming stdio disabled; a Rego `default` rule instead of an
explicit container field; mixed container values. Its words: "I found **no
correctness defect** in the verifier's cryptographic checks, windowing logic,
revocation handling, or tamper detection."

It also downloaded the wheel and `.sha256` from inferroute.ai independently,
confirmed `sha256sum -c` passes and that the wheel's verifier matches the pack's
byte-for-byte. **The provenance gap earlier rounds raised is closed** (PyPI
remains absent, recorded as informational).

**The plain-statement findings reversed direction.** Every earlier round pushed
against over-confidence; this one found **pessimism bias** — an anxious reader
latching onto "cannot rule out" and landing on "disclosure is probable", which
the evidence supports no better than its opposite. "'Cannot rule out' is
logically weaker than 'possibly happened', but in common speech they converge."

The auditor proposed leading with the reassuring clause. **Not taken** — that is
the exact placement a reader round already caught failing the other way, so it
would have relocated the defect rather than removed it. Instead neither clause
leads and the symmetry is stated outright: "No — and it does not show that
anyone read it either. On that question this record is silent both ways."

A free reader round then adjudicated the call: "an improvement without
overshooting", with residual over-reassurance confined to a reader who stops
after the first line, which the later paragraphs close. That reader still leaned
pessimistic, for a reason no wording repairs — "when I don't know and the
downside is my whole company, I round to the bad answer" — and noticed their own
lean while leaning anyway. That is a prior, not a misreading; the text should
not be bent to flatter it.

Also fixed (`320f43d`, `0.9.65`):
- the permission-is-not-an-event clause now sits **82 chars** from the alarming
  clause instead of trailing the paragraph ("a reader who stops midway" missed it);
- "receipt" removed — it connotes a *completed, satisfactory* transaction; the
  new test caught a second occurrence written earlier the same day and missed;
- "attach to **their** input and output" → "those containers' own", after a
  reader mapped the pronoun onto themselves: "my invention description was the
  input", concluding an operator had a live tap.

**Two self-inflicted items, recorded rather than smoothed over:**
- Swapping out "receipt" produced a **tautology** ("the record has not been
  altered since. That means this document has not been altered"). Caught by the
  existing separation test.
- A reader reaction — reading a gap line as "the door was unlocked" — was **not**
  acted on: it came from the raw-fallback rendering that my own test input
  triggered. The real blocker renders in plain words. Verified before concluding.

**0.9.65 published**, `2e8d9f65…`, verified by hash AND by executing the served
wheel.

### The 50 GB cap: asserted, then actually checked

Henry asked where it came from. It came from **one comment written 2026-09-14
with no measurement cited** — and I had, an hour earlier, corrected the
*adjacent line of that same comment* for being wrong by 5×, then put a decision
to him resting on the unverified neighbour. That is the failure: a number is not
more reliable for sitting next to one you just disproved.

Now verified against Microsoft's resource-and-quota-limits page, table
"Confidential Container Resources": Max CPU 31, Max Memory 180 GB, **Storage 50
GB**, "These maximums are hard limits and can't be increased." Storage is absent
from the changeable-limits table, so no quota request raises it; standard
non-confidential groups are also 50 GB, so it is not a confidential-computing
penalty. We request 3 CPU / 28 GB against 31 / 180 — **storage is the only
binding constraint**. Citation now in the code (sealed-research `aad522c`).

One unexplored lever named for Codex: ACI permits 20 volumes per group, so an
Azure Files mount could carry the index outside the 50 GB — but it is
host-managed storage outside the encrypted boundary, and the volume enters the
CCE policy, so it needs the same re-sign as the US-only route.

### Budget

**$13.32 of $15** on audits. That was the last fundable round, so 0.9.65's three
plain-statement fixes ship **audit-suggested but audit-unconfirmed**. Flagged to
Codex as the highest-value spend if they hold round budget.

**Stop condition 3 remains the only one open**: attacks are named in every
round, but no round has yet reported *no defect* in the plain statement.

---

## Iteration 12 — the other session moved, and the deepest defect surfaced

### Codex's memfd route: validated on real hardware

They proposed keeping combined coverage by holding `claims.bin` in a sealed
guest **memfd** with a 52 GB container request, and asked for `/proc/self/fd`
and memory behaviour to be verified before any re-sign. Done, in a live
confidential group in eastus2:

- **52 GB deploys** — `MemTotal 52,466,976 kB`, no swap, no regional refusal
  (that was the risk I had flagged; it did not materialise).
- **memfd needs no mount**, which is why their idea beats the tmpfs one I had:
  the CCE mount rules never come into it. `PROC-PATH-OPEN-OK`, and
  `RANDOM-READ-VIA-PATH-OK` — offset addressing, exactly what `claims.bin` does.
- **20 GiB written and read back** at ~5 GB/s. Two independent accountings agree:
  MemAvailable fell 20.04 GiB, `Shmem` rose to 20.00 GiB.

Consequence: claims (15.49 GB) to memfd leaves **41.74 GB on disk** against the
50 GB cap. Combined coverage without the encrypted-fs sidecar, without managed
HSM, and without adding MAA as a trust party.

**My first probe was green and wrong.** It reported `GROW-FINAL 15 GiB in 0s`
with MemAvailable barely moving. 15 GiB cannot be written in zero seconds — it
touched one page per GiB, so `ftruncate` left the memfd sparse and it measured
apparent size, not allocation. The tell was the impossible number, not a failure.
Rewritten to write every page. Flagged in crosstalk so the sparse version is not
reused and passed for the wrong reason.

### Their windowed min_tcb breaks the reference Henry already signed

Verified by execution, not by reading their description. Their 6 floor tests
pass. Then their own `reference_firmware_floor_at()` against the LIVE signed
reference: `min_tcb` is a **flat dict**, so it returns `None` with "reference
firmware floor has no validity window" — **the firmware row goes PASS → SKIP**.
Henry re-signed at 00:00:28Z specifically to make that row PASS.

Not an argument against their change — SKIP is the right verdict for an
unwindowed floor, and I recommended exactly that. It is a **sequencing** point,
and since every index route also needs a re-sign, the two must be ONE signing:
windowed `min_tcb` + whatever the memfd route changes. Schema requested from them.

Also found: their change lives in `sealed-research/sealedresearch/verify_record.py`
and is **absent from the shipped client** — zero occurrences of "floor valid_from"
in the served 0.9.65 bytes. The two verifier copies have now drifted twice.

### The deepest wording defect, and it was ours

Their proposed opening tested **worse on both axes** and was not shipped: the
anxious reader lands on "someone probably did"; the complacent reader collapses
it to "Says nobody read my text" and never parses the second sentence.

But rejecting it exposed a defect in wording **we have shipped since 0.9.61**:
"it does not show that anyone read it" reads as a **finding** — it implies a sign
WOULD exist if someone had. Absence of evidence dressed as a result, through four
audit rounds, each of which asked "is this sentence true?" — and it is. The
defect is in what the form implies.

Verified before acting: every verifier row concerns what was PERMITTED, none
observes an access event, `allow_runtime_logging` is denied. No read-visibility
at all. Two intermediate candidates were tested and rejected on measurement — a
standalone "No." "lands as a verdict"; "who read what" presupposes readers exist;
"in either direction" is the same cancel-out lever as the old "either".

Shipped in **0.9.66** (`e674eae8…`): *"This record cannot tell you whether your
text stayed private: it records what was permitted, not whether anyone read your
text, so on that question it says nothing."* Ranked first for both personas —
"the first version whose failure mode is not a lie". The positive anchor is the
part every earlier version lacked; saying only what an instrument cannot do
leaves a vacuum the reader fills with their prior.

Tests re-pinned for the FOURTH time, now to invariants rather than phrases, plus
a new test that forbids null-finding language outright and requires the anchor.

**Honesty:** these reader rounds are simulated and say so. Audit budget is spent
($13.32/$15), so this ships **audit-unconfirmed**. Residual risk named for the
next round: "what was permitted → only permitted people → fine" — an inference
from a true statement rather than a false one, better but still not licensed.

---

## Iteration 13 — stop condition 3 MET, and a brief that graded a ghost

### The round: `0966-local-r3`, rc=0, 74 tool turns, $3.27

> "I found no sentence that is literally false or that I could make false by
> constructing an evidence configuration... I rate it as the most defensible
> version I have seen in this audit series."

Attacks named: the reach→sentence mapping across all levels including
unwritten-level fallthrough; both the pessimistic and the reassuring direction of
the opening; five specific misreadings tested one by one (five-gaps-as-census,
keep-this-record-as-proof, permitted-implies-only-permitted, the firmware PASS
row, and whether any check observes a read).

It independently re-verified the factual claim the rewrite rests on: "I checked
the codebase. No check observes an actual access or read event. All checks
observe *permissions*... The statement `records what was permitted, not whether
anyone read your text` is therefore correct and does not understate what the
record knows."

**STOP CONDITION 3 IS MET.**

### Its one carry-forward converges with tonight's floor finding

It flagged the firmware row: "the row itself is accurate, but its framing as a
PASS rather than a descriptive match may lead a reader to credit it as an
independently meaningful threshold... still deserves scrutiny."

That is the same defect reached independently from the reference side: the floor
is a descriptive capture taken FROM the records, and the windowed `min_tcb` will
turn those rows into an honest SKIP. Two paths, same conclusion, already being
fixed. No new work.

### It took three attempts, and the first two failures were instructive

**r1 ($3.90) graded a sentence that does not ship.** Its question (a) quoted
"No — this record cannot rule out..." — 0.9.63's line. That came from MY BRIEF,
not the pack: each brief is derived from the previous round's by substituting
versions and hashes, so the PROSE travels unchanged and any quoted wording goes
stale silently. Finding void.

Killed the class rather than the instance: the runner now refuses a brief whose
quotes the current pack does not render. The test is narrow enough to have no
opinion about ordinary question prose — a quote is stale only if an OLDER pack
rendered it and the current one does not. Two bugs found while building it, each
of which would have made it useless:
- comparing against verifier SOURCE never matched, because the source splits
  sentences across adjacent string literals (`your " "text.`). It compares
  RENDERED output now;
- the first version CRASHED on a bad path and the runner turned that into a
  refusal. A guard that dies looks exactly like a guard that fired.

Question (a) now tells the auditor to read the line from the pack and quote it
verbatim, "do not take any quotation of it from this brief, which may be stale".

**r2 ($3.08) died on `502: All providers exhausted`** — caught by the transcript
gate (rc=5) although the harness exited 0. Its report looked complete and its
verdict was favourable, and it was NOT counted: a degraded run's absence
assertions are its least trustworthy output, and "I found no overclaim" is
exactly that.

**A correction inside that.** I challenged r2 for claiming it verified Intel TDX
fields, on the grounds that our enclaves are SEV-SNP. Wrong. The pack genuinely
carries TDX attestation for the CONVERSATION side (`tdx_shape: "Genuine TDX,
debug off"`, ML-KEM-768 + ChaCha20-Poly1305) — Claim 7, distinct from the SEV-SNP
search enclave. I nearly discredited a correct finding by doubting before
checking.

### Where the four stop conditions stand

1. **reach >= 1** — dropped earlier as mis-specified: it is unreachable without
   an overclaim, because the platform's own containers are outside our control.
2. **naive-reader test** — the "not less confident" half was dropped as
   mis-specified (a reader who arrives believing the sales page SHOULD leave less
   confident). The measurable half — can repeat something accurate to a third
   party — is met.
3. **independent audit finds no defect and names its attacks** — **MET**.
4. **no blocker we could have closed and did not** — pends the fresh record,
   which is blocked on the index route and one signature.

**Spend:** $23.57 of $50.

---

## Iteration 7 — 2026-09-29 — the enclave crash, found for free

### The crash was an image defect, and the guard against it could never fail

Four Azure deploys had died with `exitCode 1` roughly two minutes after the index
finished extracting. Container logs are denied by the policy on purpose
(`allow_runtime_logging: false`), so nothing was visible from the cloud side, and
each redeploy cost ~11 minutes of index transfer to learn nothing.

Running the SAME registry image locally against the mounted index root produced
the traceback in 88 seconds, for nothing:

```
M2Ranker.__init__ -> import lightgbm -> ctypes LoadLibrary("libgomp.so.1")
OSError: libgomp.so.1: cannot open shared object file
```

Two false leads were discarded rather than reported, both artifacts of the local
harness and not of ACI: a `FileNotFoundError` on `models/patents` (a four-hop
symlink chain escaping the mount set — the tar is built with `-h`, so ACI has real
bytes there) and a `PermissionError` on `model.safetensors` (mode 0600 on the
host). Neither was the defect. A first check reported "zero broken symlinks" and
was itself wrong: `models` is a symlink, so `find -type l` never descended into it.

**The guard.** `Dockerfile.m2` had dropped `apt-get install libgomp1` in 06c3cd6
(the reproducible-build work) and justified it in a comment: "faiss-cpu's wheel
bundles its own OpenMP runtime, so libgomp1 was not needed — the baked-import
check below is what proves that". Both halves were false, measured:

* faiss-cpu and scikit-learn DO bundle OpenMP, but name-mangled
  (`libgomp-e985bcbb.so.1.0.0`, empty SONAME). They can never satisfy a request
  for the soname `libgomp.so.1`. `import faiss, lightgbm` fails exactly like
  `import lightgbm` alone — so the credited mechanism was not the one operating.
* the only plain soname in the image is `torch/lib/libgomp.so.1`, and the check
  imports `sentence_transformers` (hence torch) BEFORE lightgbm, which loads it
  into the process. The later ctypes call never touched disk.

So the check passed for a reason unrelated to its claim and could not fail in this
direction, while at runtime `M2Ranker` imports lightgbm lazily, before torch. The
defect and the guard were one blind spot. Same shape as
`a-control-you-always-satisfy-inside-the-guard`.

Fixed by symlinking the soname from the same hash-pinned torch wheel into
`/opt/omp` on `LD_LIBRARY_PATH` — no apt, so the reproducible build is intact —
and rebuilding the check to run the ranker's lazy imports FIRST, each in a FRESH
interpreter, ALONE. Verified in both directions: the new check fails on the
pre-fix image and passes after. Commit 3cf3b30.

### The run then succeeded end to end

`deploy-and-capture.py`, offers/20260929T173500Z. Anchor proven reproducible
before deploy (two generations, different SAS, same HOST_DATA). `verify(prod
roots): ok=True`. Six real sealed searches, all `ok=True, hits=20`; first 3.924s,
steady median 2.918s; genuine glucose-monitoring prior art returned. Everything
reaped — only `ir-attested-durable` and `NetworkWatcherRG` remain.

**First run with the policy fully closed**: `allow_stdio_access` false on all
three containers, `allow_elevated` false on all three, `allow_runtime_logging`,
`allow_dump_stacks` and `allow_unencrypted_scratch` all false. The closure is not
merely asserted — `logs-search.txt` and `logs-skr.txt` came back 1 byte each.

### The signed reference now misses on TWO anchors, not one

| anchor | reference (signed 2026-09-29T10:09Z) | this record | |
|---|---|---|---|
| `policy_sha256` (HOST_DATA) | `011b8b1a…` | `0d6cc360…` | MISMATCH |
| `index_manifest_sha256` | `5404ee03…` | `4d9c239b…` | MISMATCH |
| `model_manifest_sha256` | `7f31cb3f…` | `7f31cb3f…` | match |

The policy move is expected — we changed the image. The index move is NOT, and
matters: the durable blob was re-staged **2026-09-28T19:25Z**, after the last of
the 15 prior records (all `5404ee03…`, 09-16 → 09-24) and the evening BEFORE the
reference was signed. So the signature already named a stale index at the moment
it was made; a record produced today would have failed identity even without the
image fix. `build_manifest_hash` itself is unchanged since 09-24, and today's two
independent paths — a local pre-mounted run with no extraction and the ACI run
with memfd extraction — agree on `4d9c239b…`, which is why that value is trusted.

**Consequence for the signing trip:** still ONE trip, but it must carry BOTH new
values. The `f7a4bb2e` policy discussed earlier is superseded and should not be
signed for.

### Also closed this iteration

Two suite failures, both from b144c32 not reaching sealed-research's copies
(commit 510dc94). The vendored verifier had drifted from canonical by the single
"this one" -> "this record" naive-reader fix; re-copied, pin moved in the same
commit. And `test_matching_reference_firmware_requirement_allows_a_verified_search`
built a FLAT `min_tcb`, which is now refused for having no validity window before
the floor is ever compared — so it failed for a reason unrelated to its subject.

That hid something worse: the parametrised refusal test above it is also all-flat,
so its two floor cases refuse on windowing and never reach the comparison. It was
green while covering nothing. Added
`test_windowed_reference_firmware_requirement_refuses_an_unmet_floor`, asserting
the REASON and explicitly that the refusal was not about the window.
Inversion-verified: fed a flat floor, it fails on exactly that assertion.

### Stop conditions

1. mis-specified, dropped (unchanged).
2. measurable half met (unchanged).
3. **MET** (unchanged).
4. **now pends only the signature.** The fresh record exists, searches, and is
   fully closed; the blockers that remain in its plain output are the two anchor
   mismatches, and those are Henry's key to close, not ours.

**Spend:** $23.57 + ~$0.30 Azure this iteration.
