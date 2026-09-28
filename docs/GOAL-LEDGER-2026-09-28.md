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
