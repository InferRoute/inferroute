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
