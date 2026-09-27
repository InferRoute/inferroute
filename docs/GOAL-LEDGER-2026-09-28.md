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
