# Processing the patent portfolio — what I would build, and what I would not

**Status**: proposal for Henry, 2026-09-20, after building the wrong thing first and stopping. **Reviewed by
the sealed-research session**; its four corrections are folded in and marked. Nothing below is built except
where it says so.

## What I got wrong

Henry described the job approximately — "recursive analysis, clustering mentality until convergence" — and I
built exactly those words: sessions that re-partition their own groupings until the partition stops moving.
A trial over two documents ran sixteen minutes and produced **nothing**. The failure is useful, because the
mechanism was wrong before it was broken.

## Why clustering-to-convergence is the wrong instrument

1. **It is a fixed point of the model's own prose, not a fact about the portfolio.** Ask a model to regroup
   its own labels and it stabilises quickly — that measures the model's stability, not the corpus. A
   converged partition is a self-confirming artefact, and it arrives looking like a result.
2. **It throws away the register.** `corpus.json` already holds 9 filings with concepts C1–C18, 27 surplus
   candidates with mechanism, status, risk and EP-urgency, each pointing at its authoritative source. The
   expensive question is not "what groups with what" — it is "does the register match what the documents
   actually say", and that has checkable answers.
3. **Tidiness is not the decision.** The decisions are: what must be filed before disclosure; what is one
   idea wearing six names; what a filing already covers; what deserves a sealed prior-art search; what is
   superseded and should stop being read. A grouping serves none of them directly.

## What the job actually is

Build an **inventory of assertions with evidence**, then answer a small set of decision questions over it,
with every answer traceable to a verbatim quote in a named file, and the model's opinions kept beside the
computed facts rather than replacing them.

The unit is not a cluster. It is **item → evidence → decision**.

## The offer, smallest first

### Slice 1 — the inventory (build this, alone, first)

- A **job planner** splits the corpus into reading jobs by byte budget: small files batched together, a
  114 KB file split into explicit byte ranges. Deterministic, host-side, no model.
- One sealed session per job: *extract every distinct technical assertion in this range* as
  `{statement, quote, source, offset}`.
- The host verifies each quote **verbatim in the file it names**, and measures how much of the document is
  actually evidenced: **the largest span between consecutive verified quotes**, with the gap distribution.
  *(Corrected in review: I first proposed the position of the LAST quote over file length. That is reach, not
  coverage — a session that jumps to something at 95% and skips the middle scores 0.95. The largest
  unevidenced span catches the hole; "last quote at 80%, evenly spaced" is more read than "last quote at 95%
  with a 70% gap".)*
- The number is reported as what it is: **evidenced span**, not "the document was read". Nothing can show a
  model read a passage it chose not to quote.
- Output: `items.jsonl`, `coverage.md`.

On its own this answers "what does this portfolio assert, and where", for 135 files no one can re-read.

### Slice 2 — register linkage (small, and where the value is)

**Blocked until one decision is made**, and the review is right to hold the slice over it: `corpus.json`
cannot be both *the thing documents are checked against* and *a derived working copy* (its own README calls
it derived, with authoritative registers elsewhere). If it is derived FROM the documents it can only LAG
them, never contradict them — and then this slice is a derivation audit, not a contradiction report. Pick
the direction before building, or the same three lists mean three different things.

With the direction settled, for each item: which register row holds it (P1–P9, C1–C18, TA-xx) or
*unregistered*, with a reason; the host checks the id exists. Four outputs, each actionable:

- **Unregistered items** — ideas the documents assert that no register row covers.
- **Unrepresented register rows** — register entries no document supports any more.
- **Contradictions** — resolved against the **authoritative source the row already points at**, never
  against the derived value, quoting the document's sentence and the authoritative value, and carrying the
  derivation's timestamp.
- **Derivation drift** — derived copy against its authoritative source, reported as itself. Otherwise a
  stale copy is smuggled in as a document contradiction, and a copy that verified once passes forever after
  its source moved.

### Slice 3 — duplicates, by decisions rather than by grouping (only if 1–2 earn it)

- Cheap local similarity (no model) proposes candidate pairs — blocking, ~5 neighbours each.
- The sealed session answers one question per pair: same mechanism or not, **citing the matching or
  distinguishing sentence on each side**.
- Groups are the transitive closure of the "same" decisions: derived, with every merge carrying its reason.
- **Every edge that would cause a merge is asked both ways**, not a 10% sample: an edge counts as "same"
  only if both orderings say same. Asymmetric edges are dropped from the closure and surfaced. (Doubling the
  questions applies only to merge candidates, so the cost is small and lands where the damage would be.)
- **Auto-merge only what more than one link holds together.** A group whose connectivity depends on a single
  edge — remove it and the group splits — is not merged silently; it is offered as a proposed merge with its
  bridge named. That is the minimum-evidence rule: *auto-confirmed iff no single link holds it together.*
- **Contradiction check inside each merged group, which is nearly free.** If A~B and B~C were "same" but
  A≠C was answered directly, that is the signature of a bad link: report it as a merge conflict with all
  three cited sentences. We already pay for a distinguishing sentence on every "different" answer; this
  spends it on catching the collapse.
- Reliability number: re-ask a sample with the sides swapped, and report the disagreement rate.

**On what that number does and does not mean** *(review's correction)*: swap-disagreement measures the
judge's **reliability**, not its accuracy — a judge can be perfectly consistent and consistently wrong.
It is reported as a reliability floor. Accuracy needs an anchor: ~20 pairs labelled once by a human, kept
as a gold set. Until that exists, the honest line is "stable, unvalidated", and the slice says so.

Each slice carries its own measure — Slice 1 host-verified quotes plus evidenced-span, Slice 3 symmetric
edges plus gold set. One number must not stand in for all of them.

### Slice 4 — what to do next

Per group the host computes what is arithmetic (documents spanned, covered-by-a-filing — which requires a
quote from the filing — EP-urgency, status). The session writes the recommendation and the argument. The
numbers stay computed. The shortlist's top entries become Probant matters by the existing one-click path,
and from there the sealed prior-art search already works.

## Cost, so the scale is not a mystery

~3.1 MB of markdown outside `04-claims` and `02-prior-art` ≈ 0.8 M tokens. Slice 1 reads all of it **once**.
Slice 3 after blocking is a few thousand short pair questions ≈ 0.4 M tokens. Cost is not the constraint here
— which is exactly why the design should spend on verifiability rather than on repeated passes. The loop I
built would have re-read summaries every round for a result that means less.

## What I would drop

The recursive re-clustering loop and its convergence stop. The movement metric behind it is now correct
(pair-counting, so splits and merges register) and stays as a diagnostic — but it is not the product.

## Later: the same thing over a repository

Keep exactly one seam: a **source adapter** yielding `(document name, bytes, optional register rows)`.
Portfolio adapter now; a repo adapter later gives files as documents and ADRs/modules as the register, and
Slices 1–3 work unchanged. Build nothing else for that case today.

## Which endpoint this calls, and the part that is a policy decision

Checked rather than asserted: an extraction session launches through the confidential lane, its panel
reports the AI as a sealed machine verified at that moment, and the agent's endpoint is a loopback proxy
that seals to the enclave. If the lane is not confidential the launch **refuses** — `confidential.py:264`
returns exit 3 rather than starting the session. So no byte of the portfolio reaches a plain model call, and
no search tool exists in this pipeline at all.

What that does NOT settle *(review's flag, and it is Henry's to rule on)*: putting the whole claim-dense
corpus through one pipeline is a crown-jewel concentration, and "technically sealed" is not the same as
"cleared to do". Whether `04-claims` and `02-prior-art` go in scope should go through the IP gate the same
way any other disclosure decision does — not be settled by the fact that it is safe in transit.

## What I need decided

1. **What should the shortlist rank for** — file-next, disclosure exposure, or defensibility? They give
   different orders, and the ranking rules are host-side, so this is a decision, not a preference.
2. **Is `corpus.json` the register** — the thing documents are checked against — or is it also suspect and
   merely another document?
3. **Are `04-claims` and `02-prior-art` in scope for the sealed agent?** I do not read them, by my own rule,
   but they are the claim-dense material and the agent can. If they are in scope, Slice 2's coverage answers
   get considerably stronger.
