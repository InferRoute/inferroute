# Processing the patent portfolio — what I would build, and what I would not

**Status**: proposal for Henry, 2026-09-20, after building the wrong thing first and stopping. Sent to the
sealed-research session for review. Nothing below is built except where it says so.

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
- The host verifies each quote **verbatim in the file it names**, and computes **read-through coverage** per
  document: the position of the last verified quote over the file's length. A document the session skimmed
  and abandoned at 20% is reported as such instead of passing as read. (Nothing today can tell those apart,
  which is the single biggest trust hole in reading long files.)
- Output: `items.jsonl`, `coverage.md`.

On its own this answers "what does this portfolio assert, and where", for 135 files no one can re-read.

### Slice 2 — register linkage (small, and where the value is)

For each item: which register row holds it (P1–P9, C1–C18, TA-xx) or *unregistered*, with a reason; the host
checks the id exists. Three outputs, each a list a professional can act on:

- **Unregistered items** — ideas the documents assert that no register row covers.
- **Unrepresented register rows** — register entries no document supports any more.
- **Contradictions** — register status against a document's own sentence, both quoted.

### Slice 3 — duplicates, by decisions rather than by grouping (only if 1–2 earn it)

- Cheap local similarity (no model) proposes candidate pairs — blocking, ~5 neighbours each.
- The sealed session answers one question per pair: same mechanism or not, **citing the matching or
  distinguishing sentence on each side**.
- Groups are the transitive closure of the "same" decisions: derived, with every merge carrying its reason.
- Quality number: re-ask 10% of pairs with the sides swapped and report the disagreement rate.

**That disagreement rate is the honest replacement for "convergence"** — stability of decisions under
perturbation, measured on a sample, rather than a partition agreeing with itself.

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

## What I need decided

1. **What should the shortlist rank for** — file-next, disclosure exposure, or defensibility? They give
   different orders, and the ranking rules are host-side, so this is a decision, not a preference.
2. **Is `corpus.json` the register** — the thing documents are checked against — or is it also suspect and
   merely another document?
3. **Are `04-claims` and `02-prior-art` in scope for the sealed agent?** I do not read them, by my own rule,
   but they are the claim-dense material and the agent can. If they are in scope, Slice 2's coverage answers
   get considerably stronger.
