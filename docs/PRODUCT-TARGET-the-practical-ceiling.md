# The practical ceiling — the target a shippable product must reach

**Set by Henry, 2026-09-28.** This is not an aspiration. It is the statement the product must be
able to make truthfully before it is worth shipping, and every workstream below is scored against it.

## The target statement

> "The program that ran is the one published at ⟨url⟩, byte for byte. Nothing else ran inside the
> protected machine, whose memory the operator could not read. Nothing could leave it except the
> sealed answer to you — not to disk, not to logs, not to the network — because the machine was
> configured so that it could not, and that configuration is part of what the chip signed. What this
> still cannot show: how long your search took and how large it was, which is observable from
> outside — and anything about your own computer."

**REVISED 2026-09-29.** The third clause used to read "we audited every path your text takes inside
it; none writes it to disk, to logs, or to the network". Two things were wrong with it. It was
FALSE as written — the response is itself network egress, so "none ... to the network" cannot hold
for any service that answers. And it was unprovable even once narrowed: "no path writes X" is a
semantic property of a program that no static analysis decides and no attested model certifies. The
replacement does not ask anyone to believe an audit. It states a property the machine was configured
to have, and that configuration is measured. See DESIGN-enforce-dont-audit-2026-09-29.md in
sealed-research.

Four positive claims and an explicit remainder. Note what it deliberately does NOT say: that your
text stayed private. That sentence is unreachable on any substrate — see the last section.

## What each clause requires, and where it stands

| Clause | Requires | Status |
|---|---|---|
| "the one published at ⟨url⟩, byte for byte" | ROW 2 — a reproducible build and a published recipe, so `HOST_DATA` is recomputable by a stranger | in progress; one file of 37,441 still non-deterministic |
| "Nothing else ran inside the protected machine" | ROW 1 — leaving ACI for a confidential VM | designed, not started (~3-4 months) |
| "whose memory the operator could not read" | SEV-SNP | already true |
| "nothing could leave except the sealed answer" | ROW 3 — **confinement**, not audit: an irreversible seccomp filter installed by measured code before the serve loop | **~1-2 weeks.** Measured 2026-09-29: the enclave touches the network in exactly two places, a startup-only index fetch and a localhost call to the attestation sidecar, so closing egress after init costs nothing operationally |
| "how long your search took and how large it was" | nothing — it is an honest remainder | permanent |

## The sentence today, for contrast

> "This record cannot tell you whether your text stayed private: it records what was permitted, not
> whether anyone read your text, so on that question it says nothing."

The distance between the two is exactly rows 1, 2 and 3. Today's sentence is defensible — an audit
round called it "the most defensible version I have seen in this audit series" — but it is a
statement of SILENCE. The target is a statement of CONTENT.

## Why row 2 is the precondition, not merely first

A confidential VM measures the WHOLE guest: firmware, kernel, initrd, rootfs. Reaching for row 1
without row 2 trades "12 Microsoft containers we can name and pin" for "an operating system nobody
has measured" — a larger TCB and a weaker record that sounds stronger. The reproducible-build
discipline is what makes a launch measurement predictable by a third party, so it is load-bearing
for row 1 rather than parallel to it.

## The line that will never move

No substrate makes "your text stayed private" provable. Attestation measures what was LOADED and
what was PERMITTED; it never observes what HAPPENED. Timing and size leak by physics and are
observable from outside the machine. Reach level 2 in `PLAIN_BY_REACH` therefore stays unwritten
permanently — not as unfinished work, but as a boundary the product states plainly.

The ceiling above is the strongest TRUE thing this product can say. Shipping short of it means
shipping a record that says less than the technology allows; claiming past it means shipping a lie.


## Timeline, as of 2026-09-29

| Clause | Was | Is |
|---|---|---|
| "byte for byte" | build not reproducible, nothing published | **done** — two no-cache builds byte-identical; gated only on the publication decision |
| "nothing else ran inside" | row 1, ~3-4 months | row 1, **4-6 weeks**, gated on a days-long spike: can the launch measurement be predicted? |
| "nothing could leave" | months, and **unprovable by inspection** | **~1-2 weeks**, and mechanically checkable |

The critical path is now **row 1**, not row 3. The ceiling moves from "months, with one clause that
could never be proven" to roughly **six to eight weeks with every clause provable** — conditional on
the spike, which should be run first because it can also rule row 1 out.

## How much source must be shared, after confinement

Far less, and none of it valuable. The claim rests on a chain a stranger can walk:

1. `HOST_DATA` equals SHA-256 of the published CCE policy — mechanical, no source.
2. The policy's dm-verity hashes equal the published image layers' — mechanical, no source.
3. The image installs the filter unconditionally before serving — **this is the only step that needs
   a human to read code.**

Step 3 needs the confinement path only: the filter installation and enough of the startup sequence
to show it is unconditional and precedes the serve loop. Tens of lines, not 3,600, and containing no
ranking logic whatsoever.

It also only has to be read **once, publicly, by anyone** — not per customer. While the measurement
is unchanged, every later user relies on the same reading. That is the shape of a transparency log
rather than an NDA.

What never needs to be shared: the 2,641 lines of ranking intelligence. Under confinement their
opacity stops mattering for the confidentiality claim, because a compiled module that cannot open a
socket cannot leak over one — which is precisely the hole that publishing only the confidentiality
source would otherwise leave open, and an operator assertion nobody could check.
