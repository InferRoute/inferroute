# The practical ceiling — the target a shippable product must reach

**Set by Henry, 2026-09-28.** This is not an aspiration. It is the statement the product must be
able to make truthfully before it is worth shipping, and every workstream below is scored against it.

## The target statement

> "The program that ran is the one published at ⟨url⟩, byte for byte. Nothing else ran inside the
> protected machine, whose memory the operator could not read. We audited every path your text takes
> inside it; none writes it to disk, to logs, or to the network. What this still cannot show: how
> long your search took and how large it was, which is observable from outside — and anything about
> your own computer."

Four positive claims and an explicit remainder. Note what it deliberately does NOT say: that your
text stayed private. That sentence is unreachable on any substrate — see the last section.

## What each clause requires, and where it stands

| Clause | Requires | Status |
|---|---|---|
| "the one published at ⟨url⟩, byte for byte" | ROW 2 — a reproducible build and a published recipe, so `HOST_DATA` is recomputable by a stranger | in progress; one file of 37,441 still non-deterministic |
| "Nothing else ran inside the protected machine" | ROW 1 — leaving ACI for a confidential VM | designed, not started (~3-4 months) |
| "whose memory the operator could not read" | SEV-SNP | already true |
| "we audited every path…; none writes it to disk, to logs, or to the network" | ROW 3 — the data-path audit, as tests rather than assertions | one clause measured; egress audited by enumeration |
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
