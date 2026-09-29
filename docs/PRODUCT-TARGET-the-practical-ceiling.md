# The practical ceiling — the target a shippable product must reach

**Set by Henry, 2026-09-28.** This is not an aspiration. It is the statement the product must be
able to make truthfully before it is worth shipping, and every workstream below is scored against it.

## The target statement

> "The program that ran is the one published at ⟨url⟩, byte for byte. Only two kinds of program
> could run inside the protected machine — ours, and the cloud platform's own startup containers,
> every one of them named in this record with what it was permitted to do. The operator could not
> read that machine's memory. The program we published could not send your text anywhere except
> back to you — not to disk, not to logs, not to the network — because the machine was configured
> so that it could not, and that configuration is part of what the chip signed. What this still
> cannot show: what the platform's own containers could reach, which is why they are named above;
> how long your search took and how large it was, which is observable from outside — and anything
> about your own computer."

**REVISED AGAIN 2026-09-29 (Henry's ruling), fourth clause.** It read "Nothing could leave it
except the sealed answer to you". An independent audit called that a behavioural negative that
attestation cannot license, since attestation measures what was LOADED and what was PERMITTED and
never what HAPPENED. That argument is correct but it is not the decisive one.

The decisive one is that **the clause contradicted the statement's own second clause.** We tell the
reader, in the same paragraph, that the cloud platform's startup containers run inside that same
protected machine — and this record's own disclosure says they may attach to their containers'
input and output and mostly run with raised powers. "Nothing could leave it" and that sentence
cannot both be true. It was not merely unprovable on this substrate; it was false, and visibly so
to anyone who read to the end.

The replacement scopes the promise to the thing we actually control and actually enforce: **our own
published program**, constrained by a configuration the chip signed. It is a smaller claim, it is
enforced rather than asserted, and it survives contact with the disclosure two clauses earlier. The
platform containers move into the remainder, where they belong, with a pointer back to the clause
that names them.

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
| "only two kinds of program could run … every one named" | the effective policy enumerates every permitted container, and `HOST_DATA` commits the chip to that enumeration | **reachable now** — the verifier already computes the disclosure; see the 2026-09-29 decision below |
| "whose memory the operator could not read" | SEV-SNP | already true |
| "the program we published could not send your text anywhere except back to you" | ROW 3 — **confinement**, not audit: an irreversible seccomp filter installed by measured code before the serve loop. Scoped to OUR program: the platform's containers are a separate surface, named in clause 2 and carried in the remainder | **~1-2 weeks.** Measured 2026-09-29: the enclave touches the network in exactly two places, a startup-only index fetch and a localhost call to the attestation sidecar, so closing egress after init costs nothing operationally |
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
| "nothing else ran inside" | row 1, ~3-4 months | **clause rewritten** — the spike killed row 1 as a shortcut; the honest form is reachable now. Row 1 deferred to future work. |

## The spike was run. Row 1 is a downgrade, not a delay.

**2026-09-29, measured on a real `Standard_DC2as_v5` confidential VM in eastus.** Evidence:
`sealed-research/docs/FINDING-cvm-spike-2026-09-29.md` (commit 72004e3).

The question this row was gated on was "can the launch measurement be predicted by a third party?"
The answer is that the question does not arise, because **the launch measurement does not cover our
software at all**. `MEASUREMENT` is Azure's CVM firmware; it does not change when our code changes.
And `HOST_DATA` — the field that carries `sha256(CCE policy)` on the confidential-container path we
already run, and which is what makes "byte for byte" checkable by a stranger — is **32 zero bytes**
on a CVM.

Making `HOST_DATA` non-empty would not rescue it. On ACI that value means something *because the
platform enforces the policy it hashes*. A CVM has no policy engine, so a value we placed there
would be a label we chose for ourselves, committing the host to nothing. The conclusion therefore
does not rest on proving that Azure exposes no knob to set it — that negative was neither proven
nor needed.

The only binding to our code available on a CVM runs through the vTPM: report → AK → quote → PCRs →
measured boot → dm-verity root. That chain must be built from scratch, requires predicting PCRs from
our published image, and terminates in a vTPM emulated by the paravisor rather than in silicon.

**So row 1 does not dominate the current path — it trades clauses:**

| clause | confidential containers (today) | confidential VM |
|---|---|---|
| "the program that ran is the one published, byte for byte" | **provable now** | **not provable** without building the whole measured-boot chain first |
| "nothing else ran inside the protected machine" | **false** — 12 platform containers, all `allow_stdio_access`, 9 `allow_elevated` | achievable, since we would own the whole image |

Note this inverts the reasoning in "Why row 2 is the precondition" above. That section argued row 2
makes row 1's launch measurement predictable. It does not: on Azure the launch measurement is
Microsoft's firmware, and no amount of reproducibility on our side reaches it.

### The open decision (with Henry, asked 2026-09-29)

**A.** Keep the containers substrate and stop claiming "nothing else ran". Say instead what is true
and checkable: that the platform's own startup containers ran alongside ours, naming them and what
each was permitted to do. The verifier already computes and prints this disclosure
(`platform_dependency_disclosure`). Days, not months.

**B.** Build the measured-boot + dm-verity chain on a CVM anyway, rebuilding the "byte for byte"
clause by hand before breaking even, and ending on a paravisor vTPM.

**Henry chose A on 2026-09-29**, with the VM chain kept as future work rather than dropped: race to
a polished client on the substrate that can already carry the claim.

The second clause has been rewritten accordingly, at the top of this document. Note that the
replacement is not a retreat from "nothing else ran" — it is **stronger**. "Nothing else ran" was a
claim about history that attestation cannot make. The replacement is a claim about what was
PERMITTED, which is exactly what attestation does measure: the effective CCE policy enumerates every
container that may start, and `HOST_DATA` binds the chip's signature to that enumeration. Saying
"only these could run, and here they are" is enforced, checkable, and names the 12 platform
containers instead of quietly excluding them.

### Future work: the measured-boot chain (deferred, not abandoned)

Row 1 returns as a later goal, to be taken up once the client is polished. It requires, in order:

1. A minimal guest image we build and publish — kernel, initrd, rootfs — not a stock Ubuntu CVM image.
2. dm-verity over the rootfs, with the root hash carried in the kernel command line.
3. Measured boot such that the resulting vTPM PCR values are predictable from the published image,
   and a published recipe for recomputing them.
4. A verifier extension: SNP report → vTPM AK certified in that report → quote → PCR comparison.

What it buys: the platform's containers disappear, so the enumeration collapses to our program
alone. What it costs beyond the build: the trust root moves from an AMD-signed policy hash to a
paravisor-emulated vTPM, which is a weaker anchor for the byte-for-byte clause than what we have
today. That trade is why this is future work and not the critical path — it should only be taken if
a client asks for the collapse to a single program AND accepts the weaker anchor.
| "our program could not send it anywhere" | months, and **unprovable by inspection** | **~1-2 weeks**, and mechanically checkable |

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
