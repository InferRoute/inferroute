# Sharing a matter with another person — a proposal

**Status**: proposal, nothing built. Written 2026-09-20 for Henry and the sealed-research session, after
confirming that no settled design exists on either side. **Nothing here may reach a client-facing surface
before the IP check clears it** — sharing and commitment on the sealed lane sit near filed claims, and
Europe has no grace period.

## The question, split

"Share a matter by sharing a private key" is three different asks, and only the third is hard.

| # | What the recipient gets | What it needs |
|---|---|---|
| 1 | A finished record to check | **Nothing.** An exported record is already self-verifying by anyone holding the published reference. No key, no account, no InferRoute. This works today. |
| 2 | The matter to read: disclosure, sessions, marks, records | A copy of the matter's folder, and a way to decrypt it |
| 3 | The matter to *continue*: their own sealed sessions, their own searches, marks that merge | All of 2, plus an answer to "whose enclave session is it" and "who may write" |

So: say 1 out loud (it is a feature, and free), design 2, and treat 3 as a separate decision.

## What sharing cannot mean

**Not the enclave's key.** Each answer is sealed to a one-time key the hardware committed to for that one
request; there is no long-lived key that "opens a matter", and building one would be a downgrade —
it would create exactly the durable secret the design avoids.

**Not a key that lets InferRoute read the matter.** Whatever is shared, the host-side matter must stay
unreadable to us. That rules out routing sharing through our servers as a convenience.

**Not a key that is also an identity.** If the shared key both decrypts the matter and authorises writing
to it, revoking one person's access means re-keying everything.

## Proposal, in one paragraph

Give every matter a **matter key** — a symmetric key, generated on the machine that creates the matter,
kept in the owner's key store, never sent to InferRoute. The matter's host-side state (disclosure, session
records, marks, exported records) is encrypted at rest under it. Sharing a matter means handing that key to
another person **out of band**, together with the matter folder — the same trust move as the publication
key in an engagement letter, and describable in one sentence to an attorney: *"the folder is the matter,
the key opens it, and we never had either."* The recipient's own Probant opens the folder with that key and
can run their own sealed sessions against it; every session still verifies its own enclave and seals its own
requests under its own one-time keys, because that is per-request and has nothing to do with the matter key.

## What that leaves open, and my leaning

1. **Two people editing one matter.** Marks and session records are append-only per session, so two people
   working separately produce files that merge without conflict *if* every record carries who wrote it.
   Lean: require a **participant identity** (a local keypair, fingerprint shown in the UI) and stamp each
   record with it. Without this, a shared matter cannot say who marked what, and "your marks are yours
   alone" stops being true the moment a matter is shared.
2. **Revocation.** Handing over a symmetric key is irreversible: the recipient keeps what they already
   have. Lean: say so plainly rather than pretend otherwise, and make re-keying (new key, re-encrypt,
   share again) the answer for "from here on, not them".
3. **Where the key lives.** Lean: the OS key store where there is one, a 0600 file otherwise, and never in
   the matter folder — a folder that carries its own key is a lock with the key taped to it.
4. **What crosses the wire.** Lean: nothing. v1 is "copy the folder however you like — USB, the firm's
   share, email if the folder is encrypted — and pass the key another way". Any transfer service we run is
   a second trust story and can wait.
5. **Date bound.** The recipient must inherit the matter's date bound, and must not be able to raise it
   silently: it is the thing the record's claims rest on. Lean: the bound travels inside the encrypted
   state, and a change is recorded as a change, exactly as it is today.

## What I would build first

Only step 2, and in this order: matter key on creation → state encrypted at rest → `ir probant share` writes
an encrypted matter bundle and prints the key once → `ir probant open-shared` takes bundle and key. Each of
those is testable without any decision about concurrent editing, and none of it changes the sealed lane.

**Before any of it**: the IP check on the scheme, and a review from the sealed-research session — this is
their territory as much as mine.

## What I need from Henry

- Is the recipient a **Probant user** (they have the product and their own account), or a **reader** who
  should need nothing installed? That decision changes everything above: the second means the shared thing
  is a record, not a matter.
- Does sharing have to work **without either party running a server**? I have assumed yes.
- Is **revocation** a requirement, or is "you shared it, they have it" acceptable, as it is for a paper file?
