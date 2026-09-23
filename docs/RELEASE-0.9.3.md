# inferroute 0.9.3 — release candidate

**STATUS: BUILT AND VERIFIED, NOT PUBLISHED.** Publishing is Henry's, and external distribution needs the
IP clearance that is still open. Nothing here has been uploaded to PyPI, and nothing has been pushed to
`master`.

    wheel    dist/inferroute-0.9.3-py3-none-any.whl   (472 KB)
    built    from `git archive HEAD` into a clean tree, not from the working directory
    tests    604 passed, 16 skipped
    branch   attested-pi-agent, 141 non-merge commits ahead of the published 0.9.2

## Why 0.9.3 and not 0.9.2

0.9.2 was published to PyPI while this branch was working, carrying the upstream-body fix. This branch was
still at 0.9.0 and did **not** have master's last six commits — including `9c07e94`, the fix for a re-check
that drops the pinned instance and then fails every later message while verified instances are available.
Cutting a release from this branch alone would have silently undone it.

Master is merged in. The re-pin fix is confirmed present by its own text and its own tests, not assumed
from a clean merge. Three conflicts in `session.py` were resolved by what each side is *for*: this branch
funnels both dialects through one `_send` which already carries the leak fix, so master's inline duplicate
is redundant here; master's `upstream_public` docstring is better than this branch's and wins.

0.9.3 is above 0.9.2, so `pip install --upgrade inferroute` will not silently replace it.

## What is new for a user

**Probant** — the whole attorney-facing product, absent from every published version until now:
`ir probant new / open / list / delete / home`, the local browser page, per-matter date bounds, marks,
exported records.

**Sharing a corpus.** `ir probant share <contact> --matter … --file …` seals a corpus of matters *and the
documents that describe the whole delivery* to one recipient's ML-KEM key, signed. The recipient opens them
as matters of their own; the sender's marks travel as the sender's. A corpus carries an identity, so three
things stay distinct: what arrived, what describes the delivery, and what the recipient creates afterwards
(`ir probant new … --from-corpus <id>`).

**Reading a portfolio.** `ir probant portfolio` reads a corpus of filings — **including `.docx` as
deposited** — and records every technical assertion with a verbatim quote the host checks against the
document it names. `portfolio-matters` renders the matter list; `--guide` renders where in each filing each
invention's evidence sits, which is the answer to "the filings are huge, what do I read".

**The audit pack tells the auditor the truth about the verifier.** `verify_record.py` ships in this wheel
for the first time, so the brief can now give an auditor the exact commands to fetch the published package
and compare hashes — turning "read it carefully" into "check it against ours". The brief also names
`verify_record.py` as untrusted code, points out that the manifest listing its hash sits in the same folder,
and says a mismatch is a finding in its own right.

**The audit can ask about the conversation, not only the searches.** A matter's work happens in a sealed
session with an AI machine, and the record described that session from this device's receipt while leaving
the receipt on the device — our own word with nothing beside it. The pack now carries each
`session-*.receipt.json`, and claim 7 states exactly what it is worth: the raw attestation behind those
verdicts is not in the folder, so an auditor cannot re-verify the quote the way they can for a search, but
they can check the measurements against the published reference and the counters against the claim that
plaintext was only ever sealed on the device. The receipt's `path` is dropped — it names the professional
and their folders and evidences nothing.

## Fixes a user would notice

- **A missing search no longer reads as weakened protection.** With no search machine configured the panel
  said "Partly protected", which told a professional their client's invention was at risk when nothing could
  leave the building at all. It now says Private, and counts only the sealed machines actually checked
  (previously it claimed "two" unconditionally).
- **A base install no longer crashes on the first command.** `ir probant identity` — the command that makes
  the key card a new user must send before anyone can share with them — died with `ModuleNotFoundError`.
  It now names the dependency and gives the one command that fixes it. *Found only by installing the
  candidate in a clean virtualenv; every development machine already had it.*
- **An audit pack is refused only when there is genuinely nothing to audit.** A pack built from a matter
  that had never been searched cost an auditor ten minutes to reach "could not check" on every claim. But
  refusing on *searches alone* then blocked the opposite case — no search machine resolves from this device,
  yet the conversation was sealed and is auditable under claim 7. It now refuses only when there is neither
  a search nor a session, and when searches are absent it says so above the brief instead of letting the
  auditor spend the fifteen minutes it asks for to reach the same verdict.
- **An absent search no longer reads as failed evidence.** `verify_record.py` printed `RESULT: FAILED`
  for a record whose only fact was that no search had been run — and the brief sends the auditor to run
  exactly that program and report its exit code, so the delivery path ended in an attorney being told the
  evidence failed. It now says `NOTHING VERIFIED`, names the session receipts that *are* present, and
  points at claim 7. It still exits 1: an empty record must never be passed off as verified.
- **A killed reading job no longer counts as having read the document.** A retry cap turned an interrupted
  run into permanent data loss: the largest filing in a portfolio was marked read-and-empty and silently
  skipped on every later resume.

## What this release does NOT change

- It does not make the sealed **search** available. The search enclave
  (`ir-sealed-search.eastus2.azurecontainer.io`) no longer resolves, so `probant` runs without prior-art
  search until an enclave exists to point at. Every other part of a matter works.
- It does not settle whether the client may be distributed externally. That is the open IP clearance.

## Before publishing — for Henry

1. Read `docs/betrancourt-email-draft.md`; the delivery depends on this release.
2. The wheel is built from `git archive`, not from the working tree, so what is in it is what is committed.
   Rebuild and compare if you want that independently:
   `git archive HEAD | tar -x -C <tmp> && cd <tmp> && uv build --wheel`
3. Publishing `verify_record.py` is the point of the audit change. If the release is cut without it, revert
   the brief's comparison instructions in the same change — an instruction that silently does not happen is
   worse than none.
