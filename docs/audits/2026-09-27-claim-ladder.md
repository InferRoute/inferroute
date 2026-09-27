# Claim ladder review, 2026-09-27

Scope: local review of `b38dfb3` and the 70-search/11-receipt pack. This is a repository-side
counterexample and regression review, not a new mac-papa audit or a claim that the deployed
application actually leaks. pi-attested owns the independent mac-papa round.

## Reproduced overclaims

At `b38dfb3`, a policy with every checked flag false, nonempty image layer roots, empty
`exec_processes`, and no external dependencies passes every posture row. With all five other
inputs true (`floor_pinned`, `revocation_checked`, `image_published`, `authenticated`,
`record_ok`) and `policy_committed=True`, `confidentiality_reach` returns `(2, [])`.
The report then licenses all three sentences, including “every channel” denied and “remained
confidential.” A nonempty `reference.image_source` object suffices for the source input: nothing
fetches, rebuilds, compares or reviews it.

Counterexample: the image's approved entrypoint itself sends plaintext to an operator endpoint.
It needs no additional exec process, elevation, stdio, logging, stack dump, or unencrypted scratch.
The policy can be authentic and the image honestly published and reproducible. Every checked
condition remains true, while the English is false. The regression supplies a main-command marker
for that behavior; it does not execute a disclosure or pretend to forge a hardware report.
Source availability and reproducibility are identification properties, not non-disclosure proofs.

The first sentence also exceeded its evidence. A signed statement and a hardware-bound key can
coexist with a plaintext ingress path, a second plaintext copy, or an externally held private key.
The archive does not independently prove encryption on the professional's computer or exclusive
key custody. A valid statement must describe saved signatures/key bindings, not assert transport
secrecy as an observed fact.

Additional mapping defects:

* `bool(min_tcb)` counted a floor for Genoa as present for a Milan operation whose real firmware
  check was SKIP. The gate now aggregates actual PASS rows across every operation.
* Policies were collected only when archived. A permissive second policy with no archived bytes
  could disappear from the posture census while its hardware commitment remained in the record.
  The report now requires the policy set to cover every observed hardware commitment and checks
  each supplied policy's bytes against its commitment.
* Missing commitment metadata defaulted to accepted; test roots could feed the same production
  sentences. Unknown commitment coverage and test roots now refuse the licensed section.
* The overall result was printed before revocation ran, so a revoked ASK could produce a passing
  headline followed by a failure. Revocation now runs before the result, and a result with SKIP rows
  says “no failing record checks,” not “every check passed.”
* Equal-rank policies discarded later blockers. The report now retains each policy's blockers.
* A valid reference signature proves agreement under a supplied key, not independent key provenance.
  The report now states that boundary even when the signature passes.
* AI scope appeared after the licensed sentences, and three necessary binding checks could be read
  as sufficient. Scope now precedes the sentences; the checklist explicitly is not sufficient.

## Implemented contract

The highest reachable level describes the specified policy controls plus passed configured
firmware-floor/ASK-revocation checks. It does not describe universal confinement. Invalid evidence
returns a separate refusal level; integrity and policy-commitment inputs must be explicit.
The hardware-only statement describes archived search signatures and hardware-bound signing keys.
It does not cover the AI conversation, omitted operations, or future requests.

The old confidentiality-throughout sentence is never licensed by these inputs, including when
all are true. Adding one more unverified boolean such as `source_reviewed` would recreate the defect.
This bounds the current evidence; it does not assert that a richer verifier could never prove a
precisely scoped privacy property.

## Future records: what the roadmap does and does not earn

Closing stdio, pinning a firmware floor, and publishing reproducible source does **not** earn the
old strong sentences, even for future records. Unresolved fragments and revocation remain, and
even closing all five original blockers leaves the entrypoint counterexample intact.

For a stronger future-session claim, first define the property and adversary: authorized recipients,
which content and operations, client-device trust, hardware/firmware trust, allowed outputs, and
whether timing/size or other side channels are excluded. Then require evidence for:

1. Exact measured image and all policy dependencies, tied to the reviewed build and initialized
   configuration. A source URL or list of candidate layer hashes is insufficient.
2. Enforced plaintext confinement, including application-initiated network output, files, memory
   lifetime, diagnostics and crash paths, with outputs sealed only to authenticated authorized
   recipients. Normal application code is within this argument; denying operator exec is not enough.
3. Client-side sealing and key custody under the stated device assumptions, and an authenticated
   binding between every operation, recipient, attested instance, and applicable configuration.
4. Separate AI-lane verification, including instance changes and distrust events, and a signed
   cross-lane binding before making any session-wide statement.
5. Per-operation verification outcomes, including firmware floors for the actual product, explicit
   revocation scope/time, and refusal when required evidence is missing or skipped.

Adversarial testing can challenge this argument; passing tests alone is not a mathematical proof.
A formal confidentiality claim would need an explicit model and checked proof connected to the
measured implementation and its assumptions. The user-facing statement must carry that scope.

For the existing 70 records, `allow_stdio_access=true` is in the signed policy and cannot be changed
by editing today's reference. Independent existing artifacts may supplement an old record, and a
later check can compare old measurements against an independently justified floor. Neither action
rewrites what controls were enforced or creates missing runtime observations. This does not hold
future records back: a new enclave must attest the corrected configuration before new disclosure.

## Coverage row decision

Withhold. Bundle presence is not verification, and this single-file verifier has no implementation
of Sigstore trust-root, identity/issuer, payload-binding and transparency-log verification.
This is an engineering boundary, not a claim that single-file verification is impossible.
`b38dfb3` already removed the computed coverage; the revised row makes the decision explicit:

> NOT VERIFIED THE BUNDLE. Coverage WITHHELD: no authenticated log time, operation count,
> or historical coverage is reported.

A separate validated result could eventually supply authenticated publication time and exact
payload/key identity with independently selected trust expectations. Even that would establish
publication/binding at a time, not the truth of operation timestamps or runtime non-disclosure.
No number is printed while the verification is absent.

## Local validation

The current verifier ran offline against the existing 70-search, 11-receipt 0.9.55 pack (without
altering its files). Record verification exited 0; only the bounded hardware-evidence statement was
licensed. The historical controls and runtime-evidence gaps remained visible; AI receipts were
explicitly outside the verified scope. The supplied reference key in this run came from the pack,
so this run is not evidence of independent key provenance.

Regression coverage includes the approved-entrypoint counterexample, source-pointer non-evidence,
missing policy coverage, unknown/test roots, failed integrity, mixed-policy blockers, and a real
AMD Milan report with a Genoa-only floor (SKIP) versus an applicable Milan floor (PASS).

Validation after the change: 174 tests passed across the canonical verifier and audit-pack suites;
60 passed across the vendored verifier, client distribution, live search verifier and sealed-search
suites. The existing pack's SHA256SUMS still match after the read-only run.
