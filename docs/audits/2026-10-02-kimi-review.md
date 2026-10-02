# Review of the 2 October Kimi audit

Report read: `REPORT-audit-run-audit-pack-20261002T100322Z-901853.md`.
Pack client: 0.9.83. Contents: 18 searches, two document reads, three receipts.
The existing report and evidence were read without modification.

Useful evidence: independent AMD-root comparison, sample signature and REPORT_DATA
recomputation, a signature tamper test, reference comparison and Sigstore checking.
These support substantive conclusions about signatures and identity matching.
They do not warrant treating its seven VERIFIED labels as seven complete claims.

## Findings

- The report retitles several claims and omits the template's Covered by fields.
  Its claim 5 establishes visible counter contiguity, not the original heading
  “Nothing removed.” Missing tails and whole sessions remain undetectable; 45
  earlier operations remain unaccounted for by this installation.
- Its timestamp argument relies on an upgraded OTS proof and `--no-bitcoin`.
  The upstream client explicitly skips Bitcoin-attestation verification in this
  mode and prints a Merkle root to check manually. The report says it did not
  perform that check and gives no independently checked block time. It therefore
  has not established that the anchor predates these operations. `published_at`
  is the operator's own clock. No finding here asserts the proof itself is bad.
- Claim 8 counts the two reads but never reports their signed coverage. Both
  declare `abstract: held`, `claims: claim_1`, `description: not_held`. Finding the
  reads is not the whole coverage question.
- The claim that instance switches are not recorded generalizes over mixed client
  versions. The 0.9.76 and 0.9.77 receipts omit the counter; the 0.9.83 receipt
  explicitly has `instance_switches: 0`. Historical gaps remain gaps, but they are
  not evidence that the current client still has that defect.
- The report calls all 20 operations searches and elsewhere counts the newest
  session as eight searches plus two reads. The pack instead holds 18 searches
  plus two reads overall, and six searches plus two reads in that session.
- It describes itself as Claude/Anthropic despite being supplied as a Kimi audit.
  Its statement that this workstation has no source code is unsupported: this is
  also the workstation holding the development workspace. Auditor identity and
  access need accurate self-disclosure.

## A defect in our own template

Claim 4 explicitly asks whether statement signatures verify. The report template
required VERIFIED IN PART solely because query/result text was withheld. Those
are different questions. The template now follows the written claim and requires
the unchecked text-to-hash bindings to remain explicit limitations. A verified
signature does not verify the withheld text or establish confidentiality.

## Client changes

The existing report template now carries a structured results form with the exact
pack hashes, fixed claim IDs/titles and coverage totals. An auditor completes it
outside the evidence folder, naming the actual model, the exact statement they
established, their evidence and their limitations.

The client accepts only complete, matching forms and checks that the original pack
has not changed. It shows each auditor's conclusions separately. These are
attributed reports; loading a JSON form does not certify the reasoning, prove the
auditor's identity or change the hardware verifier's verdict. This historical
report has not been converted into an accepted structured result.

Source for OTS semantics:
https://github.com/opentimestamps/opentimestamps-client/blob/master/otsclient/cmds.py
(`verify_timestamp`, the branch where `args.use_bitcoin` is false).
