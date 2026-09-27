# Plain blockers: scope, uncertainty, and faithful translation

Reviewed 11d0890 (0.9.59) against the real 70-search record and constructed evidence configurations.
This is a local code/wording review, not the mac-papa round or a finding of actual plaintext disclosure.

Both proposed implication risks are credible: named gaps can look like the complete set of risks,
and a named channel can look like the only channel. The plain report now states, even with an empty
list, that these are gaps identified by this verifier, not a complete list of risks or disclosure
routes. A shorter or empty list does not establish privacy. It also distinguishes future deployment
changes from controls enforced for saved operations: correcting settings cannot rewrite old records.

A third defect is demonstrable, not just a possible reader inference. The stdio blocker represents
failure to establish a denial. It is generated for true, absent, or unfamiliar field values. In
11d0890, deleting allow_stdio_access from every container still rendered “the machine's settings let
whoever operates it attach to the program while it was running.” The underlying table also printed
that missing values were true. Neither observation follows from absent evidence. The table now counts
explicitly opposite values separately; the plain reason says the control was not established, without
claiming access occurred or that those streams contained the text.

The same distinction matters for attempted/partial checks. Revocation not successfully checked does
not mean the chip maker was never asked, and it concerns signing-chain scope, not a verified lookup of
each machine's own certificate. A firmware-floor check not passing for every operation does not mean
no operation was checked. Source missing from a reference does not show that no published source
exists. The revised mappings state those narrower outcomes. Runtime properties are not established
by this verifier; they are not declared impossible for any future evidence to establish.

A separate translation defect could silently discard information. Reproduced in 11d0890:

* `new reason: certificate revocation was checked but the log is missing` became the claim that the
  chip maker was not asked, because the matcher recognized a substring and dropped the qualifier.
* `future reason: first part: second part` lost `future reason:` in the supposedly verbatim fallback.

Known translations now match the complete generated reason after removing only a recognized policy
prefix. Unknown reasons retain their entire original text. A wording change in a technical blocker
therefore falls back visibly instead of silently acquiring an outdated interpretation.

The list still shrinks automatically when the corresponding checks improve. Regression tests verify
that disabling stdio removes that particular reason while retaining the runtime/privacy boundary.
They also cover missing stdio, empty lists, unknown reasons, partial/unsuccessful checks and familiar
substrings embedded in new reasons. These tests guard particular counterexamples; they do not certify
that every possible reader will interpret the prose correctly.

Validation: 208 canonical plain/verifier/audit-pack tests passed. The current verifier ran read-only
against the real 70-record/11-receipt local pack, exited 0, and rendered the revised gaps and scope.
The existing pack's SHA256SUMS still match. Its supplied reference key came from the pack, so this run
does not establish independent key provenance. The published release requires a separate new build.
