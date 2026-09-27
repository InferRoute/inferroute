# Enforce declared firmware floors before a live disclosure

The archive verifier read `reference.min_tcb`, but the canonical `verify_offer` path only considered
an explicit argument. The local sealed-search proxy checked reference identity without enforcing its
firmware floor. A reference could therefore name a minimum and the live client still seal to a machine
below it. This change connects that requirement to the decision made before any request is sent.

The shared single-file verifier now validates declared floors and checks them against authenticated
AMD report/certificate evidence. The floor must apply to the actual product; another product's floor
is not coverage. Empty, all-zero, unknown-field, non-integer, boolean and out-of-range declarations
refuse instead of being dropped or coerced. An absent declaration creates no new PASS. In the live
offer API, a weaker explicit argument cannot remove a stricter reference requirement. Archive parsing
uses the same validation and refuses malformed declarations visibly.

The local search proxy invokes this check before sealing or POSTing the query. This supplements its
existing full offer/key/identity verification; it does not replace reference authentication, Microsoft
endorsements, key bindings, revocation checks or policy review. The caller authenticates the reference
before constructing the live verifier. No production floor value was inferred from these records,
published or signed. A configured floor is not proof that its firmware is free of vulnerabilities.

Validation: a matching floor permits a signed search against the simulated enclave; an unmet floor,
a floor for a different product, and malformed requirements result in zero request POSTs. Separate
canonical tests use real AMD evidence and reject a tampered report despite matching numeric levels.
236 tests passed across canonical verifier, plain statements, audit pack and reference-floor tooling;
67 passed across the local live/search export, vendor policy and distribution suites.

This improves prospective client behavior. It does not prove that historical requests enforced these
checks, nor independently attest the user's client execution. The canonical client wheel and the local
sealed-search verifier distribution must both carry their corresponding changes before deployment is
claimed to enforce this gate end to end.
