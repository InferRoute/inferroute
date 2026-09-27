# The 0.9.58 plain rendering exceeds the computed level

Reproduced against commit e309c40 and the real local 70-search/11-receipt pack, using the same
reference and supplied key for the old and revised verifier. Both record checks exit 0.
The reference key came from the pack; this test does not establish its independent provenance.

At computed level 0, the technical output identifies `allow_stdio_access=true` for all three
containers, yet the plain rendering says no host was in a position to read the text. The field
permits an observation channel; the evidence does not establish whether plaintext reached it.
That is enough to defeat the claim of no opportunity, without claiming that a leak occurred.
Even with all checked controls passing, the application itself can send plaintext elsewhere.
The caveat about application behavior does not make the categorical headline supported.

Two further unsupported assertions are present: “every time it answers” extrapolates the saved
statements to all answers and suggests per-answer hardware attestation/freshness; “the program is
published” appears at a level that does not check source availability or source/image correspondence.
A mapping can select precisely the correct level and still map it to false English.

The new level-0 headline is:

> The saved search statements have valid signatures linked to hardware evidence for a protected computer.

Its caveat is:

> This does not show who could read your text or verify protection of your own computer or the AI
> conversation. The program's publication and behavior were not verified.

Level 1 adds only that the recorded settings passed the listed protection checks. It does not say
that the operator could not attach, add programs, or write plaintext anywhere: the inspected controls
do not establish those universal properties. Refusal wording now describes an unavailable assurance
rather than calling every intact but insufficient or test-root record defective.

The known-phrase guard remains as a lint, explicitly not a semantic proof. Tests reproduce level 0
with host stdio permitted and absent/unverified source publication, level 1 with all checked controls
passing, and refusal from missing commitment coverage. The old implications must not reappear in
those outputs. Unknown-level refusal remains unchanged.

Validation: 195 tests passed across the plain statements, canonical verifier and audit-pack suites.
The real-pack comparison confirms the corrected output at the actual computed level. This is a local
reproduction, not a substitute for the independent mac-papa round. Published 0.9.58 and its running
round remain unchanged; the fix requires a new release artifact.
