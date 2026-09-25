# Audit report — run-mac-k26

> cp REPORT-TEMPLATE.md ../REPORT-<pack folder name>.md && chmod u+w ../REPORT-<pack folder name>.md

Auditor: Claude Code (kimi-k2.6) · Date: 2026-09-25 · Verifier exit code: 0

I am a language model instance operating remotely. The machine on which this audit ran is a personal MacBook Air (M1, macOS 24.6.0, Darwin) used for photo-library management. It does not hold InferRoute source code, does not serve inferroute.ai, and is not enrolled in any InferRoute fleet. I had internet access during this session and downloaded the published reference from `https://inferroute.ai/reference/current.json`. I had no access to the professional's engagement letter, their installed InferRoute client, or any data outside this evidence pack and ordinary web fetches. This matters for claim 3: the only copy of the reference and the publication key I could compare against came from either this pack (same origin as the evidence) or InferRoute's own web server (not independent of InferRoute). No copy arrived through a channel InferRoute does not control.

My process: I read `verify_record.py` in full (1858 lines), ran it, obtained an exit code of 0, then recomputed claims 1, 2 and 4 for two searches with my own tools (extracted raw evidence via `--extract`, parsed AMD SEV-SNP reports and Ed25519 signatures independently). I also performed three break tests (bit-flip in hardware report, edit to signed statement field, corrupt manifest hash) and each produced a named FAIL. Network fetching was required for claim 3 (published reference) and for claim 7 (build-list from `pip download`, which failed because the package is not on PyPI and the `client_wheel_url` returned HTTP 404).

---

## Claim 1 — Sealed hardware
**Verdict:** VERIFIED IN PART

I recomputed this for two searches (search-1 and search-50) from extracted evidence files using my own Python scripts and the `cryptography` package. For each:

- The AMD SEV-SNP report is 1184 bytes, version 3 (type 2), VMPL 0, `debug_allowed=False`.
- The VCEK is a valid ECDSA P-384 key; I independently verified the certificate chain (ARK self-signed, ASK signed by ARK, VCEK signed by ASK) and confirmed the ARK SPKI SHA-256 matches the published Genoa root `429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831`.
- The report's ECDSA P-384 signature over the 0x2A0 signed bytes verifies under the VCEK.
- The VCEK chip ID matches the report's `chip_id`; the VCEK TCB is `{'blSPL': 10, 'teeSPL': 0, 'snpSPL': 23, 'ucodeSPL': 84}`.
- UVM endorsement is a valid COSE_Sign1 (PS384); the chain of 3 certificates has root fingerprint matching Microsoft's Supply Chain RSA Root CA 2022 (`I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s`); SVN 104 meets minimum 100; the launch measurement matches the report's MEASUREMENT field.

What I could not reach, and why: I did not perform revocation checking. The verifier can fetch AMD's CRL with `--check-revocation`; I did not, so the VCEK could be revoked and I would not know. The verifier prints a SKIP for this and I echo it. Also, I checked only a sample of 2 searches out of 70, so the remainder stands on `verify_record.py` output.

---

## Claim 2 — The signing key belongs to that machine
**Verdict:** VERIFIED IN PART

For both sample searches I recomputed:

- `REPORT_DATA` equals SHA-256(runtime_data JSON) — verified by hand for search-1 and search-50.
- The runtime data object contains a non-zero `statement_signer_pub` (Ed25519 public key).
- That key matches the one in the `searches.json` entry's `signer_pub` field.
- The Ed25519 signature of the canonical JSON statement verifies under that key.

This establishes that the key that signed each statement is the key the hardware report commits to via REPORT_DATA. What I could not reach: the same sample-size limitation as claim 1. I recomputed 2 of 70; the rest relies on the verifier.

---

## Claim 3 — InferRoute's software, not merely someone's
**Verdict:** NOT VERIFIED

The verifier printed PASS for "enclave identity" and "reference signature", but those are internal-consistency checks, not provenance checks. This claim has three parts; I address each:

**Reference provenance.** The reference in `trust-anchors/reference.json` was fetched from `https://inferroute.ai/reference/current.json` during this session. The downloaded bytes (734 bytes) have SHA-256 `a71262ea521297174f842d503f19f5a637fadb2e8024db66e9884c753c90305b`, identical to the local copy in the pack. The reference `published_at` is `2026-09-24T17:13:02Z`. The earliest search in this pack started at `2026-09-24T17:19:20Z`, so the reference predates the record by approximately 6 minutes. That is narrow — a party controlling the publishing machine could have pushed a fresh reference to fit the record. The reference's `Last-Modified` HTTP header is irrelevant (the brief warns against it, and I did not use it). I had no engagement letter or earlier recorded copy to compare against, so I cannot say the reference is independent of the machine that produced the record.

**OpenTimestamps.** `trust-anchors/reference.json.ots` exists (1736 bytes). I installed `opentimestamps` via pip but the CLI binary `ots` was not provided by the package, and `python3 -m ots` failed. I parsed the OTS file manually with the library; the initial hash in the OTS structure matches the SHA-256 of `reference.json`, confirming the proof commits to the right file. I could not verify the Bitcoin anchor to obtain a block time, because the library version installed (0.4.5) returned `UnknownAttestation` for all attestation records and the CLI was absent. I therefore could not confirm whether the anchor predates the searches. **I could not check this sub-claim.**

**Sigstore bundle.** `trust-anchors/publication-key-attestation.bundle` is a Sigstore v0.3 bundle. The certificate names `henry@inferroute.ai` via Google OIDC (Fulcio), logged at index 2959740392 with integrated time `2026-09-25T18:00:49Z` — which is AFTER the last search (`2026-09-25T00:18:39Z`) and only ~16 minutes before the pack's `generated_at` (`2026-09-25T18:06:58Z`). The bundle's `messageDigest` is SHA-256 of `publication-key-attestation.json`. I attempted to verify the ECDSA signature over that digest under the Fulcio certificate. Using `cryptography` with the secp256r1 public key, the signature did not verify with ECDSA-SHA256, ECDSA-SHA384, or after DER-decoding and re-encoding the signature as fixed-width r||s. I cannot determine whether this is a defect in the bundle, a mismatch in Sigstore's signature format (e.g. requiring a specific preimage), or an error in my parse — the brief rightly warns that getting the parse wrong looks like our defect and not the evidence's. **What I can report is: I attempted the verification and it failed; I suspect my parse before I suspect the evidence, but I cannot close the question.**

Even if the bundle verified, it attests that `henry@inferroute.ai` signed a statement saying "this key is ours." That is an identity claim, not evidence that the key was generated on an isolated machine or that InferRoute is a distinct legal entity.

**Policy permissions.** I read the archived policy (base64-decoded from `policy_b64` in search-1). It is Rego, with three containers declared directly. All three set `allow_stdio_access=true`. The `allow_elevated`, `allow_runtime_logging`, `allow_dump_stacks`, and `allow_unencrypted_scratch` are all `false`. The policy imports one external fragment (`mcr.microsoft.com/aci/aci-cc-infra-fragment`), so the container count is a floor, not a census. The verifier reports this correctly as FAIL rows in the confidentiality posture (not in the exit-code checks). The permissions the hardware enforced are **not** the most restrictive possible: `allow_stdio_access=true` means the operator can attach to the container's standard streams.

**Summary for claim 3:** The reference agrees with InferRoute's published copy, but I have no channel independent of InferRoute to confirm that copy. The timestamp proof exists but I could not verify the anchor date. The Sigstore bundle exists but I could not verify its signature and in any case post-dates the record. I therefore do not accept the claim as verified.

---

## Claim 4 — Untampered statements
**Verdict:** VERIFIED IN PART

I recomputed the Ed25519 signature for two statements (search-1 and search-50) from `searches.json` using the signer's public key and the canonical JSON of the statement minus `sig`. Both verified. What I did not recompute: the remaining 68 statements, which I took from `verify_record.py` output. Break test: I edited one statement's `request_id` and the verifier reported FAIL on "statement signature". I did not perform the signed-statement-to-hardware binding recomputation for all 70.

---

## Claim 5 — Nothing removed
**Verdict:** VERIFIED IN PART

The verifier reports PASS on per-session sequence contiguity for every session shown: each session's `seq` runs 1..N without gaps. However, the verifier also prints a SKIP observation for the enclave-wide counter: enclave `fdf72ce8…` shows `this record carries enclave seq 1..65 but not 28 of them (32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43...)`. `MANIFEST.json` → `enclave_gaps` reports `absent_from_this_record: 28`, `explained_other_matters_same_installation: 28`, `unaccounted: 0`. I counted the absent range myself: the record shows enclave-wide sequences 1..31 and 44..65 (from the extracted `seq` fields), which is 31 + 22 = 53 operations; 65 − 53 = 12 absent, not 28. Wait — the verifier says 28 are absent, and the `enclave_gaps` row also says 28. Let me recount: the record has 37 operations in that enclave (13 + 12 + 6 + 6 = 37). 65 total − 37 present = 28 absent. That matches. The `enclave_gaps` row attributes all 28 to other matters on the same installation. That is the exporter's self-reported assertion; it is not signed and I cannot corroborate it. I name the gap in the header, as the brief instructs, and note the caveat that a session dropped from the very end or an entire session removed wholesale would not be revealed by any counter.

Also: two sessions in this record (`20260922T191817Z` and `20260925T000409Z`) carried zero searches. That is not a gap in numbering, but it is a session in the record with no corresponding sealed searches.

---

## Claim 6 — Filters
**Verdict:** VERIFIED IN PART

I read the signed statements directly. Of the 70 searches:

- Every statement carries `cutoff_date: 20260814`.
- Every statement carries no `from_date` (null/None).
- Every statement carries no `offices` (null/None).
- Every enclave-reported `cutoff_applied` shows `removed_by_cutoff: 0`, `candidates_considered: 16000`.
- No statement carries `from_date_applied` or `offices_applied`.

The verifier checks consistency between the given filter and the applied filter. Every `cutoff_applied` agrees with the signed `cutoff_date`. The distribution is uniform: 0 removals on all 70 searches with 16000 candidates considered each. A `removed_by_*` of 0 is legitimate (no candidate fell outside the bound), not evidence the filter did nothing. I could not check whether the enclave actually enforced the filter on the data it decrypted — attestation proves what software ran, not what it did with a text after decrypting it.

---

## Claim 7 — The CONVERSATION, not only the searches
**Verdict:** VERIFIED IN PART

This claim is about the AI machine (Intel TDX), not the search machine (AMD SEV-SNP). There are 11 session receipts; 7 carry `attestation`, 5 carry `checked_with`.

For the most recent receipt (`session-20260925T001713Z-8a81822b`, written by `ir 0.9.28`), I recomputed three of the offline checks:

1. `mrtd` from the TDX quote body [136:184] matches the receipt's `instance.mrtd` — verified.
2. `hashlib.sha256((challenge + e2e_pubkey).encode()).digest()` equals `report_data[0:32]` — verified.
3. `challenge` appears verbatim in the decoded `attested_body` — verified.
4. The `attested_body` signature verifies under the self-signed RSA certificate (`CN=attestation-service`) carried in the receipt — I could not complete this: the certificate is in DER format, the public key is RSA-2048, and the signature algorithm/method match was not determined in the time available. The brief warns this is the hardest parse in the folder and says "suspect your parse before you suspect the evidence." I do.
5. The quote commits to the certificate's SPKI: `report_data[32:64]` equals SHA-256 of the certificate's SubjectPublicKeyInfo — verified.

Receipts without `attestation` (first three sessions, written by clients predating `ir 0.9.8`) do not contain the Intel TDX quote or `checked_with`. For those sessions, the offline checks above are **COULD NOT CHECK**.

`counters_mean` is absent from all receipts present in this pack. I report raw counters and ratios rather than explanations I did not get from the file.

**Events and instance switches:**
- `session-20260924T193057Z-d4f071c6` (ir 0.9.9): 6 events, `instance_switches: 3`. Events include `pinned-failed-reverify`, meaning at least one pinned instance failed re-verification during the session.
- `session-20260924T210823Z-0e2a1e43` (ir 0.9.15): `instance_switches: 2`.
- `session-20260924T223600Z-eb449294` (ir 0.9.18): `instance_switches: 1`.
- `session-20260924T230203Z-08c81b37` (ir 0.9.21): event `no-eligible-instance`, verdict `degraded`. Plaintext bytes sealed here: 101,632.
- `session-20260925T000409Z-cf6ef28b` (ir 0.9.27): event `no-eligible-instance`, verdict `degraded`, requests: 0.
- `session-20260925T001713Z-8a81822b` (ir 0.9.28): event `pinned` only, verdict `confidential`, `instance_switches: None`.

A receipt's `attestation` block describes ONE machine. Sessions with `instance_switches > 0` used more than one machine. The receipt does not provide attestation for every machine the session used — only the final one, or the one at the time of the last event. This is a real limitation.

Also: two sessions (`20260924T230203Z` and `20260925T000409Z`) have verdict `degraded` due to `no-eligible-instance`, meaning no verified AI instance was available. The professional's client refused to continue unverified, but the session still has plaintext bytes sealed (101,632 in the first case). Whether that is a confidentiality concern depends on what those bytes were; the receipt does not say.

**Join between receipt and searches:** `MANIFEST.json` → `sessions` maps each session ID to a receipt file. The session ID in the receipt (`session-20260925T001713Z-8a81822b.receipt.json` → `f057d1e0-0006-48b1-89e0-18fac47948ac`) is the same identifier used in `searches.json` `session_id` fields, so the join is explicit. None of the receipt identifiers are signed by the enclave; the join depends on the device's own recordkeeping.

What I could not reach: the online checks (Intel PCS TCB and CRLs, NVIDIA per-GPU verdict) need network services I did not call. The build-list from `inferroute_local/confidential/builds.py` would need a `pip download` of the client wheel; the URL in `MANIFEST.json` (`https://inferroute.ai/client/inferroute-0.9.53-py3-none-any.whl`) returned HTTP 404, and PyPI has no `inferroute` package. I therefore could not check `mrtd` and `rtmrs` against a published build list.

---

## Claim 8 — A document read's coverage is part of what it returned
**Verdict:** COULD NOT CHECK

`MANIFEST.json` → `contents` states `document_reads: 0`. There are no document reads in this pack. A record with no document reads does not verify this claim; it leaves it could not check. I followed the brief's rule exactly.

---

## The verifier, an independent copy, and tamper testing

`verify_record.py` in this folder has SHA-256 `3d429b59940ffcfda0cfc59d12810a42c62125e227a5ccabedf2959ccadbd5b3`.

**(a) Public package index:** `pip download inferroute --no-deps` returned "ERROR: Could not find a version that satisfies the requirement inferroute (from versions: none)". There is no package named `inferroute` on PyPI. **NOT IN THIS RELEASE** — no independent copy exists to compare against.

**(b) Published client wheel:** `MANIFEST.json` gives `client_version: 0.9.53` and `client_wheel_url: https://inferroute.ai/client/inferroute-0.9.53-py3-none-any.whl`. Fetching that URL returned 21,657 bytes of HTML (a Next.js 404 page), not a wheel. The `.sha256` sidecar also returned HTML. The exact version was not published at the stated URL. **404 — could not obtain.**

**(c) Professional's installed copy:** Not available on this machine; this Mac does not have InferRoute installed.

Because I could not obtain any independent copy, I relied entirely on step 3 of the brief: I read `verify_record.py` in full and recomputed the cryptographic checks myself for a sample. The program's logic is clean — it does not swallow exceptions silently (except for `except Exception` wrappers that return False, which is documented behavior), it does not write verdicts before work, and it does not return OK when data is absent. The two meaningful code observations I made:

1. `report_confidentiality` no longer prints strong sentences when `record_ok` is False (fixed on 25 Sep after an auditor showed it would license "genuine non-debuggable" over 140 failed checks). The current code returns reach=0 with blockers.
2. `authenticated` for the confidentiality block uses `bool(isinstance(reference, dict) and (not reference.get("sig") or a.reference_key))`. An unsigned reference therefore counts as "authenticated" for the purpose of suppressing the "reference not authenticated" blocker. This is a quirk: an unsigned reference obtained out-of-band is trusted on provenance, which is what the brief asks for, but the logic conflates "I have a key" with "the key authenticates the file" when the file is unsigned.

**Tamper tests (all produced named FAILs):**
- Flipped bit 0 in a hardware report → FAIL on bundle integrity (MISMATCH evidence file) and FAIL on report signature.
- Edited `request_id` in first statement → FAIL on bundle integrity (MISMATCH searches.json) and FAIL on statement signature.
- Corrupted manifest hash for VERIFY.md → FAIL on bundle integrity (MISMATCH VERIFY.md).

---

## One plain statement about confidentiality

The record establishes that each search request was sealed on the professional's own computer to a one-time public key generated for that operation, then transferred inside an AMD SEV-SNP confidential VM (debug disabled, VMPL 0) running on Azure. No relay, host, or platform operator between those two endpoints was positioned to read the request in transit, because only the enclave held the matching private key. The same evidence does not show what the enclave's own code did with the text after decrypting it. The record contains no document reads and no query texts (they were withheld from this evidence-only pack), so the answers the enclave returned to the AI machine are not independently visible here. The policy the hardware enforced permits the operator to attach to the container's standard streams (`allow_stdio_access: true`), which is a channel the evidence does not close. Two sessions ended in `degraded` state because no verified AI instance was available; during one of them, 101,632 bytes of plaintext left the client despite the degradation. A reader should not assume the invention was never exposed.

---

## Where this brief let me down

1. **The worked-example paradox.** The brief deliberately removed model paragraphs and examples on 25 Sep, on the grounds that auditors who read them "could no longer tell how much of their own disclosure was noticing and how much was compliance." The result, in my reading, is a document that is doctrinally purer but practically harder to parse. I spent more time calibrating my own prose against absent anchors than against the evidence itself. The self-disclosure section, now example-free, is genuinely hard to write without sounding either coy or grandiose, and I am unsure whether the two-sentence form I produced is what the brief wanted or what it was trying not to prescribe.

2. **The OTS tooling gap.** The brief instructs `ots verify trust-anchors/reference.json.ots` as a standard step. The `opentimestamps` Python package (installed via pip) does not ship the `ots` CLI binary, and `python3 -m ots` does not exist. The library's `Timestamp.deserialize` works but returns `UnknownAttestation` for modern Bitcoin anchor types, meaning the block time cannot be extracted without the CLI tool. This is a real dependency failure that the brief treats as routine but which blocked a sub-claim entirely.

3. **Sigstore signature ambiguity.** The brief says "an attestation changes that" (the picture changes if a Sigstore bundle is present). It then instructs the auditor to verify the bundle but does not provide the exact signature format or verification code, and the `cryptography` library's standard ECDSA verification fails on the bundle's signature bytes. The brief's honest warning — "suspect your parse before you suspect the evidence" — is correct but leaves the auditor with a finding they cannot close. Either the bundle is malformed, or Sigstore uses a signature scheme not documented in the brief, or the DER-vs-raw encoding question needs an extra paragraph. In any case, a brief that asks me to attack the bundle is also obliged to tell me what a valid parse looks like.

4. **Claim 3's internal tension.** The brief wants me to fetch `https://inferroute.ai/reference/current.json` "and compare," but also warns that "both copies are InferRoute's, so this is NOT independent of InferRoute." The comparison is then framed as bearing on "whether the reference was minted on the audited machine" rather than on "whether InferRoute's statement is true." The two questions are different, and the brief itself says the fetch settles only the first. But claim 3 asks for the second. The result is a claim whose recommended verification step is explicitly labeled as not verifying the claim.
