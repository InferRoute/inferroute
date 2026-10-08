# The relay finds and carries enclaves; the device decides whether to trust them

**Status: design, approved in direction by Henry 2026-10-08** ("hide it as much as possible and abstract it
through our backend … later we can add competitors … and run our own sealed machines … never compromise on the
strength of the verification and audit target statement").

Companion to `DESIGN-host-neutral-confidentiality-2026-09-30.md`, which is about the *coding agent* axis.
This note is about the other axis: **which enclave operator** serves the model.

## The rule that decides every placement

> **The relay is a locator and a courier, never an authority.**

Anything that only affects *which* enclave is tried, *where* bytes come from, or *what a thing is called*
may live in the relay. Anything that decides *whether an enclave is trusted* stays on the device and checks
bytes against roots the relay cannot forge:

| trusted by the device | why the relay cannot fake it |
|---|---|
| a fresh nonce the device generates | the relay never chooses it; evidence that does not commit to it fails |
| hardware vendor roots (Intel PCS, NVIDIA NRAS, AMD KDS), pinned by SPKI | vendor-signed; fetched by the device directly from the vendor |
| the binding of the sealing key and signing key into the hardware report | computed by the device from the report itself |
| InferRoute's build records | bundled in a signed release, or signed run-time additions under an offline key |

Under that rule, moving evidence fetching to the relay **costs nothing**: the relay can withhold an enclave
(availability), which it can already do today because it carries the ciphertext, but it cannot make the device
accept one. The existing docstring that said evidence is fetched "never through InferRoute" gave a reason that
was never the real one; the real one is the table above, and it is unchanged.

## What the relay takes over

1. **Provider adapters.** One adapter per operator (the current one first; others and our own fleet later),
   each mapping the neutral contract below onto that operator's API, keys, quotas and rate limits.
2. **Evidence courier.** `POST /confidential/v2/candidates {lane, nonce, want}`. The relay fetches evidence
   *with the device's nonce*, collects sealing keys and invocation nonces, and returns a candidate set.
   It unions several bounded instance draws so the candidate pool is not capped at one random sample
   (the 2026-10-07 "no verified alternative" failures), spaces requests to stay under the operator's rate
   limit, and may use authenticated per-instance evidence endpoints the device could never call itself.
   It never caches evidence across sessions: the per-session nonce is the anti-replay proof.
3. **Neutral naming.** Lanes are InferRoute names (`kimi-k2.6`, `glm-5.2`). Fleet and instance ids are
   opaque relay handles. The operator's model name is handed to the device only as the string to place
   *inside* the ciphertext; it is never displayed, logged in a receipt, or put in a model list.
4. **Build records.** Served by the relay, **signed by InferRoute's offline key**. A new operator image is
   recognised within minutes with no client release, and a compromised relay still cannot add one.
5. **Error hygiene.** No upstream URL, header name or operator wording in any error the device receives.

## What stays on the device, unchanged in strength

* Every check in `REQUIRED` + `REQUIRED_ONLINE`, run per candidate, before any byte is sealed.
* Vendor roots and collateral fetched **directly from the vendor** (Intel, NVIDIA, AMD), never via the relay.
* The bundled build list and the signature check on run-time additions; refused builds stay refused.
* The e2ee primitives.

## Attestation schemes, not operators

The device knows **schemes** — evidence shapes plus verification recipes — named neutrally:

| scheme | used by | verifier |
|---|---|---|
| `tdx-nvgpu-signed-body/v1` | the current operator | `attest.py` + `attest_intel.py` + `attest_nvidia.py` |
| `snp-aci/v1` (planned) | our own sealed machines | the vendored SEV-SNP verifier already shipping for Probant |

and **wire formats** for sealing: `mlkem768-chacha20/v1` (today), `x25519-chacha20/v1` (Probant's envelope).

A new operator that speaks an existing scheme needs **no client release**: an adapter in the relay and
signed build records. A new *evidence shape* needs a client release, because verification code must run on
the device. That is the honest boundary of "server-side abstraction", and it is the right one.

## What stays visible, stated rather than hidden

* **The evidence names its operator.** The enclave's own signing certificate is issued by the operator's CA.
  Receipts and audit packs must keep raw evidence so a third party can re-verify it, so anyone who decodes
  that certificate learns the operator. We do not surface it; we do not strip it.
* The operator's model name exists in device memory and inside the ciphertext.
* Clients released before this change keep contacting the operator directly. The v1 relay routes stay
  so they keep working.

None of these touches what is proven. The audit target statement does not change: the same checks, against
the same roots, on the same device.

## Rollout

| step | where | ships as |
|---|---|---|
| v2 routes + first adapter + candidate union + rate spacing + error scrub | relay | relay deploy (Henry's go) |
| v2 transport, scheme selector, candidate pool with refresh-before-refuse, recent-failure memory, signed quote | client | 0.9.111 (Henry signs) |
| neutral names in catalog/receipt/display/model list; wheel-wide identifier guard test | client | 0.9.111 |
| sign the build list; populate `SIGNING_KEYS` | offline key + client | 0.9.111 |
| `snp-aci/v1` scheme + own-fleet adapter | both | later |

## The v2 contract (relay ⇄ device)

All routes need the user's InferRoute key. All ids the device sees are **opaque relay handles**: deterministic
(`HMAC(server secret, operator id)`, base32, prefixed `fl_` for a lane's fleet and `in_` for an instance) so
they are stable across sessions — the device's recent-failure memory is keyed on them — and reversible only
by the relay, through a table it rebuilds on demand after a restart. No route returns an operator URL, an
operator header name, or an operator id.

`GET /confidential/v2/lanes`

    {"lanes": [{"lane": "kimi-k2.6", "fleet": "fl_…", "scheme": "tdx-nvgpu-signed-body/v1",
                "wire": "mlkem768-chacha20/v1", "sealed_model": "<string to put inside the ciphertext>",
                "context_length": 262144}]}

`POST /confidential/v2/candidates`   body `{"fleet": "fl_…", "nonce": "<64 hex, chosen by the device>"}`

    {"scheme": "tdx-nvgpu-signed-body/v1",
     "nonce_expires_in": 60,
     "instances": [{"instance_id": "in_…", "e2e_pubkey": "<b64>", "nonces": ["…"]}],   # union of bounded draws
     "evidence":  [<one row per instance, the operator's row byte-for-byte except instance_id → in_…>],
     "unavailable_instance_ids": ["in_…"],      # the operator could not produce evidence for these
     "registry": <the operator's published measurement list, verbatim>}

The evidence is fetched by the relay **with the device's nonce**, once per call, never cached across calls.
`instances` is the union of up to `CONFIDENTIAL_DRAWS` (default 3) instance listings, spaced to respect the
operator's rate limit; a listing that 429s is retried after `Retry-After` up to a bounded budget, and the
union so far is returned rather than an error once at least one listing succeeded.

`POST /confidential/v2/nonces`   body `{"fleet": "fl_…"}` — the same `instances` union and
`nonce_expires_in`, **without evidence**. Used to refill invocation nonces and find an alternative instance
among those already verified, at no evidence cost.

`POST /confidential/v2/invoke` — the sealed blob as the body; headers `X-IR-Fleet: fl_…`,
`X-IR-Instance: in_…`, `X-IR-Nonce`, `X-IR-Stream`, `X-IR-Path`. Reply streamed byte-for-byte as today.

`GET /confidential/builds` — unchanged route; rows gain `"sig"` (Ed25519 over `builds.signed_bytes(row)`,
hex) once the offline key signs them.

`POST /confidential/usage` — unchanged; `fleet_id` carries the `fl_` handle and `upstream_model` the lane name.

Errors: `{"error": {"type": "...", "message": "<neutral sentence>"}}` with the status passed through;
never an httpx string, never an upstream body.
