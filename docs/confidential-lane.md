# The confidential lane — `ir --confidential`

> Your words are encrypted on your machine and can only be opened inside a hardware enclave
> that your machine verified itself, moments ago — not on anyone's word.

This document says exactly what that sentence means, how it is achieved, what the client
checks, and what it cannot check. The display in the terminal is rendered from the same
receipt this document describes; nothing on screen can be stronger than what is written here.

## What happens when you run it

```
ir --confidential                       # default model: kimi-k2.6
ir --confidential --model glm-5.2
ir --confidential -c                    # continue the latest session, still sealed
ir confidential show                    # re-print the last session's panel
ir confidential card                    # export the last panel as an SVG card
ir confidential models                  # models that can run confidentially
```

Inside Claude Code the model reads `kimi-k2.6 [confidential]` — the one persistent on-screen
reminder of the lane. `ir --resume` recognises a confidential session and resumes it on the
confidential lane; a sealed transcript is never replayed through the plaintext lane.

1. **Attestation, fetched by you, from the provider, with your own challenge.** The client draws
   a random 32-byte nonce and asks Chutes for the evidence of every running instance of the
   model (`GET api.chutes.ai/chutes/{id}/evidence?nonce=…`, unauthenticated). This request never
   goes through InferRoute: the point is that you do not have to trust InferRoute about it.
2. **Seven checks, on your device, no vendor SDK** (`inferroute_local/confidential/attest.py`):

   | check | what it proves |
   |---|---|
   | fresh challenge answered | your nonce is inside the signed body → made for this session, not replayed |
   | signature valid | the body is signed by the key in the instance's certificate |
   | key bound to enclave | the Intel TDX quote's `report_data[32:64]` = SHA-256 of that certificate's public key → the hardware quote commits to the signer |
   | genuine TDX, debug off | `tee_type` 0x81, quote v4, TD DEBUG attribute clear |
   | known build | MRTD + RTMR0–3 all appear in one config of the provider's published measurement registry |
   | certificate chain sound | every embedded PCK certificate verifies under the next, ending in a self-signed root |
   | **encryption key bound to enclave** | the quote's `report_data[0:32]` = SHA-256(your nonce ‖ the instance's ML-KEM public key) → the hardware quote commits to the very key your requests are sealed to |

   An instance is *verified* only if all seven pass. Fail-closed: a check that cannot be run is a
   failure, and an empty fleet is never "verified".
3. **Pin.** The session picks one instance that is both verified and able to accept sealed
   requests, and keeps it for the whole session (this also keeps the enclave's own prefix cache
   warm — measured: cache hits on turn two, invisible to anyone outside the enclave).
4. **Seal every request on your device** (`e2ee.py`): a fresh ML-KEM-768 encapsulation to the
   instance's key, HKDF-SHA256, ChaCha20-Poly1305. The response is encrypted by the enclave to
   a per-request key that also never leaves your process. The byte format is the one Chutes'
   own clients speak; it is re-implemented here so every byte can be read in one file.
5. **Translate on your device** (`translate.py`): Claude Code speaks the Anthropic Messages API;
   the enclave speaks OpenAI Chat Completions. On the normal lane InferRoute translates; on this
   lane InferRoute cannot see the request, so the client does — including tools, tool results,
   images, streaming, and reasoning (`thinking` blocks). Claude Code's `metadata.user_id` is
   dropped before sealing: the model does not need it.
6. **Relay.** The sealed blob travels `you → InferRoute → Chutes → enclave`. InferRoute's relay
   (`/confidential/invoke`) adds its provider credential and forwards bytes; it logs who, which
   model and instance, sizes, timing and status — never a body. With your own Chutes key
   (`IR_CHUTES_API_KEY`) InferRoute is not in the path at all.
7. **Receipt.** `~/.inferroute/confidential/receipts/<time>-<session>.json` records every check
   with its reason, the instance's measurements, the counters (bytes sealed here, bytes opened
   here, tokens), every pin/switch/re-verification event, and the stated limitations.

If any step fails, the session **refuses to open** and says why. It never falls back to the
normal lane silently. If the pinned instance disappears mid-session, the client switches only to
another *verified* instance and records the switch; if none exists it refuses further requests.

## What this does not prove

Rendered on screen as stated limitations, never as passed checks:

* ~~The encryption key is attributed, not attested~~ — **closed 2026-09-12.** It looked
  unbound because the obvious derivations (hash of the key, of the nonce, of both as bytes) did
  not match. Chutes' evidence service in fact derives the quote's challenge as
  `sha256((nonce + e2e_pubkey).encode())` — the nonce *string* concatenated with the base64 key
  *string* (`chutes/entrypoint/verify.py`). Confirmed live on 8/8 instances across both model
  families, with a negative result for every other instance's key. The client now fetches the
  instance keys first, verifies the quote against exactly those keys, and refuses to seal to any
  key the quote did not commit to. No change on the provider's side was needed.
* **Intel TCB / revocation are not checked** — no Intel PCS lookup; the chain is verified for
  internal soundness and its root named, not pinned to Intel's published root key.
* **GPU attestation is counted, not verified** against NVIDIA's service; its binding to the CPU
  enclave is the provider's own claim (their claim string says so).
* **Metadata is visible to relays**: message sizes, timing, model, instance id. The words are not.
* **Server-side repair heuristics are off.** The normal lane applies model-specific fix-ups
  (fenced-JSON early stops, tool-call text repairs). This lane cannot, because it cannot see the
  text. Expect slightly more rough edges on long agentic runs.

## Verified live (2026-09-12)

**Product path, deployed:** real Claude Code → `ir --confidential` → `api.inferroute.ai`
(relay image `20260912-005639-0546461`) → GLM-5.2 and Kimi-K2.6 enclaves; Bash and Read tools
ran; the relay's metadata log holds user, instance, sizes, timing — and no words.


Both TEE model families, through the encrypted path, zero errors: `moonshotai/Kimi-K2.6-TEE`
(vLLM) and `zai-org/GLM-5.2-TEE` (SGLang) — non-streaming, streaming with reasoning, and a full
tool-call round trip. Then real Claude Code, headless, through `ir --confidential`: it ran `ls`
with its Bash tool and reported the count — 3 requests, 391.8 KB sealed on-device, 0 plaintext
bytes left the machine.

## Files

```
inferroute_local/confidential/
  attest.py     evidence parsing + the six checks + LABELS/LIMITATIONS the display prints
  e2ee.py       ML-KEM-768 / HKDF / ChaCha20-Poly1305 envelope, streaming opener
  translate.py  Anthropic ⇄ OpenAI, request and streaming response
  transport.py  InferRouteRelay and DirectChutes carriers
  session.py    verify → pin → seal → open → receipt; nonce pool; re-verification; refusal
  server.py     the per-session 127.0.0.1 endpoint Claude Code talks to
  receipt.py    the receipt on disk
  display.py    the panel, the fleet table, the closing line, the SVG card
inferroute_cli/confidential.py   `ir --confidential`, `ir confidential …`
tests/test_confidential_*.py     known-positive / known-negative pairs for every layer
```

Extra dependencies: `pip install 'inferroute[confidential]'` (`cryptography>=50` bundles
ML-KEM; `kyber-py` is a pure-Python fallback the code picks up automatically).
