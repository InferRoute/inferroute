// The page's failure classifier over MID-STREAM failures — the ones that happen after the enclave has
// started answering. Henry, 2026-09-30, on seeing the unnamed sentence in a session that then continued
// normally: "really i guess that message should not have been displayed".
//
// Three things were true at once and each is covered below:
//   1. the lane's retry-on-another-instance is behind us once the stream starts, so these never retried
//      (`upstream_retries` read 0 across 26 sessions, one of them with 28 errors)
//   2. none of them matched MODEL_ERROR_CASES, so all showed the blandest sentence the page has
//   3. three of four did not match isTransient, so they were shown loudly and permanently
const { readFileSync } = require("node:fs");
const src = readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const cut = (a, b) => src.slice(src.indexOf(a), src.indexOf(b));
// `function` declarations hoist out of eval; a `const` does not, so UNNAMED_FAILURE is handed out
// explicitly rather than re-declared here — a copy would pass while the page said something else.
eval(cut("const MODEL_ERROR_CASES", "  // The sentence for a failure")
   + cut("  // The sentence for a failure", "const RETRY_TEXT")
   + cut("  // Failures no retry can clear.", "const AUTO_RETRIES")
   + "\nglobalThis.UNNAMED_FAILURE = UNNAMED_FAILURE;");
const { UNNAMED_FAILURE } = globalThis;

let bad = 0;
const check = (what, cond) => { if (cond) console.log(`  ok   ${what}`); else { console.log(`  FAIL ${what}`); bad++; } };

// ── the mid-stream four: quiet, because nothing went out in the clear and retrying is the answer
for (const d of [
  "the enclave's reply ended part-way through, without finishing the answer; please retry",
  "the connection to the enclave dropped mid-reply (ReadError); please retry",
  "upstream: a provider sentence nobody wrote a case for",
]) check(`quiet: ${d.slice(0, 46)}`, isTransient(d) === true);

// REVERSED, same night, after adversarial review. "could not open the enclave's reply" was in the list
// above. It is a ChaCha20-Poly1305 authentication failure against the key an Intel TDX quote committed
// to — indistinguishable from a substituted key or a substituted machine, and the only runtime sign that
// the receipt's central sentence ("No relay, and no provider, could substitute the key or the hardware
// without failing a check on this device") is being tested in anger.
//
// The check fails closed either way, so nothing is ever shown unverified. What making it quiet destroyed
// was the NOTIFICATION: a relay attempting key substitution across a fleet would have presented to a
// patent attorney as a slightly slow afternoon. A tripwire that is retried and scored is not a tripwire.
check("an unopenable reply is NEVER quiet",
      isTransient("could not open the enclave's reply: bad tag") === false);
check("...and it keeps its own plain words",
      /discarded rather than shown unverified/.test(plainModelError("could not open the enclave's reply: x")));

// three of them now have their own words for when the retries run out
check("truncated has its own sentence", plainModelError("the enclave's reply ended part-way through") !== UNNAMED_FAILURE);
check("mid-reply drop has its own sentence", plainModelError("dropped mid-reply (ReadError)") !== UNNAMED_FAILURE);
check("unopenable reply has its own sentence", plainModelError("could not open the enclave's reply: x") !== UNNAMED_FAILURE);

// ── UNRECOGNISED IS NOT SUBSTANTIVE. The default was backwards: the case we understood least produced
// the loudest output. Not recognising a sentence is a fact about this list, not about severity.
for (const d of ["something entirely novel", "", "a sentence from a future version of the lane"])
  check(`unnamed goes quiet: ${JSON.stringify(d).slice(0, 34)}`, isTransient(d) === true);

// ── AND THE EXCLUSIONS HOLD. A quiet retry here would train someone to ignore the one message that must
// always be read, so these are the cases the change had to leave alone.
for (const d of [
  "the AI machine could not be verified; refusing to continue",
  "attestation not verified",
  "verification failed: measurement mismatch",
  "unverified instance offered",
  "refused to seal: policy mismatch",
]) check(`stays loud: ${d.slice(0, 44)}`, isTransient(d) === false);

// substantive provider outcomes stay loud too — each is a decision, not a hiccup
for (const d of ["the request was rejected as malformed", "our credentials were refused"])
  check(`stays loud: ${d.slice(0, 44)}`, isTransient(d) === false);

// a nonce rejected TWICE says in its own words that retrying will not clear it. It fell into the bare
// "nonce" token and was quietly retried twice, against the advice it was about to print. Pre-existing.
check("nonce-twice is not quietly retried",
      isTransient("the gateway rejected our request nonce twice, including one from a fresh pool") === false);
// ...while an ordinary nonce expiry still is
check("an ordinary nonce expiry is still quiet", isTransient("its one-time key had expired: nonce") === true);

// a socket refusal is not a verification refusal — two senses of one word
check("connection refused is quiet", isTransient("connection refused") === true);


// ── TERMINAL: conditions no retry can clear, which must not be swallowed by the quiet default.
// These arrive as Pi's `message.errorMessage`, not as a sentence this lane wrote. Pi carries 338
// distinct error strings, so "unrecognised" is the normal case here and the quiet default is right —
// but for these three, retrying is WORSE than showing: a context overflow gets one more message added
// to the context that just overflowed, twice, while the sentence telling the reader what to do is
// hidden behind an ellipsis.
const TERMINAL_CASES = [
  "Context overflow recovery failed after one compact-and-retry attempt. Try reducing context or switching to a larger-context model.",
  "Context overflow detected, ",
  "Compaction failed: the model refused",
  "the gateway rejected our request nonce twice, including one from a fresh pool",
];
for (const d of TERMINAL_CASES) check(`terminal, never quiet: ${d.slice(0, 40)}`, isTransient(d) === false);
// and the two Pi conditions say what to do rather than falling through to the unnamed sentence
check("context overflow points at a fresh session",
      /fresh session/.test(plainModelError("Context overflow recovery failed after one compact-and-retry attempt.")));
check("compaction failure points at a fresh session",
      /fresh session/.test(plainModelError("Compaction failed: the model refused")));
// Pi's OWN truncation detection for the dialect our lane does not check is still transient
check("pi's truncated-stream message stays quiet",
      isTransient("Anthropic stream ended before message_stop") === true);
console.log(bad ? `\n${bad} FAILED` : "\nall passed");
process.exit(bad ? 1 : 0);
