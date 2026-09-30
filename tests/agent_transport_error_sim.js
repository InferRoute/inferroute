// The one string Henry actually saw, taken off the live SSE stream on 2026-09-30:
//
//     {"stopped":"error","error":"Connection error."}
//
// It is the OpenAI Node SDK's APIConnectionError default message, raised when the agent's fetch to
// THIS MACHINE's verifying proxy throws — so the request never reached the sealing step, and the
// session's own receipt correctly recorded 7 requests and 0 errors while the page showed a failure.
//
// Two things have to hold for that reading to be honest:
//   * the page NAMES it, rather than falling through to the sentence for a failure we could not name;
//   * it is TRANSIENT, so the page retries quietly instead of handing over a red block.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");

const a = src.indexOf("  const MODEL_ERROR_CASES = [");
const b = src.indexOf("\n  const RETRY_TEXT", a);
const c = src.indexOf("  const TERMINAL = [");
const d = src.indexOf("\n  const AUTO_RETRIES", c);
if (a < 0 || b < 0 || c < 0 || d < 0) { console.error("HARNESS: the classifier moved"); process.exit(2); }
const body = src.slice(a, b) + "\n" + src.slice(c, d);
const name = new Function("detail", `${body}\n return plainModelError(detail);`);
const quiet = new Function("detail", `${body}\n return isTransient(detail);`);
const UNNAMED = "The AI machine did not complete this request, and nothing was sent in the clear.";

// Every shape a JS HTTP client produces for "the socket died": the SDK's own wording, plus what
// undici surfaces when the peer resets, half-closes, or the relay tears the pair down.
const cases = ["Connection error.", "ECONNRESET", "socket hang up", "fetch failed", "write EPIPE"];
let bad = 0;
for (const c2 of cases) {
  const s = name(c2);
  if (s === UNNAMED) { console.error(`UNNAMED: ${c2}`); bad++; }
  if (!quiet(c2)) { console.error(`NOT QUIET: ${c2}`); bad++; }
  // The sentence must not claim the AI machine did anything: it never saw the request.
  if (!/never saw it|never left|before the request left/.test(s)) {
    console.error(`WRONG CAUSE: ${c2} -> ${s}`); bad++;
  }
}

// A CONTROL, so this file cannot pass by naming everything transient. A machine that could not be
// verified is never quiet, and a connection failure must not have widened that hole.
if (quiet("the enclave could not be verified")) { console.error("CONTROL FAILED: verification went quiet"); bad++; }
if (quiet("could not open the enclave")) { console.error("CONTROL FAILED: unopenable reply went quiet"); bad++; }

if (bad) process.exit(1);
console.log(`all ${cases.length} transport shapes named and quietly retried; 2 controls held`);
