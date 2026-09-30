// Every failure string the confidential lane can hand the page, generated the way the lane generates
// them (UPSTREAM_PUBLIC + the Refused/transport messages), run through the page's own plainModelError.
// The point is COVERAGE: before this, five of the ten provider statuses fell through to the blandest
// sentence in the function, including 402 — the one that names the actual problem.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  const MODEL_ERROR_CASES = [");
const b = src.indexOf("\n  const RETRY_TEXT", a);
if (a < 0 || b < 0) { console.error("HARNESS: plainModelError moved"); process.exit(2); }
const f = new Function("detail", `${src.slice(a, b)}\n return plainModelError(detail);`);

// verbatim from inferroute_local/confidential/session.py UPSTREAM_PUBLIC
const UP = {400:"the request was rejected as malformed",401:"our credentials were refused",
  402:"this lane is temporarily out of capacity",403:"our credentials were refused",
  404:"the model or route was not found",429:"rate-limited — try again in a minute",
  500:"the provider failed",502:"the provider failed",
  503:"the provider is temporarily unavailable",504:"the provider timed out"};
const cases = {};
for (const [st, cause] of Object.entries(UP)) cases[`provider_${st}`] = `the provider answered ${st} (${cause})`;
cases.unknownStatus   = "the provider answered 418 (no further detail)";
cases.relayUnreachable= "the relay is unreachable: the attestation service is unreachable (ConnectError)";
cases.couldNotSeal    = "could not seal the request: Refused: no fresh nonce for any verified instance";
cases.noEligible      = "the verified instance is gone and no verified alternative is available — refusing to continue unverified";
cases.notSent         = "the request could not be sent";
cases.nonceTwice      = "the provider answered 401 (our credentials were refused) — the gateway rejected our request nonce twice, including one from a fresh pool";

const out = {};
for (const [k, v] of Object.entries(cases)) out[k] = f(v);
console.log(JSON.stringify(out, null, 1));
