// The page's own plainModelError(), over the strings the confidential lane actually raises.
// Lifted verbatim from app.js. Two of these are ORDERING tests: the no-eligible-instance refusal
// contains "nonce" and arrives as a 503, so it trips the expired-key and unreachable branches by
// accident unless it is matched first.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function plainModelError(detail) {");
const b = src.indexOf("\n  const RETRY_TEXT", a);
if (a < 0 || b < 0) { console.error("HARNESS: plainModelError moved"); process.exit(2); }
const f = new Function("detail", `${src.slice(a, b)}\n return plainModelError(detail);`);
console.log(JSON.stringify({
  // verbatim from inferroute_local/confidential/session.py, returned as ("error", 503, str(e))
  capacity: f("503: the verified instance is gone and no verified alternative is available — refusing to continue unverified"),
  capacityNote: f("no-eligible-instance: pinned instance gone and no verified alternative has nonces"),
  nonceOnly: f("the nonce for this request expired"),
  unreachable: f("502 the relay is unreachable: bad gateway"),
  // the exact phrase the lane raises — "not verified" does not appear in it
  unverified: f("the enclave could not be verified"),
  rateLimited: f("429 rate limited"),
}));
