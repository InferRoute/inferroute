// The page's own isTransient(), run over the failure strings it must classify. Lifted verbatim from app.js.
// The property that matters is NEGATIVE: a machine that could not be VERIFIED must never be retried quietly,
// because that refusal is the product working and silence would train the reader to ignore it.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
// isTransient now ASKS the classifier whether we could name the failure, instead of keeping a second
// token list that can disagree with it — so the harness must lift both, or it fails with a
// ReferenceError rather than a wrong verdict (which is how this was caught).
const cut = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) { console.error(`HARNESS: '${from}' moved`); process.exit(2); }
  return src.slice(a, b);
};
const body = cut("  const MODEL_ERROR_CASES", "\n  const RETRY_TEXT")
           + cut("  function isTransient(detail) {", "\n  const AUTO_RETRIES");
const isTransient = new Function("detail", `${body}\n return isTransient(detail);`);

const out = {};
// Transport: nothing left this machine, so retrying is the honest response.
out.transient = ["enclave unreachable", "HTTP 502 Bad Gateway", "503", "504 gateway timeout",
                 "request timed out", "429 Too Many Requests", "rate limited",
                 "nonce expired", "ECONNRESET", "connection refused"].map(isTransient);
// Verification: must NEVER be quiet, including when the text also looks transient.
out.verification = ["the enclave could not be verified", "refused to seal",
                    "unreachable: refused because the machine could not be verified",
                    "502 but the enclave was not verified"].map(isTransient);
// REVERSED 2026-09-30, deliberately. This used to assert that an unrecognised failure is NOT transient.
// Henry saw the unnamed sentence mid-session and the session then continued normally: "really i guess
// that message should not have been displayed". The default was backwards — the case we understood LEAST
// produced the loudest, most permanent output, and not recognising a sentence is a fact about our list
// rather than about severity.
//
// The concern behind the old property — an unknown failure must not be SWALLOWED — is preserved by
// AUTO_RETRIES, not by loudness: two quiet tries, then the ordinary error block. That is pinned
// separately in test_the_quiet_retry_still_reaches_the_loud_error_and_the_fresh_session, and the
// verification group above is untouched and still the line that never moves.
out.unknown = ["something else entirely", "", "disk full"].map(isTransient);
console.log(JSON.stringify(out));
