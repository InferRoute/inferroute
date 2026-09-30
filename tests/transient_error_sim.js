// The page's own isTransient(), run over the failure strings it must classify. Lifted verbatim from app.js.
// The property that matters is NEGATIVE: a machine that could not be VERIFIED must never be retried quietly,
// because that refusal is the product working and silence would train the reader to ignore it.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function isTransient(detail) {");
const b = src.indexOf("\n  const AUTO_RETRIES", a);
if (a < 0 || b < 0) { console.error("HARNESS: isTransient moved"); process.exit(2); }
const isTransient = new Function("detail", `${src.slice(a, b)}\n return isTransient(detail);`);

const out = {};
// Transport: nothing left this machine, so retrying is the honest response.
out.transient = ["enclave unreachable", "HTTP 502 Bad Gateway", "503", "504 gateway timeout",
                 "request timed out", "429 Too Many Requests", "rate limited",
                 "nonce expired", "ECONNRESET", "connection refused"].map(isTransient);
// Verification: must NEVER be quiet, including when the text also looks transient.
out.verification = ["the enclave could not be verified", "refused to seal",
                    "unreachable: refused because the machine could not be verified",
                    "502 but the enclave was not verified"].map(isTransient);
// Anything unrecognised is NOT assumed transient: an unknown failure is shown, not swallowed.
out.unknown = ["something else entirely", "", "disk full"].map(isTransient);
console.log(JSON.stringify(out));
