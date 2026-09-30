// The page's own plainRefusal(), over the refusal strings the search verifier actually produces.
// Lifted verbatim from app.js. The composed text still carries a "did not verify" prefix, so these
// branches must REPLACE the sentence, and the connection case must win over the verification case.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function plainRefusal(text) {");
const b = src.indexOf("\n  // Parallel requests slip together", a);
if (a < 0 || b < 0) { console.error("HARNESS: plainRefusal moved"); process.exit(2); }
const plainRefusal = new Function("text", `${src.slice(a, b)}\n return plainRefusal(text);`);

const P = "the search enclave did not verify (search enclave reachable: ";
console.log(JSON.stringify({
  // exactly what a reaped enclave now produces, prefix and all
  absent: plainRefusal(P + "nothing answered — no connection. The search machine is probably not running; this is a connection failure, NOT a failed verification); nothing was sent"),
  junk: plainRefusal(P + "answered, but not with a usable offer (BadStatusLine) — something is listening there)"),
  // a REAL verification failure must keep saying so
  real: plainRefusal("the search enclave did not verify (container policy: HOST_DATA is not the pinned policy)"),
  declined: plainRefusal("the user declined this search"),
  unknown: plainRefusal("something nobody anticipated"),
}));
