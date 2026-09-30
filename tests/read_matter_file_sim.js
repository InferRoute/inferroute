// The read_matter_file guard, extracted from ir-attested.ts, exercised over the calls a model actually
// makes. It blocked a real session on 2026-09-30: the tool's own promptSnippet is "Read the disclosure",
// a model took that literally and called it with NO argument, and the guard answered "undefined is
// outside the matter workspace" — an error naming a path that does not exist, about a constraint that
// was not the problem. A required argument whose only correct value is a constant is a trap, not a
// parameter.
const { resolve, relative } = require("node:path");
const DISCLOSURE = "disclosure.md";

function guard(params, root, readable) {
  const asked = String(params.path ?? "").trim() || DISCLOSURE;
  const want = resolve(root, asked);
  const rel = relative(root, want);
  if (rel.startsWith("..") || rel === "" || resolve(root, rel) !== want) return { err: "outside", asked };
  const allowed = new Set([DISCLOSURE, ...String(readable ?? "").split(",")].map((x) => x.trim()).filter(Boolean));
  if (!allowed.has(rel)) return { err: "not-allowlisted", rel };
  return { ok: rel };
}

const ROOT = "/matter/acme/cooling";
let failed = 0;
function is(got, want, what) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g !== w) { console.log(`  FAIL ${what}\n       got  ${g}\n       want ${w}`); failed++; }
  else console.log(`  ok   ${what}`);
}

// the regression: a call with no path reads the disclosure rather than erroring
is(guard({}, ROOT), { ok: DISCLOSURE }, "no path at all -> the disclosure");
is(guard({ path: undefined }, ROOT), { ok: DISCLOSURE }, "path undefined -> the disclosure");
is(guard({ path: "" }, ROOT), { ok: DISCLOSURE }, "empty path -> the disclosure");
is(guard({ path: "   " }, ROOT), { ok: DISCLOSURE }, "whitespace path -> the disclosure");

// the forms a model does use
is(guard({ path: "disclosure.md" }, ROOT), { ok: DISCLOSURE }, "plain name");
is(guard({ path: "./disclosure.md" }, ROOT), { ok: DISCLOSURE }, "dot-relative");
is(guard({ path: ROOT + "/disclosure.md" }, ROOT), { ok: DISCLOSURE }, "absolute, inside");

// THE POINT OF THE TOOL still holds: the default must not widen the allowlist
is(guard({ path: "disclosure.md.bak" }, ROOT), { err: "not-allowlisted", rel: "disclosure.md.bak" },
   "a backup is still refused");
is(guard({ path: "notes.txt" }, ROOT), { err: "not-allowlisted", rel: "notes.txt" }, "an unnamed file is refused");
is(guard({ path: "../../etc/passwd" }, ROOT), { err: "outside", asked: "../../etc/passwd" }, "climbing out is refused");
is(guard({ path: "/etc/passwd" }, ROOT), { err: "outside", asked: "/etc/passwd" }, "an absolute escape is refused");

// a named file is readable, and naming one does not unname the disclosure
is(guard({ path: "annex.md" }, ROOT, "annex.md"), { ok: "annex.md" }, "a file named for the session is readable");
is(guard({}, ROOT, "annex.md"), { ok: DISCLOSURE }, "naming a file leaves the default alone");

// the error text must name what was actually asked for, never "undefined"
const e = guard({ path: "/etc/passwd" }, ROOT);
is(String(e.asked).includes("undefined"), false, "the refusal never says 'undefined'");

console.log(failed ? `\n${failed} FAILED` : "\nall passed");
process.exit(failed ? 1 : 0);
