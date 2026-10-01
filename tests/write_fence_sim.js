// Henry, 2026-10-01: "cant we just limit read access at the agent level?" — reading already was
// (`read`/`grep` withheld for read_matter_file, and no shell, so no second route to a file). WRITING was
// not: `edit` and `write` are Pi's built-ins, and the only thing stopping a write outside the matter was
// LANDLOCK, which is Linux-only. That is what made macOS look unsupportable rather than merely missing a
// backstop. This is the tool-level half.
import fs from "fs";
import os from "os";
import path from "path";

const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\tconst WRITE_TOOLS = new Set");
const b = src.indexOf("\n\t});\n", src.indexOf('pi.on("tool_call"', a)) + 5;
if (a < 0 || b < 5) { console.error("HARNESS: the write fence moved"); process.exit(2); }

// A real matter folder, a real file outside it, and a real symlink out of it.
const root = fs.mkdtempSync(path.join(os.tmpdir(), "matter-"));
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "elsewhere-"));
fs.writeFileSync(path.join(root, "disclosure.md"), "the invention");
fs.writeFileSync(path.join(outside, "secret.txt"), "another client");
fs.symlinkSync(outside, path.join(root, "escape"));
process.chdir(root);

const hooks = {};
const pi = { on: (n, f) => { hooks[n] = f; } };
// The block is TypeScript; strip the annotations this harness cannot parse, without touching the logic.
const body = src.slice(a, b)
  .replace(/function insideMatter\(target: string\): boolean/, "function insideMatter(target)")
  .replace(/const rest: string\[\] = \[\];/, "const rest = [];")
  .replace(/\(event as \{ input\?: \{ path\?: unknown \} \}\)/, "event");
new Function("pi", "TOOLS", "NEXT_STEPS_TOOL", "realpathSync", "resolve", "dirname", "basename", "sep",
  body
)(pi, new Set(["edit", "write", "ls"]), "suggest_next_steps",
  fs.realpathSync, path.resolve, path.dirname, path.basename, path.sep);

const call = async (toolName, p) => await hooks.tool_call({ toolName, input: p === undefined ? {} : { path: p } });
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
const blocked = (r) => r && r.block === true;

// ALLOWED: the matter's own files — the real case, the professional asking for an edit to their disclosure.
if (blocked(await call("write", "disclosure.md"))) fail("a file in the matter must be writable");
if (blocked(await call("edit", path.join(root, "notes.md")))) fail("an absolute path inside the matter must be writable");
if (blocked(await call("write", "sub/new.md"))) fail("a new file in a subfolder must be writable");

// REFUSED: outside, by every route.
if (!blocked(await call("write", path.join(outside, "secret.txt")))) fail("an absolute path outside the matter must be refused");
if (!blocked(await call("write", "../elsewhere/x.txt"))) fail("climbing out with ../ must be refused");
if (!blocked(await call("edit", "escape/secret.txt"))) fail("a SYMLINK out of the matter must be refused — resolving the string alone would miss it");
if (!blocked(await call("write", os.homedir() + "/.bashrc"))) fail("the home directory must be refused");
if (!blocked(await call("write", undefined))) fail("a call with no path must be refused, not waved through");

// The refusal must say what happened and that nothing was written.
const r = await call("write", path.join(outside, "secret.txt"));
if (!/outside it/.test(r.reason) || !/Nothing was written/.test(r.reason)) fail("the refusal must be legible: " + r.reason);

// CONTROLS: the fence must not touch anything else.
if (blocked(await call("ls", "/etc"))) fail("ls is deliberately unfenced — seeing that a file exists is not reading it");
if (!blocked(await call("bash", "x"))) fail("the allowlist block must still work");

if (bad) process.exit(1);
console.log("write fence: matter writable, outside refused via path, .., symlink and home; ls untouched");
