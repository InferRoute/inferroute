// A name check's notes guard: the assistant may fill an empty block of disclosure.md (what the product is, the
// markets) but never rewrite the file whole or take a heading away, because the home page and the session page
// read the notes back by those headings. The block is lifted VERBATIM from ir-attested.ts and run against a fake pi.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\t\t// ── notes guard ──"), b = src.indexOf("\t\t// ── end notes guard ──");
if (a < 0 || b < 0) { console.error("HARNESS: notes guard block missing"); process.exit(2); }
const mod = path.join(os.tmpdir(), `notes_guard_${process.pid}.ts`);
fs.writeFileSync(mod, `export function install(pi: any) {\n${src.slice(a, b)}\n}\n`);
const { install } = await import(`file://${mod}`);
fs.unlinkSync(mod);
const hooks: Function[] = [];
install({ on: (n: string, f: Function) => { if (n === "tool_call") hooks.push(f); } });
const call = async (toolName: string, input: any) => { for (const h of hooks) { const r = await h({ toolName, input }); if (r) return r; } };

let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };
const P = "The product, in one or two sentences:", M = "Where you will sell it (for example France, the EU, the US):";
// 1. filling the empty product line, heading kept: allowed (both edit shapes)
if (await call("edit", { path: "disclosure.md", edits: [{ oldText: `${P}\n\n${M}`, newText: `${P}\nAn app for patent searches.\n\n${M}` }] }))
  fail("filling the product block was refused");
if (await call("edit", { path: "./disclosure.md", oldText: `${P}\n`, newText: `${P}\nAn app.\n` }))
  fail("the single-edit shape was refused");
// 2. a whole-file write: refused, and the reason says to use edit
const w = await call("write", { path: "disclosure.md", content: "An app." });
if (!w?.block || !/use edit/i.test(w.reason)) fail("a whole-file write of the notes was not refused");
// 3. an edit that drops a heading: refused, naming it
const d = await call("edit", { path: "disclosure.md", edits: [{ oldText: `${P}\n`, newText: "Product: an app\n" }] });
if (!d?.block || !d.reason.includes(P)) fail("an edit that removes a heading was not refused");
// 4. other files are not this guard's business
if (await call("write", { path: "name-check.md", content: "# Report" })) fail("name-check.md was caught by the notes guard");
if (bad) process.exit(1);
console.log("notes guard: fill allowed, rewrite and lost heading refused");
