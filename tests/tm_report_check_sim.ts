// rc 0.9.125 e2e (D2, shots 16, 25): the first draft of name-check.md carried mark details no search had returned,
// and the assistant told the founder "I fabricated mark details in my first draft". The extension now checks the
// report against what this session's searches returned BEFORE it is written. The block is lifted VERBATIM from
// ir-attested.ts and run against a fake pi.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\t\t// ── report check ──");
const b = src.indexOf("\t\t// ── end report check ──");
if (a < 0 || b < 0) { console.error("HARNESS: the report-check block is missing"); process.exit(2); }
const mod = path.join(os.tmpdir(), `tm_report_check_${process.pid}.ts`);
fs.writeFileSync(mod, `export function install(pi: any, tmReturned: Map<string, any>) {\n${src.slice(a, b)}\n}\n`);
const { install } = await import(`file://${mod}`);
fs.unlinkSync(mod);
const hooks: Record<string, Function[]> = {};
const returned = new Map<string, any>([
  ["US 78844430", { status: "registered", classes: ["42"] }],
  ["US 99312660", { status: "pending", classes: ["9", "42"] }],
  ["FR 5125110", { status: "registered", classes: ["30", "32", "43"] }],
]);
install({ on: (n: string, f: Function) => { (hooks[n] ??= []).push(f); } }, returned);
const call = async (toolName: string, input: any) => {
  for (const f of hooks.tool_call ?? []) { const r = await f({ toolName, input }); if (r?.block) return r; }
  return undefined;
};
let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };

// 1. A faithful report is written.
const good = "## Brewlio\n- BREW (US 78844430, registered, class 42): is part of your name, in your classes.\n" +
  "- BREW (US 99312660, pending, classes 9, 42)\n## Teavora\n- teavora (FR 5125110, registered, classes 30, 32, 43): same spelling.\n";
if (await call("write", { path: "/m/Personal/kettle-names/name-check.md", content: good })) fail("a faithful report was refused");

// 2. A number no search returned, a wrong status, a class the mark does not have: refused, each named, and the
//    refusal tells the assistant not to narrate the correction.
const bad1 = good.replace("US 99312660, pending", "US 99312660, registered").replace("classes 30, 32, 43", "classes 11, 30") +
  "- BRAILLIO (US 97583472, registered, class 42)\n";
const r = await call("write", { path: "name-check.md", content: bad1 });
if (!r) fail("a report citing an unreturned mark was written");
else {
  for (const want of ["US 97583472: no search in this session returned", "US 99312660: the search gives its status as pending",
                      "FR 5125110: class 11 is not among"]) if (!r.reason.includes(want)) fail(`refusal does not name: ${want}`);
  if (!/do not mention it/.test(r.reason)) fail("the refusal must say not to narrate the check to the founder");
}

// 3. An edit is checked on the text it puts in; other files are not checked at all.
if (!(await call("edit", { path: "name-check.md", edits: [{ oldText: "x", newText: "ZEBRA (US 12345678, registered)" }] })))
  fail("an edit adding an unreturned mark was not refused");
if (await call("edit", { path: "name-check.md", edits: [{ oldText: "x", newText: "BREW (US 78844430, registered)" }] }))
  fail("an edit citing a returned mark was refused");
if (await call("write", { path: "notes.md", content: "US 12345678" })) fail("only the report is checked");

// 4. EU marks: cited as EU, EUIPO or EUTM, with or without EUIPO's leading zeros. A real one is status-checked, an
//    invented one refused, and "EU 27" in prose is not a citation.
returned.set("EU 275933", { status: "registered", classes: ["9"] });
if (await call("write", { path: "name-check.md", content: "- FESTO (EUTM 000275933, registered, class 9)\n- FESTO (EU 275933). The EU 27.\n" }))
  fail("a faithful EU citation was refused");
const eu = await call("write", { path: "name-check.md", content: "- FESTO (EU 275933, pending)\n- FESTI (EUIPO 018999999, registered)\n" });
if (!eu) fail("a wrong EU status and an invented EU number were written");
else for (const want of ["EU 275933: the search gives its status as registered", "EU 18999999: no search in this session returned"])
  if (!eu.reason.includes(want)) fail(`refusal does not name: ${want}`);

// 5. After a token that only names the EU register, a short number is checked too: an invented one is refused.
for (const cite of ["EUTM 000004321", "EUTM 4321", "EU trade mark 4321"]) {
  const r5 = await call("write", { path: "name-check.md", content: `- FESTO (${cite}, registered)\n` });
  if (!r5 || !r5.reason.includes("EU 4321: no search in this session returned")) fail(`an invented ${cite} was not refused`);
}

if (bad) process.exit(1);
console.log("report check: a faithful report is written; an unreturned number, a wrong status or class is refused, quietly");
