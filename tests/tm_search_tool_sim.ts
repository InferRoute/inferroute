// What the assistant is shown by one trademark search, and what its report may then cite. Since grouping, a name
// filed more than once is one hit with its other filings under "also"; the tool text must show them, count names
// and filings each in one unit, and let the report cite an "also" filing. The tool block and the report-check block
// are lifted VERBATIM from ir-attested.ts and run against a fake pi and a stubbed host search.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const lift = (from: string, to: string) => {
  const a = src.indexOf(from), b = src.indexOf(to);
  if (a < 0 || b < 0) { console.error(`HARNESS: block missing: ${from}`); process.exit(2); }
  return src.slice(a, b);
};
const tool = lift("\t\t// ── trademark search tool ──", "\t\t// ── end trademark search tool ──");
const check = lift("\t\t// ── report check ──", "\t\t// ── end report check ──");
const mod = path.join(os.tmpdir(), `tm_search_tool_${process.pid}.ts`);
fs.writeFileSync(mod, `export function install(pi: any, ENDPOINT: string, ENDPOINT_KEY: string, Type: any, Box: any, Text: any) {\n` +
  `${tool}\n${check}\nreturn tmReturned;\n}\n`);
const { install } = await import(`file://${mod}`);
fs.unlinkSync(mod);

const tools: Record<string, any> = {}; const hooks: Record<string, Function[]> = {};
const pi = { registerTool: (t: any) => { tools[t.name] = t; }, on: (n: string, f: Function) => { (hooks[n] ??= []).push(f); } };
const Type = new Proxy({}, { get: () => (..._a: any[]) => ({}) });
class Box { kids: any[] = []; constructor(..._a: any[]) {} addChild(c: any) { this.kids.push(c); } }
class Text { text: string; constructor(text: string, ..._a: any[]) { this.text = text; } }
const tmReturned = install(pi, "http://host", "k", Type, Box, Text);

let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };
const hit = (reg: string, num: string, text: string, also: any[] = []) => ({ register: reg, number: num, text, status: "registered",
  classes: ["9"], filed: "", reasons: ["same spelling"], overlapping_classes: [], ...(also.length ? { also } : {}) });
const filing = (reg: string, num: string) => ({ register: reg, number: num, text: "FESTO", status: "registered", classes: ["7"] });
const also = [filing("FR", "5000001"), ...[2, 3, 4, 5, 6, 7, 8].map((i) => filing("US", `9000000${i}`))];  // 8 filings
let reply: any = {};
(globalThis as any).fetch = async () => ({ ok: true, json: async () => reply });
const search = async () => tools["trademark_search"].execute("id", { name: "Festo" }, undefined);

// 1. Two names, one with 8 more filings; 3 more names past the shown ones; 14 filings in all, more than 5 names.
reply = { name: "Festo", classes: [], hits: [hit("US", "80000001", "FESTO", also), hit("US", "80000002", "FESTOOL")], more: 3, filings: 14 };
const r1 = await search(); const t1: string = r1.content[0].text;
const line = t1.split("\n").find((l) => l.startsWith("  also filed as:")) ?? "";
if (!line.includes("FR 5000001 (registered, classes 7)")) fail("the first also-filing is not shown: " + line);
if (!line.includes("US 90000006") || line.includes("US 90000007")) fail("not exactly the first six also-filings: " + line);
if (!line.endsWith("; and 2 more")) fail("the tail of the also-filings is missing: " + line);
if (!t1.includes("(3 more names, less close)")) fail("more is not counted in names");
if (!t1.includes("(14 filings under these names in all)")) fail("the filings total is missing when filings > names");
if (r1.details.filings !== 14) fail("details does not carry the filings");
const shown = tools["trademark_search"].renderResult(r1, {}, { bold: (s: string) => s, bg: (_c: string, s: string) => s }).kids[0].text;
if (!shown.includes("2 close name(s) (+3) (14 filings)")) fail("the panel line: " + shown);

// 2. Filings equal to names: no filings clause, in the text or on the panel.
reply = { name: "Solo", classes: [], hits: [hit("US", "80000003", "SOLO")], more: 1, filings: 2 };
const r2 = await search();
if (r2.content[0].text.includes("filings")) fail("a filings clause shown when filings = names");
if (tools["trademark_search"].renderResult(r2, {}, { bold: (s: string) => s, bg: (_c: string, s: string) => s }).kids[0].text.includes("filings"))
  fail("the panel shows filings when filings = names");

// 3. Every also-filing may be cited; a number no search returned still may not.
for (const f of also) if (!tmReturned.has(`${f.register} ${f.number}`)) fail(`not returned to the report check: ${f.register} ${f.number}`);
const write = async (content: string) => {
  for (const f of hooks.tool_call ?? []) { const r = await f({ toolName: "write", input: { path: "name-check.md", content } }); if (r?.block) return r; }
  return undefined;
};
if (await write("## Festo\n- FESTO (US 90000008, registered, class 7): same spelling, filed again.\n"))
  fail("a report citing an also-filing (the 8th, not shown in the line) was refused");
const refused = await write("## Festo\n- FESTO (US 91234567, registered, class 7)\n");
if (!refused || !refused.reason.includes("US 91234567")) fail("a number no search returned was not refused");

if (bad) process.exit(1);
console.log("trademark search tool: also-filings shown (six and a tail), names and filings counted apart, every filing citable");
