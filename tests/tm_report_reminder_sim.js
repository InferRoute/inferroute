// A name session that searches and then stops without writing name-check.md gets ONE reminder (measured on a
// Mac on 19 Oct: seven searches, "Now writing the report…", and the turn ended). Runs the real block from
// ir-attested.ts against a fake pi.
import fs from "fs";

const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\t\tconst TM_REMIND");
const b = src.indexOf("\t\t// ── end report reminder ──");
if (a < 0 || b < 0) { console.error("HARNESS: the report reminder moved"); process.exit(2); }

const hooks = {};
const sent = [];
const pi = { on: (n, f) => { (hooks[n] ??= []).push(f); }, sendUserMessage: (t) => { sent.push(t); } };
new Function("pi", src.slice(a, b))(pi);
const emit = async (n, e = {}) => { for (const f of hooks[n] ?? []) await f(e); };
const input = (text) => emit("input", { text, source: "interactive" });
const tool = (toolName, input = {}) => emit("tool_call", { toolName, input });

let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };

// 1. Searched, wrote nothing: exactly one reminder, naming the file.
await input("check Anteriora");
await tool("trademark_search", { name: "Anteriora" });
await emit("agent_settled");
if (sent.length !== 1 || !/name-check\.md/.test(sent[0])) fail(`one reminder expected, got ${JSON.stringify(sent)}`);
// The reminder arrives as input itself; it must not reset the round, so a second stop is NOT reminded again.
await input(sent[0]);
await emit("agent_settled");
if (sent.length !== 1) fail("a model that will not write must not be reminded in a loop");

// 2. Searched and wrote the report (any path ending in name-check.md, write or edit): no reminder.
sent.length = 0;
await input("check Priorsight");
await tool("trademark_search", { name: "Priorsight" });
await tool("write", { path: "/m/Test/brand/name-check.md" });
await emit("agent_settled");
if (sent.length) fail("a round that wrote the report must not be reminded");

// 3. Controls: no search ⇒ no reminder; another file written ⇒ still reminded; a new question re-arms it.
sent.length = 0;
await input("what classes fit a SaaS?");
await emit("agent_settled");
if (sent.length) fail("a round with no search must not be reminded");
await input("search Foo");
await tool("trademark_search", { name: "Foo" });
await tool("write", { path: "notes.md" });
await tool("write", { path: "name-check.md.bak" });
await emit("agent_settled");
if (sent.length !== 1) fail("writing some other file is not writing the report");

if (bad) process.exit(1);
console.log("report reminder: one reminder after search-without-report; none after a report, none without a search; no loop");
