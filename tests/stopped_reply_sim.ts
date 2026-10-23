// After Stop, the next request must not carry two user messages in a row. Pi drops an "aborted" (or "error")
// assistant message from what it sends the model; the extension's `context` hook keeps it as a closed reply.
// The block is lifted VERBATIM from ir-attested.ts and run against a fake pi, then fed through the same rule
// Pi applies afterwards (an aborted/error assistant message is skipped), so the check is on what reaches the model.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\t// ── a stopped reply stays in the conversation ──");
const b = src.indexOf("\t// ── end stopped reply ──");
if (a < 0 || b < 0) { console.error("HARNESS: the stopped-reply block is missing"); process.exit(2); }
const mod = path.join(os.tmpdir(), `stopped_reply_${process.pid}.ts`);
fs.writeFileSync(mod, `export function install(pi: any) {\n${src.slice(a, b)}\n}\n`);
const { install } = await import(`file://${mod}`);
fs.unlinkSync(mod);
const hooks: Record<string, Function[]> = {};
install({ on: (n: string, f: Function) => { (hooks[n] ??= []).push(f); } });
if (!hooks.context?.length) { console.error("FAIL: no context hook"); process.exit(1); }
const context = async (messages: any[]) => {
  let cur = structuredClone(messages);
  for (const f of hooks.context) { const r = await f({ type: "context", messages: cur }); if (r?.messages) cur = r.messages; }
  return cur;
};
// What Pi does next (pi-ai transformMessages): an aborted or errored assistant message is not sent at all.
const sent = (ms: any[]) => ms.filter((m) => !(m.role === "assistant" && (m.stopReason === "aborted" || m.stopReason === "error")));
const roles = (ms: any[]) => ms.map((m) => m.role).join(",");

let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };
const user = (t: string) => ({ role: "user", content: [{ type: "text", text: t }] });

// 1. Stopped while thinking: no text yet. The stopped turn still closes, so the roles alternate.
let out = sent(await context([user("List 12 features"),
  { role: "assistant", stopReason: "aborted", errorMessage: "Request aborted", content: [{ type: "thinking", thinking: "The user wants" }] },
  user("In one sentence: the core idea?")]));
if (roles(out) !== "user,assistant,user") fail(`stopped while thinking: ${roles(out)}`);
else if (!/stopped this reply/.test(out[1].content[0].text)) fail("the closed reply must say it was stopped");

// 2. Stopped while writing, with a half-written tool call: the text is kept, the thinking and tool call are not.
out = sent(await context([user("Write an essay"),
  { role: "assistant", stopReason: "aborted", content: [{ type: "thinking", thinking: "plan" }, { type: "text", text: "The history of the cold chain begins" },
    { type: "toolCall", id: "c1", name: "read", arguments: {} }] },
  user("In one word: powered?")]));
if (roles(out) !== "user,assistant,user") fail(`stopped while writing: ${roles(out)}`);
const blocks = out[1]?.content ?? [];
if (blocks.length !== 1 || blocks[0].type !== "text" || !blocks[0].text.startsWith("The history of the cold chain begins")) fail(`kept text: ${JSON.stringify(blocks)}`);
if ("errorMessage" in out[1]) fail("the closed reply must not carry an error");

// 3. Ended on an error (not retried): closed too, and said differently.
out = sent(await context([user("q"), { role: "assistant", stopReason: "error", errorMessage: "x", content: [] }, user("q2")]));
if (roles(out) !== "user,assistant,user" || !/error/.test(out[1].content[0].text)) fail("an errored reply must be closed as one");

// 4. A complete history is left exactly as it is.
const whole = [user("q"), { role: "assistant", stopReason: "stop", content: [{ type: "text", text: "a" }] }, user("q2")];
const r = await hooks.context[0]({ type: "context", messages: whole });
if (r !== undefined) fail("a history with nothing interrupted must not be rewritten");

if (bad) process.exit(1);
console.log("stopped reply: kept and closed; roles alternate after Stop; untouched otherwise");
