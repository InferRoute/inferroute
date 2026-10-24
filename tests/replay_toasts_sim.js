// rc 0.9.125 e2e (D8): a reopened session replayed its old notices as toasts ("retrying…", "your report is ready"),
// and a reading that succeeded after two failures still said "This session keeps failing to reach the AI machine…
// Start a fresh session". Drives the real handle()/toast() and resolveErrors() from probant_web/app.js.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
function cut(start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a + 1);
  if (a < 0 || b < 0) { console.error(`HARNESS: ${start.trim()} moved`); process.exit(2); }
  return src.slice(a, b);
}
const shown = [];
const container = { append: (t) => shown.push(t.text) };
const $ = () => container;
function node(cls, ...kids) {
  const n = { cls: new Set(String(cls).split(" ")), text: kids.filter((k) => typeof k === "string").join(""), kids: [], isConnected: true,
    parent: null,
    remove() { if (n.parent) n.parent.kids.splice(n.parent.kids.indexOf(n), 1); n.isConnected = false; },
    append(...xs) { for (const x of xs) if (x && typeof x === "object") { x.parent = n; n.kids.push(x); } },
    classList: { add: (c) => n.cls.add(c) },
    querySelectorAll(sel) {
      const want = sel.split(",").map((x) => x.trim().replace(/^\./, ""));
      const out = []; const walk = (m) => { for (const k of m.kids) { if (want.some((w) => k.cls.has(w))) out.push(k); walk(k); } };
      walk(n); return out;
    } };
  n.append(...kids);
  return n;
}
const el = (tag, cls, ...kids) => node(cls || "", ...kids);
const setTimeout = () => 0;
let lastEventAt = 0;
const events = [];
const code = cut("  const recentToasts = new Map();", "  // Back to the home page")
  + cut("  function handle(ev) {", "  function handleEvent(ev) {")
  + "function handleEvent(ev) { events.push(ev.kind); if (ev.kind === \"notify\") toast(ev.message, ev.level); }\n"
  + cut("  let openErrors = [];", "  function showError(detail) {");
// Sloppy-mode eval hoists functions and vars into this scope; `let`/`const` would stay inside the eval.
eval(code.replace(/^  (let|const) /gm, "  var "));

let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
openedAt = 10_000;
handle({ kind: "notify", message: "The AI machine didn't answer; retrying…", at: 5_000 });
handle({ kind: "notify", message: "Your name-check report is ready.", at: 8_000 });
if (shown.length) fail(`notices from before the page opened must not pop up again: ${JSON.stringify(shown)}`);
if (events.length !== 2) fail("replayed events are still handled (the transcript is rebuilt from them)");
handle({ kind: "notify", message: "A new notice", at: 12_000 });
if (shown.length !== 1) fail("a notice that happens while the page is open is shown");
if (replaying) fail("the replay flag must not outlive the event");

// Two failures, then an answer: the "start a fresh session" advice goes, the failures stay as history.
const err = (n) => node("msg-error", node("", `failure ${n}`), node("sub err-hint", "This session keeps failing to reach the AI machine."),
                        node("row err-actions", node("primary small", "Start a fresh session on this matter")));
const e1 = err(1), e2 = err(2);
openErrors.push(e1, e2);
resolveErrors();
for (const e of [e1, e2]) {
  if (e.querySelectorAll(".err-actions, .err-hint").length) fail("the advice to start afresh must go once an answer got through");
  if (!e.cls.has("resolved") || !e.kids.some((k) => /answered after this/.test(k.text))) fail("the failure says it was followed by an answer");
}
if (openErrors.length) fail("resolved failures are not resolved twice");
if (bad) process.exit(1);
console.log("replay: no old notices pop up again; an answer resolves the failures before it");
