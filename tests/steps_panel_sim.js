// Drives the REAL renderSteps()/markCandidates()/covered() from probant_web/app.js through the scenarios
// in test_probant_web.py. Run by that test with the repository root as the working directory.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const cut = (from, to) => {
  const i = src.indexOf(from), j = src.indexOf(to, i);
  if (i < 0 || j < 0) throw new Error(`app.js no longer contains ${i < 0 ? from : to} — update this harness`);
  return src.slice(i, j);
};
// Minimal page: a panel whose buttons we can read back, plus the state the functions use.
function el(tag, cls, text) { return { tag, cls, text, kids: [], append(...k) { this.kids.push(...k); }, addEventListener() {} }; }
const dom = { "mark-steps": { hidden: true }, "mark-steps-list": el("div"), empty: { hidden: true } };
const $ = (id) => dom[id]; const clear = (n) => { n.kids = []; };
let busy = false, ended = false; const cards = new Map(); const marks = new Map(); const markOrder = [];
const DEEPER = "Look deeper at the ones I marked relevant: search their features one at a time and find documents like them";
const LEAVE_OUT = "Continue the survey, leaving out what I marked known or not relevant";
eval(cut("  const SUMMARISE_IDEA", "  function markButtons(").replace(/\bconst\b|\blet\b/g, "var"));
const shown = () => { if (dom["mark-steps"].hidden) return "(panel hidden)";
  return dom["mark-steps-list"].kids.map((k) => k.cls === "steps-sub" ? `  [${k.text}]` : k.kids.map((b) => `    · ${b.text.slice(0, 70)}`).join("\n")).join("\n"); };
const mark = (k, v) => { marks.set(k, v); const i = markOrder.indexOf(k); if (i >= 0) markOrder.splice(i, 1); markOrder.unshift(k); };


const groups = () => dom["mark-steps"].hidden ? null : (() => { const out = []; let cur = null;
  for (const k of dom["mark-steps-list"].kids) { if (k.cls === "steps-sub") { cur = { title: k.text, steps: [] }; out.push(cur); }
    else { if (!cur) { cur = { title: "", steps: [] }; out.push(cur); } cur.steps.push(...k.kids.map((b) => b.text)); cur = null; } }
  return out; })();
const R = {};
mark("US-A1", "relevant"); renderSteps(); R.s1 = groups();
cards.set("c0", {}); renderSteps(); R.s1b = groups(); cards.clear();      // this session has searched
marksAtTurn = new Map(marks);
assistantSteps = ["Find documents like US-A1, the replay-based trainer you marked relevant", "Search the gating step on its own", "Try a broad search on sealed trace replay"];
renderSteps(); R.s2 = groups();
mark("US-B2", "relevant"); mark("US-C3", "not-relevant"); renderSteps(); R.s3 = groups();
assistantSteps = [...assistantSteps, "Search the admission gate on its own"]; renderSteps(); R.s4 = groups();
busy = true; clearNext(); R.s5 = groups();
busy = false; marks.clear(); markOrder.length = 0; assistantSteps = []; renderSteps(); R.s6 = groups();
$("empty").hidden = false; renderSteps(); R.s7 = groups();
console.log(JSON.stringify(R));
