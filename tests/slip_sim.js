// Drives the REAL recordSlip() from probant_web/app.js over a tiny DOM: ten parallel searches whose malformed
// requests come back OUT of order must end as ONE line. Run by test_probant_web.py from the repository root.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const i = src.indexOf("  function recordSlip(");
if (i < 0) throw new Error("app.js no longer has recordSlip — update this harness");
const kids = [];                                   // the conversation, as a flat list of nodes
function node(cls) {
  const n = { cls: new Set(cls.split(" ")), text: "", slipCount: undefined, counter: null,
    classList: { contains: (c) => n.cls.has(c) },
    get previousElementSibling() { return kids[kids.indexOf(n) - 1] || null; },
    get nextElementSibling() { return kids[kids.indexOf(n) + 1] || null; },
    remove() { kids.splice(kids.indexOf(n), 1); },
    replaceWith(m) { kids.splice(kids.indexOf(n), 1, m); },
    querySelector() { return n.counter; } };
  return n;
}
function el(tag, cls) { const n = node(cls); if (cls === "step slip") n.counter = { textContent: "" }; return n; }
eval(src.slice(i, src.indexOf("\n  }\n", i) + 4));
kids.push(node("msg-user"));
const cards = Array.from({ length: 10 }, () => { const c = node("card"); kids.push(c); return c; });
kids.push(node("card ok"));                         // a search that succeeded, after them
for (const k of [3, 0, 9, 5, 1, 2, 8, 4, 7, 6]) recordSlip(cards[k]);
const first = kids.filter((n) => n.cls.has("slip"));
// A message is a new moment: a later slip does not fold into the earlier run.
kids.push(node("msg-assistant"));
const late = node("card"); kids.push(late); recordSlip(late);
const slips = kids.filter((n) => n.cls.has("slip"));
console.log(JSON.stringify({ lines: first.length, count: first[0] && first[0].counter.textContent,
  total: kids.length, afterMessage: slips.length, lateCount: slips[1] && slips[1].counter.textContent }));
