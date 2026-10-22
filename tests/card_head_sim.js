// Drives the REAL refreshCardSummary()/shortAbout() from probant_web/app.js: what a folded search card's head
// says. Run by test_probant_web.py with the repository root as the working directory.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const fn = (name) => {
  const i = src.indexOf(`  function ${name}(`);
  if (i < 0) throw new Error(`app.js no longer has function ${name} — update this harness`);
  return src.slice(i, src.indexOf("\n  }\n", i) + 4);
};
const marks = new Map(); const searchesByNo = new Map(); const cards = new Map();
const shownByNo = new Map(); const shownNo = (no) => shownByNo.get(no) || no;
function outlineUpdate() {}
eval(fn("shortAbout") + fn("refreshCardSummary") + fn("renumber"));
const node = () => ({ textContent: "", hidden: false });
searchesByNo.set(1, { about: "A wrist worn device measuring blood glucose with near infrared light" });
searchesByNo.set(2, { about: "Routing by permission" });
searchesByNo.set(3, { about: "Ledger of what has been drawn governs the budget" });
searchesByNo.set(5, { about: "Escalation beyond permission" });
const docs = [["US-1", 2], ["US-2", 2], ["US-3", 2], ["US-4", 3], ["US-5", 3], ["US-6", 1], ["US-7", 5], ["US-8", 0], ["US-9", 0]];
const entry = { sub: node(), notes: node(), n: docs.length, fresh: docs.filter(([, a]) => !a).length, keys: docs.map(([k]) => k),
                overlap: new Map() };
for (const [, a] of docs) if (a) entry.overlap.set(a, (entry.overlap.get(a) || 0) + 1);
marks.set("US-1", "relevant"); marks.set("US-8", "relevant"); marks.set("US-4", "not-relevant");
refreshCardSummary(entry);
const withMarks = { sub: entry.sub.textContent, notes: entry.notes.textContent, hidden: entry.notes.hidden };
const lone = { sub: node(), notes: node(), n: 10, fresh: 10, keys: [], overlap: new Map() };
refreshCardSummary(lone);
const naming = { known: shortAbout(2), long: shortAbout(1), unknown: shortAbout(9) };
// Numbering in PAGE order (21 Oct audit: "Search 4, 5, 3, 7, 6"). Five cards appear in this order; the extension
// numbered them as they completed. One was not sent; a survey's two queries sit between the others.
const card = (searchNo, failed) => ({ searchNo, failed, title: node(), outline: { which: node() } });
const legs = [{ searchNo: 6, paint() { this.painted = this.shown; } }, { searchNo: 4, paint() { this.painted = this.shown; } }];
cards.set("a", card(3)); cards.set("b", card(0)); cards.set("c", card(0, true));
cards.set("d", { deep: true, legs }); cards.set("e", card(5));
renumber();
const order = { titles: ["a", "b", "c", "e"].map((k) => cards.get(k).title.textContent),
                index: ["a", "b", "c", "e"].map((k) => cards.get(k).outline.which.textContent),
                legs: legs.map((l) => l.painted), alsoIn6: shortAbout(6) };
console.log(JSON.stringify({ withMarks, lone: { sub: lone.sub.textContent, hidden: lone.notes.hidden }, naming, order }));
