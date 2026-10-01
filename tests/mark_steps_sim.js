// The page's own markCandidates(), run over marks that outlive a sitting. Lifted verbatim from app.js.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function markCandidates(onlyNew) {");
const b = src.indexOf("\n  // Does the assistant's list already offer this", a);
if (a < 0 || b < 0) { console.error("HARNESS: markCandidates moved"); process.exit(2); }

const body = `
  const DEEPER = "look deeper"; const LEAVE_OUT = "continue, leaving out";
  const marks = new Map(o.marks); const markOrder = [...marks.keys()];
  const marksAtTurn = null;
  const cards = { size: o.cards };
  const relevantOrdered = () => markOrder.filter((k) => marks.get(k) === "relevant");
  ${src.slice(a, b)}
  return markCandidates(false);
`;
const run = (o) => new Function("o", body)(o);

const out = {};
// "known" was retired on 2026-10-01; what makes the leave-out offer appear is an EXCLUDED
// document, and the only value that excludes one is now "not relevant".
const both = [["US-A1", "relevant"], ["US-C3", "not-relevant"]];
// A fresh sitting that has never searched: marks are the matter's, not this room's.
out.emptySession = run({ marks: both, cards: 0 });
// The same marks once a survey is on screen.
out.afterSearching = run({ marks: both, cards: 2 });
// Nothing set aside: nothing to leave out, searches or not.
out.onlyRelevant = run({ marks: [["US-A1", "relevant"]], cards: 2 });
console.log(JSON.stringify(out));
