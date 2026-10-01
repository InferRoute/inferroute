// The page's guaranteed deep row, exercised as the professional meets it: press, press again with nothing
// changed, mark something relevant. The four deciding lines are lifted VERBATIM from app.js and assembled
// into one scope — evaluating them separately would let each `const` die in its own eval and test nothing.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const grab = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) { console.error(`HARNESS: markers moved (${from})`); process.exit(2); }
  return src.slice(a, b);
};
const keyLine = grab("const deepMarksKeyHere =", "\n");
const gateLine = grab("const deepWouldRepeat =", "\n");
const stepLine = grab("const deepStep = deepMarksAtLastPress === null", "\n");
const addLine = grab("if (searchOffered && !deepWouldRepeat", "steps: [deepStep] });") + "steps: [deepStep] });\n}";
const armLine = grab("if (ev.ok && !d.repeat && d.sent)", "\n");

const body = `
  const marks = new Map(); const markOrder = []; const DEEP = "deep";
  const searchOffered = true;
  const relevantOrdered = () => markOrder.filter((k) => marks.get(k) === "relevant");
  const DEEP_FOCUSED = "focused";
  let deepMarksAtLastPress = null;
  ${keyLine}
  const offered = () => { const groups = []; ${gateLine} ${stepLine} ${addLine}
                          return groups.length ? groups[0].steps[0] : null; };
  const press = (ev, d) => { ${armLine} };
  const mark = (k, v) => { marks.set(k, v); markOrder.push(k); };
  const out = {};
  out.beforeAnyPress = offered();
  press({ ok: true }, { sent: 6 });
  out.afterPress = offered();
  mark("US-A", "relevant");
  out.afterMarkingRelevant = offered();
  press({ ok: true }, { sent: 4 });
  out.afterSecondPress = offered();
  mark("US-B", "known");                       // not a relevance mark: the press would be identical
  out.afterMarkingKnown = offered();
  marks.delete("US-A");                        // clearing the relevant mark IS a change
  out.afterClearingTheRelevantMark = offered();
  deepMarksAtLastPress = null;
  press({ ok: true }, { repeat: true, sent: 0 });   // the tool refused an identical press: nothing ran
  out.afterRefusedRepeat = offered();
  press({ ok: false }, { sent: 0 });                // a press that failed did not cover these marks
  out.afterFailedPress = offered();

  // ORDER IS NOT A CHANGE. Two relevant marks made in either order describe the same press, because the
  // planner walks outward from a SET of documents. Without the sort, re-marking the same two in the other
  // order would offer a press that puts identical queries.
  marks.clear(); markOrder.length = 0; deepMarksAtLastPress = null;
  mark("US-C", "relevant"); mark("US-D", "relevant");
  press({ ok: true }, { sent: 8 });
  out.afterTwoRelevant = offered();
  marks.clear(); markOrder.length = 0;
  mark("US-D", "relevant"); mark("US-C", "relevant");     // same set, marked the other way round
  out.sameTwoMarkedInTheOtherOrder = offered();
  mark("US-E", "relevant");                                // a genuinely new one
  out.afterAThirdRelevant = offered();
  return out;
`;
console.log(JSON.stringify(new Function(body)()));
