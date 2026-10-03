// renderSteps() as the professional meets it, lifted VERBATIM from app.js and run against three states.
//
// The question is the one Henry asked on 1 Oct: does the next-steps bar appear on a session with no messages?
// Marks belong to the MATTER and outlive a sitting, so a fresh session opens holding every mark ever made —
// which is exactly the state that used to show the bar underneath the welcome panel's own buttons.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function renderSteps() {");
if (a < 0) { console.error("HARNESS: renderSteps moved"); process.exit(2); }
const b = src.indexOf("\n  }\n", a);
const renderSteps = src.slice(a, b + 4);

// The constants renderSteps closes over, lifted too, so their wording cannot drift from the page's.
const grab = (from) => { const i = src.indexOf(from); return src.slice(i, src.indexOf("\n", i)); };
const consts = ["const SUMMARISE_IDEA =", "const SURVEY =", "const DEEP =", "const DEEP_FOCUSED =",
                "const STEPS_MAX =", "const deepMarksKeyHere =", "const DEEPER =", "const LEAVE_OUT ="]
  .map(grab).join("\n");
// IDEAS spans three lines and names SURVEY, so it is lifted whole rather than retyped.
const ideas = src.slice(src.indexOf("  const IDEAS = ["), src.indexOf("\n", src.indexOf("SUMMARISE_IDEA];")) + 1);

const body = `
  // DOM enough to record what the bar was told to do.
  const node = (extra) => ({ children: [], append(...k) { this.children.push(...k); }, addEventListener() {}, ...extra });
  const nodes = { "mark-steps": node({ hidden: null }), "mark-steps-list": node({}), empty: node({ hidden: false }) };
  const $ = (id) => nodes[id];
  const clear = (n) => { n.children = []; };
  const el = (tag, cls, ...kids) => node({ tag, cls, kids });
  const stick = () => () => {};
  const log = { lastElementChild: null, append() {} };
  const cards = new Map();
  const marks = new Map(); const markOrder = [];
  let assistantSteps = [], marksAtTurn = null, deepMarksAtLastPress = null;
  let searchOffered = true, busy = false, ended = false;
  const readingSession = false;   // same stub as steps_panel_sim.js, same reason
  const relevantOrdered = () => {
    const out = markOrder.filter((k) => marks.get(k) === "relevant");
    for (const k of Array.from(marks.keys())) if (marks.get(k) === "relevant" && !out.includes(k)) out.push(k);
    return out;
  };
  const markCandidates = (onlyNew) => {
    const isNew = (k) => !onlyNew || !marksAtTurn || marksAtTurn.get(k) !== marks.get(k);
    const relevant = relevantOrdered().filter(isNew);
    const excluded = Array.from(marks.keys()).some((k) => isNew(k) && marks.get(k) === "not-relevant");
    const like = relevant.slice(0, 2).map((k) => \`Find documents like \${k}\`);
    const canContinue = excluded && cards.size > 0;
    if (onlyNew) return [...like.slice(0, 1), ...(relevant.length ? [DEEPER] : []), ...like.slice(1), ...(canContinue ? [LEAVE_OUT] : [])];
    return [...(relevant.length ? [DEEPER] : []), ...like, ...(canContinue ? [LEAVE_OUT] : [])];
  };
  const covered = () => false;
${consts}
${ideas}
${renderSteps}
  const shown = () => {
    renderSteps();
    if (nodes["mark-steps"].hidden) return null;
    const out = [];
    for (const row of nodes["mark-steps-list"].children) {
      if (row.cls === "steps-sub") out.push("SUB:" + row.kids[0]);
      else for (const btn of row.children) out.push(btn.kids[0]);
    }
    return out;
  };
  const out = {};
  // 1. Empty session, marks carried over from an earlier sitting. THE CASE HENRY SAW.
  marks.set("US-1-A1", "relevant"); markOrder.push("US-1-A1");
  out.emptySessionWithOldMarks = shown();
  // 2. Empty session, no marks at all.
  marks.clear(); markOrder.length = 0;
  out.emptySessionNoMarks = shown();
  // 3. The conversation has begun: the welcome is gone and the bar is the only place suggestions live.
  nodes.empty.hidden = true;
  out.startedNoMarks = shown();
  marks.set("US-1-A1", "relevant"); markOrder.push("US-1-A1");
  out.startedWithMarks = shown();
  // 4. And with the assistant's own list, which must come first.
  assistantSteps = ["Read US-1-A1 against claim 1"];
  out.startedWithAssistantSteps = shown();
  console.log(JSON.stringify(out));
`;
await import("data:text/javascript," + encodeURIComponent(body));
