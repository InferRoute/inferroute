// Runs the page's own deepCoverage() against fixture legs, in a DOM stub — the function the professional
// actually reads, not a copy of its wording.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const start = src.indexOf("  function deepCoverage(d) {");
const end = src.indexOf("  function seenIn(");
if (start < 0 || end < 0 || end < start) { console.error("HARNESS: deepCoverage not found where expected"); process.exit(2); }
const body = src.slice(start, end);
const el = (tag, cls, ...kids) => {
  const n = { tag, cls: cls || "", kids: [], text: "" };
  for (const k of kids) {
    if (k == null) continue;
    if (typeof k === "string") n.text += k; else n.kids.push(k);
  }
  n.append = (...more) => { for (const m of more) if (m != null) (typeof m === "string" ? (n.text += m) : n.kids.push(m)); };
  return n;
};
const flat = (n) => n == null ? "" : n.text + n.kids.map(flat).join(" | ");
const fn = new Function("el", body + "\nreturn deepCoverage;")(el);
const out = {};
out.none = flat(fn({ legs: [{ status: "ok", hits: 4, added: 4, feature: "a" }] }));
out.empty_only = flat(fn({ legs: [{ status: "empty", hits: 0, feature: "leg three" }] }));
out.spent_only = flat(fn({ legs: [{ status: "ok", hits: 9, added: 0, feature: "leg two" }] }));
out.both = flat(fn({ legs: [
  { status: "ok", hits: 5, added: 5, feature: "the disclosure as a whole" },
  { status: "empty", hits: 0, feature: "leg three" },
  { status: "ok", hits: 9, added: 0, feature: "leg two" },
  { status: "failed", hits: 0, feature: "leg four" },
]}));
// A leg with NO `added` field (an older record) must not be counted as having added nothing.
out.legacy = flat(fn({ legs: [{ status: "ok", hits: 9, feature: "old leg" }] }));
console.log(JSON.stringify(out));
