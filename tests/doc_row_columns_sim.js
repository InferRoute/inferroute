// The result row's grid must have exactly as many columns as the row has children.
//
// It did not. `.doc` declared three columns — rank, document, marks — and a relevance bar was added as a
// fourth child without widening it. Every later child shifted one column left: the bar took the document's
// column, the document took the marks' column, and the mark buttons wrapped onto an implicit second row
// into the 26px rank column, where they rendered as "evant" and "nown". Seen on henry-ft, 2026-09-30.
//
// A count, because that is what actually broke. No screenshot and no eye is needed to catch it again.
const { readFileSync } = require("node:fs");
const js = readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const css = readFileSync("inferroute_cli/probant_web/app.css", "utf8");

let bad = 0;
const is = (what, ok) => { console.log(`  ${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) bad++; };

// how many columns does .doc declare?
const m = css.match(/^\.doc \{[^}]*grid-template-columns:([^;]+);/m);
is("`.doc` declares grid-template-columns", !!m);
const cols = m ? m[1].trim().split(/\s+(?![^(]*\))/).length : 0;

// how many children does every `el("li", "doc", ...)` construct? Parsed by BALANCING PARENS from the
// opening call, not by a regex ending on an assumed indentation — which is what the first version of
// this test did, and it found nothing while reporting nothing wrong.
const OPEN = 'el("li", "doc",';
const rows = [];
for (let at = js.indexOf(OPEN); at !== -1; at = js.indexOf(OPEN, at + 1)) {
  // Scan from the OPENING PAREN, or depth never reaches 1 and no argument separator is ever counted —
  // the second version of this test reported 3 children for a 4-child row for exactly that reason.
  let depth = 0, i = at + 2, args = 1;
  for (; i < js.length; i++) {
    const ch = js[i];
    if (ch === "(") depth++;
    else if (ch === ")") { depth--; if (depth === 0) break; }
    else if (ch === "," && depth === 1) args++;
  }
  const inner = js.slice(at + OPEN.length, i).trim();
  if (inner.endsWith(",")) args--;                 // a trailing comma is not another argument
  rows.push(args - 2);                             // less the tag and the class name
}
is(`found the row constructors (${rows.length})`, rows.length >= 2);
rows.forEach((kids, i) => is(`row ${i + 1}: ${kids} children vs ${cols} columns`, kids === cols));

// and the bar must never be null, or a row silently has one child fewer
is("relBar always returns a node (never null)", !/return null;[\s\S]{0,40}relbar/.test(js)
   && /relbar relbar-none/.test(js));
is("the empty track is styled to show nothing", /\.relbar\.relbar-none\s*\{[^}]*transparent/.test(css));

console.log(bad ? `\n${bad} FAILED` : "\nall passed");
process.exit(bad ? 1 : 0);
