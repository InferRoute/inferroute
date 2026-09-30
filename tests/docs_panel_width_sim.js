// The documents list lives in a FIXED-WIDTH column (.layout's first track is 244px). Henry, 2026-10-01:
// "small display issue here with the texts being cut with the window" — titles hard-clipped at the panel
// edge with no ellipsis, because a grid item's default min-width:auto refuses to shrink below its content,
// so the overflow happened one box further out than the rule that was supposed to handle it.
//
// This is a layout rule, so it is checked as a layout rule: every element in the panel that can be squeezed
// must be able to shrink, and the title must not be a single clipped line.
import fs from "fs";
const css = fs.readFileSync("inferroute_cli/probant_web/app.css", "utf8");

function block(sel) {
  const i = css.indexOf(sel + " {");
  if (i < 0) return null;
  return css.slice(i, css.indexOf("}", i));
}

let bad = 0;
const fail = (m) => { console.error("FAIL: " + m); bad++; };

// The column really is fixed — if this changes, the rest of this test is about nothing.
const layout = block(".layout");
if (!layout || !/grid-template-columns:\s*244px/.test(layout)) fail("the outline is no longer a fixed 244px track; re-derive this test");

// Every box between the fixed track and the text must be allowed to shrink.
for (const sel of [".docs-panel ol", ".docs-panel li", ".docs-panel button"]) {
  const b = block(sel);
  if (!b) { fail(`${sel} is missing`); continue; }
  if (!/min-width:\s*0/.test(b)) fail(`${sel} can't shrink below its content — a long title will overflow the column`);
}

// The title wraps rather than being cut to one line: a patent title carries its distinguishing words late.
const t = block(".docs-panel .dtitle");
if (!t) fail(".docs-panel .dtitle is missing");
else {
  if (/white-space:\s*nowrap/.test(t)) fail("a nowrap title in a fixed column is the bug that was reported");
  if (!/line-clamp:\s*2/.test(t)) fail("the title should clamp to two lines, so the list stays scannable");
  if (!/overflow:\s*hidden/.test(t)) fail("a clamp without overflow:hidden does not clamp");
}

// The publication number must not force the column wider than it is.
const k = block(".docs-panel .dkey");
if (k && !/overflow-wrap:\s*anywhere/.test(k)) fail(".dkey must be breakable — an unbreakable key widens the track");

if (bad) process.exit(1);
console.log("documents panel: shrinkable at every level, title clamped to two lines");
