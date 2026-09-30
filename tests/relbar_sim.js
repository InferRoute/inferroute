// The page's own relBar()/scoreRange(), run over the REAL scores of a real sealed search
// (capture 20260929T221411Z, k=20). Lifted verbatim from app.js with a minimal element stub — the
// geometry is what is checked here: that different relevance produces visibly different bars, in the
// right order, and that the weakest is still visible rather than a zero-width sliver that reads as
// missing data. This is not a pixel check and does not claim to be one.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function relBar(score, lo, hi) {");
const b = src.indexOf("\n  function offerDeeper(card) {", a);
if (a < 0 || b < 0) { console.error("HARNESS: relBar/scoreRange moved"); process.exit(2); }

const el = (tag, cls) => ({ tag, cls, style: {}, children: [], title: "", attrs: {},
  append(...c) { this.children.push(...c); },
  setAttribute(k, v) { this.attrs[k] = v; } });
const relSrc = src.slice(a, b);
const mk = new Function("el", `${relSrc}\n return { relBar, scoreRange };`)(el);

const scores = [1.212,0.622,0.578,0.375,0.350,0.333,0.285,0.183,0.153,0.149,
                0.129,0.112,-0.056,-0.060,-0.060,-0.072,-0.116,-0.127,-0.143,-0.172];
const docs = scores.map((s, i) => ({ key: `US-${i}`, score: s }));
const [lo, hi] = mk.scoreRange(docs);
const widths = docs.map((d) => {
  const bar = mk.relBar(d.score, lo, hi);
  return bar ? parseFloat(bar.children[0].style.width) : null;
});
console.log(JSON.stringify({
  range: [lo, hi],
  widths,
  monotonic: widths.every((w, i) => i === 0 || w <= widths[i - 1] + 1e-9),
  top: widths[0], bottom: widths[widths.length - 1],
  spread: widths[0] - widths[widths.length - 1],
  // a search where every result scored the same must render NO bars rather than all-full ones
  allEqual: mk.relBar(0.5, ...mk.scoreRange([{score:0.5},{score:0.5}])) === null,
  // older sessions have no score at all
  noScore: mk.relBar(undefined, 0, 1) === null,
  hasLabel: !!mk.relBar(0.5, 0, 1).attrs["aria-label"],
}));
