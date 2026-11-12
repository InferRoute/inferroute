// The page's own Asian-list block (app.js, "── the Asian list ──"), with relBar/scoreRange, run over search details
// of every shape the engine sends: a list with hits, offices searched with none back, no Asian office requested, a
// CN-only search, an office nothing indexes, an older index with no Asian layer, and a list without its labels.
// Lifted verbatim with a minimal DOM stub that keeps text nodes apart from elements, so what is checked is the
// rendered TEXT and the TREE, and that nothing is built from markup.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  // ── the Asian list ──");
const b = src.indexOf("  // ── end Asian list ──", a);
const r0 = src.indexOf("  function relBar(score, lo, hi) {");
const r1 = src.indexOf("\n  function offerDeeper(card) {", r0);
if (a < 0 || b < 0 || r0 < 0 || r1 < 0) { console.error("HARNESS: the Asian-list block or relBar moved"); process.exit(2); }
const block = src.slice(a, b);
if (/innerHTML|outerHTML|insertAdjacentHTML|DOMParser|createContextualFragment/.test(block)) {
  console.error("FAIL: the Asian-list block builds markup"); process.exit(1);
}

const node = (tag, cls) => ({
  tag, className: cls || "", children: [], title: "", attrs: {}, style: {}, listeners: {},
  classList: { toggle() {} },
  append(...c) { this.children.push(...c); },
  setAttribute(k, v) { this.attrs[k] = v; },
  addEventListener(k, f) { this.listeners[k] = f; },
});
const el = (tag, cls, ...children) => {
  const n = node(tag, cls);
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    n.append(typeof c === "string" || typeof c === "number" ? { text: String(c) } : c);
  }
  return n;
};
const mk = new Function("el", `${src.slice(r0, r1)}\n${block}\n return { asiaSection, mainNotRunNote, familyOf, sideSections };`)(el);

const text = (n) => !n ? "" : n.text !== undefined ? n.text : (n.children || []).map(text).join(" ");
const find = (n, pred, acc = []) => { if (n && n.tag) { if (pred(n)) acc.push(n); for (const c of n.children) find(c, pred, acc); } return acc; };

const hit = (i, extra = {}) => ({ key: `CN-10${i}-A`, year: 2019, title: `Cooling plate ${i}`, score: 0.9 - i / 100, ...extra });
const frHit = (i, extra = {}) => ({ key: `FR-200${i}-A1`, year: 1994, title: `Echangeur ${i}`, score: 0.7 - i / 100, ...extra });
const states = {
  with_hits: { asia: { offices: ["CN", "JP", "KR", "TW"], k: 20,
                       docs: [hit(1, { family: ["CN-101-A", "JP-2001-A", "KR-3-B"], familyTotal: 3 }),
                              hit(2, { family: ["TW-9-A"], familyTotal: 70 }), hit(3)] },
               officesUnindexed: [], index: "patent1m-asia-2611+epwo+usall@88844190" },
  index_2612: { asia: { offices: ["CN", "JP", "KR", "TW"], k: 20, docs: [hit(1)] },
                index: "patent1m-asia-2612+epwo+usall@90000000" },
  empty: { asia: { offices: ["CN", "JP"], k: 20, docs: [] } },
  not_requested: { asia: { offices: [], k: 20, docs: [] } },
  cn_only: { asia: { offices: ["CN"], k: 20, docs: [hit(1)] }, mainNotRun: ["CN"] },
  unindexed: { asia: { offices: [], k: 20, docs: [] }, officesUnindexed: ["DE"], mainNotRun: ["DE"] },
  unindexed_two: { asia: { offices: ["CN", "JP", "KR", "TW"], k: 20, docs: [hit(1)] }, officesUnindexed: ["DE", "FR"] },
  old_root: {},
  unlabelled: { asiaUnlabelled: true },
  // side lists (FR first), as ir-attested.ts hands them over in `details.side`
  fr_hits: { asia: { offices: ["CN"], k: 20, docs: [hit(1)] },
             side: [{ name: "fr", offices: ["FR"], k: 20,
                      docs: [frHit(1, { family: ["FR-2001-A1", "FR-2001-B1"], familyTotal: 4 }), frHit(2)] }],
             index: "patent1m-asia-2611-fr-2611+epwo+usall@89000000" },
  fr_index_2612: { side: [{ name: "fr", offices: ["FR"], k: 20, docs: [frHit(1)] }],
                   index: "patent1m-asia-2611-fr-2612+epwo+usall@89100000" },
  fr_not_requested: { asia: { offices: ["CN"], k: 20, docs: [] }, side: [{ name: "fr", offices: [], k: 20, docs: [] }] },
  fr_empty: { side: [{ name: "fr", offices: ["FR"], k: 20, docs: [] }] },
  fr_only: { asia: { offices: [], k: 20, docs: [] }, side: [{ name: "fr", offices: ["FR"], k: 20, docs: [frHit(1)] }], mainNotRun: ["FR"] },
  side_unknown: { side: [{ name: "de", offices: ["DE"], k: 20, docs: [frHit(1)] }], sideUnlabelled: true },
  side_unlabelled: { sideUnlabelled: true },
  both_unlabelled: { asiaUnlabelled: true, sideUnlabelled: true },
};
const out = {};
for (const [name, d] of Object.entries(states)) {
  const sec = mk.asiaSection(d);
  const note = mk.mainNotRunNote(d);
  out[name] = {
    section: sec ? text(sec).replace(/\s+/g, " ").trim() : null,
    note: note ? text(note) : null,
    ranks: sec ? find(sec, (n) => n.className === "rank").map(text) : [],
    marks: sec ? find(sec, (n) => /\bmarks\b/.test(n.className)).length : 0,
    keyLinks: sec ? find(sec, (n) => /key-link/.test(n.className)).length : 0,
    families: sec ? find(sec, (n) => n.className === "year" && /in this family/.test(text(n))).map((n) => [text(n), n.title]) : [],
    barTitles: sec ? find(sec, (n) => n.className === "relbar").map((n) => n.title) : [],
    side: mk.sideSections(d).map((x) => ({
      section: text(x).replace(/\s+/g, " ").trim(),
      ranks: find(x, (n) => n.className === "rank").map(text),
      marks: find(x, (n) => /\bmarks\b/.test(n.className)).length,
      keyLinks: find(x, (n) => /key-link/.test(n.className)).length,
      families: find(x, (n) => n.className === "year" && /in this family/.test(text(n))).map((n) => [text(n), n.title]),
    })),
  };
}
console.log(JSON.stringify(out));
