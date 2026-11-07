// The extension's Asian-list block (ir-attested.ts, "── the Asian list ──") run over sealed results of every shape
// the engine sends. It is what the terminal card and the assistant are told, and what the page receives in `details`:
// asiaOf() turns a result into the separate list (never into `docs`), asiaLines() words it. Lifted verbatim and
// imported, so node's own type stripping runs it exactly as it ships.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("// ── the Asian list ──");
const b = src.indexOf("// ── end Asian list ──", a);
if (a < 0 || b < 0) { console.error("HARNESS: the Asian-list block is missing"); process.exit(2); }
// The two places a search's documents are built and worded, lifted too, so "an Asian hit never enters the ranking"
// is checked on what they produce: searchProofOf (the `docs` the page, the marks and the counts read) and hitsText
// (what the assistant is told). isInferRoutes is stubbed: it only decides whose machine it was.
const p0 = src.indexOf("function searchProofOf(");
const p1 = src.indexOf("// What the model is told a read returned", p0);
const t0 = src.indexOf("function renderSearchProof(");
const t1 = src.indexOf("// The corpus, said in a way", t0);
const h0 = src.indexOf("function corpusName(");
const h1 = src.indexOf("// A suggested next step is sent", h0);
if (p0 < 0 || p1 < 0 || h0 < 0 || h1 < 0 || t0 < 0 || t1 < 0) { console.error("HARNESS: searchProofOf or hitsText moved"); process.exit(2); }
const mod = path.join(os.tmpdir(), `asia_list_${process.pid}.ts`);
// renderSearchProof (the terminal card) with the TUI stubbed to collect its lines as plain text.
const stubs = `class Box { lines: string[] = []; constructor(..._a: any[]) {} addChild(t: any) { this.lines.push(t.s); } }
class Text { s: string; constructor(s: string, ..._a: any[]) { this.s = s; } }
const plainRefusal = (s: string) => s;
type Theme = any;
`;
fs.writeFileSync(mod, `${stubs}${src.slice(a, b)}\nconst isInferRoutes = (_v: any) => false;\n${src.slice(p0, p1)}\n${src.slice(t0, t1)}\n${src.slice(h0, h1)}\n`
  + `export { asiaOf, asiaLines, searchProofOf, hitsText, renderSearchProof };\n`);
const { asiaOf, asiaLines, searchProofOf, hitsText, renderSearchProof } = await import(`file://${mod}`);
const theme = { fg: (_c: string, t: string) => t, bold: (t: string) => t, bg: (_c: string, t: string) => t };
fs.unlinkSync(mod);

const hit = (i: number, extra: Record<string, unknown> = {}) => ({
  key: `CN-10${i}-A`, score: 0.8 - i / 100, scores: { dense: 0.8 }, legs: ["semantic"], source: "patent",
  year: 2018, date_known: true, title: `Heat sink ${i}`, text: `Heat sink ${i}. An abstract.`, ...extra });
const asia = (offices: string[], hits: unknown[]) =>
  ({ kind: "dense_only", expanded: false, reranked: false, offices, k: 20, hits });
const mainHit = { key: "US-1-A", score: 1, title: "Main" };
const results: Record<string, Record<string, unknown>> = {
  long_title: { hits: [mainHit], offices: null, offices_unindexed: [],
                asia: asia(["CN", "JP", "KR", "TW"], [hit(1, { title: "A".repeat(150), family_members: ["CN-101-A"], family_members_total: 642 })]) },
  with_hits: { hits: [mainHit], offices: null, offices_unindexed: [],
               asia: asia(["CN", "JP", "KR", "TW"], [hit(1, { family_members: ["CN-101-A", "JP-1-A"], family_members_total: 2 }),
                                                    hit(2, { family_members: ["KR-1-B"], family_members_total: 90 }), hit(3)]) },
  empty: { hits: [mainHit], offices: ["CN", "JP", "US"], offices_unindexed: [], asia: asia(["CN", "JP"], []) },
  not_requested: { hits: [mainHit], offices: ["US"], offices_unindexed: [], asia: asia([], []) },
  cn_only: { hits: [], offices: ["CN"], offices_unindexed: [], asia: asia(["CN"], [hit(1)]) },
  unindexed: { hits: [], offices: ["DE"], offices_unindexed: ["DE"], asia: asia([], []) },
  old_root: { hits: [mainHit], offices: null },
  unlabelled: { hits: [mainHit], asia: { kind: "dense_only", expanded: true, reranked: false, offices: ["CN"], k: 20, hits: [hit(1)] } },
};
const out: Record<string, unknown> = {};
for (const [name, r] of Object.entries(results)) {
  const p = asiaOf(r);
  const { notes, rows } = asiaLines(p);
  const verdict = { ok: true, steps: [], enclave: { index_snapshot: "patent1m-asia-2611+epwo+usall@1" }, statement: { hits_n: (r.hits as unknown[]).length }, result: r };
  const sp = searchProofOf(verdict, "search");
  out[name] = { part: p, notes, rows, docKeys: sp.docs.map((d: { key: string }) => d.key), spAsia: sp.asia ?? null,
                model: hitsText(verdict, "Search 1", new Map()),
                terminal: renderSearchProof(sp, true, theme).lines, terminalFolded: renderSearchProof(sp, false, theme).lines };
}
console.log(JSON.stringify(out));
