// Runs the deep press's END — from the gap computation through the record write and the ledger — with
// everything it reads stubbed. Sliced VERBATIM from ir-attested.ts.
//
// This exists because every test of that region asserted a string was in the file and not one of them
// executed it. A `const` referenced thirty lines before its declaration is a temporal dead zone: the file
// parses, every grep passes, and it throws at runtime — after four sealed queries have been paid for.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf('\t\t\tconst failed = results.filter((x) => x.status === "failed");');
// Stop BEFORE the tool's own `return`: the harness supplies its own, and slicing into an unclosed object
// literal produced a module that would not parse — which is its own small lesson about slicing source.
const b = src.indexOf("\n\t\t\treturn {", a);
if (a < 0 || b < 0) { console.error("HARNESS: markers moved"); process.exit(2); }
const region = src.slice(a, b);

const mod = path.join(os.tmpdir(), `deep_ledger_${process.pid}.ts`);
fs.writeFileSync(mod, `
export function run(o: Record<string, any>) {
  const { results, sent, legs, generation, composed, params, followUp, started, union, plan,
          inputsKey, relevant, text, disclosure, corpusId, blocks, DEEP_MAX, DEEP_GENERATIONS } = o;
  const deepMarksKey = (r: string[]) => [...r].sort().join("\\u0000");
  const deepTextKey = (t: string) => t.replace(/\\s+/g, " ").trim();
  const corpusPhrase = (id: string) => id || "the corpus";
${region}
  return { nextRound, recorded: disclosure.fanouts[disclosure.fanouts.length - 1], ledger };
}
`);
const { run } = await import(`file://${mod}`);

const press = (legStates: {status: string, added?: number, feature: string}[], generation = 1) => {
  const results = legStates.map((l, i) => ({ ...l, about: l.feature, hits: l.status === "ok" ? 10 : 0,
                                             searchNo: i + 1, docs: [] }));
  const fanouts: any[] = [];
  return run({ results, sent: results.filter(r => r.status !== "failed").length, legs: results, generation,
               composed: [], params: {}, followUp: false, started: "2026-09-25T00:00:00Z",
               union: new Map([["US-1", {}]]), plan: { legs: results, notes: ["n"] },
               inputsKey: "k", relevant: [], text: "a disclosure of some length here",
               disclosure: { fanouts, write() {} }, corpusId: "corpus", blocks: [],
               DEEP_MAX: 8, DEEP_GENERATIONS: 3 });
};

const out: Record<string, any> = {};
// A press that left gaps asks for another round, and the record says it asked.
const gappy = press([{ status: "ok", added: 3, feature: "whole" },
                     { status: "empty", feature: "cuvette" },
                     { status: "ok", added: 0, feature: "restatement" }]);
out.gapsAsk = Boolean(gappy.nextRound);
out.gapsRecorded = gappy.recorded.brief_emitted;
out.gapsNamed = /cuvette.*found nothing/.test(gappy.nextRound) && /restatement/.test(gappy.nextRound);
// A press where every leg contributed asks for nothing.
const clean = press([{ status: "ok", added: 4, feature: "whole" }, { status: "ok", added: 2, feature: "f2" }]);
out.cleanAsks = Boolean(clean.nextRound);
out.cleanRecorded = clean.recorded.brief_emitted;
// The last allowed generation asks for nothing more.
out.lastGenerationAsks = Boolean(press([{ status: "empty", feature: "x" }], 3).nextRound);
out.ledgerCarriesBrief = gappy.ledger.includes(gappy.nextRound);
console.log(JSON.stringify(out));
