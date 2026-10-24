// rc 0.9.125 e2e (D7, shots 40, 43): with patent search down, the status bar showed a red "⛔ Search: the search
// machine isn't answering" while the trust panel said a calm "(off)". Lifted VERBATIM from ir-attested.ts.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("function searchStatus(ctx");
const b = src.indexOf("function renderSearchProof(");
if (a < 0 || b < 0 || b < a) { console.error("HARNESS: searchStatus moved"); process.exit(2); }
const mod = path.join(os.tmpdir(), `search_status_${process.pid}.ts`);
fs.writeFileSync(mod, `const SEARCH_STATUS_KEY = "k"; let sessionTotals = { searches: 0, documents: 0 };\n` +
  `const hhmm = (x: any) => "16:22"; type ExtensionContext = any; type SearchProof = any; type SearchVerdict = any;\n` +
  `${src.slice(a, b)}\nexport { searchStatus };\n`);
const { searchStatus } = await import(`file://${mod}`);
fs.unlinkSync(mod);
const set: any[] = [];
const ctx = { hasUI: true, ui: { theme: { fg: (c: string, t: string) => `[${c}]${t}` }, setStatus: (k: string, t: string) => set.push(t) } };
let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };
for (const refusal of ["the local search verifier did not answer",
                       "the search enclave did not verify (nothing answered — no connection. The search machine is probably not running)"]) {
  searchStatus(ctx, { ok: false, refusal, steps: [] });
  const t = set.pop();
  if (t !== "[dim]○ Patent search is offline right now") fail(`an outage must read like Home, neutrally; got ${t}`);
}
searchStatus(ctx, { ok: false, refusal: "the search enclave did not verify (container policy: HOST_DATA is not the pinned policy)", steps: [] });
const real = set.pop();
if (!real.startsWith("[error]⛔ Search: not verified")) fail(`a failed check stays a red refusal; got ${real}`);
if (bad) process.exit(1);
console.log("search status: an outage is neutral and worded like Home; a failed check stays red");
