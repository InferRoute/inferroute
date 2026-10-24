// rc 0.9.125 e2e (D9, shot 43): with patent search offline the bar still offered "Search deeply…" and "Summarise
// what the searches have surfaced so far". Drives the real offerableWhileOffline()/asksForSearch() from app.js.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const line = (start) => { const a = src.indexOf(start); if (a < 0) { console.error(`HARNESS: ${start} moved`); process.exit(2); } return src.slice(a, src.indexOf("\n", a)); };
const block = (start, end) => { const a = src.indexOf(start), b = src.indexOf(end, a); if (a < 0 || b < 0) { console.error(`HARNESS: ${start} moved`); process.exit(2); } return src.slice(a, b); };
const code = [line("const DEEPER ="), line("const LEAVE_OUT ="), line("const SUMMARISE_IDEA ="), line("const SURVEY ="), line("const DEEP ="),
  line("const DEEP_FOCUSED ="), block("const IDEAS = [SURVEY,", ";\n") + ";",
  block("function asksForSearch(t) {", "\n  }\n") + "\n  }", block("function offerableWhileOffline(step) {", "\n  }\n") + "\n  }"].join("\n");
const ok = new Function(`${code}\n return { offerableWhileOffline, SURVEY, DEEP, DEEP_FOCUSED, DEEPER, SUMMARISE_IDEA, IDEAS };`)();
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
for (const s of [ok.SURVEY, ok.DEEP, ok.DEEP_FOCUSED, ok.DEEPER, ok.SUMMARISE_IDEA, ok.IDEAS[1], "Find documents like US-1234567-B2",
                 "Search deeply: put the whole disclosure to the search machine", "Run a prior-art search on the lid sensor"])
  if (ok.offerableWhileOffline(s)) fail(`offered while search is offline: ${s}`);
for (const s of ["Tighten the disclosure's description of the lid sensor", "Explain claim 1 in plain words",
                 "Draft three independent claims from the disclosure"])
  if (!ok.offerableWhileOffline(s)) fail(`a step that needs no search was hidden: ${s}`);
if (bad) process.exit(1);
console.log("offline steps: search suggestions hidden while search is offline; the rest kept");
