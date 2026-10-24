// rc 0.9.125 e2e (D3, shot 16): "Your report is ready… the report itself is complete" appeared on the FIRST write of
// name-check.md, and the assistant then rewrote the report. Drives the real reportWriteEnded/reportTurnSettled from
// probant_web/app.js: the card comes once, when the turn has settled, never on a write mid-turn.
const src = require("fs").readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function reportWriteEnded(");
const b = src.indexOf("  function toolEnd(ev)");
if (a < 0 || b < 0 || b < a) { console.error("HARNESS: the report-ready functions moved"); process.exit(2); }
let reportWritten = false, toolRunning = "", reportCall = "", shown = 0;
function reportReady() { shown += 1; }
eval(src.slice(a, b));
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
reportCall = "w1"; reportCall = ""; reportWriteEnded(true);       // the first draft is written
if (shown) fail("the card must not appear on a write while the turn is still running");
reportCall = "w2";                                                   // the assistant rewrites it
reportTurnSettled();
if (shown) fail("not while a rewrite of the report is under way");
reportCall = ""; reportWriteEnded(true); toolRunning = "trademark_search";
reportTurnSettled();
if (shown) fail("not while a tool is still running");
toolRunning = "";
reportTurnSettled();
if (shown !== 1) fail(`once, when the turn settled; got ${shown}`);
reportTurnSettled();
if (shown !== 1) fail("a later idle moment does not announce it again");
reportWriteEnded(false); reportTurnSettled();
if (shown !== 1) fail("a refused write is not a report");
if (bad) process.exit(1);
console.log("report ready: shown once, after the turn settled, never on a first draft");
