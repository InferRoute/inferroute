// Henry, 2026-10-01: "control from the inferroute backend wether we want to be in a mode where the enclave
// is opening a small window each day in which case it should say so in home page or wether its always open
// in such that it not mention those scheduled on the home page".
//
// This was live-wrong at the time: the enclave had just been deployed to run CONTINUOUSLY, and the page
// still had 13:00–15:00 Paris compiled in — so it would have told a client "closed until 13:00" about a
// machine that was up. A confident timetable is worse than none, because nobody questions a timetable.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/home.js", "utf8");
const a = src.indexOf("  function searchStatusBar(d) {");
const b = src.indexOf("\n  }\n", src.indexOf("return bar;", a)) + 4;
if (a < 0 || b < 4) { console.error("HARNESS: searchStatusBar moved"); process.exit(2); }

const texts = [];
const el = (tag, cls, ...ch) => { const n = { tag, cls, children: [], textContent: "",
  append(...c) { this.children.push(...c); } };
  for (const c of ch) { if (typeof c === "string") { n.textContent += c; texts.push(c); } else if (c) n.children.push(c); }
  return n; };
const bar = new Function("el", "hourAt", "untilText", `${src.slice(a, b)}\n return searchStatusBar;`)(
  el, (iso, tz) => (iso ? "13:00" : ""), () => "in 2 h");

const say = (d) => { texts.length = 0; bar(d); return texts.join(" | "); };
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
const MENTIONS_HOURS = /Paris|every day|\d\d:00|opens|closed until|outside its usual hours|normally runs/i;

// ALWAYS-ON, reachable: says it is available and NOTHING about hours.
let t = say({ configured: true, mode: "always", reachable: true, found: true, open_now: true });
if (!/Search is available/.test(t)) fail("always+up must say it is available: " + t);
if (MENTIONS_HOURS.test(t)) fail("always-on must not mention a timetable: " + t);

// ALWAYS-ON, not answering: a fault, explicitly NOT a closing time.
t = say({ configured: true, mode: "always", reachable: false, found: true, open_now: true });
if (MENTIONS_HOURS.test(t)) fail("a continuous machine that is down must not be given hours: " + t);
if (!/not a closing time/.test(t)) fail("it must say this is not a schedule: " + t);

// ALWAYS-ON, address gone: still the distinct 'cannot be found' state, never a timetable.
t = say({ configured: true, mode: "always", reachable: false, found: false, open_now: true });
if (!/cannot be found/.test(t)) fail("an unresolvable address keeps its own state: " + t);
if (MENTIONS_HOURS.test(t)) fail("no hours here either: " + t);

// SCHEDULED still behaves exactly as before — the mode must not have eaten the feature.
t = say({ configured: true, mode: "scheduled", reachable: true, open_now: true, found: true,
          opens_at: "2026-10-01T11:00:00Z", closes_at: "2026-10-01T13:00:00Z", tz: "Europe/Paris", from_hour: 13, to_hour: 15 });
if (!MENTIONS_HOURS.test(t)) fail("scheduled mode must still state its hours: " + t);

t = say({ configured: true, mode: "scheduled", reachable: false, open_now: false, found: true,
          opens_at: "2026-10-01T11:00:00Z", closes_at: "2026-10-01T13:00:00Z", tz: "Europe/Paris", from_hour: 13, to_hour: 15 });
if (!/closed/i.test(t)) fail("scheduled+closed must still say closed: " + t);

// Not configured at all is untouched by the mode.
t = say({ configured: false, mode: "always" });
if (!/not set up on this computer/.test(t)) fail("unconfigured must keep its own message: " + t);

if (bad) process.exit(1);
console.log("availability: always-on never mentions hours; scheduled keeps its timetable; faults stay distinct");
