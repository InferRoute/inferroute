// Henry, 2026-10-01: "control from the inferroute backend wether we want to be in a mode where the enclave
// is opening a small window each day in which case it should say so in home page or wether its always open
// in such that it not mention those scheduled on the home page".
//
// This was live-wrong at the time: the enclave had just been deployed to run CONTINUOUSLY, and the page
// still had 13:00–15:00 Paris compiled in — so it would have told a client "closed until 13:00" about a
// machine that was up. A confident timetable is worse than none, because nobody questions a timetable.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/home.js", "utf8");
const a = src.indexOf("  function searchStatusBar(d, onStart) {");
const b = src.indexOf("\n  }\n", src.indexOf("return bar;", a)) + 4;
if (a < 0 || b < 4) { console.error("HARNESS: searchStatusBar moved"); process.exit(2); }

const texts = [];
const el = (tag, cls, ...ch) => { const n = { tag, cls, children: [], textContent: "",
  append(...c) { this.children.push(...c); } };
  for (const c of ch) { if (typeof c === "string") { n.textContent += c; texts.push(c); } else if (c) n.children.push(c); }
  return n; };
const buttons = [];
const button = (label) => { buttons.push(label); return { label }; };
const bar = new Function("el", "hourAt", "untilText", "button", "clear", "api", `${src.slice(a, b)}\n return searchStatusBar;`)(
  el, (iso, tz) => (iso ? "13:00" : ""), () => "in 2 h", button, () => {}, async () => ({}));

const say = (d, onStart) => { texts.length = 0; buttons.length = 0; bar(d, onStart); return texts.join(" | "); };
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
const MENTIONS_HOURS = /Paris|every day|\d\d:00|opens|closed until|outside its usual hours|normally runs/i;

// ALWAYS-ON, reachable: says it is available and NOTHING about hours.
let t = say({ configured: true, mode: "always", reachable: true, found: true, open_now: true });
if (!/search is available/i.test(t)) fail("always+up must say it is available: " + t);
if (MENTIONS_HOURS.test(t)) fail("always-on must not mention a timetable: " + t);

// ALWAYS-ON, not answering, or its address gone: an OUTAGE, said calmly (0.9.124 test), with what still works and
// who to ask — and never a timetable, because this machine keeps none.
for (const found of [true, false]) {
  t = say({ configured: true, mode: "always", reachable: false, found, open_now: true });
  if (MENTIONS_HOURS.test(t)) fail("a continuous machine that is down must not be given hours: " + t);
  if (!/offline right now/.test(t)) fail("it must say search is offline: " + t);
  if (!/Name checks and readings still work/.test(t)) fail("it must say what still works: " + t);
  if (!/support@inferroute\.ai/.test(t)) fail("with no hours to give, it must say who to ask: " + t);
  if (/needs looking at|cannot be found/.test(t)) fail("no alarm wording: " + t);
}

// SCHEDULED, but its address is gone during or outside its hours: offline, its hours, and who to ask.
t = say({ configured: true, mode: "scheduled", reachable: false, open_now: false, found: false,
          opens_at: "2026-10-01T11:00:00Z", closes_at: "2026-10-01T13:00:00Z", tz: "Europe/Paris", from_hour: 13, to_hour: 15 });
if (!/offline right now/.test(t) || !MENTIONS_HOURS.test(t) || !/support@inferroute\.ai/.test(t)) fail("scheduled+gone: " + t);

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

// STARTED ON REQUEST (0.9.129): a machine with a wake service offers a start button when it is off, says it is
// starting (with the usual time) once asked, and says plainly when a request did not start it.
const go = () => {};
const base = { configured: true, mode: "always", reachable: false, found: true, open_now: true, startable: true };
t = say({ ...base, remote: { state: "off" } }, go);
if (!/switched off for now/.test(t) || !/15 to 20 minutes/.test(t) || !/keep working/.test(t)) fail("off+startable: " + t);
if (buttons.join() !== "Start patent search") fail("off+startable must offer the start button: " + buttons.join());
if (/offline right now|support@/.test(t)) fail("an off machine that can be started is not an outage: " + t);
t = say({ ...base, remote: { state: "off" } });
if (buttons.length) fail("no button without a handler: " + buttons.join());
const soon = new Date(Date.now() + 10 * 60000).toISOString(), past = new Date(Date.now() - 30 * 60000).toISOString();
t = say({ ...base, remote: { state: "starting", ready_by: soon } }, go);
if (!/is starting/.test(t) || !/ready by 13:00/.test(t) || buttons.length) fail("starting: " + t + " / " + buttons.join());
// "starting" long past its time is not left saying "starting" forever
t = say({ ...base, remote: { state: "starting", ready_by: past } }, go);
if (!/has not started/.test(t) || buttons.join() !== "Try again") fail("starting, long late: " + t);
// running per the service but unreachable from here: a network problem, said as one, with no button
t = say({ ...base, remote: { state: "ready" } }, go);
if (!/can't reach it/.test(t) || !/support@inferroute\.ai/.test(t) || buttons.length) fail("ready+unreachable: " + t);
// declined by the service's limits: no Try again (it would be declined too)
for (const req of [undefined, new Date(Date.now() - 60000).toISOString()]) {
  t = say({ ...base, remote: { state: "off", declined: "budget" }, requested_at: req }, go);
  if (!/can't be started right now/.test(t) || buttons.length) fail("declined: " + t + " / " + buttons.join());
}
t = say({ ...base, remote: { state: "unknown" }, requested_at: new Date(Date.now() - 60000).toISOString() }, go);
if (!/is starting/.test(t) || buttons.length) fail("just asked: " + t);
t = say({ ...base, remote: { state: "off" }, requested_at: new Date(Date.now() - 10 * 60000).toISOString() }, go);
if (!/has not started/.test(t) || !/support@inferroute\.ai/.test(t) || buttons.join() !== "Try again") fail("asked, still off: " + t);
for (const st of ["off", "starting", "unknown"]) {
  t = say({ ...base, remote: { state: st } }, go);
  if (/verified|safe|secure|private/i.test(t)) fail("availability only, never a trust word: " + t);
}

if (bad) process.exit(1);
console.log("availability: always-on never mentions hours; scheduled keeps its timetable; faults stay distinct");
