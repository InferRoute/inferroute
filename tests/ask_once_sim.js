// Henry, 2026-10-01, with a screenshot of nine queued questions of which SEVEN were identical: clicking a
// patent that has not been read queues "Open <key>…", nothing visibly happens until the assistant reaches
// it, so the natural response is to click again. Each click was a real sealed request and a real turn.
//
// Deduplicating the DISPLAY would have been worse than the bug: the agent would still hold the copies and
// answer each in turn. So the check is before the POST.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  const outstanding = new Set();");
const b = src.indexOf("  function autosize()", a);
if (a < 0 || b < 0) { console.error("HARNESS: send() moved"); process.exit(2); }

let posted = [], toasts = [], flashed = [], inputValue = "";
const waiting = [];
const $ = () => ({ get value() { return inputValue; }, set value(v) { inputValue = v; } });
const api = async (path, body) => { posted.push(body.text); return { ok: true }; };

const mk = () => new Function(
  "api", "ended", "$", "autosize", "clearNext", "toast", "waiting", "flashWaitingSpy", "setTimeout",
  `${src.slice(a, b)}
   flashWaiting = flashWaitingSpy;
   return { send, outstanding };`
)(api, false, $, () => {}, () => {}, (m, k) => toasts.push(m), waiting,
  (t) => flashed.push(t), (f) => f);

let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };
const Q = "Open US-2018146899-A1: read that document and show me what it discloses";

const api1 = mk();
await api1.send(Q);
if (posted.length !== 1) fail("the first ask must be sent: " + posted.length);

// The SEVEN clicks from the screenshot.
for (let i = 0; i < 6; i++) await api1.send(Q);
if (posted.length !== 1) fail(`asked once, sent ${posted.length} times — each one is a sealed request and a turn`);
if (flashed.length !== 6) fail("every repeat must point at the copy already waiting: " + flashed.length);
if (!toasts.every((t) => /already waiting/.test(t))) fail("the repeat must be explained, not silently dropped");

// A DIFFERENT question is unaffected.
await api1.send("Open EP-3636141-A1: read that document and show me what it discloses");
if (posted.length !== 2) fail("a different question must still be sent");

// Once it is taken up, asking again is legitimate — it is no longer outstanding.
api1.outstanding.delete(Q);
await api1.send(Q);
if (posted.length !== 3) fail("after it is answered, the same question may be asked again");

// A failed POST must not leave the question un-askable forever.
posted = [];
const failing = new Function("api", "ended", "$", "autosize", "clearNext", "toast", "waiting", "flashWaitingSpy", "setTimeout",
  `${src.slice(a, b)}\n flashWaiting = flashWaitingSpy;\n return { send, outstanding };`
)(async () => { throw new Error("offline"); }, false, $, () => {}, () => {}, (m) => toasts.push(m), waiting, () => {}, (f) => f);
try { await failing.send("Q-fails"); } catch { /* handled inside */ }
if (failing.outstanding.has("Q-fails")) fail("a send that failed must be retryable");

if (bad) process.exit(1);
console.log("ask once: seven clicks, one request; repeats explained; retryable after failure");
