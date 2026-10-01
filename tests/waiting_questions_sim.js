// Henry, 2026-10-01: "when many instructions are given in a short time all the questions display and then
// all the answers display in that order. it would be better if the unprocessed questions remain unanchored
// in the chat until they are processed so that it can look like actual conversation".
//
// The server publishes `user` on RECEIPT, and a message sent while the agent is busy is only queued. So the
// transcript read Q Q Q A A A — an order that never happened. A queued question now waits outside the
// transcript and is anchored when its turn begins.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  const waiting = [];");
const b = src.indexOf("  // ── \"still working\"", a);
if (a < 0 || b < 0) { console.error("HARNESS: the waiting room moved"); process.exit(2); }

const mkNode = (cls, text) => ({ cls, textContent: text || "", children: [], hidden: false, id: "",
  append(...c) { this.children.push(...c); }, prepend(c) { this.children.unshift(c); },
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((x) => x !== this); },
  querySelector(sel) { return this.children.find((c) => "." + c.cls === sel) || null; } });
const log = mkNode("log");
const room = mkNode("waiting");
const el = (tag, cls, text) => { const n = mkNode(cls, text); n.parent = null; return n; };
const origAppend = log.append.bind(log);
log.append = (...c) => { for (const x of c) x.parent = log; origAppend(...c); };

let busy = false;
const api = new Function("el", "log", "stick", "hideWelcome", "clearNext", "outlineAdd", "$", "getBusy",
  `${src.slice(a, b)}
   return { addUser: (t) => { busy = getBusy(); return addUser(t); }, takeUp: takeUpQuestion, waiting };`
)(el, log, () => () => {}, () => {}, () => {},
  () => {}, (id) => (id === "waiting" ? room : null), () => busy);

const transcript = () => log.children.filter((c) => (c.cls || "").includes("msg-user") && !(c.cls || "").includes("waiting")).map((c) => c.textContent);
const held = () => api.waiting.map((w) => w.text);
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };

// Idle: the first question is the one about to be answered, so it anchors at once.
busy = false; api.addUser("Q1");
if (transcript().join() !== "Q1") fail("an idle question must anchor immediately: " + transcript());
if (held().length) fail("nothing should be waiting yet");

// Busy: two more arrive while Q1 is being answered. Neither joins the transcript.
busy = true; api.addUser("Q2"); api.addUser("Q3");
if (transcript().join() !== "Q1") fail("queued questions must NOT anchor: " + transcript());
if (held().join() !== "Q2,Q3") fail("both must be held, in order: " + held());
if (!/2 questions/.test((room.children[0] || {}).textContent || "")) fail("the waiting note must count them");

// Q1's answer finishes; the next turn begins → Q2 is anchored, and only Q2.
api.takeUp();
if (transcript().join() !== "Q1,Q2") fail("the oldest waiting question must anchor when its turn starts: " + transcript());
if (held().join() !== "Q3") fail("only one is taken up per turn: " + held());
if (!/Waiting — this is delivered/.test((room.children[0] || {}).textContent || "")) fail("the note must go singular");

api.takeUp();
if (transcript().join() !== "Q1,Q2,Q3") fail("final order must be Q1,Q2,Q3 interleaved with answers");
if (held().length) fail("nothing left waiting");
api.takeUp();                                    // a turn with nothing queued must be harmless
if (transcript().join() !== "Q1,Q2,Q3") fail("an empty take-up must not duplicate anything");

if (bad) process.exit(1);
console.log("waiting questions: held outside the transcript, anchored one per turn, in order");
