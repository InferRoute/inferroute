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

const mkNode = (cls, text) => ({ cls, textContent: text || "", children: [], hidden: false, id: "", listeners: {},
  addEventListener(k, f) { (this.listeners[k] ||= []).push(f); },
  append(...c) { this.children.push(...c); }, prepend(c) { this.children.unshift(c); },
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((x) => x !== this); },
  querySelector(sel) { return this.children.find((c) => "." + c.cls === sel) || null; } });
const log = mkNode("log");
const room = mkNode("waiting");
// Like the page's el(tag, cls, ...children): a string child is the text, a node child is appended.
const el = (tag, cls, ...kids) => {
  const n = mkNode(cls, kids.filter((k) => typeof k === "string").join(""));
  n.parent = null;
  for (const k of kids) if (k && typeof k === "object") { k.parent = n; n.children.push(k); }
  return n;
};
const origAppend = log.append.bind(log);
log.append = (...c) => { for (const x of c) x.parent = log; origAppend(...c); };

let busy = false;
const api = new Function("el", "log", "stick", "hideWelcome", "clearNext", "outlineAdd", "$", "getBusy", "outstanding", "api", "toast",
  `${src.slice(a, b)}
   return { addUser: (t) => { busy = getBusy(); return addUser(t); }, takeUp: takeUpQuestion, waiting, drop: dropWaiting };`
)(el, log, () => () => {}, () => {}, () => {},
  () => {}, (id) => (id === "waiting" ? room : null), () => busy, new Set(), async () => ({ ok: true }), () => {});

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

// A waiting question can be taken back (Henry, 3 Oct). Every waiting row carries a Cancel button.
busy = true; api.addUser("Q4"); api.addUser("Q5"); api.addUser("Q6");
if (held().join() !== "Q4,Q5,Q6") fail("setup: " + held());
if (!api.waiting.every((w) => w.node.children.some((c) => c.cls.includes("cancel-queued")))) fail("every waiting row needs a Cancel button");
api.drop("Q5", 1);
if (held().join() !== "Q4,Q6") fail("the cancelled question must leave the waiting room: " + held());
if (!/2 questions/.test((room.children[0] || {}).textContent || "")) fail("the note must count what is left");
api.drop("Q5", 1);                                // the same cancel arriving again (an event after the click's own answer)
if (held().join() !== "Q4,Q6") fail("a repeated cancel must change nothing: " + held());
api.drop("Q6", 0);                                // index stale, text right: still the right question
if (held().join() !== "Q4") fail("a stale index must fall back to the text: " + held());
api.takeUp();
if (transcript().join() !== "Q1,Q2,Q3,Q4") fail("a cancelled question must never anchor: " + transcript());
if (held().length || !room.hidden) fail("nothing left waiting; the room hides");

if (bad) process.exit(1);
console.log("waiting questions: held outside the transcript, anchored one per turn, in order; cancel removes only what was asked");
