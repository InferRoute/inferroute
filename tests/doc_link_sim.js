// Clicking a publication number. Henry, 2026-10-01: "i just clicked a second time on the same patent and
// instead of opening the popup for that patent that was already just computed/loaded it redid the
// processing and conversation processing".
//
// Re-reading a document already on this computer costs a sealed request, spends a turn of the conversation
// re-answering an answered question, and pushes the first reading further up the log — for the same text.
// So the click prefers what we have, and only asks the assistant when we do not have it.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  function docLink(keyNo) {");
const b = src.indexOf("\n  }\n", src.indexOf("return a;", a)) + 4;
if (a < 0 || b < 4) { console.error("HARNESS: docLink moved"); process.exit(2); }

const mk = () => ({ listeners: {}, title: "", type: "",
  addEventListener(k, f) { (this.listeners[k] ||= []).push(f); },
  fire(k, ev) { for (const f of this.listeners[k] || []) f(ev || { stopPropagation() {} }); } });
const el = () => mk();

let sent = [], shown = [], have = new Set(), ended = false;
const make = new Function("el", "ended_", "send", "showDocument", "haveDocument", "OPEN_DOC",
  `${src.slice(a, b)}\n return docLink;`
)(el, null, (t) => sent.push(t), (k) => shown.push(k), (k) => have.has(k),
  (k) => `Open ${k}: read that document and show me what it discloses`);

// `ended` is a closure variable in the page; rebuild with it bound per case.
function linkFor(key, isEnded) {
  ended = isEnded;
  const f = new Function("el", "ended", "send", "showDocument", "haveDocument", "OPEN_DOC",
    `${src.slice(a, b)}\n return docLink;`
  )(el, isEnded, (t) => sent.push(t), (k) => shown.push(k), (k) => have.has(k),
    (k) => `Open ${k}: read that document and show me what it discloses`);
  return f(key);
}

let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };

// NOT yet read → ask the assistant.
sent = []; shown = []; have = new Set();
let l = linkFor("US-1-A", false);
l.fire("pointerenter");
if (!/Ask the assistant to read/.test(l.title)) fail("an unread document must say it will ask: " + l.title);
l.fire("click");
if (sent.length !== 1 || shown.length !== 0) fail("an unread document must go to the assistant");
if (!/read that document/.test(sent[0])) fail("the prompt must be the read request");

// ALREADY read → show it, and send nothing.
sent = []; shown = []; have = new Set(["US-1-A"]);
l = linkFor("US-1-A", false);
l.fire("pointerenter");
if (!/already read on this matter/.test(l.title)) fail("a read document must say so before the click: " + l.title);
if (!/nothing new is sent/.test(l.title)) fail("the label must say no request is spent");
l.fire("click");
if (shown.length !== 1 || shown[0] !== "US-1-A") fail("a read document must open the popup");
if (sent.length !== 0) fail("a read document must NOT spend a request or a conversation turn");

// A closed session does neither.
sent = []; shown = []; have = new Set(["US-1-A"]);
l = linkFor("US-1-A", true);
l.fire("click");
if (sent.length || shown.length) fail("an ended session must do nothing");

if (bad) process.exit(1);
console.log("document link: shows what we have, asks only for what we do not, silent when ended");
