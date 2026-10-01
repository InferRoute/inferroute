// The page's own showThinking/hideThinking, over the sequence Henry actually saw: a deep search finishes,
// then nothing for a long time while the model composes. The bottom bar DID say "The assistant is
// working… 33 s", ~450px below the card the eye was on, which is why it did not land.
//
// Four properties, each a way this could be worse than silence:
//   * it appears after a tool finishes (the gap where the doubt lives);
//   * the FIRST token removes it — prose is its own proof, and two indicators at once is hedging;
//   * it never shows when the turn is over, or the page claims work that stopped;
//   * it does not accumulate — one indicator, however many tools ran.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  let thinkingNode = null;");
const b = src.indexOf("  function assistantStart()", a);
if (a < 0 || b < 0) { console.error("HARNESS: the indicator moved"); process.exit(2); }

const log = { children: [], append(n) { this.children = this.children.filter((c) => c !== n); this.children.push(n); } };
const mk = (cls) => ({ cls, children: [], isConnected: true, attrs: {},
  append(...c) { this.children.push(...c); }, setAttribute(k, v) { this.attrs[k] = v; },
  remove() { this.isConnected = false; log.children = log.children.filter((c) => c !== this); } });
const el = (tag, cls) => mk(cls);
const stick = () => () => {};

let ended = false, busy = false, current = null;
const api = new Function("el", "log", "stick", "getState",
  `${src.slice(a, b)}\n return { show: () => { const s = getState(); ended = s.ended; busy = s.busy; current = s.current; return showThinking(); }, hide: hideThinking, node: () => thinkingNode };`
)(el, log, stick, () => ({ ended, busy, current }));

const count = () => log.children.filter((c) => c.cls === "thinking" && c.isConnected).length;
let bad = 0; const fail = (m) => { console.error("FAIL: " + m); bad++; };

busy = true; current = null;
api.show();
if (count() !== 1) fail("a finished tool must leave an indicator in the flow");
if (api.node().children.length !== 3) fail("three dots");
if (!/still working/i.test(api.node().attrs["aria-label"] || "")) fail("it must be announced to a screen reader");

// A second tool finishing must not stack a second one.
api.show(); api.show();
if (count() !== 1) fail("indicators accumulated: " + count());

// The first token removes it.
api.hide();
if (count() !== 0) fail("the first token must remove it");

// While text is streaming it must not come back — the prose is the proof.
current = { node: {}, text: "hello" };
api.show();
if (count() !== 0) fail("it must not appear alongside streaming text");

// A finished or ended turn never shows it.
current = null; busy = false; api.show();
if (count() !== 0) fail("it must not claim work after the turn ended");
busy = true; ended = true; api.show();
if (count() !== 0) fail("a closed session must not show work");

if (bad) process.exit(1);
console.log("working indicator: appears in the gap, one at a time, removed by the first token, silent when idle");
