import fs from "fs";
import assert from "node:assert/strict";
const source = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const start = source.indexOf("  function renderAuditResults(box, data)");
const end = source.indexOf("  // Proof, not only our word:", start);
assert(start >= 0 && end > start, "audit functions moved");
class Element {
  constructor(tag, cls, ...children) {
    this.tag = tag; this.className = cls; this.children = []; this.listeners = {};
    this.disabled = false; this.value = ""; this.append(...children);
  }
  append(...children) {
    for (const child of children) {
      if (child == null || child === false) continue;
      this.children.push(child);
      if (this.tag === "select" && !this.value) this.value = child.value;
    }
  }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  get textContent() { return this.children.map(c => typeof c === "string" ? c : c.textContent).join(""); }
  set textContent(value) { this.children = [value]; }
  async fire(name) { await this.listeners[name](); }
}
const all = root => [root, ...root.children.flatMap(c => c instanceof Element ? all(c) : [])];
const pack = {manifest_sha256: "m", evidence_list_sha256: "e"};
const report = {auditor: {name: "External AI", model: "Kimi"}, completed_at: "2026-10-02T12:00:00Z",
  verified_statement: "Signatures verified. <script>untrusted report text</script>",
  limitations: ["This does not prove privacy."],
  claims: Array.from({length: 8}, (_, i) => ({id: i + 1, title: `Claim ${i + 1}`,
    verdict: i === 6 ? "VERIFIED IN PART" : "VERIFIED", verified_statement: "A scoped conclusion.",
    evidence: "Recomputed.", limitations: i === 6 ? ["Receipt join unsigned."] : [],
    coverage: {tool: 2, independent: 1, total: 2, unchecked: i === 6 ? "Receipt join" : ""}}))};
const result = {prepared: true, pack, results: [report], rejected: []};

function harness(api) {
  return new Function("el", "clear", "api", "toast", "navigator",
    `let key = "key", auditResultsTarget = null, auditResultsSnapshot = "", auditResultsBusy = false, auditResultsPack = null, auditResultsDisconnected = false;
     ${source.slice(start, end)}
     return { renderAuditResults, refreshAuditResults, auditOffer,
       target: (box, pack) => { auditResultsTarget = box; auditResultsPack = pack; } };`
  )((tag, cls, ...children) => new Element(tag, cls, ...children), e => {e.children = [];},
    api, () => {}, {clipboard: {writeText: async () => {}}});
}

const h = harness(async () => result);
const box = new Element("div", "");
h.renderAuditResults(box, result);
assert(box.textContent.includes("Kimi"));
assert(box.textContent.includes("These are the auditor's conclusions"));
assert(box.textContent.includes("This does not prove privacy"));
assert(box.textContent.includes("Receipt join unsigned"));
assert.equal(all(box).filter(e => e.className === "audit-claim verified").length, 7);
assert.equal(all(box).filter(e => e.className === "audit-claim partial").length, 1);
assert(!all(box).some(e => e.tag === "script"), "an auditor's text became markup");
const empty = new Element("div", "");
h.renderAuditResults(empty, {prepared: true, results: [], rejected: [{reason: "wrong pack"}]});
assert.equal(all(empty).filter(e => e.className.startsWith("audit-claim")).length, 0);
assert(empty.textContent.includes("wrong pack"));

let resolve;
const pending = harness(() => new Promise(r => {resolve = r;}));
const oldBox = new Element("div", ""), newBox = new Element("div", "");
pending.target(oldBox, pack);
const request = pending.refreshAuditResults();
pending.target(newBox, {manifest_sha256: "different"});
resolve(result); await request;
assert.equal(newBox.children.length, 0, "old audit was shown against a new export");

const mismatch = harness(async () => result);
mismatch.target(newBox, {manifest_sha256: "different"});
await mismatch.refreshAuditResults();
assert.equal(newBox.children.length, 0, "a mismatched pack lit up claims");

for (const canLaunch of [true, false]) {
  const calls = [];
  const controls = harness(async (path, body) => {
    calls.push({path, body});
    if (path === "/api/audit-pack") return {path: "/tmp/pack", pack_identity: pack,
      claude: "claude 'audit'", codex: "codex 'audit'", ir: "ir 'audit'", can_launch: canLaunch};
    if (path === "/api/audit-launch") return {terminal: "Terminal"};
    return result;
  });
  const panel = new Element("div", "");
  controls.auditOffer(panel);
  await all(panel).find(e => e.tag === "button").fire("click");
  const choice = all(panel).find(e => e.tag === "select");
  choice.value = "codex"; await choice.fire("change");
  assert(all(panel).find(e => e.tag === "code").textContent.endsWith("codex 'audit'"));
  const run = all(panel).find(e => e.tag === "button" && e.textContent === "Run audit");
  assert.equal(!!run, canLaunch);
  if (run) {await run.fire("click"); assert.equal(calls.at(-1).body.agent, "codex");}
}
console.log("PASS: attributed claim lights, limits, text safety, stale-result refusal, Codex selection and terminal fallback");
