// Drives the REAL renderSharing() from probant_web/home.js: what the Sharing page puts on screen, and what
// it sends when a corpus is shared. Run by test_probant_home.py with the repository root as cwd.
//
// The check that matters is the first one. This page holds the one screen in Probant that is near a private
// key, and the failure it must never have is rendering one — a card built from the wrong object, a debug
// dump of the identity — because a secret on screen is a secret in a screenshot, a support ticket and a
// shoulder. So the identity handed to the page here CARRIES secrets, and the whole rendered tree is searched
// for them afterwards.
const src = require("fs").readFileSync("inferroute_cli/probant_web/home.js", "utf8");
const fn = (name) => {
  const head = [`  async function ${name}(`, `  function ${name}(`].map((h) => src.indexOf(h)).find((i) => i >= 0);
  if (head === undefined) throw new Error(`home.js no longer has ${name} — update this harness`);
  return src.slice(head, src.indexOf("\n  }\n", head) + 4);
};

// ── the smallest DOM these functions touch ──
const node = (tag) => ({
  tag, cls: "", value: "", rows: 0, type: "", placeholder: "", hidden: false, disabled: false, children: [],
  textContent: "", classList: { toggle() {}, add() {}, remove() {} }, dataset: {},
  // a real <select> takes its value from its first option; without that, "send to" reads as empty here
  append(...kids) {
    for (const k of kids) {
      if (!k) continue;
      this.children.push(k);
      if (this.tag === "select" && !this.value && k.tag === "option") this.value = k.value;
    }
  },
  addEventListener(name, f) { this[`on:${name}`] = f; },
  remove() {},
});
global.document = { createElement: node, getElementById: () => node("div"), querySelectorAll: () => [] };
global.navigator = { clipboard: { writeText: () => Promise.resolve() } };
global.location = { hash: "" };
function el(tag, cls, ...children) {
  const n = node(tag);
  n.cls = cls || "";
  for (const c of children) {
    if (c === null || c === undefined) continue;
    if (typeof c === "string") n.textContent += c;
    else n.children.push(c);
  }
  return n;
}
function clear(n) { n.children.length = 0; n.textContent = ""; }
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const localTime = () => "20 Sep 2026";
function button(label, cls, onClick) { const b = el("button", cls, label); b["on:click"] = onClick; return b; }
function field(label, input, hint) { return el("label", "field", el("span", "", label), input, hint ? el("span", "", hint) : null); }
function input(type, placeholder) { const i = node(type === "textarea" ? "textarea" : "input"); i.type = type; i.placeholder = placeholder || ""; return i; }
function toast(m, level) { toasts.push({ m, level }); }
function dialog(title, body, actions) { dialogs.push({ title, body, actions }); }
function closeDialog() {}
const toasts = []; const dialogs = [];
const PAGE = el("div", "page");
const page = () => PAGE;

// ── what the server would answer, with SECRETS included in the identity on purpose ──
const SECRETS = { mlkem_sk: "SK-MLKEM-must-never-render", ed_sk: "SK-ED-must-never-render", mlkem_seed: "SEED-must-never-render" };
const CARD = { schema: "inferroute.probant-card/1", mlkem_pub: "PUB-MLKEM", ed_pub: "PUB-ED", fingerprint: "1a2b-3c4d-5e6f-7a8b" };
let sent = null;
async function api(path, body) {
  // NOTE the ...SECRETS: this stands in for a server that over-shares one day. The page must render its
  // public card and nothing else, so that a change on the server side cannot quietly put a key on screen.
  if (path === "/api/sharing") return { ...SECRETS, fingerprint: CARD.fingerprint, card: CARD, contacts: [{ name: "betrancourt", fingerprint: "9f8e-7d6c-5b4a-3928", added_at: "2026-09-20T09:00:00Z" }] };
  if (path === "/api/overview") return { matters: [{ id: "Acme/battery-0", date_bound: "2021-03-01", marks: 2 }, { id: "Acme/battery-1", date_bound: "", marks: 0 }] };
  if (path === "/api/sharing/share") { sent = body; return { matters: body.matters.length, to_fingerprint: "9f8e-7d6c-5b4a-3928", from_fingerprint: CARD.fingerprint, path: "/home/henry/Probant/probant-corpus-for-betrancourt-x.probant-share" }; }
  if (path === "/api/sharing/open") {
    return body.client ? { opened: ["FromHenry/battery-0"] }
      : { from: "9f8e-7d6c-5b4a-3928", from_name: "", known: false, note: "for review",
          matters: [{ matter: "Acme/battery-0", date_bound: "2021-03-01", claims: 3, marks: 2 }] };
  }
  throw new Error(`unexpected call ${path}`);
}

eval(fn("renderSharing") + fn("addContactDialog") + fn("openShareDialog"));

const walk = (n, out = []) => { out.push(n); for (const c of n.children) walk(c, out); return out; };
const textOf = (n) => walk(n).map((x) => `${x.textContent} ${x.value} ${x.placeholder}`).join(" ");

(async () => {
  await renderSharing();
  const shown = textOf(PAGE);
  const leaked = Object.values(SECRETS).filter((s) => shown.includes(s));
  const boxes = walk(PAGE).filter((n) => n.type === "checkbox");
  boxes[0].checked = true; boxes[0]["on:change"]();      // choose the first matter only
  const go = walk(PAGE).find((n) => n.tag === "button" && n.textContent.startsWith("Seal"));
  await go["on:click"]();
  const after = textOf(PAGE);

  // the unknown-sender path: a preview of a share signed by a fingerprint that is not a contact
  openShareDialog();
  const open = dialogs[dialogs.length - 1];
  open.body.find((n) => n.tag === "label").children[1].value = "/tmp/x.probant-share";
  await open.actions.find((a) => a.textContent === "Look at it")["on:click"]();

  console.log(JSON.stringify({
    leaked,
    showsFingerprint: shown.includes(CARD.fingerprint),
    showsPublicCard: shown.includes("PUB-MLKEM"),
    listsBothMatters: shown.includes("Acme/battery-0") && shown.includes("Acme/battery-1"),
    sent,
    confirmed: after.includes("1 matter(s) sealed to betrancourt"),
    pathShown: after.includes("probant-corpus-for-betrancourt"),
    unknownWarned: textOf(el("div", "", ...open.body)).includes("not one of your contacts"),
  }));
})().catch((e) => { console.error(e.stack || String(e)); process.exit(1); });
