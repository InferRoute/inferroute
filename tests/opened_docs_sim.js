// The page's own document list and popup, over what /api/documents really returns.
//
// Henry, 2026-10-01: "im not seeing any popup or list of opened patents we can come back to". Four documents
// he had opened sat only in a 2,774-event transcript. Two properties matter and both are behavioural:
//   * the SCOPE is stated before the text, and names what was not read — the same order the model gets it in,
//     for the same reason: a short text handed over without its scope is taken for the document;
//   * a document with no assistant reading yet says so, rather than showing an empty pane.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const a = src.indexOf("  const COVER_WORDS =");
const b = src.indexOf("  function hideDocument()", a);
if (a < 0 || b < 0) { console.error("HARNESS: the document popup moved"); process.exit(2); }

const nodes = {};
const mk = () => ({ textContent: "", hidden: true, children: [],
  append(...c) { this.children.push(...c); for (const x of c) if (x && x.textContent) this.textContent += x.textContent; } });
for (const id of ["docview-title", "docview-scope", "docview-text", "docview-said", "docview-prov", "docview", "docview-marks"]) nodes[id] = mk();
const $ = (id) => nodes[id];
const el = (tag, cls, ...ch) => { const n = mk(); n.tag = tag; n.cls = cls;
  for (const c of ch) n.textContent += typeof c === "string" ? c : (c && c.textContent) || ""; return n; };
const yearOf = (d) => { const p = String(d.published ?? ""); return /^\d{8}$/.test(p) ? p.slice(0, 4) : ""; };

let docsCache = { documents: [], readings: {} };
// The popup now leans on the page's own machinery: markdown() renders the assistant's prose (it used to be
// printed raw, "**bold**" and all) and markButtons() supplies the SAME controls a search card carries.
// Stubbed here so the sim can see that each was actually used, and with what.
let mdCalls = [], markCalls = [];
const markdown = (t) => { mdCalls.push(t); const n = mk(); n.textContent = "[rendered] " + t; return n; };
const markButtons = (k) => { markCalls.push(k); const n = mk(); n.textContent = "Relevant Not relevant Known"; return n; };
const clear = (n) => { n.textContent = ""; n.children = []; };
const body = src.slice(a, b);
const show = new Function("$", "el", "yearOf", "getCache", "markdown", "markButtons", "clear",
  `${body}\n return (k) => { docsCache = getCache(); return showDocument(k); };`)(
  $, el, yearOf, () => docsCache, markdown, markButtons, clear);

let bad = 0;
const fail = (m) => { console.error("FAIL: " + m); bad++; };

// Real shape, straight from matter_documents on Henry's own matter.
docsCache = {
  documents: [{ key: "US-5553613-A", published: 19960910, text: "Non invasive blood analyte sensor. A sensor for…",
                coverage: { abstract: "held", claims: "not_held", description: "not_held" },
                at: "2026-10-01T00:55:00Z", index: "patent1m-epwo+usall@29595902", measurement: "6d6c354511d6f7c6" }],
  readings: {},
};
show("US-5553613-A");
if (!$("docview-scope").textContent.includes("abstract in full")) fail("coverage must be stated in words");
if (!$("docview-scope").textContent.includes("claims and description was not read")
    && !$("docview-scope").textContent.includes("claims and description were not read")) fail("what was NOT read must be named: " + $("docview-scope").textContent);
if (!$("docview-said").textContent.includes("has not written about this document yet")) fail("an empty reading must say so");
if (!$("docview-title").textContent.includes("published 1996")) fail("the publication year belongs in the title");
if (!$("docview-prov").textContent.includes("patent1m-epwo")) fail("provenance must name the index");
if ($("docview").hidden !== false) fail("the popup must open");

// With a reading captured, the pane carries it and labels whose words they are.
docsCache.readings["US-5553613-A"] = "It is an optical sensor using two wavelengths.";
show("US-5553613-A");
if (!$("docview-said").textContent.includes("What the assistant said about it")) fail("the reading must be attributed, not presented as the document");
if (!$("docview-said").textContent.includes("two wavelengths")) fail("the reading must be shown");
// RENDERED, not printed. Henry, 2026-10-01: "the assistant side formatting could be made more readable".
if (!mdCalls.length) fail("the assistant's prose must go through markdown(), or the reader sees ** and - as characters");
if (!$("docview-said").textContent.includes("[rendered]")) fail("the rendered fragment must be what is appended");

// Claim 1 held (after the staged enclave change) must not read as "the claims".
docsCache.documents[0].coverage = { abstract: "held", claims: "claim_1", description: "not_held" };
docsCache.readings = {};
show("US-5553613-A");
const sc = $("docview-scope").textContent;
if (!sc.includes("claims first claim only")) fail("claim_1 must be worded, not printed raw: " + sc);
if (sc.includes("claims and description was not read")) fail("one claim WAS read; the sentence must not deny it");
if (!sc.includes("description was not read")) fail("the description is still absent and must be named");

// JUDGE IT WHERE YOU READ IT: the same three controls a card carries, for this document.
if (!markCalls.includes("US-5553613-A")) fail("the popup must carry the mark controls, for the document it is showing");
if (!$("docview-marks").textContent.includes("Not relevant")) fail("the mark controls must be placed in the popup");
if (markCalls.length !== 3) fail("the controls are rebuilt once per open, not accumulated: " + markCalls.length);

if (bad) process.exit(1);
console.log("document popup: scope before text, absences named, reading rendered and attributed, marks present — all held");
