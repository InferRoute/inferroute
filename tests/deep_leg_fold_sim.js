// A deep survey's legs fold, start folded, and open from the left index. The toggle and the outline's
// open step are lifted VERBATIM from app.js; the DOM is a stub with just enough classList and attributes.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const grab = (from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  if (a < 0 || b < 0) { console.error(`HARNESS: markers moved (${from})`); process.exit(2); }
  return src.slice(a, b);
};
const setLegFn = grab("const setLeg = (open) => {", "head.addEventListener");
// Anchored AFTER setLeg: there is an earlier `head.addEventListener("click"` on the card head, and
// indexOf would have handed back that one — a harness quietly testing the wrong control.
const legAt = src.indexOf("const setLeg = (open) => {");
const clickLine = (() => {
  const a = src.indexOf('head.addEventListener("click"', legAt);
  if (a < 0) { console.error("HARNESS: the leg's click handler moved"); process.exit(2); }
  return src.slice(a, src.indexOf("\n", a));
})();
const outlineOpen = grab("if (item.open) item.open();", "\n");

const node = (cls) => {
  const set = new Set(String(cls).split(" ").filter(Boolean));
  const attrs = {};
  return {
    classList: { contains: (c) => set.has(c),
                 toggle: (c, on) => { if (on === undefined) { set.has(c) ? set.delete(c) : set.add(c); }
                                      else if (on) set.add(c); else set.delete(c); } },
    setAttribute: (k, v) => { attrs[k] = v; },
    get attrs() { return attrs; },
    get classes() { return [...set].join(" "); },
    handlers: {},
    addEventListener: function (n, f) { this.handlers[n] = f; },
  };
};

// One scope: a `const` declared inside its own eval does not leak to the next, so the toggle and the
// handler that calls it are assembled together, as they are in the file.
const body = `
  const block = node("deep-leg ok folded");
  const head = node("deep-leg-head");
  head.setAttribute("aria-expanded", "false");
  ${setLegFn}
  ${clickLine}
  const state = () => ({ folded: block.classList.contains("folded"), expanded: head.attrs["aria-expanded"] });
  const out = {};
  out.initial = state();
  head.handlers.click();
  out.afterFirstClick = state();
  head.handlers.click();
  out.afterSecondClick = state();
  // The left index must OPEN it, not only scroll to it: being sent to a folded block is the same
  // nothing-happened Henry reported on 24 Sep for folded cards.
  const item = { open: () => setLeg(true) };
  ${outlineOpen}
  out.afterOutlineClick = state();
  // ...and opening one that is already open must leave it open.
  item.open();
  out.afterOpeningTwice = state();
  return out;
`;
console.log(JSON.stringify(new Function("node", body)(node)));
