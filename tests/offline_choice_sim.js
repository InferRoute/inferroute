// The session page's gate before a search while the search machine is offline. Lifted from app.js: the button
// wordings it compares against, and asksForSearch() itself.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/probant_web/app.js", "utf8");
const pick = (start, end) => {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  if (a < 0 || b < 0) { console.error(`HARNESS: ${start} moved`); process.exit(2); }
  return src.slice(a, b);
};
const consts = ["  const DEEPER =", "  const LEAVE_OUT =", "  const SURVEY =", "  const DEEP =", "  const DEEP_FOCUSED ="]
  .map((c) => pick(c, "\n")).join("\n");
const ideas = pick("  const IDEAS = [", ";\n") + ";";
const fn = pick("  function asksForSearch(t) {", "\n  // Said BEFORE");
const asks = new Function("t", `${consts}\nconst SUMMARISE_IDEA = "x";\n${ideas}\n${fn}\nreturn asksForSearch(t);`);
const gated = src.includes("if (searchIsOffline && !nameSession && !readingSession && asksForSearch(t) && !(await offlineChoice())) return;");
const fromTrust = src.includes('searchIsOffline = (t.items || []).some((i) => i.key === "search" && i.offline);');
console.log(JSON.stringify({
  survey: asks("Run a prior-art survey of the disclosure"),
  typed: asks("please run a prior-art search on the lid"),
  like: asks("Find documents like US-1234567-B2"),
  chat: asks("Summarise the disclosure's key technical features"),
  gated, fromTrust,
}));
