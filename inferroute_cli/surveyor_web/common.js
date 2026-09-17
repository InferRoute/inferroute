// Shared by the Surveyor pages (the live session page and the home page). Builds TEXT NODES only: nothing
// received is parsed as markup, made a link, or used as a resource address. tests/test_surveyor_web.py and
// tests/test_surveyor_home.py grep this file for the constructs that would break that rule.
"use strict";

window.SurveyorUI = (() => {
  // ── DOM helpers: text only ──
  function el(tag, cls, ...children) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    for (const c of children) {
      if (c === null || c === undefined || c === false) continue;
      n.append(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    }
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  // A small formatter for the assistant's markdown: headings, lists, tables, code, **bold**, *italic*,
  // `code`. Links are shown as their text and address in plain type; images are not shown.
  function inline(text) {
    const frag = document.createDocumentFragment();
    const re = /(\*\*[^*\n]+\*\*|`[^`\n]+`|\*[^*\s][^*\n]*\*|\[[^\]\n]+\]\([^)\n]+\))/g;
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
      const t = m[0];
      if (t.startsWith("**")) frag.append(el("strong", "", t.slice(2, -2)));
      else if (t.startsWith("`")) frag.append(el("code", "", t.slice(1, -1)));
      else if (t.startsWith("[")) {
        const mm = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(t);
        frag.append(document.createTextNode(mm ? `${mm[1]} (${mm[2]})` : t));
      } else frag.append(el("em", "", t.slice(1, -1)));
      last = m.index + t.length;
    }
    if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
    return frag;
  }

  function markdown(src) {
    const out = document.createDocumentFragment();
    const lines = String(src || "").replace(/\r/g, "").split("\n");
    let i = 0;
    const isTable = (l) => /^\s*\|.*\|\s*$/.test(l);
    while (i < lines.length) {
      const line = lines[i];
      if (/^\s*```/.test(line)) {
        const buf = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
        i++;
        out.append(el("pre", "", el("code", "", buf.join("\n"))));
        continue;
      }
      if (!line.trim()) { i++; continue; }
      if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) { out.append(el("hr", "")); i++; continue; }
      const h = /^\s*#{1,6}\s+(.*)$/.exec(line);
      if (h) { out.append(el("h4", "", inline(h[1]))); i++; continue; }
      if (/^\s*!\[/.test(line)) { i++; continue; }
      if (isTable(line)) {
        const table = el("table", "");
        let header = true;
        while (i < lines.length && isTable(lines[i])) {
          const row = lines[i++];
          if (/^[\s|:-]+$/.test(row) && row.includes("-")) { header = false; continue; }   // | --- | :--: |
          const cells = row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|");
          const tr = el("tr", "");
          for (const c of cells) tr.append(el(header ? "th" : "td", "", inline(c.trim())));
          table.append(tr);
          header = false;
        }
        out.append(table);
        continue;
      }
      const ul = /^\s*[-*•]\s+(.*)$/, ol = /^\s*\d+[.)]\s+(.*)$/;
      if (ul.test(line) || ol.test(line)) {
        const ordered = ol.test(line) && !ul.test(line);
        const list = el(ordered ? "ol" : "ul", "");
        // Keep the model's own numbering: items separated by a paragraph are still 1, 2, 3, not 1, 1, 1.
        if (ordered) list.start = Number(/^\s*(\d+)/.exec(line)[1]) || 1;
        const re = ordered ? ol : ul;
        while (i < lines.length && re.test(lines[i])) list.append(el("li", "", inline(re.exec(lines[i++])[1])));
        out.append(list);
        continue;
      }
      const para = [];
      while (i < lines.length && lines[i].trim() && !/^\s*(#{1,6}\s|```|[-*•]\s|\d+[.)]\s|\||-{3,}\s*$)/.test(lines[i])) para.push(lines[i++].trim());
      if (!para.length) { para.push(lines[i++].trim()); }
      out.append(el("p", "", inline(para.join(" "))));
    }
    return out;
  }

  return { el, clear, inline, markdown };
})();
